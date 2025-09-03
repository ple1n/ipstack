use dashmap::{mapref, DashMap, OccupiedEntry};
pub use error::IpStackError;
use futures::{
    future::{join_all, Join, JoinAll},
    SinkExt,
};
use packet::{NetworkPacket, NetworkTuple};
use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use stream::IpStackStream;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
    sync::{
        self,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
    time::Instant,
};
use tracing::{debug, error, info, trace, warn};
use tun_rs::AsyncDevice;

use crate::{
    packet::IpStackPacketProtocol,
    stream::{IpStackTcpStream, IpStackUdpStream},
};
mod error;
mod packet;
pub mod stream;
pub use flume;

pub type TUNDev = Arc<AsyncDevice>;
pub type Sender<T> = mpsc::UnboundedSender<T>;
pub type Recver<T> = mpsc::UnboundedReceiver<T>;
pub type PacketSender = Sender<NetworkPacket>;
pub type PacketRecver = Recver<NetworkPacket>;

pub fn make_packet_channel() -> (PacketSender, PacketRecver) {
    mpsc::unbounded_channel()
}

const DROP_TTL: u8 = 0;

#[cfg(not(target_os = "windows"))]
const TTL: u8 = 64;

#[cfg(target_os = "windows")]
const TTL: u8 = 128;

#[cfg(not(target_os = "windows"))]
const TUN_FLAGS: [u8; 2] = [0x00, 0x00];

#[cfg(target_os = "linux")]
const TUN_PROTO_IP6: [u8; 2] = [0x86, 0xdd];
#[cfg(target_os = "linux")]
const TUN_PROTO_IP4: [u8; 2] = [0x08, 0x00];

#[cfg(target_os = "macos")]
const TUN_PROTO_IP6: [u8; 2] = [0x00, 0x02];
#[cfg(target_os = "macos")]
const TUN_PROTO_IP4: [u8; 2] = [0x00, 0x02];

pub struct IpStackConfig {
    pub mtu: u16,
    pub packet_info: bool,
    pub tcp_timeout: Duration,
    pub udp_timeout: Duration,
}

impl Default for IpStackConfig {
    fn default() -> Self {
        IpStackConfig {
            mtu: u16::MAX,
            packet_info: false,
            tcp_timeout: Duration::from_secs(60),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

impl IpStackConfig {
    pub fn tcp_timeout(&mut self, timeout: Duration) {
        self.tcp_timeout = timeout;
    }
    pub fn udp_timeout(&mut self, timeout: Duration) {
        self.udp_timeout = timeout;
    }
    pub fn mtu(&mut self, mtu: u16) {
        self.mtu = mtu;
    }
    pub fn packet_info(&mut self, packet_info: bool) {
        self.packet_info = packet_info;
    }
}

pub struct IpStack {
    accept_receiver: UnboundedReceiver<IpStackStream>,
}

impl IpStack {
    pub fn new(config: IpStackConfig, mut device: TUNDev) -> IpStack {
        let (accept_sender, accept_receiver) = mpsc::unbounded_channel::<IpStackStream>();

        tokio::spawn(async move {
            let streams: Arc<DashMap<NetworkTuple, PacketSender>> = DashMap::new().into();

            let (pkt_sender, pkt_receiver) = make_packet_channel();
            // This only applies to linux. see multi-queue
            const CONCURRENCY: usize = 1;

            // In this fn the device is only cloned once, to create reader and writer.
            let single_dev =
                |dev: TUNDev,
                 streams: Arc<DashMap<NetworkTuple, PacketSender>>,
                 mut pkt_recv: PacketRecver,
                 pkt_sx: PacketSender,
                 stream_sx: UnboundedSender<IpStackStream>| async {
                    let dev_sx = dev;
                    let dev_rx = dev_sx.clone();
                    let streams1 = streams.clone();
                    let from_dev = async move {
                        let streams = streams1;
                        let offset = if config.packet_info && cfg!(not(target_os = "windows")) {
                            4
                        } else {
                            0
                        };
                        loop {
                            let mut buffer = [0u8; u16::MAX as usize];
                            match dev_rx.recv(&mut buffer).await {
                                Ok(len) => {
                                    trace!(
                                        "read {} from dev {:?}",
                                        len,
                                        UNIX_EPOCH.elapsed().map(|k| k.as_millis())
                                    );
                                    let streams = streams.clone();
                                    let pkt_sx = pkt_sx.clone();
                                    let stream_sx = stream_sx.clone();
                                    tokio::spawn(async move {
                                        let parse = NetworkPacket::parse(&buffer[offset..len]);
                                        let Ok(packet) = parse else {
                                            debug!("packet parse error {:?}", parse.err());
                                            return Ok(());
                                        };
                                        // info!("from dev {:?}", &packet.network_tuple());

                                        match streams.entry(packet.network_tuple()) {
                                            mapref::entry::Entry::Occupied(entry) => {
                                                trace!("known {}", &packet.network_tuple());
                                                let sx = entry.get();
                                                let sending = sx.send(packet);
                                                if let Err(e) = sending {
                                                    error!("sending packet to stack {:?}", e);
                                                    return Result::<(), IpStackError>::Ok(());
                                                }
                                            }
                                            mapref::entry::Entry::Vacant(entry) => {
                                                trace!("new {}", &packet.network_tuple());
                                                match packet.transport_protocol() {
                                                    IpStackPacketProtocol::Tcp(h) => {
                                                        match IpStackTcpStream::new(
                                                            packet.src_addr(),
                                                            packet.dst_addr(),
                                                            h,
                                                            pkt_sx.clone(),
                                                            config.mtu,
                                                            config.tcp_timeout,
                                                        )
                                                        .await
                                                        {
                                                            Ok(stream) => {
                                                                entry
                                                                    .insert(stream.stream_sender());
                                                                stream_sx
                                                                    .send(IpStackStream::Tcp(
                                                                        stream,
                                                                    ))
                                                                    .unwrap();
                                                            }
                                                            Err(e) => {
                                                                error!("{}", e);
                                                            }
                                                        }
                                                    }
                                                    IpStackPacketProtocol::Udp => {
                                                        let stream = IpStackUdpStream::new(
                                                            packet.src_addr(),
                                                            packet.dst_addr(),
                                                            packet.payload,
                                                            pkt_sx.clone(),
                                                            config.mtu,
                                                            config.udp_timeout,
                                                        );
                                                        entry.insert(stream.stream_sender());
                                                        stream_sx
                                                            .send(IpStackStream::Udp(stream))
                                                            .unwrap();
                                                    }
                                                }
                                            }
                                        }
                                        Result::<(), IpStackError>::Ok(())
                                    });
                                }
                                Err(ex) => {
                                    warn!("tun read {:?}", ex);
                                }
                            }
                        }
                    };

                    let send_to_dev = async move {
                        trace!("send_to_dev");
                        while let Some(packet) = pkt_recv.recv().await {
                            trace!("send packet to dev");
                            if packet.ttl() == 0 {
                                streams.remove(&packet.reverse_network_tuple());
                                trace!("removed {:?}", &packet.reverse_network_tuple());
                                // If the tuple is not removed properly, and the connection is in fact broken
                                // The user may start another connection reusing the tuple, causing packets to get sent into wrong place.
                                continue;
                            }
                            #[cfg(not(target_os = "windows"))]
                            let Ok(mut packet_byte) = packet.to_bytes() else {
                                trace!("to_bytes error");
                                continue;
                            };
                            #[cfg(target_os = "windows")]
                            let Ok(packet_byte) = packet.to_bytes() else {
                                trace!("to_bytes error");
                                continue;
                            };
                            #[cfg(not(target_os = "windows"))]
                            if config.packet_info {
                                if packet.src_addr().is_ipv4() {
                                    packet_byte.splice(0..0, [TUN_FLAGS, TUN_PROTO_IP4].concat());
                                } else {
                                    packet_byte.splice(0..0, [TUN_FLAGS, TUN_PROTO_IP6].concat());
                                }
                            }
                            let dev_sx = dev_sx.clone();
                            tokio::spawn(async move {
                                trace!("write {} to dev", packet_byte.len());
                                dev_sx.send(&packet_byte).await.unwrap();
                            });
                        }
                        error!("device writer stopped");
                    };

                    futures::join!(send_to_dev, from_dev)
                };

            single_dev(device, streams, pkt_receiver, pkt_sender, accept_sender).await

            // let mut fut = vec![];
            // for _ in 0..CONCURRENCY {
            //     let dev = Arc::new(device.try_clone().unwrap());
            //     fut.push(single_dev(
            //         dev,
            //         streams.clone(),
            //         pkt_receiver.clone(),
            //         pkt_sender.clone(),
            //         accept_sender.clone(),
            //     ));
            // }
            // join_all(fut).await;
        });

        IpStack { accept_receiver }
    }
    pub async fn accept(&mut self) -> Result<IpStackStream, IpStackError> {
        if let Some(s) = self.accept_receiver.recv().await {
            Ok(s)
        } else {
            Err(IpStackError::AcceptError)
        }
    }
}
