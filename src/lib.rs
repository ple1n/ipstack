use dashmap::{DashMap, OccupiedEntry, mapref};
pub use error::IpStackError;
use futures::{
    SinkExt,
    future::{Join, JoinAll, join_all},
};
use packet::{NetworkPacket, NetworkTuple};
use std::{
    collections::{
        HashMap,
        hash_map::Entry::{Occupied, Vacant},
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
    packet::TransportHeader,
    stream::{IpStackTcpStream, IpStackUdpStream, tcp::TcpConfig},
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

#[derive(Clone)]
pub struct IpStackConfig {
    pub mtu: u16,
    pub packet_information: bool,
    pub tcp_config: Arc<TcpConfig>,
    pub udp_timeout: Duration,
}

impl Default for IpStackConfig {
    fn default() -> Self {
        IpStackConfig {
            mtu: u16::MAX,
            packet_information: false,
            tcp_config: Arc::new(TcpConfig::default()),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

impl IpStackConfig {
    /// Set custom TCP configuration
    pub fn with_tcp_config(&mut self, config: TcpConfig) -> &mut Self {
        self.tcp_config = Arc::new(config);
        self
    }
    pub fn udp_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.udp_timeout = timeout;
        self
    }
    pub fn mtu(&mut self, mtu: u16) -> &mut Self {
        self.mtu = mtu;
        self
    }
    pub fn packet_information(&mut self, packet_information: bool) -> &mut Self {
        self.packet_information = packet_information;
        self
    }
}

pub struct IpStack {
    accept_receiver: UnboundedReceiver<IpStackStream>,
}

impl IpStack {
    pub fn new(config: IpStackConfig, mut device: TUNDev) -> IpStack {
        let (accept_sender, accept_receiver) = mpsc::unbounded_channel::<IpStackStream>();
        let config2 = config.clone();
        tokio::spawn(async move {
            let streams: Arc<DashMap<NetworkTuple, PacketSender>> = DashMap::new().into();

            let (pkt_sender, pkt_receiver) = make_packet_channel();
            let pkt_sender2 = pkt_sender.clone();            
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
                        let offset =
                            if config.packet_information && cfg!(not(target_os = "windows")) {
                                4
                            } else {
                                0
                            };
                        let config = config.clone();

                        loop {
                            let mut buffer = [0u8; u16::MAX as usize];
                            let config = config.clone();
                            let pkt_sender = pkt_sender.clone();
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

                                        // Helper to create and register a new stream
                                        let create_stream = |packet: NetworkPacket| -> Result<(), IpStackError> {
                                            let tuple = packet.network_tuple();
                                            let (tx, _rx) = tokio::sync::oneshot::channel::<()>();
                                            trace!("new {}", &tuple);
                                            
                                            match packet.transport_header() {
                                                TransportHeader::Tcp(h) => {
                                                    match IpStackTcpStream::new(
                                                        packet.src_addr(),
                                                        packet.dst_addr(),
                                                        h.clone(),
                                                        pkt_sender.clone(),
                                                        config.mtu,
                                                        Some(tx),
                                                        config.tcp_config.clone(),
                                                    ) {
                                                        Ok(stream) => {
                                                            streams.insert(tuple, stream.stream_sender());
                                                            stream_sx
                                                                .send(IpStackStream::Tcp(stream))
                                                                .unwrap();
                                                        }
                                                        Err(e) => {
                                                            error!("{}", e);
                                                        }
                                                    }
                                                }
                                                TransportHeader::Udp(_) => {
                                                    let stream = IpStackUdpStream::new(
                                                        packet.src_addr(),
                                                        packet.dst_addr(),
                                                        packet.payload.unwrap_or_default(),
                                                        pkt_sx.clone(),
                                                        config.mtu,
                                                        config.udp_timeout,
                                                        Some(tx),
                                                    );
                                                    streams.insert(tuple, stream.stream_sender());
                                                    stream_sx
                                                        .send(IpStackStream::Udp(stream))
                                                        .unwrap();
                                                }
                                                TransportHeader::Unknown => {
                                                    return Err(IpStackError::UnsupportedTransportProtocol);
                                                }
                                            }
                                            Ok(())
                                        };

                                        // For TCP, only attempt to create a new stream for SYN packets.
                                        // Non-SYN packets arriving for an unknown or dead stream are
                                        // late/retransmitted segments — silently discard them.
                                        let is_tcp_syn = matches!(
                                            packet.transport_header(),
                                            TransportHeader::Tcp(h) if h.syn
                                        );
                                        let is_tcp = matches!(
                                            packet.transport_header(),
                                            TransportHeader::Tcp(_)
                                        );

                                        let tuple = packet.network_tuple();
                                        match streams.entry(tuple) {
                                            mapref::entry::Entry::Occupied(entry) => {
                                                trace!("known {}", &tuple);
                                                let sx = entry.get();
                                                match sx.send(packet) {
                                                    Ok(_) => {}
                                                    Err(send_err) => {
                                                        drop(entry);
                                                        streams.remove(&tuple);
                                                        let packet = send_err.0;
                                                        if is_tcp && !is_tcp_syn {
                                                            // Stream is gone; late non-SYN packet, discard quietly.
                                                            trace!("stream dead, discarding non-SYN packet for {:?}", &tuple);
                                                        } else {
                                                            warn!("stream dead, recreating {:?}", &tuple);
                                                            create_stream(packet)?;
                                                        }
                                                    }
                                                }
                                            }
                                            mapref::entry::Entry::Vacant(entry) => {
                                                drop(entry);
                                                if is_tcp && !is_tcp_syn {
                                                    // No existing stream and not a SYN — late/stray packet, discard.
                                                    trace!("no stream, discarding non-SYN TCP packet for {:?}", &tuple);
                                                } else {
                                                    create_stream(packet)?;
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
                    let config = config2;
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
                            if config.packet_information {
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
            let pkt_sender=  pkt_sender2.clone();
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
