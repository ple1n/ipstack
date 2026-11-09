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
    io,
    net::SocketAddr,
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

struct TcpConnectRequest {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    result: tokio::sync::oneshot::Sender<Result<IpStackTcpStream, IpStackError>>,
}

/// Exchanges complete IP packets with the stack.
///
/// Packets are passed without an Ethernet header. On non-Windows targets, when
/// `IpStackConfig::packet_information` is enabled, the four-byte TUN packet-information
/// prefix is included in `receive` and `send_packet` buffers.
pub trait PacketIo: Send + Sync + 'static {
    fn receive<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send + 'a;
    fn send_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> impl std::future::Future<Output = io::Result<()>> + Send + 'a;
}

struct TunPacketIo(TUNDev);

impl PacketIo for TunPacketIo {
    fn receive<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send + 'a {
        async move { self.0.recv(buffer).await }
    }

    fn send_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> impl std::future::Future<Output = io::Result<()>> + Send + 'a {
        async move {
            let written = self.0.send(packet).await?;
            if written != packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TUN device accepted only part of an IP packet",
                ));
            }
            Ok(())
        }
    }
}

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
    connect_sender: UnboundedSender<TcpConnectRequest>,
}

impl IpStack {
    pub fn new(config: IpStackConfig, device: TUNDev) -> IpStack {
        Self::new_with_packet_io(config, TunPacketIo(device))
    }

    /// Creates a stack backed by an asynchronous packet transport instead of a TUN device.
    pub fn new_with_packet_io<D: PacketIo>(config: IpStackConfig, device: D) -> IpStack {
        let (accept_sender, accept_receiver) = mpsc::unbounded_channel::<IpStackStream>();
        let (connect_sender, mut connect_receiver) = mpsc::unbounded_channel::<TcpConnectRequest>();
        let config2 = config.clone();
        let device = Arc::new(device);
        tokio::spawn(async move {
            let streams: Arc<DashMap<NetworkTuple, PacketSender>> = DashMap::new().into();

            let (pkt_sender, pkt_receiver) = make_packet_channel();
            let pkt_sender2 = pkt_sender.clone();
            let connect_streams = streams.clone();
            let connect_packet_sender = pkt_sender.clone();
            let connect_mtu = config.mtu;
            let connect_config = config.tcp_config.clone();
            tokio::spawn(async move {
                while let Some(request) = connect_receiver.recv().await {
                    let tuple = NetworkTuple::new(request.peer_addr, request.local_addr, true);
                    let mut stream = IpStackTcpStream::new_client(
                        request.local_addr,
                        request.peer_addr,
                        connect_packet_sender.clone(),
                        connect_mtu,
                        connect_config.clone(),
                    );
                    let occupied = match connect_streams.entry(tuple) {
                        mapref::entry::Entry::Occupied(_) => true,
                        mapref::entry::Entry::Vacant(entry) => {
                            entry.insert(stream.stream_sender());
                            false
                        }
                    };
                    if occupied {
                        let _ = request
                            .result
                            .send(Err(IpStackError::IoError(io::Error::new(
                                io::ErrorKind::AddrInUse,
                                "TCP flow already exists",
                            ))));
                        continue;
                    }

                    let handshake = match stream.start_connect() {
                        Ok(handshake) => handshake,
                        Err(error) => {
                            connect_streams.remove(&tuple);
                            let _ = request.result.send(Err(IpStackError::IoError(error)));
                            continue;
                        }
                    };

                    let streams = connect_streams.clone();
                    let timeout = connect_config.timeout;
                    tokio::spawn(async move {
                        let result = tokio::time::timeout(timeout, handshake).await;
                        match result {
                            Ok(Ok(Ok(()))) => {
                                let _ = request.result.send(Ok(stream));
                            }
                            Ok(Ok(Err(error))) => {
                                streams.remove(&tuple);
                                let _ = request.result.send(Err(IpStackError::IoError(error)));
                            }
                            Ok(Err(_)) => {
                                streams.remove(&tuple);
                                let _ = request.result.send(Err(IpStackError::IoError(
                                    io::Error::new(
                                        io::ErrorKind::ConnectionAborted,
                                        "TCP connection task stopped during handshake",
                                    ),
                                )));
                            }
                            Err(_) => {
                                streams.remove(&tuple);
                                let _ = request.result.send(Err(IpStackError::IoError(
                                    io::Error::new(
                                        io::ErrorKind::TimedOut,
                                        "TCP connection timed out",
                                    ),
                                )));
                            }
                        }
                    });
                }
            });
            // This only applies to linux. see multi-queue
            const CONCURRENCY: usize = 1;

            // In this fn the device is only cloned once, to create reader and writer.
            let single_dev =
                |dev: Arc<D>,
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
                            match dev_rx.receive(&mut buffer).await {
                                Ok(len) => {
                                    trace!(
                                        "read {} from dev {:?}",
                                        len,
                                        UNIX_EPOCH.elapsed().map(|k| k.as_millis())
                                    );
                                    if len > buffer.len() || len < offset {
                                        warn!(
                                            "packet transport returned invalid packet length {len}"
                                        );
                                        continue;
                                    }
                                    let parse = NetworkPacket::parse(&buffer[offset..len]);
                                    let Ok(packet) = parse else {
                                        debug!("packet parse error {:?}", parse.err());
                                        continue;
                                    };

                                    let is_tcp_syn = matches!(
                                        packet.transport_header(),
                                        TransportHeader::Tcp(h) if h.syn
                                    );
                                    let is_tcp = matches!(
                                        packet.transport_header(),
                                        TransportHeader::Tcp(_)
                                    );
                                    let tuple = packet.network_tuple();

                                    // Try dispatching to existing stream.
                                    // Release the DashMap read-lock before any write operation.
                                    let packet = match streams.get(&tuple) {
                                        Some(sender_ref) => match sender_ref.send(packet) {
                                            Ok(_) => {
                                                trace!("known {}", &tuple);
                                                continue;
                                            }
                                            Err(send_err) => {
                                                drop(sender_ref);
                                                streams.remove(&tuple);
                                                let packet = send_err.0;
                                                if is_tcp && !is_tcp_syn {
                                                    trace!(
                                                        "stream dead, discarding non-SYN packet for {:?}",
                                                        &tuple
                                                    );
                                                    continue;
                                                }
                                                warn!("stream dead, recreating {:?}", &tuple);
                                                packet
                                            }
                                        },
                                        None => {
                                            if is_tcp && !is_tcp_syn {
                                                trace!(
                                                    "no stream, discarding non-SYN TCP packet for {:?}",
                                                    &tuple
                                                );
                                                continue;
                                            }
                                            packet
                                        }
                                    };

                                    // Create and register a new stream
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
                                            stream_sx.send(IpStackStream::Udp(stream)).unwrap();
                                        }
                                        TransportHeader::Unknown => {
                                            info!("unsupported transport protocol");
                                        }
                                    }
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
                            trace!("write {} to dev", packet_byte.len());
                            dev_sx.send_packet(&packet_byte).await.unwrap();
                        }
                        error!("device writer stopped");
                    };

                    futures::join!(send_to_dev, from_dev)
                };
            let pkt_sender = pkt_sender2.clone();
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

        IpStack {
            accept_receiver,
            connect_sender,
        }
    }

    /// Initiates a TCP connection through this stack using the provided local and peer addresses.
    ///
    /// The local address supplies the source IP and port for packets sent through `PacketIo`.
    pub async fn connect_tcp(
        &self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Result<IpStackTcpStream, IpStackError> {
        if local_addr.is_ipv4() != peer_addr.is_ipv4()
            || local_addr.port() == 0
            || peer_addr.port() == 0
            || local_addr.ip().is_unspecified()
            || peer_addr.ip().is_unspecified()
        {
            return Err(IpStackError::IoError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP connection requires concrete, nonzero local and peer addresses",
            )));
        }

        let (result, receiver) = tokio::sync::oneshot::channel();
        self.connect_sender
            .send(TcpConnectRequest {
                local_addr,
                peer_addr,
                result,
            })
            .map_err(|_| {
                IpStackError::IoError(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "IP stack connection manager stopped",
                ))
            })?;
        receiver.await.map_err(|_| {
            IpStackError::IoError(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "IP stack dropped the connection request",
            ))
        })?
    }

    pub async fn accept(&mut self) -> Result<IpStackStream, IpStackError> {
        if let Some(s) = self.accept_receiver.recv().await {
            Ok(s)
        } else {
            Err(IpStackError::AcceptError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        packet::{TransportHeader, tcp_header_flags},
        stream::tcp::{TcpOptions, create_raw_packet},
    };
    use tokio::sync::Mutex;

    struct ChannelPacketIo {
        incoming: Mutex<UnboundedReceiver<Vec<u8>>>,
        outgoing: UnboundedSender<Vec<u8>>,
    }

    impl PacketIo for ChannelPacketIo {
        fn receive<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> impl std::future::Future<Output = io::Result<usize>> + Send + 'a {
            async move {
                let packet = self.incoming.lock().await.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "test input closed")
                })?;
                if packet.len() > buffer.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "test packet exceeds receive buffer",
                    ));
                }
                buffer[..packet.len()].copy_from_slice(&packet);
                Ok(packet.len())
            }
        }

        fn send_packet<'a>(
            &'a self,
            packet: &'a [u8],
        ) -> impl std::future::Future<Output = io::Result<()>> + Send + 'a {
            async move {
                self.outgoing
                    .send(packet.to_vec())
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test output closed"))
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn packet_io_supports_outbound_tcp_and_preserves_stream_api() {
        let (peer_to_stack, peer_packets) = mpsc::unbounded_channel();
        let (stack_to_peer, mut stack_packets) = mpsc::unbounded_channel();
        let stack = IpStack::new_with_packet_io(
            IpStackConfig::default(),
            ChannelPacketIo {
                incoming: Mutex::new(peer_packets),
                outgoing: stack_to_peer,
            },
        );
        let local_addr = "10.0.0.2:40000".parse().unwrap();
        let peer_addr = "203.0.113.1:443".parse().unwrap();
        let connect_task =
            tokio::spawn(async move { stack.connect_tcp(local_addr, peer_addr).await });

        let syn_bytes = tokio::time::timeout(Duration::from_secs(2), stack_packets.recv())
            .await
            .unwrap()
            .unwrap();
        let syn = NetworkPacket::parse(&syn_bytes).unwrap();
        assert_eq!(syn.src_addr(), local_addr);
        assert_eq!(syn.dst_addr(), peer_addr);
        let TransportHeader::Tcp(syn_header) = syn.transport_header() else {
            panic!("expected TCP SYN");
        };
        assert!(syn_header.syn);
        assert!(!syn_header.ack);
        let client_syn_seq = syn_header.sequence_number;

        let syn_ack_options = vec![TcpOptions::MaximumSegmentSize(4)];
        let syn_ack = create_raw_packet(
            peer_addr,
            local_addr,
            |_, _| 1500,
            crate::packet::tcp_flags::SYN | crate::packet::tcp_flags::ACK,
            TTL,
            1000,
            client_syn_seq.wrapping_add(1),
            u16::MAX,
            Vec::new(),
            Some(&syn_ack_options),
        )
        .unwrap();
        peer_to_stack.send(syn_ack.to_bytes().unwrap()).unwrap();

        let mut stream = tokio::time::timeout(Duration::from_secs(2), connect_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(stream.local_addr(), local_addr);
        assert_eq!(stream.peer_addr(), peer_addr);

        let ack_bytes = tokio::time::timeout(Duration::from_secs(2), stack_packets.recv())
            .await
            .unwrap()
            .unwrap();
        let ack = NetworkPacket::parse(&ack_bytes).unwrap();
        let TransportHeader::Tcp(ack_header) = ack.transport_header() else {
            panic!("expected TCP ACK");
        };
        assert_eq!(tcp_header_flags(ack_header), crate::packet::tcp_flags::ACK);

        let response = create_raw_packet(
            peer_addr,
            local_addr,
            |_, _| 1500,
            crate::packet::tcp_flags::ACK | crate::packet::tcp_flags::PSH,
            TTL,
            1001,
            client_syn_seq.wrapping_add(1),
            u16::MAX,
            b"hello".to_vec(),
            None,
        )
        .unwrap();
        peer_to_stack.send(response.to_bytes().unwrap()).unwrap();

        let mut response_bytes = [0; 5];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut response_bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response_bytes, b"hello");

        let response_ack = tokio::time::timeout(Duration::from_secs(2), stack_packets.recv())
            .await
            .unwrap()
            .unwrap();
        let response_ack = NetworkPacket::parse(&response_ack).unwrap();
        let TransportHeader::Tcp(response_ack_header) = response_ack.transport_header() else {
            panic!("expected TCP ACK");
        };
        assert_eq!(
            tcp_header_flags(response_ack_header),
            crate::packet::tcp_flags::ACK
        );

        tokio::io::AsyncWriteExt::write_all(&mut stream, b"request")
            .await
            .unwrap();
        let first_request_bytes =
            tokio::time::timeout(Duration::from_secs(2), stack_packets.recv())
                .await
                .unwrap()
                .unwrap();
        let first_request = NetworkPacket::parse(&first_request_bytes).unwrap();
        assert_eq!(first_request.src_addr(), local_addr);
        assert_eq!(first_request.dst_addr(), peer_addr);
        assert_eq!(first_request.payload.as_deref(), Some(b"requ".as_slice()));

        let second_request_bytes =
            tokio::time::timeout(Duration::from_secs(2), stack_packets.recv())
                .await
                .unwrap()
                .unwrap();
        let second_request = NetworkPacket::parse(&second_request_bytes).unwrap();
        assert_eq!(second_request.payload.as_deref(), Some(b"est".as_slice()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn outbound_tcp_reports_connection_refusal() {
        let (peer_to_stack, peer_packets) = mpsc::unbounded_channel();
        let (stack_to_peer, mut stack_packets) = mpsc::unbounded_channel();
        let stack = IpStack::new_with_packet_io(
            IpStackConfig::default(),
            ChannelPacketIo {
                incoming: Mutex::new(peer_packets),
                outgoing: stack_to_peer,
            },
        );
        let local_addr = "10.0.0.2:40001".parse().unwrap();
        let peer_addr = "203.0.113.1:443".parse().unwrap();
        let connect_task =
            tokio::spawn(async move { stack.connect_tcp(local_addr, peer_addr).await });

        let syn_bytes = tokio::time::timeout(Duration::from_secs(2), stack_packets.recv())
            .await
            .unwrap()
            .unwrap();
        let syn = NetworkPacket::parse(&syn_bytes).unwrap();
        let TransportHeader::Tcp(syn_header) = syn.transport_header() else {
            panic!("expected TCP SYN");
        };
        let client_syn_seq = syn_header.sequence_number;
        let retransmitted_bytes =
            tokio::time::timeout(Duration::from_secs(2), stack_packets.recv())
                .await
                .unwrap()
                .unwrap();
        let retransmitted = NetworkPacket::parse(&retransmitted_bytes).unwrap();
        let TransportHeader::Tcp(retransmitted_header) = retransmitted.transport_header() else {
            panic!("expected retransmitted TCP SYN");
        };
        assert!(retransmitted_header.syn);
        assert_eq!(retransmitted_header.sequence_number, client_syn_seq);

        let reset = create_raw_packet(
            peer_addr,
            local_addr,
            |_, _| 1500,
            crate::packet::tcp_flags::RST | crate::packet::tcp_flags::ACK,
            TTL,
            1000,
            client_syn_seq.wrapping_add(1),
            u16::MAX,
            Vec::new(),
            None,
        )
        .unwrap();
        peer_to_stack.send(reset.to_bytes().unwrap()).unwrap();

        let error = tokio::time::timeout(Duration::from_secs(2), connect_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            error,
            IpStackError::IoError(ref io_error)
                if io_error.kind() == io::ErrorKind::ConnectionRefused
        ));
    }
}
