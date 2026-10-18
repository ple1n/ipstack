use crate::{
    IpStackError, PacketRecver, PacketSender, TTL,
    packet::{IpHeader, NetworkPacket, TransportHeader},
};
use etherparse::{IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, UdpHeader};
use std::{future::Future, net::SocketAddr, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    time::Sleep,
};

#[derive(Debug)]
pub struct IpStackUdpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    stream_sender: PacketSender,
    stream_receiver: PacketRecver,
    up_pkt_sender: PacketSender,
    first_payload: Option<Vec<u8>>,
    timeout: Pin<Box<Sleep>>,
    timeout_interval: Duration,
    mtu: u16,
    destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
}

impl IpStackUdpStream {
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: Vec<u8>,
        up_pkt_sender: PacketSender,
        mtu: u16,
        timeout_interval: Duration,
        destroy_messenger: Option<::tokio::sync::oneshot::Sender<()>>,
    ) -> Self {
        let (stream_sender, stream_receiver) = mpsc::unbounded_channel::<NetworkPacket>();
        let deadline = tokio::time::Instant::now() + timeout_interval;
        IpStackUdpStream {
            src_addr,
            dst_addr,
            stream_sender,
            stream_receiver,
            up_pkt_sender,
            first_payload: Some(payload),
            timeout: Box::pin(tokio::time::sleep_until(deadline)),
            timeout_interval,
            mtu,
            destroy_messenger,
        }
    }

    pub(crate) fn stream_sender(&self) -> PacketSender {
        self.stream_sender.clone()
    }

    fn create_rev_packet(
        &self,
        remote_addr: SocketAddr,
        ttl: u8,
        mut payload: Vec<u8>,
    ) -> std::io::Result<NetworkPacket> {
        const UHS: usize = 8; // udp header size is 8
        match (remote_addr.ip(), self.src_addr.ip()) {
            (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
                let mut ip_h = Ipv4Header::new(0, ttl, IpNumber::UDP, src.octets(), dst.octets())
                    .map_err(IpStackError::from)?;
                let line_buffer = self.mtu.saturating_sub((ip_h.header_len() + UHS) as u16);
                payload.truncate(line_buffer as usize);
                ip_h.set_payload_len(payload.len() + UHS)
                    .map_err(IpStackError::from)?;
                let udp_header = UdpHeader::with_ipv4_checksum(
                    remote_addr.port(),
                    self.src_addr.port(),
                    &ip_h,
                    &payload,
                )
                .map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv4(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload: Some(payload),
                })
            }
            (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
                let mut ip_h = Ipv6Header {
                    traffic_class: 0,
                    flow_label: Ipv6FlowLabel::ZERO,
                    payload_length: 0,
                    next_header: IpNumber::UDP,
                    hop_limit: ttl,
                    source: src.octets(),
                    destination: dst.octets(),
                };
                let line_buffer = self.mtu.saturating_sub((ip_h.header_len() + UHS) as u16);

                payload.truncate(line_buffer as usize);

                ip_h.payload_length = (payload.len() + UHS) as u16;
                let udp_header = UdpHeader::with_ipv6_checksum(
                    remote_addr.port(),
                    self.src_addr.port(),
                    &ip_h,
                    &payload,
                )
                .map_err(IpStackError::from)?;
                Ok(NetworkPacket {
                    ip: IpHeader::Ipv6(ip_h),
                    transport: TransportHeader::Udp(udp_header),
                    payload: Some(payload),
                })
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP source and local destination address families differ",
            )),
        }
    }

    /// Inject a UDP datagram into the TUN stack with an explicit remote source.
    ///
    /// Use this when an intermediary (such as a SOCKS5 UDP relay) reports the
    /// datagram's source independently of the flow's original destination.
    pub fn write_datagram_from(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> std::io::Result<usize> {
        self.reset_timeout();
        let packet = self.create_rev_packet(remote_addr, TTL, payload.to_vec())?;
        let payload_len = packet.payload.as_ref().map_or(0, Vec::len);
        self.up_pkt_sender
            .send(packet)
            .map_err(|_| std::io::ErrorKind::UnexpectedEof)?;
        Ok(payload_len)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    fn reset_timeout(&mut self) {
        let deadline = tokio::time::Instant::now() + self.timeout_interval;
        self.timeout.as_mut().reset(deadline);
    }
}

impl AsyncRead for IpStackUdpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(p) = self.first_payload.take() {
            buf.put_slice(&p);
            return std::task::Poll::Ready(Ok(()));
        }
        if matches!(self.timeout.as_mut().poll(cx), std::task::Poll::Ready(_)) {
            return std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        }

        self.reset_timeout();

        match self.stream_receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(p)) => {
                if let Some(payload) = p.payload {
                    buf.put_slice(&payload);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for IpStackUdpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let remote_addr = self.dst_addr;
        std::task::Poll::Ready(self.write_datagram_from(remote_addr, buf))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for IpStackUdpStream {
    fn drop(&mut self) {
        if let Some(messenger) = self.destroy_messenger.take() {
            let _ = messenger.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn write_datagram_from_uses_reported_source_and_local_destination() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let local_addr = SocketAddr::from_str("10.8.0.2:51257").unwrap();
        let original_remote = SocketAddr::from_str("198.51.100.10:33429").unwrap();
        let reported_remote = SocketAddr::from_str("203.0.113.8:41844").unwrap();
        let mut stream = IpStackUdpStream::new(
            local_addr,
            original_remote,
            Vec::new(),
            sender,
            1500,
            Duration::from_secs(30),
            None,
        );

        assert_eq!(
            stream
                .write_datagram_from(reported_remote, b"reply")
                .unwrap(),
            5
        );

        let packet = receiver.try_recv().unwrap();
        assert_eq!(packet.src_addr(), reported_remote);
        assert_eq!(packet.dst_addr(), local_addr);
        assert_eq!(packet.payload.as_deref(), Some(&b"reply"[..]));
    }

    #[tokio::test]
    async fn write_uses_original_virtual_peer_as_reply_source() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let local_addr = SocketAddr::from_str("10.8.0.2:51257").unwrap();
        let virtual_peer = SocketAddr::from_str("198.18.0.9:3478").unwrap();
        let mut stream = IpStackUdpStream::new(
            local_addr,
            virtual_peer,
            Vec::new(),
            sender,
            1500,
            Duration::from_secs(30),
            None,
        );

        stream.write_all(b"reply").await.unwrap();

        let packet = receiver.try_recv().unwrap();
        assert_eq!(packet.src_addr(), virtual_peer);
        assert_eq!(packet.dst_addr(), local_addr);
        assert_eq!(packet.payload.as_deref(), Some(&b"reply"[..]));
    }

    #[tokio::test]
    async fn write_datagram_from_rejects_mixed_address_families() {
        let (sender, _receiver) = mpsc::unbounded_channel();
        let mut stream = IpStackUdpStream::new(
            "[fd00::2]:51257".parse().unwrap(),
            "198.51.100.10:33429".parse().unwrap(),
            Vec::new(),
            sender,
            1500,
            Duration::from_secs(30),
            None,
        );

        let error = stream
            .write_datagram_from("203.0.113.8:41844".parse().unwrap(), b"reply")
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
