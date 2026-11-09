An asynchronous lightweight implementation of TCP/IP stack for Tun device.
Unstable, under development.

### Usage
````rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use udp_stream::UdpStream;
use tokio::io{AsyncRead, AsyncWrite};
async fn copy_from_lhs_to_rhs(lhs:impl AsyncRead + AsyncWrite, rhs:impl AsyncRead + AsyncWrite){
	let (lhs_reader,lhs_writer) = tokio::io::split(lhs);
	let (rhs_reader, rhs_writer) = tokio::io::split(rhs);
        tokio::join! {
		tokio::io::copy(&mut lhs_reader, &mut rhs_writer) ,
		tokio::io::copy(&mut rhs_reader, &mut lhs_writer),
        }
}
#[tokio::main]
async fn main(){
	const MTU: u16 = 1500;
	let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
	let mut config = tun::Configuration::default();
        config
         .address(ipv4)
         .netmask((255, 255, 255, 0))
         .mtu(MTU as i32)
         .up();

        let mut ipstack_config = ipstack::IpStackConfig::default();
        ipstack_config.mtu(MTU);
        ipstack_config.packet_info(cfg!(target_family = "unix"));
	let mut ip_stack = ipstack::IpStack::new(ipstack_config,tun::create_as_async(&config).unwrap());
	while let Ok(stream) = ip_stack.accept().await{
		match stream{
			IpStackStream::Tcp(tcp) => {
				let rhs = TcpStream::connect("1.1.1.1:80").await.unwrap();
				tokio::spawn(async move {
                                  copy_from_lhs_to_rhs(tcp,rhs).await;
                                });
			}
			IpStackStream::Udp(udp) => {
                              let rhs = UdpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)).await.unwrap();
                              tokio::spawn(async move {
                                 copy_from_lhs_to_rhs(udp,rhs).await;
                              });	
			}
		}
	}
}
````

### Embedded packet I/O and outbound TCP

`IpStack::new` remains the TUN-device entry point. Embedders can instead implement
`PacketIo` to exchange raw IP packets with another transport and construct the stack
with `IpStack::new_with_packet_io`. The same stack can initiate TCP connections with
`connect_tcp(local_addr, peer_addr)`; the local address must be concrete, use a
nonzero port, and match the peer's IP version. This returns the same
`IpStackTcpStream` type used by accepted TUN connections.

We also suggest that you take a look at the complete [examples](https://github.com/narrowlink/ipstack/tree/main/examples).
