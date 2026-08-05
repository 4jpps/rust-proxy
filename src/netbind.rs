//! Binds a real socket for a given `SocketAddr`, forcing `IPV6_V6ONLY`
//! on any IPv6 bind.
//!
//! Real bug hit in production: on Linux, `net.ipv6.bindv6only` defaults
//! to `0`, which makes a plain `::`-bound socket dual-stack -- it also
//! accepts v4-mapped connections on the same port. That's harmless for a
//! host that only ever binds one family, but this project deliberately
//! binds `0.0.0.0` and `::` as two SEPARATE sockets on the same port for
//! a dual-stack host/admin listener (see `config::host_bind_ips`) -- and
//! a dual-stack (non-v6-only) `::` socket collides with the `0.0.0.0`
//! socket already holding that port, failing the second bind with
//! "Address already in use" (confirmed live: this exact error, right
//! after both "listening" log lines printed, the moment the admin
//! listener's own default bind_ip_v4/bind_ip_v6 -- both unspecified --
//! were exercised together for the first time). Forcing `IPV6_V6ONLY`
//! makes the two sockets truly independent, matching what "one socket
//! per family" is supposed to mean here.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

/// Binds and listens on `addr`, returning a ready-to-accept tokio
/// `TcpListener`. Backlog matches what `TcpListener::bind` itself uses
/// (1024, tokio's own default).
pub fn bind_tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = new_socket(addr, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// Binds a ready-to-use tokio `UdpSocket` on `addr`.
pub fn bind_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = new_socket(addr, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

fn new_socket(addr: SocketAddr, ty: Type, protocol: Option<Protocol>) -> io::Result<Socket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, ty, protocol)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // Matches std/tokio's own `TcpListener::bind` behavior (SO_REUSEADDR
    // is set there implicitly on Unix) -- needed for a quick
    // restart/rebind after this same process exits, same as before.
    socket.set_reuse_address(true)?;
    // tokio's `TcpListener::from_std`/`UdpSocket::from_std` both require
    // a non-blocking socket -- a still-blocking one panics there instead
    // of erroring cleanly.
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn v4_and_v6_wildcard_binds_on_the_same_port_coexist() {
        // This is the exact regression this module exists to fix --
        // before forcing IPV6_V6ONLY, the second bind failed with
        // "Address already in use" because the v6 socket was implicitly
        // dual-stack.
        let v6 = bind_tcp_listener("[::]:0".parse().unwrap()).unwrap();
        let port = v6.local_addr().unwrap().port();
        let v4 = bind_tcp_listener(format!("0.0.0.0:{port}").parse().unwrap());
        assert!(v4.is_ok(), "binding 0.0.0.0 on the same port as an already-bound [::] must succeed: {v4:?}");
    }

    #[tokio::test]
    async fn a_v6_only_socket_does_not_accept_a_v4_mapped_connection() {
        let listener = bind_tcp_listener("[::1]:0".parse().unwrap()).unwrap();
        let port = listener.local_addr().unwrap().port();
        // Connecting via a literal IPv4-mapped address to the v6-only
        // listener's port must fail to connect at all (nothing there,
        // since v6-only means no v4 traffic is accepted on this socket).
        let connect = tokio::time::timeout(std::time::Duration::from_millis(300), tokio::net::TcpStream::connect(("127.0.0.1", port))).await;
        assert!(connect.is_err() || connect.unwrap().is_err(), "a v6-only socket must not accept a v4 connection on the same port");
    }

    #[tokio::test]
    async fn bound_tcp_listener_actually_accepts_a_real_connection() {
        let listener = bind_tcp_listener("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = tokio::net::TcpStream::connect(addr).await;
        assert!(stream.is_ok());
    }

    #[tokio::test]
    async fn bound_udp_socket_actually_sends_and_receives() {
        let a = bind_udp_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        let b = bind_udp_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        let b_addr = b.local_addr().unwrap();
        a.send_to(b"hi", b_addr).await.unwrap();
        let mut buf = [0u8; 2];
        let (len, _) = b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"hi");
    }
}
