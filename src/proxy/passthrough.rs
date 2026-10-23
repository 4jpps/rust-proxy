//! Raw TCP/UDP forwarding for `PortRule`s with a `passthrough_target`
//! (RustDesk, a game server, anything that isn't HTTP). Rules *without* a
//! target don't get a listener here at all -- they're just a firewall
//! carve-out for a service already listening locally (see
//! `nftables::generator`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[cfg(test)]
use tokio::net::TcpListener;

/// Accepts on `bind_addr`, dials `upstream` for every new connection, and
/// copies bytes bidirectionally until either side closes. Runs until the
/// listener itself errors (socket closed, etc).
pub async fn run_tcp_passthrough(
    bind_addr: SocketAddr,
    upstream: SocketAddr,
) -> std::io::Result<()> {
    let listener = crate::netbind::bind_tcp_listener(bind_addr)?;
    tracing::info!(%bind_addr, %upstream, "tcp passthrough listening");
    loop {
        let (mut inbound, peer) = listener.accept().await?;
        tokio::spawn(async move {
            match super::connect::connect_upstream(upstream).await {
                Ok(mut outbound) => {
                    if let Err(err) =
                        tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                    {
                        tracing::debug!(%peer, error = %err, "tcp passthrough session ended");
                    }
                }
                Err(err) => {
                    tracing::warn!(%peer, %upstream, error = %err, "tcp passthrough: upstream connect failed");
                }
            }
        });
    }
}

const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const UDP_BUF_SIZE: usize = 64 * 1024;

/// UDP has no connection to accept, so this keeps a small NAT-like session
/// table keyed by client address: the first datagram from a new client
/// spawns a dedicated upstream socket + a task relaying upstream ->
/// client, and every subsequent datagram from that client just gets
/// forwarded through the existing session. Idle sessions are reaped.
pub async fn run_udp_passthrough(
    bind_addr: SocketAddr,
    upstream: SocketAddr,
) -> std::io::Result<()> {
    let socket = Arc::new(crate::netbind::bind_udp_socket(bind_addr)?);
    tracing::info!(%bind_addr, %upstream, "udp passthrough listening");

    let sessions: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; UDP_BUF_SIZE];

    loop {
        let (len, client_addr) = socket.recv_from(&mut buf).await?;

        let upstream_socket = {
            let mut guard = sessions.lock().await;
            if let Some(existing) = guard.get(&client_addr) {
                existing.clone()
            } else {
                let new_socket = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await?);
                new_socket.connect(upstream).await?;
                guard.insert(client_addr, new_socket.clone());
                spawn_udp_return_path(
                    new_socket.clone(),
                    socket.clone(),
                    client_addr,
                    sessions.clone(),
                );
                new_socket
            }
        };

        if let Err(err) = upstream_socket.send(&buf[..len]).await {
            tracing::debug!(%client_addr, %upstream, error = %err, "udp passthrough: send to upstream failed");
        }
    }
}

fn spawn_udp_return_path(
    upstream_socket: Arc<UdpSocket>,
    client_facing_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    sessions: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF_SIZE];
        loop {
            let recv =
                tokio::time::timeout(UDP_SESSION_IDLE_TIMEOUT, upstream_socket.recv(&mut buf))
                    .await;
            match recv {
                Ok(Ok(len)) => {
                    if let Err(err) = client_facing_socket.send_to(&buf[..len], client_addr).await {
                        tracing::debug!(%client_addr, error = %err, "udp passthrough: send to client failed");
                        break;
                    }
                }
                Ok(Err(err)) => {
                    tracing::debug!(%client_addr, error = %err, "udp passthrough: upstream recv failed");
                    break;
                }
                Err(_timeout) => break,
            }
        }
        sessions.lock().await.remove(&client_addr);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tcp_passthrough_relays_bytes_both_directions() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            sock.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            sock.write_all(b"world").await.unwrap();
        });

        let passthrough_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bind_addr = passthrough_listener.local_addr().unwrap();
        drop(passthrough_listener); // release the port for run_tcp_passthrough to rebind
        tokio::spawn(run_tcp_passthrough(bind_addr, upstream_addr));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = tokio::net::TcpStream::connect(bind_addr).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    }

    #[tokio::test]
    async fn udp_passthrough_relays_a_datagram_round_trip() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (len, peer) = upstream_socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"ping");
            upstream_socket.send_to(b"pong", peer).await.unwrap();
        });

        let bind_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind_addr = bind_socket.local_addr().unwrap();
        drop(bind_socket);
        tokio::spawn(run_udp_passthrough(bind_addr, upstream_addr));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"ping", bind_addr).await.unwrap();
        let mut buf = [0u8; 64];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("timed out waiting for udp reply")
            .unwrap();
        assert_eq!(&buf[..len], b"pong");
    }
}
