//! Raw TCP/UDP forwarding for `PortRule`s with a `passthrough_target`
//! (RustDesk, a game server, anything that isn't HTTP). Rules *without* a
//! target don't get a listener here at all -- they're just a firewall
//! carve-out for a service already listening locally (see
//! `nftables::generator`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

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
    limiter: Arc<super::limits::ConnLimiter>,
) -> std::io::Result<()> {
    let listener = crate::netbind::bind_tcp_listener(bind_addr)?;
    tracing::info!(%bind_addr, %upstream, "tcp passthrough listening");
    loop {
        // An accept error (EMFILE under fd pressure) must not end the
        // listener: nothing restarts it until its rule changes.
        let (mut inbound, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(%bind_addr, error = %err, "tcp passthrough accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(slot) = limiter.try_acquire(peer.ip()) else {
            tracing::debug!(%peer, "tcp passthrough: per-client connection limit reached");
            super::limits::count(&super::limits::CONNECTIONS_REFUSED);
            continue;
        };
        tokio::spawn(async move {
            let _slot = slot;
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

const UDP_BUF_SIZE: usize = 64 * 1024;
/// Each session owns an upstream socket (a file descriptor), so the table
/// is capped overall; each session also holds a slot from this listener's
/// own per-client limiter, so one client (or /64) varying its source port
/// can't take the whole table from everyone else. UDP sources can be
/// forged, so this limiter is never the one shared with TCP/HTTPS: a
/// spoofed flood can't use up a real visitor's web allowance.
const MAX_UDP_SESSIONS: usize = 4096;

struct UdpSession {
    upstream: Arc<UdpSocket>,
    /// When the client last sent anything, as ms since `epoch`.
    last_client_ms: AtomicU64,
    /// Set once the upstream has answered. Only then does client traffic
    /// alone keep the session open -- forged sources never get a reply
    /// path, so their sessions expire on the plain idle timeout.
    upstream_replied: AtomicBool,
    epoch: Instant,
    _slot: super::limits::ConnGuard,
}

impl UdpSession {
    fn touch(&self) {
        self.last_client_ms
            .store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn client_idle(&self) -> Duration {
        let last = Duration::from_millis(self.last_client_ms.load(Ordering::Relaxed));
        self.epoch.elapsed().saturating_sub(last)
    }
}

type UdpSessions = Arc<Mutex<HashMap<SocketAddr, Arc<UdpSession>>>>;

/// UDP has no connection to accept, so this keeps a small NAT-like session
/// table keyed by client address: the first datagram from a new client
/// spawns a dedicated upstream socket + a task relaying upstream ->
/// client, and every subsequent datagram from that client just gets
/// forwarded through the existing session. Sessions idle in both
/// directions for `idle_timeout` are reaped.
pub async fn run_udp_passthrough(
    bind_addr: SocketAddr,
    upstream: SocketAddr,
    max_sessions_per_client: usize,
    idle_timeout: Duration,
) -> std::io::Result<()> {
    let socket = Arc::new(crate::netbind::bind_udp_socket(bind_addr)?);
    tracing::info!(%bind_addr, %upstream, "udp passthrough listening");
    let limiter = super::limits::ConnLimiter::new(max_sessions_per_client);

    let sessions: UdpSessions = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; UDP_BUF_SIZE];

    loop {
        let (len, client_addr) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(err) => {
                tracing::debug!(%bind_addr, error = %err, "udp passthrough recv failed");
                continue;
            }
        };

        let session = {
            let mut guard = sessions.lock().await;
            if let Some(existing) = guard.get(&client_addr) {
                existing.clone()
            } else {
                if guard.len() >= MAX_UDP_SESSIONS {
                    tracing::debug!(%client_addr, "udp passthrough: session table full, datagram dropped");
                    continue;
                }
                let Some(slot) = limiter.try_acquire(client_addr.ip()) else {
                    tracing::debug!(%client_addr, "udp passthrough: per-client limit reached, datagram dropped");
                    continue;
                };
                // A failed bind/connect (fd pressure) drops this datagram
                // rather than ending the listener.
                let new_socket = match UdpSocket::bind(("0.0.0.0", 0)).await {
                    Ok(s) => Arc::new(s),
                    Err(err) => {
                        tracing::warn!(%client_addr, error = %err, "udp passthrough: upstream socket failed");
                        continue;
                    }
                };
                if let Err(err) = new_socket.connect(upstream).await {
                    tracing::warn!(%client_addr, %upstream, error = %err, "udp passthrough: upstream connect failed");
                    continue;
                }
                let session = Arc::new(UdpSession {
                    upstream: new_socket,
                    last_client_ms: AtomicU64::new(0),
                    upstream_replied: AtomicBool::new(false),
                    epoch: Instant::now(),
                    _slot: slot,
                });
                guard.insert(client_addr, session.clone());
                spawn_udp_return_path(
                    session.clone(),
                    socket.clone(),
                    client_addr,
                    sessions.clone(),
                    idle_timeout,
                );
                session
            }
        };

        session.touch();
        if let Err(err) = session.upstream.send(&buf[..len]).await {
            tracing::debug!(%client_addr, %upstream, error = %err, "udp passthrough: send to upstream failed");
        }
    }
}

fn spawn_udp_return_path(
    session: Arc<UdpSession>,
    client_facing_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    sessions: UdpSessions,
    idle_timeout: Duration,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF_SIZE];
        loop {
            let recv = tokio::time::timeout(idle_timeout, session.upstream.recv(&mut buf)).await;
            match recv {
                Ok(Ok(len)) => {
                    session.upstream_replied.store(true, Ordering::Relaxed);
                    if let Err(err) = client_facing_socket.send_to(&buf[..len], client_addr).await {
                        tracing::debug!(%client_addr, error = %err, "udp passthrough: send to client failed");
                        break;
                    }
                }
                Ok(Err(err)) => {
                    tracing::debug!(%client_addr, error = %err, "udp passthrough: upstream recv failed");
                    break;
                }
                // Upstream quiet: keep an answered session while the client
                // still talks.
                Err(_timeout)
                    if session.upstream_replied.load(Ordering::Relaxed)
                        && session.client_idle() < idle_timeout =>
                {
                    continue;
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
        tokio::spawn(run_tcp_passthrough(
            bind_addr,
            upstream_addr,
            super::super::limits::ConnLimiter::new(0),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = tokio::net::TcpStream::connect(bind_addr).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    }

    #[tokio::test]
    async fn tcp_passthrough_closes_connections_over_the_per_client_cap() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = upstream_listener.accept().await {
                held.push(sock);
            }
        });
        let passthrough_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bind_addr = passthrough_listener.local_addr().unwrap();
        drop(passthrough_listener);
        let limiter = super::super::limits::ConnLimiter::new(2);
        tokio::spawn(run_tcp_passthrough(
            bind_addr,
            upstream_addr,
            limiter.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let refused_before =
            super::super::limits::total(&super::super::limits::CONNECTIONS_REFUSED);
        let _a = tokio::net::TcpStream::connect(bind_addr).await.unwrap();
        let _b = tokio::net::TcpStream::connect(bind_addr).await.unwrap();
        let mut c = tokio::net::TcpStream::connect(bind_addr).await.unwrap();
        // The third is accepted by the kernel, then closed by the proxy.
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .expect("over-cap connection should be closed promptly")
            .unwrap_or(0);
        assert_eq!(n, 0);
        assert_eq!(limiter.top(1)[0].1, 2);
        assert!(
            super::super::limits::total(&super::super::limits::CONNECTIONS_REFUSED)
                > refused_before
        );
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
        tokio::spawn(run_udp_passthrough(
            bind_addr,
            upstream_addr,
            0,
            Duration::from_secs(120),
        ));
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
