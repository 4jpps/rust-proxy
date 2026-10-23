//! Opening the TCP connection to an upstream, with a short per-attempt timeout and a fresh retry.
//!
//! Every proxied request opens its own upstream connection, and a plain `TcpStream::connect` has no
//! timeout: when a SYN goes unanswered the kernel keeps retransmitting it from the same source port
//! for about two minutes before failing, and the client's request hangs all that time. In production
//! (proxy on VLAN 62, backends on other VLANs behind the router) a few connections an hour were
//! blackholed like that, which looked like random "the site is hanging" reports. A connection that
//! doesn't complete within `ATTEMPT_TIMEOUT` is abandoned and retried on a new socket, so a new
//! source port, which gets through in practice. A refused connection is a definite answer and is
//! not retried.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

/// How long one connection attempt may take. LAN backends answer in well under a millisecond.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
/// Attempts in total, each on a fresh socket.
pub const ATTEMPTS: u32 = 3;

pub async fn connect_upstream(upstream: SocketAddr) -> io::Result<TcpStream> {
    connect_with(upstream, ATTEMPT_TIMEOUT, ATTEMPTS).await
}

async fn connect_with(
    upstream: SocketAddr,
    attempt_timeout: Duration,
    attempts: u32,
) -> io::Result<TcpStream> {
    for attempt in 1..=attempts {
        match tokio::time::timeout(attempt_timeout, TcpStream::connect(upstream)).await {
            Ok(Ok(stream)) => {
                if attempt > 1 {
                    tracing::info!(%upstream, attempt, "upstream connect succeeded on retry");
                }
                return Ok(stream);
            }
            Ok(Err(err)) if err.kind() == io::ErrorKind::TimedOut => {
                tracing::warn!(%upstream, attempt, error = %err, "upstream connect timed out, retrying");
            }
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                tracing::warn!(%upstream, attempt, "upstream connect got no answer within {attempt_timeout:?}, retrying");
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("no answer from upstream {upstream} after {attempts} attempts"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connects_to_a_listening_upstream_on_the_first_attempt() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(connect_upstream(addr).await.is_ok());
    }

    #[tokio::test]
    async fn a_refused_connection_fails_at_once_without_retrying() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let started = std::time::Instant::now();
        let err = connect_with(addr, Duration::from_secs(5), 3)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn an_unanswered_connection_gives_up_after_the_attempts() {
        // TEST-NET-1 (RFC 5737): never routed, so the SYN goes unanswered (or the network is
        // reported unreachable, which also ends the attempt quickly).
        let addr: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let started = std::time::Instant::now();
        assert!(
            connect_with(addr, Duration::from_millis(200), 2)
                .await
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
