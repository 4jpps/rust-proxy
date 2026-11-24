//! HTTP/3 (QUIC over UDP) beside each HTTPS listener, when `network.http3` is on (Jeff 2026-11-21).
//!
//! Every request takes the same path as HTTPS: each QUIC connection gets an in-memory HTTP/2 link into
//! the very service the TCP listener runs (`handle_https_request`), so access lists, logins, rate
//! limits, logging and forwarding are shared code, not a second copy. Only the outside changes.
//!
//! Hosts that ask for a client certificate never use HTTP/3: whether to ask is decided per host before
//! the handshake on TCP (`should_request_client_cert`), which a QUIC endpoint can't do. Their QUIC
//! connections are closed right after the handshake, so a browser falls back to HTTPS, and they never
//! get an `Alt-Svc` header advertising HTTP/3 in the first place.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper::body::{Frame, Incoming};
use hyper::header::{ALT_SVC, HeaderValue};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::task::JoinHandle;

use super::{
    deliver, handle_https_request, limits, server_builder, should_request_client_cert, tls,
};
use crate::state::AppState;

/// H3_NO_ERROR (RFC 9114 8.1): a normal close.
const H3_NO_ERROR: u32 = 0x100;
/// How long browsers may remember that a host speaks HTTP/3.
const ALT_SVC_MAX_AGE: u32 = 86_400;
/// Handshakes one listener holds open at once; more are refused until some finish.
const MAX_UNFINISHED_HANDSHAKES: usize = 2048;
/// Room for the in-memory HTTP/2 link between the QUIC side and the shared service.
const BRIDGE_BUFFER: usize = 256 * 1024;

/// The `Alt-Svc` value advertising HTTP/3 on this port.
pub(super) fn alt_svc(port: u16) -> HeaderValue {
    HeaderValue::from_str(&format!("h3=\":{port}\"; ma={ALT_SVC_MAX_AGE}")).expect("plain ASCII")
}

/// Adds `Alt-Svc` to a response when this connection may use HTTP/3 (and the response hasn't one).
pub(super) fn advertise<B>(resp: &mut Response<B>, enabled: bool, port: u16) {
    if enabled && !resp.headers().contains_key(ALT_SVC) {
        resp.headers_mut().insert(ALT_SVC, alt_svc(port));
    }
}

/// QUIC server settings: the same certificates as HTTPS (TLS 1.3 only, as QUIC requires), ALPN h3.
pub(super) fn server_config(state: AppState) -> Option<quinn::ServerConfig> {
    let resolver = Arc::new(tls::CertResolver::new(state));
    let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = match quinn::crypto::rustls::QuicServerConfig::try_from(tls) {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(error = %err, "http/3: TLS settings not usable for QUIC");
            return None;
        }
    };
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    // Connections waiting to be picked up (quinn's default is 65536); `serve` caps those in handshake.
    cfg.max_incoming(MAX_UNFINISHED_HANDSHAKES);
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(100u32.into())
        .max_concurrent_uni_streams(16u32.into())
        .max_idle_timeout(Some(
            std::time::Duration::from_secs(30)
                .try_into()
                .expect("30 s fits"),
        ));
    cfg.transport_config(Arc::new(transport));
    Some(cfg)
}

/// Starts HTTP/3 on `bind_ip:bind_port` (UDP). Only for a specific address: a wildcard UDP socket
/// would answer from whichever address the kernel picks, and production binds exact addresses.
pub(super) fn spawn_listener(
    state: AppState,
    bind_ip: IpAddr,
    bind_port: u16,
) -> Option<JoinHandle<()>> {
    if bind_ip.is_unspecified() {
        return None;
    }
    let cfg = server_config(state.clone())?;
    let addr = SocketAddr::new(bind_ip, bind_port);
    let socket = match bind_udp(addr) {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(%addr, error = %err, "http/3: couldn't open the UDP port");
            return None;
        }
    };
    let endpoint = match quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(cfg),
        socket,
        Arc::new(quinn::TokioRuntime),
    ) {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(%addr, error = %err, "http/3: couldn't start");
            return None;
        }
    };
    tracing::info!(%addr, "http/3 listening");
    Some(tokio::spawn(serve(state, endpoint, bind_ip, bind_port)))
}

fn bind_udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Accepts QUIC connections until the endpoint closes. `bind_ip`/`bind_port` are the listener's
/// configured address (what hosts are matched against), whatever the socket is actually bound to.
/// What to do with a new QUIC connection, given how many handshakes are already in progress.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Admit {
    Accept,
    /// Ask the client to prove its address first (stateless: nothing is kept for it meanwhile).
    Retry,
    Refuse,
}

/// Handshakes in progress are capped at `max`; past half of that, a client whose address isn't
/// proven yet must prove it with a Retry before it may take one of the remaining places.
pub(super) fn admit(address_validated: bool, in_progress: usize, max: usize) -> Admit {
    if in_progress >= max {
        Admit::Refuse
    } else if !address_validated && in_progress >= max / 2 {
        Admit::Retry
    } else {
        Admit::Accept
    }
}

pub(super) async fn serve(
    state: AppState,
    endpoint: quinn::Endpoint,
    bind_ip: IpAddr,
    bind_port: u16,
) {
    let handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_UNFINISHED_HANDSHAKES));
    while let Some(incoming) = endpoint.accept().await {
        let peer_ip = incoming.remote_address().ip();
        if state.block_index().is_globally_blocked(peer_ip) {
            tracing::debug!(%peer_ip, "http/3 connection refused: globally blocked");
            incoming.refuse();
            continue;
        }
        let in_progress = MAX_UNFINISHED_HANDSHAKES - handshakes.available_permits();
        match admit(
            incoming.remote_address_validated(),
            in_progress,
            MAX_UNFINISHED_HANDSHAKES,
        ) {
            Admit::Accept => {}
            Admit::Retry => {
                if let Err(err) = incoming.retry() {
                    err.into_incoming().refuse();
                }
                continue;
            }
            Admit::Refuse => {
                tracing::debug!(%peer_ip, "http/3 connection refused: too many handshakes in progress");
                limits::count(&limits::CONNECTIONS_REFUSED);
                incoming.refuse();
                continue;
            }
        }
        let Ok(handshake) = handshakes.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let finished = tokio::time::timeout(limits::TLS_HANDSHAKE_TIMEOUT, incoming).await;
            drop(handshake);
            let conn = match finished {
                Ok(Ok(c)) => c,
                Ok(Err(err)) => {
                    tracing::debug!(%peer_ip, error = %err, "http/3 handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer_ip, "http/3 handshake timed out");
                    limits::count(&limits::TLS_HANDSHAKE_TIMEOUTS);
                    return;
                }
            };
            // The per-client slot is taken only now: the opening UDP packet's address can be forged,
            // and a finished handshake proves it, so forged packets can't use up a visitor's slots
            // (shared with HTTPS). Unfinished handshakes are capped by `max_incoming` instead.
            let Some(_slot) = state.conn_limiter().try_acquire(peer_ip) else {
                tracing::debug!(%peer_ip, "http/3 connection closed: per-client connection limit");
                limits::count(&limits::CONNECTIONS_REFUSED);
                conn.close(H3_NO_ERROR.into(), b"too many connections");
                return;
            };
            let sni = conn
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.server_name);
            if should_request_client_cert(&state, bind_ip, bind_port, peer_ip, sni.as_deref()).await
            {
                // A client-certificate host: the browser falls back to HTTPS, which can ask for one.
                conn.close(H3_NO_ERROR.into(), b"use HTTPS over TCP for this host");
                return;
            }
            serve_connection(state, conn, bind_ip, bind_port, peer_ip, sni).await;
        });
    }
}

async fn serve_connection(
    state: AppState,
    conn: quinn::Connection,
    bind_ip: IpAddr,
    bind_port: u16,
    peer_ip: IpAddr,
    sni: Option<String>,
) {
    // The in-memory HTTP/2 link into the shared HTTPS service.
    let (near, far) = tokio::io::duplex(BRIDGE_BUFFER);
    {
        let state = state.clone();
        let sni = sni.clone();
        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
            let state = state.clone();
            let sni = sni.clone();
            async move {
                match handle_https_request(state, bind_ip, bind_port, peer_ip, sni, None, req).await
                {
                    Ok(resp) => deliver(resp),
                    Err(never) => match never {},
                }
            }
        });
        tokio::spawn(async move {
            let _ = server_builder()
                .serve_connection(TokioIo::new(far), service)
                .await;
        });
    }
    let sender =
        match hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(near)).await
        {
            Ok((sender, link)) => {
                tokio::spawn(link);
                sender
            }
            Err(err) => {
                tracing::warn!(error = %err, "http/3: internal link failed");
                return;
            }
        };

    let mut h3_conn =
        match h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await {
            Ok(c) => c,
            Err(err) => {
                tracing::debug!(%peer_ip, error = %err, "http/3 connection setup failed");
                return;
            }
        };
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let sender = sender.clone();
                tokio::spawn(async move {
                    let (req, stream) = match resolver.resolve_request().await {
                        Ok(r) => r,
                        Err(err) => {
                            tracing::debug!(error = %err, "http/3 request headers unreadable");
                            return;
                        }
                    };
                    if let Err(err) = serve_request(sender, req, stream, bind_port).await {
                        tracing::debug!(error = %err, "http/3 request ended early");
                    }
                });
            }
            Ok(None) => break,
            Err(err) => {
                tracing::debug!(%peer_ip, error = %err, "http/3 connection ended");
                break;
            }
        }
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A request body fed from a queue (the QUIC reader task on the other end).
struct ChannelBody(tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, BoxError>>);

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.0.poll_recv(cx)
    }
}

async fn serve_request<S>(
    mut sender: hyper::client::conn::http2::SendRequest<
        http_body_util::combinators::BoxBody<Bytes, BoxError>,
    >,
    req: Request<()>,
    stream: h3::server::RequestStream<S, Bytes>,
    bind_port: u16,
) -> Result<(), BoxError>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
    <S as h3::quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
{
    let (mut send, mut recv) = stream.split();
    // The request body, read from QUIC as the shared service asks for it (a small queue between them).
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(8);
    tokio::spawn(async move {
        loop {
            match recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    if tx.send(Ok(Frame::data(bytes))).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    let _ = tx.send(Err(Box::new(err) as BoxError)).await;
                    break;
                }
            }
        }
    });
    let body = ChannelBody(rx).boxed();
    let (parts, ()) = req.into_parts();
    let resp = sender.send_request(Request::from_parts(parts, body)).await;
    let mut resp = match resp {
        Ok(r) => r,
        Err(err) => {
            tracing::debug!(error = %err, "http/3: shared service didn't answer");
            send.send_response(
                Response::builder()
                    .status(502)
                    .body(())
                    .expect("static response"),
            )
            .await?;
            send.finish().await?;
            return Ok(());
        }
    };
    advertise(&mut resp, true, bind_port);
    let (parts, mut body) = resp.into_parts();
    send.send_response(Response::from_parts(parts, ())).await?;
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        match frame.into_data() {
            Ok(data) => send.send_data(data).await?,
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    send.send_trailers(trailers).await?;
                }
            }
        }
    }
    send.finish().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyHost;
    use hyper::service::service_fn;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    /// A backend that answers with the request's method, path and body, and a marker header.
    async fn echo_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let service = service_fn(|req: Request<Incoming>| async move {
                        let line = format!("{} {} ", req.method(), req.uri().path());
                        let host = req
                            .headers()
                            .get("host")
                            .map(|h| h.to_str().unwrap().to_string())
                            .unwrap_or_default();
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let text = format!("{line}{}", String::from_utf8_lossy(&body));
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("x-backend", "yes")
                                .header("x-seen-host", host)
                                .body(http_body_util::Full::new(Bytes::from(text)))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        addr
    }

    fn host(domain: &str, upstream: SocketAddr, client_cert: bool) -> ProxyHost {
        let mut h = super::super::tests::plain_host_for_h3(domain);
        h.upstream = upstream.to_string();
        h.pass_client_cert_header = client_cert;
        h
    }

    /// The QUIC server on 127.0.0.1 (any port), matching hosts as if it were 10.0.0.2:443.
    async fn start(state: AppState) -> SocketAddr {
        let cfg = server_config(state.clone()).unwrap();
        let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(serve(state, endpoint, "10.0.0.2".parse().unwrap(), 443));
        addr
    }

    async fn client_conn(
        addr: SocketAddr,
        sni: &str,
    ) -> Result<quinn::Connection, quinn::ConnectionError> {
        let mut tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(super::super::tests::AcceptAnyCert))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        endpoint.connect(addr, sni).unwrap().await
    }

    #[tokio::test]
    async fn a_request_over_http3_reaches_the_backend_through_the_shared_path() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let upstream = echo_upstream().await;
        let state = super::super::tests::test_state_with_cert_for_h3("example.com").await;
        state.set_hosts(vec![host("example.com", upstream, false)]);
        let addr = start(state).await;

        let conn = client_conn(addr, "example.com").await.unwrap();
        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let req = Request::builder()
            .method("POST")
            .uri("https://example.com/hello")
            .body(())
            .unwrap();
        let mut stream = send.send_request(req).await.unwrap();
        stream
            .send_data(Bytes::from_static(b"over quic"))
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-backend").unwrap(),
            "yes",
            "came from the backend"
        );
        assert_eq!(
            resp.headers().get("x-seen-host").unwrap(),
            "example.com",
            "host passed through"
        );
        assert_eq!(
            resp.headers().get(ALT_SVC).unwrap(),
            "h3=\":443\"; ma=86400"
        );
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        assert_eq!(String::from_utf8(body).unwrap(), "POST /hello over quic");
    }

    #[tokio::test]
    async fn a_client_certificate_host_is_sent_back_to_https() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let upstream = echo_upstream().await;
        let state = super::super::tests::test_state_with_cert_for_h3("portal.example.com").await;
        state.set_hosts(vec![host("portal.example.com", upstream, true)]);
        let addr = start(state).await;

        let conn = client_conn(addr, "portal.example.com").await.unwrap();
        let reason = conn.closed().await;
        assert!(
            matches!(&reason, quinn::ConnectionError::ApplicationClosed(c) if c.error_code == H3_NO_ERROR.into()),
            "{reason:?}"
        );
    }

    #[tokio::test]
    async fn the_connection_limit_is_charged_after_the_handshake_proves_the_address() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let upstream = echo_upstream().await;
        let state = super::super::tests::test_state_with_cert_for_h3("example.com").await;
        state.set_hosts(vec![host("example.com", upstream, false)]);
        // Use up every slot 127.0.0.1 has (as its HTTPS connections would).
        let mut held = Vec::new();
        while let Some(slot) = state
            .conn_limiter()
            .try_acquire("127.0.0.1".parse().unwrap())
        {
            held.push(slot);
        }
        let addr = start(state).await;
        // The handshake still completes (nothing is charged before it), then the connection is closed.
        let conn = client_conn(addr, "example.com")
            .await
            .expect("handshake completes");
        let reason = conn.closed().await;
        assert!(
            matches!(&reason, quinn::ConnectionError::ApplicationClosed(c) if &c.reason[..] == b"too many connections"),
            "{reason:?}"
        );
        drop(held);
    }

    #[test]
    fn handshakes_are_capped_and_unproven_addresses_retry_once_busy() {
        assert_eq!(
            admit(false, 0, 2048),
            Admit::Accept,
            "quiet: no extra round trip"
        );
        assert_eq!(admit(false, 1023, 2048), Admit::Accept);
        assert_eq!(
            admit(false, 1024, 2048),
            Admit::Retry,
            "busy: prove the address first"
        );
        assert_eq!(
            admit(true, 1024, 2048),
            Admit::Accept,
            "a proven address may proceed"
        );
        assert_eq!(admit(true, 2048, 2048), Admit::Refuse, "full: nobody");
        assert_eq!(admit(false, 4000, 2048), Admit::Refuse);
    }

    #[test]
    fn alt_svc_is_only_added_when_allowed_and_absent() {
        let mut r = Response::new(());
        advertise(&mut r, false, 443);
        assert!(r.headers().get(ALT_SVC).is_none());
        advertise(&mut r, true, 443);
        assert_eq!(r.headers().get(ALT_SVC).unwrap(), "h3=\":443\"; ma=86400");
        r.headers_mut()
            .insert(ALT_SVC, HeaderValue::from_static("clear"));
        advertise(&mut r, true, 8443);
        assert_eq!(
            r.headers().get(ALT_SVC).unwrap(),
            "clear",
            "a backend's own Alt-Svc is kept"
        );
    }
}
