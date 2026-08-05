//! HTTP request forwarding to an upstream, including WebSocket upgrade
//! passthrough. One upstream TCP connection per proxied request (no
//! pooling yet -- see the module-level TODO in `mod.rs` if this becomes
//! a bottleneck) so there's no shared connection state to reason about
//! under concurrent hot-reloads.

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{CONNECTION, UPGRADE};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use crate::config::{RedirectStatus, RedirectTarget};
use crate::state::AppState;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Both a plain `TcpStream` and a `tokio_rustls` TLS-wrapped one need to
/// end up as the same `TokioIo<_>` type for `hyper::client::conn::http1`
/// -- this trait lets `forward_http` box either behind one type instead
/// of duplicating the whole handshake/send/upgrade sequence per branch.
trait UpstreamIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> UpstreamIo for T {}

/// Everything about how to reach and speak to one host's upstream,
/// beyond the already-resolved `SocketAddr` -- grouped so `forward_http`
/// doesn't need a five-argument signature; see each field's own comment
/// for what it controls.
pub struct UpstreamOptions<'a> {
    pub websockets_enabled: bool,
    /// Whether to speak TLS to the upstream at all -- `config::ProxyHost::upstream_https`.
    pub https: bool,
    /// Only consulted when `https` is set -- `config::ProxyHost::upstream_tls_verify`.
    pub tls_verify: bool,
    /// The original `host:port` string from `ProxyHost.upstream` (not
    /// the resolved `SocketAddr`) -- the host part (port stripped) is
    /// used as the TLS SNI/certificate-name when `https` is set, and
    /// the whole string is used as the literal `Host` header sent to
    /// the upstream when `preserve_host` is false.
    pub upstream_host_port: &'a str,
    /// `true` forwards the client's original `Host` header unmodified
    /// (the existing, unchanged behavior). `false` rewrites it to
    /// `upstream_host_port` instead -- `config::ProxyHost::upstream_preserve_host`.
    pub preserve_host: bool,
}

pub fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    let has_upgrade_header = req
        .headers()
        .get(UPGRADE)
        .map(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
        .unwrap_or(false);
    let has_connection_upgrade = req
        .headers()
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').any(|tok| tok.trim().eq_ignore_ascii_case("upgrade")))
        .unwrap_or(false);
    has_upgrade_header && has_connection_upgrade
}

/// Forwards `req` to `upstream`, streaming the response body back
/// unmodified. If `opts.websockets_enabled` and the request is a
/// WebSocket upgrade, splices the client and upstream connections
/// together after the 101 response instead of treating it as a normal
/// request/response. See `UpstreamOptions` for the HTTPS-upstream/
/// `Host`-header-rewrite knobs.
pub async fn forward_http(
    mut req: Request<Incoming>,
    upstream: SocketAddr,
    opts: UpstreamOptions<'_>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, BoxError> {
    if !opts.preserve_host {
        let value = hyper::header::HeaderValue::from_str(opts.upstream_host_port)?;
        req.headers_mut().insert(hyper::header::HOST, value);
    }

    let want_upgrade = opts.websockets_enabled && is_websocket_upgrade(&req);
    let client_upgrade = want_upgrade.then(|| hyper::upgrade::on(&mut req));

    let tcp = TcpStream::connect(upstream).await?;
    let io: TokioIo<Box<dyn UpstreamIo>> = if opts.https {
        let host_only = opts.upstream_host_port.rsplit_once(':').map_or(opts.upstream_host_port, |(host, _)| host);
        let server_name = rustls_pki_types::ServerName::try_from(host_only.to_string())?;
        let config = if opts.tls_verify { super::upstream_tls::verified_client_config() } else { super::upstream_tls::insecure_client_config() };
        let tls_stream = tokio_rustls::TlsConnector::from(config).connect(server_name, tcp).await?;
        TokioIo::new(Box::new(tls_stream) as Box<dyn UpstreamIo>)
    } else {
        TokioIo::new(Box::new(tcp) as Box<dyn UpstreamIo>)
    };
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            tracing::debug!(error = %err, "upstream connection closed");
        }
    });

    let mut resp = sender.send_request(req).await?;

    if let (true, Some(client_upgrade)) = (resp.status() == hyper::StatusCode::SWITCHING_PROTOCOLS, client_upgrade) {
        let upstream_upgrade = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            match (client_upgrade.await, upstream_upgrade.await) {
                (Ok(client), Ok(upstream)) => {
                    let mut client = TokioIo::new(client);
                    let mut upstream = TokioIo::new(upstream);
                    if let Err(err) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                        tracing::debug!(error = %err, "websocket passthrough ended");
                    }
                }
                _ => tracing::warn!("websocket upgrade failed on client or upstream side"),
            }
        });
        let (parts, _empty) = resp.into_parts();
        return Ok(Response::from_parts(
            parts,
            http_body_util::Empty::new().map_err(|never: std::convert::Infallible| match never {}).boxed(),
        ));
    }

    let (parts, body) = resp.into_parts();
    Ok(Response::from_parts(parts, body.map_err(|e| e).boxed()))
}

/// Plain 301 redirect from `http://<host><path>` to the same on `https`,
/// used for `force_https` hosts' port-80 listener.
pub fn https_redirect_response<B>(req: &Request<B>) -> Response<BoxBody<Bytes, hyper::Error>> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let host_no_port = host.split(':').next().unwrap_or(host);
    let path_and_query = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let location = format!("https://{host_no_port}{path_and_query}");

    Response::builder()
        .status(hyper::StatusCode::MOVED_PERMANENTLY)
        .header(hyper::header::LOCATION, location)
        .body(http_body_util::Empty::new().map_err(|e: std::convert::Infallible| match e {}).boxed())
        .expect("static redirect response is always valid")
}

/// Serves a `redirect` host's response -- the request never reaches an
/// upstream at all. `target.target` is an admin-configured absolute URL
/// (validated by `config::validate_redirect_target`), not something
/// reflected from request input, so -- unlike `proxy::login`'s
/// `return_to` -- it's fine for this to leave the site; that's the whole
/// point of the feature.
pub fn redirect_target_response<B>(req: &Request<B>, target: &RedirectTarget) -> Response<BoxBody<Bytes, hyper::Error>> {
    let location = if target.preserve_path {
        let path_and_query = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        format!("{}{}", target.target.trim_end_matches('/'), path_and_query)
    } else {
        target.target.clone()
    };
    let status = match target.status {
        RedirectStatus::Permanent => hyper::StatusCode::MOVED_PERMANENTLY,
        RedirectStatus::Temporary => hyper::StatusCode::FOUND,
    };

    Response::builder()
        .status(status)
        .header(hyper::header::LOCATION, location)
        .body(http_body_util::Empty::new().map_err(|e: std::convert::Infallible| match e {}).boxed())
        .expect("static redirect response is always valid")
}

/// If `req`'s path is an ACME http-01 challenge fetch
/// (`/.well-known/acme-challenge/<token>`) for a token `state` currently
/// has a pending key authorization for, serves it directly per RFC 8555
/// SS8.3. This must be checked before `https_redirect_response` on a
/// `force_https` host's port-80 listener -- the CA's validator speaks
/// plain HTTP and never follows a redirect to `https`.
pub fn http01_challenge_response<B>(state: &AppState, req: &Request<B>) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
    let token = req.uri().path().strip_prefix(crate::acme::http01::CHALLENGE_PATH_PREFIX)?;
    let key_authorization = state.get_http01_challenge(token)?;
    Some(
        Response::builder()
            .status(hyper::StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(
                http_body_util::Full::new(Bytes::from(key_authorization))
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed(),
            )
            .expect("static challenge response is always valid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn detects_websocket_upgrade_headers() {
        let req = Request::builder()
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .body(())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn plain_request_is_not_a_websocket_upgrade() {
        let req = Request::builder().body(()).unwrap();
        assert!(!is_websocket_upgrade(&req));
    }

    #[test]
    fn connection_header_with_multiple_tokens_still_detected() {
        let req = Request::builder()
            .header(CONNECTION, "keep-alive, Upgrade")
            .header(UPGRADE, "websocket")
            .body(())
            .unwrap();
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn redirect_response_preserves_host_and_path() {
        let req = Request::builder()
            .uri("/some/path?x=1")
            .header(hyper::header::HOST, "example.com")
            .body(())
            .unwrap();
        let resp = https_redirect_response(&req);
        assert_eq!(resp.status(), hyper::StatusCode::MOVED_PERMANENTLY);
        let location = resp.headers().get(hyper::header::LOCATION).unwrap().to_str().unwrap();
        assert_eq!(location, "https://example.com/some/path?x=1");
    }

    async fn test_state() -> AppState {
        use crate::config::{AcmeConfig, AdminConfig, Config, DnsProviderKind, NetworkConfig};
        use std::path::PathBuf;

        let cfg = Config {
            network: NetworkConfig { bind_ranges: vec![] },
            admin: AdminConfig {
                bind_ip: "127.0.0.1".parse().unwrap(),
                bind_port: 8080,
                allowed_ips: vec![],
                session_secret: Some("test-secret".into()),
                admin_username: Some("admin".into()),
                admin_password_hash: Some("$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g".into()),
                db_path: PathBuf::from(":memory:"),
            },
            acme: AcmeConfig {
                directory_url: "https://example.invalid/directory".into(),
                contact_email: "admin@example.com".into(),
                dns_provider: DnsProviderKind::Cloudflare,
                dns_api_token: "token".into(),
                cert_dir: PathBuf::from("/tmp/certs"),
                account_key_path: PathBuf::from("/tmp/account.key"),
                renew_before_days: 30,
            },
            hosts: vec![],
            port_rules: vec![],
        };
        let pool = crate::db::connect(&PathBuf::from(":memory:")).await.unwrap();
        AppState::new(cfg, pool, vec![], vec![], None, None)
    }

    #[tokio::test]
    async fn http01_challenge_response_serves_a_pending_key_authorization() {
        let state = test_state().await;
        state.set_http01_challenge("tok-1".into(), "tok-1.thumbprint".into());

        let req = Request::builder()
            .uri("/.well-known/acme-challenge/tok-1")
            .body(())
            .unwrap();
        let resp = http01_challenge_response(&state, &req).unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from("tok-1.thumbprint"));
    }

    #[tokio::test]
    async fn http01_challenge_response_is_none_for_an_unknown_token() {
        let state = test_state().await;
        let req = Request::builder()
            .uri("/.well-known/acme-challenge/unknown")
            .body(())
            .unwrap();
        assert!(http01_challenge_response(&state, &req).is_none());
    }

    #[tokio::test]
    async fn http01_challenge_response_is_none_for_unrelated_paths() {
        let state = test_state().await;
        state.set_http01_challenge("tok-1".into(), "tok-1.thumbprint".into());
        let req = Request::builder().uri("/some/other/path").body(()).unwrap();
        assert!(http01_challenge_response(&state, &req).is_none());
    }

    #[test]
    fn redirect_strips_port_from_host_header() {
        let req = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "example.com:80")
            .body(())
            .unwrap();
        let resp = https_redirect_response(&req);
        let location = resp.headers().get(hyper::header::LOCATION).unwrap().to_str().unwrap();
        assert_eq!(location, "https://example.com/");
    }

    fn redirect_target(target: &str, preserve_path: bool, status: RedirectStatus) -> RedirectTarget {
        RedirectTarget {
            target: target.into(),
            preserve_path,
            status,
        }
    }

    #[test]
    fn redirect_target_response_appends_the_request_path_when_preserving_it() {
        let req = Request::builder().uri("/blog/post?x=1").body(()).unwrap();
        let target = redirect_target("https://new.example.com", true, RedirectStatus::Permanent);
        let resp = redirect_target_response(&req, &target);
        assert_eq!(resp.status(), hyper::StatusCode::MOVED_PERMANENTLY);
        let location = resp.headers().get(hyper::header::LOCATION).unwrap().to_str().unwrap();
        assert_eq!(location, "https://new.example.com/blog/post?x=1");
    }

    #[test]
    fn redirect_target_response_does_not_double_up_a_trailing_slash() {
        let req = Request::builder().uri("/post").body(()).unwrap();
        let target = redirect_target("https://new.example.com/", true, RedirectStatus::Permanent);
        let resp = redirect_target_response(&req, &target);
        let location = resp.headers().get(hyper::header::LOCATION).unwrap().to_str().unwrap();
        assert_eq!(location, "https://new.example.com/post");
    }

    #[test]
    fn redirect_target_response_ignores_the_request_path_when_not_preserving_it() {
        let req = Request::builder().uri("/whatever/path").body(()).unwrap();
        let target = redirect_target("https://new.example.com/landing", false, RedirectStatus::Permanent);
        let resp = redirect_target_response(&req, &target);
        let location = resp.headers().get(hyper::header::LOCATION).unwrap().to_str().unwrap();
        assert_eq!(location, "https://new.example.com/landing");
    }

    #[test]
    fn redirect_target_response_uses_302_for_a_temporary_redirect() {
        let req = Request::builder().uri("/").body(()).unwrap();
        let target = redirect_target("https://new.example.com", true, RedirectStatus::Temporary);
        let resp = redirect_target_response(&req, &target);
        assert_eq!(resp.status(), hyper::StatusCode::FOUND);
    }

    /// End-to-end: a real fake upstream on loopback, our proxy server
    /// (using `forward_http` in its service_fn) in front of it, and a
    /// real client request driven all the way through -- proves the
    /// forwarding path actually works, not just that it compiles.
    #[tokio::test]
    async fn forward_http_proxies_a_real_request_to_a_loopback_upstream() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(|_req: Request<Incoming>| async {
                let body: BoxBody<Bytes, hyper::Error> =
                    Empty::<Bytes>::new().map_err(|e: std::convert::Infallible| match e {}).boxed();
                Ok::<_, std::convert::Infallible>(Response::builder().status(200).header("x-upstream", "yes").body(body).unwrap())
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| async move {
                let upstream_host_port = upstream_addr.to_string();
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: false,
                    tls_verify: true,
                    upstream_host_port: &upstream_host_port,
                    preserve_host: true,
                };
                forward_http(req, upstream_addr, opts).await.map_err(|e| e.to_string())
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
        });

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "example.com")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-upstream").unwrap(), "yes");
    }

    /// `preserve_host: false` must rewrite the `Host` header the
    /// upstream actually receives to `upstream_host_port`, not just
    /// leave the client's original value on the request untouched.
    #[tokio::test]
    async fn forward_http_rewrites_the_host_header_when_preserve_host_is_disabled() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(|req: Request<Incoming>| async move {
                let seen_host = req.headers().get(hyper::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let body: BoxBody<Bytes, hyper::Error> = Empty::<Bytes>::new().map_err(|e: std::convert::Infallible| match e {}).boxed();
                Ok::<_, std::convert::Infallible>(Response::builder().status(200).header("x-seen-host", seen_host).body(body).unwrap())
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| async move {
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: false,
                    tls_verify: true,
                    upstream_host_port: "backend.internal:9999",
                    preserve_host: false,
                };
                forward_http(req, upstream_addr, opts).await.map_err(|e| e.to_string())
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
        });

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = Request::builder().uri("/").header(hyper::header::HOST, "public.example.com").body(Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-seen-host").unwrap(), "backend.internal:9999", "the upstream must see its own host:port, not the client's original Host header");
    }

    fn self_signed_server_config(domain: &str) -> rustls::ServerConfig {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let entry = crate::proxy::tls::self_signed_entry(domain);
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(entry.cert_chain.clone(), entry.private_key.clone_key())
            .unwrap()
    }

    /// Same three-hop shape as `forward_http_proxies_a_real_request_to_a_loopback_upstream`
    /// (real client -> real "proxy" listener running `forward_http` in
    /// its `service_fn` -> real upstream), except the upstream here
    /// speaks real self-signed TLS -- proves `https: true` actually
    /// completes a real TLS handshake and forwards the request, not
    /// just that the code compiles or that a verifier type is wired in
    /// somewhere. `verify: false` accepts it; `verify: true` (the next
    /// test) must reject the same upstream.
    async fn run_https_upstream_round_trip(tls_verify: bool) -> Result<Response<Incoming>, BoxError> {
        let tls_config = Arc::new(self_signed_server_config("upstream.internal"));
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = upstream_listener.accept().await else { return };
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
            let Ok(tls_stream) = acceptor.accept(stream).await else { return };
            let io = TokioIo::new(tls_stream);
            let service = service_fn(|_req: Request<Incoming>| async {
                let body: BoxBody<Bytes, hyper::Error> =
                    Empty::<Bytes>::new().map_err(|e: std::convert::Infallible| match e {}).boxed();
                Ok::<_, std::convert::Infallible>(Response::builder().status(200).header("x-upstream-tls", "yes").body(body).unwrap())
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| async move {
                let opts = UpstreamOptions {
                    websockets_enabled: false,
                    https: true,
                    tls_verify,
                    upstream_host_port: "upstream.internal:0",
                    preserve_host: true,
                };
                forward_http(req, upstream_addr, opts).await.map_err(|e| e.to_string())
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
        });

        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = Request::builder().uri("/").header(hyper::header::HOST, "example.com").body(Empty::<Bytes>::new()).unwrap();
        sender.send_request(req).await.map_err(|e| Box::new(e) as BoxError)
    }

    #[tokio::test]
    async fn forward_http_reaches_a_self_signed_https_upstream_when_verify_is_disabled() {
        let resp = run_https_upstream_round_trip(false).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-upstream-tls").unwrap(), "yes");
    }

    /// When `forward_http` fails inside the "proxy" hop's `service_fn`,
    /// hyper aborts that connection rather than synthesizing a response
    /// (same reason `handle_https_request` in production converts this
    /// into an explicit 502 itself instead of relying on hyper to do
    /// it) -- so from the real client's side, a rejected upstream
    /// certificate surfaces as the request itself failing, not as a
    /// successful response carrying an error body.
    #[tokio::test]
    async fn forward_http_rejects_a_self_signed_https_upstream_when_verify_is_enabled() {
        let result = run_https_upstream_round_trip(true).await;
        assert!(result.is_err(), "a self-signed cert must be rejected when tls_verify is enabled, not silently accepted");
    }
}
