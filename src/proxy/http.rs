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
/// unmodified. If `websockets_enabled` and the request is a WebSocket
/// upgrade, splices the client and upstream connections together after
/// the 101 response instead of treating it as a normal request/response.
pub async fn forward_http(
    mut req: Request<Incoming>,
    upstream: SocketAddr,
    websockets_enabled: bool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, BoxError> {
    let want_upgrade = websockets_enabled && is_websocket_upgrade(&req);
    let client_upgrade = want_upgrade.then(|| hyper::upgrade::on(&mut req));

    let stream = TcpStream::connect(upstream).await?;
    let io = TokioIo::new(stream);
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
                session_secret: "test-secret".into(),
                admin_username: "admin".into(),
                admin_password_hash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g".into(),
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
        AppState::new(cfg, pool, vec![], vec![])
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
                forward_http(req, upstream_addr, false).await.map_err(|e| e.to_string())
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
}
