//! L7 proxy data plane: multi-IP/multi-port listeners, SNI-based TLS,
//! HTTP/WebSocket forwarding, HTTP->HTTPS redirects, and raw TCP/UDP
//! passthrough. A supervisor loop diffs the desired listener set against
//! what's currently running every time `hosts`/`port_rules` change (see
//! `state::AppState::wait_for_change`) and only starts/stops what
//! actually changed -- routing *content* changes (a host's upstream,
//! websockets toggle, etc.) never touch the listener itself, since the
//! request handler re-reads `state.hosts()` fresh on every request. Only
//! a bind_ip/port *topology* change (added/removed/moved host or port
//! rule) causes a listener to start or stop, so unrelated connections are
//! never dropped.

pub mod access;
pub mod http;
pub mod passthrough;
pub mod router;
pub mod tls;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::config::Protocol;
use crate::state::AppState;

pub async fn run(state: AppState) -> anyhow::Result<()> {
    // Only fails if a previous call in this process already installed a
    // different provider -- harmless, ring is the only one this crate
    // links, so any prior install is this same provider.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut https: HashMap<(Ipv4Addr, u16), JoinHandle<()>> = HashMap::new();
    let mut redirects: HashMap<(Ipv4Addr, u16), JoinHandle<()>> = HashMap::new();
    let mut passthroughs: HashMap<(Ipv4Addr, u16, Protocol), JoinHandle<()>> = HashMap::new();

    // `Notify::notify_waiters` only wakes tasks already parked in
    // `.notified().await` at the moment it's called -- a change that lands
    // in the brief window between `reconcile` finishing and the next
    // `.await` would otherwise be silently missed forever. This periodic
    // fallback (same pattern as `nftables::run_sync_loop`) bounds how
    // stale the listener set can ever get.
    const FALLBACK_RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

    loop {
        reconcile(&state, &mut https, &mut redirects, &mut passthroughs);
        tokio::select! {
            _ = state.wait_for_change() => {}
            _ = tokio::time::sleep(FALLBACK_RECONCILE_INTERVAL) => {}
        }
    }
}

fn reconcile(
    state: &AppState,
    https: &mut HashMap<(Ipv4Addr, u16), JoinHandle<()>>,
    redirects: &mut HashMap<(Ipv4Addr, u16), JoinHandle<()>>,
    passthroughs: &mut HashMap<(Ipv4Addr, u16, Protocol), JoinHandle<()>>,
) {
    let hosts = state.hosts();
    let port_rules = state.port_rules();

    reconcile_map(https, &router::https_listener_keys(&hosts), |key| {
        spawn_https_listener(state.clone(), key.0, key.1)
    });
    reconcile_map(redirects, &router::redirect_listener_keys(&hosts), |key| {
        spawn_redirect_listener(state.clone(), key.0, key.1)
    });
    reconcile_map(passthroughs, &passthrough_keys(&port_rules), |key| {
        spawn_passthrough_listener(&port_rules, key.0, key.1, key.2)
    });
}

fn reconcile_map<K: std::hash::Hash + Eq + Copy, F: Fn(&K) -> JoinHandle<()>>(
    current: &mut HashMap<K, JoinHandle<()>>,
    desired: &[K],
    spawn: F,
) {
    current.retain(|key, handle| {
        let keep = desired.contains(key);
        if !keep {
            handle.abort();
        }
        keep
    });
    for key in desired {
        current.entry(*key).or_insert_with(|| spawn(key));
    }
}

fn passthrough_keys(port_rules: &[crate::config::PortRule]) -> Vec<(Ipv4Addr, u16, Protocol)> {
    let mut keys = Vec::new();
    for rule in port_rules.iter().filter(|r| r.enabled && r.passthrough_target.is_some()) {
        for port in rule.port_start..=rule.port_end {
            keys.push((rule.bind_ip, port, rule.protocol));
        }
    }
    keys.sort_by_key(|(ip, port, proto)| (*ip, *port, matches!(proto, Protocol::Udp)));
    keys.dedup();
    keys
}

fn spawn_https_listener(state: AppState, bind_ip: Ipv4Addr, bind_port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from((bind_ip, bind_port));
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(err) => {
                tracing::error!(%addr, error = %err, "failed to bind HTTPS listener");
                return;
            }
        };
        tracing::info!(%addr, "https listener started");

        let acceptor = TlsAcceptor::from(Arc::new(build_https_server_config(state.clone())));

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "https listener accept failed");
                    continue;
                }
            };
            // The listener only ever binds an IPv4 `bind_ip`, so `peer`
            // is always `V4` in practice; `UNSPECIFIED` is an unreachable
            // fallback that fails closed (matches no `access_allow_ips`
            // range) rather than panicking.
            let peer_ip = match peer.ip() {
                std::net::IpAddr::V4(v4) => v4,
                std::net::IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            };
            let acceptor = acceptor.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(err) => {
                        tracing::debug!(error = %err, "tls handshake failed");
                        return;
                    }
                };
                let sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
                let io = TokioIo::new(tls_stream);
                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let state = state.clone();
                    let sni = sni.clone();
                    async move { handle_https_request(state, bind_ip, bind_port, peer_ip, sni, req).await }
                });
                // `auto::Builder` sniffs the connection preface to pick
                // HTTP/1 vs HTTP/2 per-connection -- ALPN already steered
                // the client here (see `build_https_server_config`), this
                // just has to actually speak whichever one shows up.
                // `_with_upgrades` is what still makes `hyper::upgrade::on`
                // (WebSocket passthrough, see `http::forward_http`) work
                // on the HTTP/1 side; HTTP/2 clients get real h2
                // multiplexing with no code-path changes needed here.
                if let Err(err) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(io, service)
                    .await
                {
                    tracing::debug!(error = %err, "https connection ended");
                }
            });
        }
    })
}

/// ALPN offers `h2` before `http/1.1` (server preference order) but
/// deliberately never calls `.http2().enable_connect_protocol()` on the
/// auto builder above -- that's what advertises HTTP/2 Extended CONNECT
/// (RFC 8441, WebSocket-over-h2) support in the SETTINGS frame. Per
/// that RFC, a client MUST NOT attempt a WebSocket handshake over h2
/// unless it first confirms that setting is present; leaving it off
/// means a WebSocket-bound client falls back to a normal HTTP/1.1
/// connection (where the `Upgrade:` mechanism `forward_http` already
/// implements works unchanged), while every other request gets real
/// HTTP/2 multiplexing -- the same split Nginx itself makes.
fn build_https_server_config(state: AppState) -> rustls::ServerConfig {
    let resolver = Arc::new(tls::CertResolver::new(state));
    let mut server_config = rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(resolver);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    server_config
}

async fn handle_https_request(
    state: AppState,
    bind_ip: Ipv4Addr,
    bind_port: u16,
    peer_ip: Ipv4Addr,
    sni: Option<String>,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, std::convert::Infallible> {
    let host_header = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let lookup_name = sni.or(host_header);

    let hosts = state.hosts();
    let matched = lookup_name
        .as_deref()
        .and_then(|name| router::match_host(&hosts, bind_ip, bind_port, name));

    let Some(host) = matched else {
        return Ok(not_found());
    };

    if !access::ip_allowed(&host.access_allow_ips, peer_ip) {
        return Ok(forbidden());
    }
    let auth_header = req.headers().get(hyper::header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if !access::check_basic_auth(&host.access_basic_auth, auth_header) {
        return Ok(unauthorized(&host.domain));
    }

    let Ok(upstream) = resolve_upstream(&host.upstream) else {
        return Ok(bad_gateway());
    };

    match http::forward_http(req, upstream, host.websockets).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::warn!(domain = %host.domain, error = %err, "upstream request failed");
            Ok(bad_gateway())
        }
    }
}

/// Serves both plain-HTTP purposes port 80 ever has here: an ACME http-01
/// challenge fetch (checked first -- see `http::http01_challenge_response`,
/// since the CA's validator never follows a redirect) and, for anything
/// else, the `force_https` redirect to the same path on `https`.
fn spawn_redirect_listener(state: AppState, bind_ip: Ipv4Addr, bind_port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from((bind_ip, bind_port));
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(err) => {
                tracing::error!(%addr, error = %err, "failed to bind redirect listener");
                return;
            }
        };
        tracing::info!(%addr, "http redirect listener started");

        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "redirect listener accept failed");
                    continue;
                }
            };
            let io = TokioIo::new(stream);
            let state = state.clone();
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                async move {
                    if let Some(resp) = http::http01_challenge_response(&state, &req) {
                        return Ok::<_, std::convert::Infallible>(resp);
                    }
                    Ok::<_, std::convert::Infallible>(http::https_redirect_response(&req))
                }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
            });
        }
    })
}

fn spawn_passthrough_listener(
    port_rules: &[crate::config::PortRule],
    bind_ip: Ipv4Addr,
    port: u16,
    protocol: Protocol,
) -> JoinHandle<()> {
    let target = port_rules
        .iter()
        .find(|r| r.enabled && r.bind_ip == bind_ip && (r.port_start..=r.port_end).contains(&port) && r.protocol == protocol)
        .and_then(|r| r.passthrough_target.clone());

    let bind_addr = SocketAddr::from((bind_ip, port));
    tokio::spawn(async move {
        let Some(target) = target else {
            tracing::error!(%bind_addr, "passthrough listener spawned with no matching target rule");
            return;
        };
        let Ok(upstream) = resolve_upstream(&target) else {
            tracing::error!(%bind_addr, target, "passthrough target does not resolve to host:port");
            return;
        };
        let result = match protocol {
            Protocol::Tcp => passthrough::run_tcp_passthrough(bind_addr, upstream).await,
            Protocol::Udp => passthrough::run_udp_passthrough(bind_addr, upstream).await,
        };
        if let Err(err) = result {
            tracing::error!(%bind_addr, error = %err, "passthrough listener exited");
        }
    })
}

fn resolve_upstream(upstream: &str) -> Result<SocketAddr, std::io::Error> {
    use std::net::ToSocketAddrs;
    upstream
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "upstream did not resolve to any address"))
}

fn not_found() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(hyper::StatusCode::NOT_FOUND)
        .body(http_body_util::Empty::new().map_err(|e: std::convert::Infallible| match e {}).boxed())
        .expect("static response is always valid")
}

fn bad_gateway() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(hyper::StatusCode::BAD_GATEWAY)
        .body(http_body_util::Empty::new().map_err(|e: std::convert::Infallible| match e {}).boxed())
        .expect("static response is always valid")
}

fn forbidden() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(hyper::StatusCode::FORBIDDEN)
        .body(http_body_util::Empty::new().map_err(|e: std::convert::Infallible| match e {}).boxed())
        .expect("static response is always valid")
}

/// `WWW-Authenticate` prompts a browser's own login dialog, same as any
/// server enforcing Basic Auth directly. `realm` is the domain rather
/// than a fixed string so a client juggling multiple protected hosts
/// through this proxy sees which one it's authenticating against.
fn unauthorized(realm: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(hyper::StatusCode::UNAUTHORIZED)
        .header(hyper::header::WWW_AUTHENTICATE, format!("Basic realm=\"{realm}\""))
        .body(http_body_util::Empty::new().map_err(|e: std::convert::Infallible| match e {}).boxed())
        .expect("static response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcmeConfig, AdminConfig, Config, DnsProviderKind, NetworkConfig, PortRule, ProxyHost, Protocol};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName as RustlsServerName, UnixTime};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn rule(bind_ip: &str, start: u16, end: u16, proto: Protocol, target: Option<&str>) -> PortRule {
        PortRule {
            id: Uuid::new_v4(),
            bind_ip: bind_ip.parse().unwrap(),
            port_start: start,
            port_end: end,
            protocol: proto,
            description: "test".into(),
            passthrough_target: target.map(|t| t.to_string()),
            enabled: true,
        }
    }

    #[test]
    fn passthrough_keys_expand_a_range_into_one_key_per_port() {
        let rules = vec![rule("10.0.0.4", 21115, 21119, Protocol::Tcp, Some("127.0.0.1:9000"))];
        let keys = passthrough_keys(&rules);
        assert_eq!(keys.len(), 5);
        assert!(keys.contains(&("10.0.0.4".parse().unwrap(), 21117, Protocol::Tcp)));
    }

    #[test]
    fn passthrough_keys_skip_rules_without_a_target() {
        let rules = vec![rule("10.0.0.3", 22, 22, Protocol::Tcp, None)];
        assert!(passthrough_keys(&rules).is_empty());
    }

    #[test]
    fn resolve_upstream_parses_host_port() {
        let addr = resolve_upstream("127.0.0.1:8080").unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn resolve_upstream_rejects_malformed_input() {
        assert!(resolve_upstream("not-a-host-port").is_err());
    }

    async fn test_state_with_cert(domain: &str) -> AppState {
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
        let state = AppState::new(cfg, pool, vec![], vec![]);
        state.upsert_cert(domain.to_string(), {
            let entry = tls::self_signed_entry(domain);
            entry
        });
        state
    }

    async fn test_state_with_host(host: ProxyHost) -> AppState {
        let state = test_state_with_cert(&host.domain).await;
        state.set_hosts(vec![host]);
        state
    }

    fn access_host(domain: &str, access_allow_ips: Vec<ipnet::Ipv4Net>, access_basic_auth: Option<crate::config::BasicAuth>) -> ProxyHost {
        ProxyHost {
            id: Uuid::new_v4(),
            domain: domain.into(),
            bind_ip: "10.0.0.2".parse().unwrap(),
            bind_port: 443,
            upstream: "127.0.0.1:1".into(),
            websockets: false,
            force_https: false,
            acme_enabled: false,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            access_allow_ips,
            access_basic_auth,
            enabled: true,
        }
    }

    /// Drives `handle_https_request` through a real loopback HTTP/1.1
    /// connection (same shape as `proxy::http`'s own
    /// `forward_http_proxies_a_real_request_to_a_loopback_upstream` test)
    /// rather than fabricating a `Request<Incoming>` -- `Incoming` is a
    /// real hyper body type tied to an actual connection, so there's no
    /// safe way to construct one without a real client/server round trip.
    async fn send_test_request(
        state: AppState,
        bind_ip: Ipv4Addr,
        bind_port: u16,
        peer_ip: Ipv4Addr,
        sni: Option<String>,
        auth_header: Option<String>,
    ) -> Response<Incoming> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                let sni = sni.clone();
                async move { handle_https_request(state, bind_ip, bind_port, peer_ip, sni, req).await }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let mut builder = Request::builder().uri("/");
        if let Some(value) = auth_header {
            builder = builder.header(hyper::header::AUTHORIZATION, value);
        }
        let req = builder.body(http_body_util::Empty::<Bytes>::new()).unwrap();
        sender.send_request(req).await.unwrap()
    }

    #[tokio::test]
    async fn request_from_an_ip_outside_the_allow_list_is_forbidden() {
        let state = test_state_with_host(access_host("example.com", vec!["192.168.1.0/24".parse().unwrap()], None)).await;
        let resp = send_test_request(
            state,
            "10.0.0.2".parse().unwrap(),
            443,
            "203.0.113.7".parse().unwrap(),
            Some("example.com".to_string()),
            None,
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn request_from_an_allowed_ip_without_basic_auth_configured_is_not_blocked() {
        let state = test_state_with_host(access_host("example.com", vec!["10.0.0.0/24".parse().unwrap()], None)).await;
        let resp = send_test_request(
            state,
            "10.0.0.2".parse().unwrap(),
            443,
            "10.0.0.42".parse().unwrap(),
            Some("example.com".to_string()),
            None,
        )
        .await;
        // Upstream is unreachable (127.0.0.1:1) so this proves access
        // control let the request through, not that it fully succeeded.
        assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn request_without_credentials_is_challenged_when_basic_auth_is_configured() {
        let auth = crate::config::BasicAuth {
            username: "viewer".into(),
            password_hash: crate::api::auth::hash_password("s3cret").unwrap(),
        };
        let state = test_state_with_host(access_host("example.com", vec![], Some(auth))).await;
        let resp = send_test_request(
            state,
            "10.0.0.2".parse().unwrap(),
            443,
            "203.0.113.7".parse().unwrap(),
            Some("example.com".to_string()),
            None,
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(hyper::header::WWW_AUTHENTICATE).unwrap(),
            "Basic realm=\"example.com\""
        );
    }

    #[tokio::test]
    async fn request_with_correct_basic_auth_credentials_passes_through_to_the_upstream_lookup() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let auth = crate::config::BasicAuth {
            username: "viewer".into(),
            password_hash: crate::api::auth::hash_password("s3cret").unwrap(),
        };
        let state = test_state_with_host(access_host("example.com", vec![], Some(auth))).await;
        let header = format!("Basic {}", STANDARD.encode("viewer:s3cret"));
        let resp = send_test_request(
            state,
            "10.0.0.2".parse().unwrap(),
            443,
            "203.0.113.7".parse().unwrap(),
            Some("example.com".to_string()),
            Some(header),
        )
        .await;
        // Upstream is unreachable (127.0.0.1:1) so this proves the
        // credentials cleared access control, not that it fully succeeded.
        assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY);
    }

    /// A test-only "trust anything" verifier -- the self-signed cert
    /// `test_state_with_cert` hands out has no real CA chain, so a
    /// normal verifier would reject it outright; this test cares about
    /// ALPN negotiation and HTTP/2 transport, not certificate trust
    /// (that's an orthogonal, already-real concern once a real CA
    /// issues the cert via ACME).
    #[derive(Debug)]
    struct AcceptAnyCert;
    impl ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &RustlsServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
        }
    }

    /// End-to-end: real TLS handshake against `build_https_server_config`
    /// (the exact config `spawn_https_listener` uses), a real client
    /// offering `h2` in ALPN, and a real HTTP/2 request driven all the
    /// way through `serve_connection_with_upgrades`'s auto h1/h2
    /// dispatch -- proves the ALPN change actually results in a working
    /// HTTP/2 connection, not just that the config value changed.
    #[tokio::test]
    async fn https_listener_negotiates_http2_and_serves_a_real_request() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let state = test_state_with_cert("example.com").await;
        let acceptor = TlsAcceptor::from(Arc::new(build_https_server_config(state)));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls_stream = acceptor.accept(stream).await.unwrap();
            let io = TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(|_req: Request<Incoming>| async {
                let body: BoxBody<Bytes, hyper::Error> =
                    http_body_util::Empty::new().map_err(|e: std::convert::Infallible| match e {}).boxed();
                Ok::<_, std::convert::Infallible>(Response::builder().status(200).header("x-h2-test", "yes").body(body).unwrap())
            });
            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
                .unwrap();
        });

        let mut client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = RustlsServerName::try_from("example.com").unwrap();
        let tls_stream = connector.connect(server_name, tcp).await.unwrap();

        let negotiated = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        assert_eq!(negotiated, Some(b"h2".to_vec()), "server should have negotiated h2 when the client offered it");

        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await.unwrap();
        tokio::spawn(conn);
        let req = Request::builder().uri("/").body(http_body_util::Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-h2-test").unwrap(), "yes");
    }

    /// A client that only offers `http/1.1` (no h2) must still work --
    /// the WebSocket-fallback case this whole design hinges on.
    #[tokio::test]
    async fn https_listener_still_negotiates_http1_when_thats_all_the_client_offers() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let state = test_state_with_cert("example.com").await;
        let acceptor = TlsAcceptor::from(Arc::new(build_https_server_config(state)));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls_stream = acceptor.accept(stream).await.unwrap();
            let io = TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(|_req: Request<Incoming>| async {
                let body: BoxBody<Bytes, hyper::Error> =
                    http_body_util::Empty::new().map_err(|e: std::convert::Infallible| match e {}).boxed();
                Ok::<_, std::convert::Infallible>(Response::builder().status(200).body(body).unwrap())
            });
            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
                .unwrap();
        });

        let mut client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = RustlsServerName::try_from("example.com").unwrap();
        let tls_stream = connector.connect(server_name, tcp).await.unwrap();

        let negotiated = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        assert_eq!(negotiated, Some(b"http/1.1".to_vec()));

        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "example.com")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
    }
}
