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
pub mod login;
pub mod passthrough;
pub mod router;
pub mod tls;
pub mod upstream_tls;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
#[cfg(test)]
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

    let mut https: HashMap<(IpAddr, u16), JoinHandle<()>> = HashMap::new();
    let mut redirects: HashMap<(IpAddr, u16), JoinHandle<()>> = HashMap::new();
    let mut passthroughs: HashMap<(IpAddr, u16, Protocol), JoinHandle<()>> = HashMap::new();

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
    https: &mut HashMap<(IpAddr, u16), JoinHandle<()>>,
    redirects: &mut HashMap<(IpAddr, u16), JoinHandle<()>>,
    passthroughs: &mut HashMap<(IpAddr, u16, Protocol), JoinHandle<()>>,
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

fn passthrough_keys(port_rules: &[crate::config::PortRule]) -> Vec<(IpAddr, u16, Protocol)> {
    let mut keys = Vec::new();
    for rule in port_rules.iter().filter(|r| r.enabled && r.passthrough_target.is_some()) {
        for bind_ip in crate::config::port_rule_bind_ips(rule) {
            for port in rule.port_start..=rule.port_end {
                keys.push((bind_ip, port, rule.protocol));
            }
        }
    }
    keys.sort_by_key(|(ip, port, proto)| (*ip, *port, matches!(proto, Protocol::Udp)));
    keys.dedup();
    keys
}

fn spawn_https_listener(state: AppState, bind_ip: IpAddr, bind_port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from((bind_ip, bind_port));
        let listener = match crate::netbind::bind_tcp_listener(addr) {
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
            let peer_ip = peer.ip();
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
    bind_ip: IpAddr,
    bind_port: u16,
    peer_ip: IpAddr,
    sni: Option<String>,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, std::convert::Infallible> {
    // Real HTTP/2 clients (every modern browser) send the target host
    // as the `:authority` pseudo-header, not a literal `Host:` header --
    // hyper/h2 surfaces that in `req.uri()`'s authority component, not
    // `req.headers()`. `req.headers().get(HOST)` alone is therefore
    // `None` for the overwhelming majority of real h2 traffic (confirmed
    // live: a real h2 request logged `host_header="<none>"` despite
    // definitely carrying a target host), silently falling through to
    // `sni` below -- which defeats the whole point of preferring the
    // per-request host over the per-connection SNI, since exactly the h2
    // clients capable of connection coalescing are the ones this never
    // engaged for. `req.uri().host()` covers h2 (and any h1 client using
    // absolute-form request targets, e.g. through another proxy); the
    // header remains the fallback for ordinary h1 origin-form requests,
    // where `req.uri()` is just the path with no authority at all.
    let uri_host = req.uri().host().map(|s| s.to_string());
    let host_header = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // Either form of "the request's own declared host" must win over
    // `sni` when they disagree -- `sni` is captured once per TLS
    // connection at handshake time, but a single connection can carry
    // requests for more than one domain: HTTP/2 connection coalescing
    // (RFC 7540 §9.1.1) lets a browser reuse an existing connection for
    // a *different* origin whenever the connection's cert also covers
    // it (exactly what a wildcard/SAN cert does), and each request on
    // that connection still carries its own real target host. Routing
    // by `sni` first sent every request after the first to whichever
    // host the connection originally happened to be for -- confirmed as
    // a real production bug: visiting store.jpps.us after proxy.jpps.us
    // (both under the *.jpps.us wildcard cert, same bind_ip:port) served
    // proxy.jpps.us's admin login page instead. `sni` is still what
    // `proxy::tls::CertResolver` uses to pick the TLS certificate itself
    // (that part's connection-scoped by nature); this is purely about
    // which *host* a given request routes to. `sni` remains the
    // fallback for the rare case a request genuinely declares no host
    // at all.
    let lookup_name = uri_host.clone().or_else(|| host_header.clone()).or_else(|| sni.clone());

    let hosts = state.hosts();
    let matched = lookup_name
        .as_deref()
        .and_then(|name| router::match_host(&hosts, bind_ip, bind_port, name));

    // The daemon's only per-request routing-decision log -- exactly
    // what's needed to diagnose "request for X got routed to Y" without
    // reasoning about it in the abstract: sni is the TLS connection's
    // own (possibly stale, see above), uri_host/host_header are what
    // this specific request actually declared (uri_host is what real h2
    // traffic actually carries -- see above), and matched_domain is
    // what it was actually routed to. debug-level, so it only lands in
    // proxy.log (see logging.rs), not stdout/journald.
    tracing::debug!(
        %bind_ip,
        bind_port,
        %peer_ip,
        sni = sni.as_deref().unwrap_or("<none>"),
        uri_host = uri_host.as_deref().unwrap_or("<none>"),
        host_header = host_header.as_deref().unwrap_or("<none>"),
        matched_domain = matched.map(|h| h.domain.as_str()).unwrap_or("<no match>"),
        "routing decision"
    );

    let Some(host) = matched else {
        return Ok(not_found());
    };

    let resolved_acls = if host.acl_ids.is_empty() {
        crate::db::ResolvedAcls::default()
    } else {
        match crate::db::resolve_acl_ids(state.db(), &host.acl_ids).await {
            Ok(resolved) => resolved,
            Err(err) => {
                tracing::error!(domain = %host.domain, error = %err, "failed to resolve host ACLs");
                return Ok(bad_gateway());
            }
        }
    };

    // IP-allow and login gates combine by OR, not AND, when a host has
    // both kinds of ACL selected -- passing either is sufficient, and
    // "IP over login" means the IP check is tried first: a matching
    // source IP admits the request outright, without ever touching the
    // login gate, even if one is also configured. An IP-allow ACL that
    // DOESN'T match falls through to the login gate instead of an
    // immediate 403 (a real lockout this fixes: an operator whose source
    // IP no longer matches a host's IP-allow list, but who still has
    // valid login credentials for it, must still be able to sign in).
    // Only a host with an IP-allow ACL and NO login ACL at all still
    // 403s outright on a non-matching IP, same as it always has.
    let ip_allowed = access::ip_allowed(&resolved_acls.allow_ips, peer_ip);
    if !(resolved_acls.has_ip_allow_acl && ip_allowed) {
        if resolved_acls.has_login_acl {
            let has_valid_session = find_cookie(&req, login::SESSION_COOKIE)
                .zip(state.admin_identity())
                .map(|(token, identity)| login::verify_session(&identity.session_secret, &host.domain, &token))
                .unwrap_or(false);
            if !has_valid_session {
                return Ok(handle_login_gate(&state, &host.domain, &resolved_acls.credentials, req).await);
            }
        } else if resolved_acls.has_ip_allow_acl {
            return Ok(forbidden_page(&host.domain));
        }
    }

    if let Some(redirect) = &host.redirect {
        return Ok(http::redirect_target_response(&req, redirect));
    }

    let mut req = req;
    if let Some(path_rewrite) = &host.path_rewrite {
        apply_path_rewrite(&mut req, path_rewrite);
    }

    let Ok(upstream) = resolve_upstream(&host.upstream) else {
        return Ok(bad_gateway());
    };

    let opts = http::UpstreamOptions {
        websockets_enabled: host.websockets,
        https: host.upstream_https,
        tls_verify: host.upstream_tls_verify,
        upstream_host_port: &host.upstream,
        preserve_host: host.upstream_preserve_host,
    };
    match http::forward_http(req, upstream, opts).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::warn!(domain = %host.domain, error = %err, "upstream request failed");
            Ok(bad_gateway())
        }
    }
}

/// Rewrites `req`'s path (leaving the query string intact) per
/// `rewrite`'s pattern/replacement -- see `config::ProxyHost::path_rewrite`'s
/// doc comment for the exact semantics. A no-op if the pattern doesn't
/// compile (already validated at host-save time, see
/// `api::routes::validate_host_request`, so this should never actually
/// happen in practice) or doesn't match this request's path at all.
fn apply_path_rewrite<B>(req: &mut Request<B>, rewrite: &crate::config::PathRewrite) {
    let Ok(re) = regex::Regex::new(&rewrite.pattern) else {
        return;
    };
    let original_path = req.uri().path();
    if !re.is_match(original_path) {
        return;
    }
    let new_path = re.replace(original_path, rewrite.replacement.as_str()).into_owned();
    let new_path_and_query = match req.uri().query() {
        Some(query) => format!("{new_path}?{query}"),
        None => new_path,
    };
    let Ok(path_and_query) = hyper::http::uri::PathAndQuery::try_from(new_path_and_query) else {
        return;
    };
    let mut parts = req.uri().clone().into_parts();
    parts.path_and_query = Some(path_and_query);
    if let Ok(new_uri) = hyper::http::Uri::from_parts(parts) {
        *req.uri_mut() = new_uri;
    }
}

fn find_cookie(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.headers().get(hyper::header::COOKIE).and_then(|v| v.to_str().ok()).and_then(|raw| {
        raw.split(';').find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
    })
}

/// Handles every request to a login-gated host that arrived without a
/// valid session: either a login submission (`POST` to
/// `login::LOGIN_SUBMIT_PATH`), or any other request, which gets the
/// login page rendered in place of the resource it actually wanted --
/// `return_to` carries that original path/query so a successful login
/// lands the visitor back where they meant to go.
async fn handle_login_gate(
    state: &AppState,
    domain: &str,
    credentials: &[crate::config::HostAuth],
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    if req.method() == hyper::Method::POST && req.uri().path() == login::LOGIN_SUBMIT_PATH {
        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return login_page_response(domain, "/", Some("invalid request"), hyper::StatusCode::BAD_REQUEST),
        };
        let Ok(submission) = serde_json::from_slice::<login::LoginSubmission>(&body_bytes) else {
            return login_page_response(domain, "/", Some("invalid request"), hyper::StatusCode::BAD_REQUEST);
        };
        if login::verify_credentials_any(credentials, &submission.username, &submission.password) {
            let Some(identity) = state.admin_identity() else {
                // No admin identity resolved yet (e.g. instance awaiting
                // first-launch setup) -- the host-level login gate
                // derives its session-signing key from the same secret,
                // so there's nothing to sign with.
                return service_unavailable();
            };
            let token = login::sign_session(&identity.session_secret, domain, &submission.username);
            return login_success_response(&token);
        }
        return login_page_response(
            domain,
            &submission.return_to,
            Some("Invalid username or password"),
            hyper::StatusCode::UNAUTHORIZED,
        );
    }

    let return_to = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();
    login_page_response(domain, &return_to, None, hyper::StatusCode::OK)
}

fn login_page_response(domain: &str, return_to: &str, error: Option<&str>, status: hyper::StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
    let html = login::render_login_page(domain, return_to, error);
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(http_body_util::Full::new(Bytes::from(html)).map_err(|e: std::convert::Infallible| match e {}).boxed())
        .expect("static login page response is always valid")
}

/// `Secure` is always correct here -- this handler only ever runs behind
/// the HTTPS listener, never the plain-HTTP redirect one.
fn login_success_response(token: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let cookie = format!(
        "{}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        login::SESSION_COOKIE,
        login::SESSION_LIFETIME_SECS
    );
    Response::builder()
        .status(hyper::StatusCode::OK)
        .header(hyper::header::SET_COOKIE, cookie)
        .body(http_body_util::Empty::new().map_err(|e: std::convert::Infallible| match e {}).boxed())
        .expect("static login success response is always valid")
}

/// Serves both plain-HTTP purposes port 80 ever has here: an ACME http-01
/// challenge fetch (checked first -- see `http::http01_challenge_response`,
/// since the CA's validator never follows a redirect) and, for anything
/// else, the `force_https` redirect to the same path on `https`.
fn spawn_redirect_listener(state: AppState, bind_ip: IpAddr, bind_port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from((bind_ip, bind_port));
        let listener = match crate::netbind::bind_tcp_listener(addr) {
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
    bind_ip: IpAddr,
    port: u16,
    protocol: Protocol,
) -> JoinHandle<()> {
    let target = port_rules
        .iter()
        .find(|r| r.enabled && crate::config::port_rule_bind_ips(r).contains(&bind_ip) && (r.port_start..=r.port_end).contains(&port) && r.protocol == protocol)
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

/// A real "Access denied" page, not a bare unstyled 403 -- shown for a
/// host with an IP-allow ACL and no login ACL to fall back to, whose
/// visitor's source IP didn't match (see `handle_https_request`'s
/// "IP over login" combination).
fn forbidden_page(domain: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let html = login::render_forbidden_page(domain);
    Response::builder()
        .status(hyper::StatusCode::FORBIDDEN)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(http_body_util::Full::new(Bytes::from(html)).map_err(|e: std::convert::Infallible| match e {}).boxed())
        .expect("static forbidden page response is always valid")
}

fn service_unavailable() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
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

    fn path_rewrite(pattern: &str, replacement: &str) -> crate::config::PathRewrite {
        crate::config::PathRewrite { pattern: pattern.into(), replacement: replacement.into() }
    }

    #[test]
    fn apply_path_rewrite_inserts_gitlab_wikis_segment_for_a_bare_project_path() {
        let rw = path_rewrite(r"^/([^/]+/[^/]+)(?:/(.*))?$", "/$1/-/wikis/$2");
        let mut req = Request::builder().uri("/jpps/rust-proxy").body(()).unwrap();
        apply_path_rewrite(&mut req, &rw);
        assert_eq!(req.uri().path(), "/jpps/rust-proxy/-/wikis/");
    }

    #[test]
    fn apply_path_rewrite_preserves_a_deeper_path_after_the_project() {
        let rw = path_rewrite(r"^/([^/]+/[^/]+)(?:/(.*))?$", "/$1/-/wikis/$2");
        let mut req = Request::builder().uri("/jpps/rust-proxy/getting-started").body(()).unwrap();
        apply_path_rewrite(&mut req, &rw);
        assert_eq!(req.uri().path(), "/jpps/rust-proxy/-/wikis/getting-started");
    }

    #[test]
    fn apply_path_rewrite_preserves_the_query_string() {
        let rw = path_rewrite(r"^/old(/.*)?$", "/new$1");
        let mut req = Request::builder().uri("/old/page?x=1&y=2").body(()).unwrap();
        apply_path_rewrite(&mut req, &rw);
        assert_eq!(req.uri().path(), "/new/page");
        assert_eq!(req.uri().query(), Some("x=1&y=2"));
    }

    #[test]
    fn apply_path_rewrite_leaves_a_non_matching_path_untouched() {
        let rw = path_rewrite(r"^/only-this-path$", "/rewritten");
        let mut req = Request::builder().uri("/something-else").body(()).unwrap();
        apply_path_rewrite(&mut req, &rw);
        assert_eq!(req.uri().path(), "/something-else");
    }

    #[test]
    fn apply_path_rewrite_leaves_the_request_untouched_when_the_pattern_is_invalid() {
        let rw = path_rewrite("(unclosed", "/rewritten");
        let mut req = Request::builder().uri("/original").body(()).unwrap();
        apply_path_rewrite(&mut req, &rw);
        assert_eq!(req.uri().path(), "/original");
    }

    fn rule(bind_ip: &str, start: u16, end: u16, proto: Protocol, target: Option<&str>) -> PortRule {
        PortRule {
            id: Uuid::new_v4(),
            bind_ip_v4: Some(bind_ip.parse().unwrap()),
            bind_ip_v6: None,
            port_start: start,
            port_end: end,
            protocol: proto,
            description: "test".into(),
            passthrough_target: target.map(|t| t.to_string()),
            acl_ids: vec![],
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
                bind_ip_v4: Some("127.0.0.1".parse().unwrap()),
                bind_ip_v6: None,
                bind_port: 8080,
                allowed_ips: vec![],
                expose_admin_port: None,
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
                organization: None,
                organizational_unit: None,
            },
            hosts: vec![],
            port_rules: vec![],
        };
        let pool = crate::db::connect(&PathBuf::from(":memory:")).await.unwrap();
        let state = AppState::new(cfg, pool, vec![], vec![], None, None, None);
        state.upsert_cert(domain.to_string(), tls::self_signed_entry(domain));
        state
    }

    async fn test_state_with_host(host: ProxyHost) -> AppState {
        let state = test_state_with_cert(&host.domain).await;
        state.set_hosts(vec![host]);
        state
    }

    async fn test_state_with_access(
        domain: &str,
        access_allow_ips: Vec<ipnet::Ipv4Net>,
        access_login: Option<crate::config::HostAuth>,
    ) -> AppState {
        let state = test_state_with_cert(domain).await;
        let host = access_host(state.db(), domain, access_allow_ips, access_login).await;
        state.set_hosts(vec![host]);
        state
    }

    /// Creates the ACL list(s) needed to back the given IP-allow/login
    /// requirements (via the same `db::` CRUD the real API uses) and
    /// returns a host whose `acl_ids` selects them -- resolution happens
    /// live via `db::resolve_acl_ids` on every request, same as
    /// production, so these tests exercise the real DB-backed path.
    async fn access_host(
        pool: &sqlx::SqlitePool,
        domain: &str,
        access_allow_ips: Vec<ipnet::Ipv4Net>,
        access_login: Option<crate::config::HostAuth>,
    ) -> ProxyHost {
        let mut acl_ids = Vec::new();
        if !access_allow_ips.is_empty() {
            let acl_id = Uuid::new_v4();
            crate::db::create_acl_list(pool, acl_id, "test ip allow", crate::config::AclKind::IpAllow, chrono::Utc::now()).await.unwrap();
            let cidrs: Vec<String> = access_allow_ips.iter().map(|net| net.to_string()).collect();
            crate::db::add_acl_ip_entries(pool, acl_id, &cidrs).await.unwrap();
            acl_ids.push(acl_id);
        }
        if let Some(auth) = access_login {
            let acl_id = Uuid::new_v4();
            crate::db::create_acl_list(pool, acl_id, "test login", crate::config::AclKind::Login, chrono::Utc::now()).await.unwrap();
            crate::db::add_acl_credentials(pool, acl_id, &[(auth.username.clone(), auth.password_hash.clone())]).await.unwrap();
            acl_ids.push(acl_id);
        }
        ProxyHost {
            id: Uuid::new_v4(),
            domain: domain.into(),
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: "127.0.0.1:1".into(),
            upstream_https: false,
            upstream_tls_verify: true,
            upstream_preserve_host: true,
            websockets: false,
            force_https: false,
            acme_enabled: false,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            acl_ids,
            dns_credential_id: None,
            redirect: None,
            path_rewrite: None,
            enabled: true,
        }
    }

    /// Drives `handle_https_request` through a real loopback HTTP/1.1
    /// connection (same shape as `proxy::http`'s own
    /// `forward_http_proxies_a_real_request_to_a_loopback_upstream` test)
    /// rather than fabricating a `Request<Incoming>` -- `Incoming` is a
    /// real hyper body type tied to an actual connection, so there's no
    /// safe way to construct one without a real client/server round trip.
    /// `bind_ip`/`bind_port`/SNI are fixed at `access_host`'s own values
    /// (10.0.0.2:443, "example.com") since every test in this module
    /// uses them unchanged -- only `peer_ip` and the request itself vary.
    async fn send_test_request(
        state: AppState,
        peer_ip: IpAddr,
        method: &str,
        path: &str,
        cookie: Option<String>,
        json_body: Option<serde_json::Value>,
    ) -> Response<Incoming> {
        let bind_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let bind_port = 443;
        let sni = Some("example.com".to_string());

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

        let mut builder = Request::builder().method(method).uri(path);
        if let Some(value) = cookie {
            builder = builder.header(hyper::header::COOKIE, value);
        }
        let body_bytes = match &json_body {
            Some(v) => {
                builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
                serde_json::to_vec(v).unwrap()
            }
            None => Vec::new(),
        };
        let req = builder.body(http_body_util::Full::new(Bytes::from(body_bytes))).unwrap();
        sender.send_request(req).await.unwrap()
    }

    async fn response_text(resp: Response<Incoming>) -> String {
        String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    /// Real production bug this guards against: HTTP/2 connection
    /// coalescing (RFC 7540 §9.1.1, or any other keep-alive reuse) can
    /// carry a request for a *different* domain than the one the TLS
    /// connection's SNI named, whenever one cert (a wildcard/SAN cert)
    /// covers both -- confirmed live: visiting store.jpps.us right
    /// after proxy.jpps.us (both under the same *.jpps.us cert, same
    /// bind_ip:port) served proxy.jpps.us's admin login page instead of
    /// the store. Each request still carries its own real `Host`
    /// header naming which domain it's actually for; routing must key
    /// off that, not the connection-level SNI captured once at
    /// handshake time.
    #[tokio::test]
    async fn the_host_header_wins_over_a_stale_connection_level_sni_when_they_disagree() {
        let target_b = crate::config::RedirectTarget {
            target: "https://b.example.com".into(),
            preserve_path: false,
            status: crate::config::RedirectStatus::Permanent,
        };
        let host_a = redirect_host(
            "first.example.com",
            crate::config::RedirectTarget {
                target: "https://a.example.com".into(),
                preserve_path: false,
                status: crate::config::RedirectStatus::Permanent,
            },
        );
        let host_b = redirect_host("second.example.com", target_b);
        let state = test_state_with_cert("first.example.com").await;
        state.set_hosts(vec![host_a, host_b]);

        let bind_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let bind_port = 443;
        let stale_sni = Some("first.example.com".to_string());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                let sni = stale_sni.clone();
                async move { handle_https_request(state, bind_ip, bind_port, "203.0.113.7".parse().unwrap(), sni, req).await }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, service).await;
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "second.example.com")
            .body(http_body_util::Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();

        let location = resp.headers().get(hyper::header::LOCATION).unwrap().to_str().unwrap();
        assert_eq!(location, "https://b.example.com", "the request's real Host header must win over the connection's stale SNI");
    }

    /// Real production gap the first fix (preferring the `Host` header
    /// over `sni`) missed: genuine HTTP/2 clients -- every modern
    /// browser -- send the target host as the `:authority`
    /// pseudo-header, which hyper/h2 surfaces via `req.uri()`, never as
    /// a literal `Host:` header in `req.headers()`. A real h2 request
    /// carrying no `Host` header at all (confirmed live: production
    /// logs showed `host_header="<none>"` on real h2 traffic) must
    /// still route by its own declared host, not fall through to the
    /// connection's possibly-stale `sni` -- the exact scenario
    /// connection coalescing creates.
    #[tokio::test]
    async fn an_h2_requests_authority_wins_over_a_stale_connection_level_sni_with_no_host_header_at_all() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let target_first = crate::config::RedirectTarget {
            target: "https://a.example.com".into(),
            preserve_path: false,
            status: crate::config::RedirectStatus::Permanent,
        };
        let target_second = crate::config::RedirectTarget {
            target: "https://b.example.com".into(),
            preserve_path: false,
            status: crate::config::RedirectStatus::Permanent,
        };
        let host_first = redirect_host("first.example.com", target_first);
        let host_second = redirect_host("second.example.com", target_second);
        let state = test_state_with_cert("first.example.com").await;
        state.set_hosts(vec![host_first, host_second]);

        let acceptor = TlsAcceptor::from(Arc::new(build_https_server_config(state.clone())));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bind_ip: IpAddr = "10.0.0.2".parse().unwrap();
        let bind_port = 443;

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls_stream = acceptor.accept(stream).await.unwrap();
            // Real connection-level SNI, exactly as the production
            // listener captures it -- "first.example.com", the domain
            // this same TLS connection was originally established for.
            let sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
            let io = TokioIo::new(tls_stream);
            let state = state.clone();
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                let sni = sni.clone();
                async move { handle_https_request(state, bind_ip, bind_port, "203.0.113.7".parse().unwrap(), sni, req).await }
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
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = RustlsServerName::try_from("first.example.com").unwrap();
        let tls_stream = connector.connect(server_name, tcp).await.unwrap();
        assert_eq!(tls_stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]), "must actually be h2 -- that's the whole point of this test");

        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await.unwrap();
        tokio::spawn(conn);

        // Absolute-form URI, no Host header at all -- hyper's h2 client
        // derives the :authority pseudo-header from the URI itself,
        // same as a real browser reusing a coalesced connection for a
        // different origin than the one it originally connected to.
        let req = Request::builder().uri("https://second.example.com/").body(http_body_util::Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.unwrap();

        let location = resp.headers().get(hyper::header::LOCATION).unwrap().to_str().unwrap();
        assert_eq!(
            location, "https://b.example.com",
            "an h2 request's :authority (no Host header at all) must win over the connection's stale SNI"
        );
    }

    #[tokio::test]
    async fn request_from_an_ip_outside_the_allow_list_is_forbidden() {
        let state = test_state_with_access("example.com", vec!["192.168.1.0/24".parse().unwrap()], None).await;
        let resp = send_test_request(
            state,
            "203.0.113.7".parse().unwrap(),
            "GET",
            "/",
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::FORBIDDEN);
        assert_eq!(resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(), "text/html; charset=utf-8");
        let body = response_text(resp).await;
        assert!(body.contains("Access denied"), "an IP-only-denied host must get a real page, not a bare empty 403");
    }

    #[tokio::test]
    async fn request_from_an_allowed_ip_without_a_login_gate_configured_is_not_blocked() {
        let state = test_state_with_access("example.com", vec!["10.0.0.0/24".parse().unwrap()], None).await;
        let resp = send_test_request(
            state,
            "10.0.0.42".parse().unwrap(),
            "GET",
            "/",
            None,
            None,
        )
        .await;
        // Upstream is unreachable (127.0.0.1:1) so this proves access
        // control let the request through, not that it fully succeeded.
        assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY);
    }

    /// Regression test for a real lockout: a host with both an IP-allow
    /// ACL and a login ACL selected used to require BOTH to pass (IP
    /// checked first, 403 immediately on a mismatch, login never even
    /// consulted) -- an operator whose source IP stopped matching the
    /// allow list could no longer sign in at all, even with valid
    /// credentials. The two now combine by OR: a matching IP admits the
    /// request outright, without ever touching the login gate.
    #[tokio::test]
    async fn matching_ip_admits_the_request_without_requiring_login_even_when_a_login_acl_is_also_configured() {
        let state = test_state_with_access("example.com", vec!["10.0.0.0/24".parse().unwrap()], Some(viewer_auth())).await;
        let resp = send_test_request(state, "10.0.0.42".parse().unwrap(), "GET", "/", None, None).await;
        // Upstream is unreachable (127.0.0.1:1) so BAD_GATEWAY (not the
        // login page) proves the IP match alone was enough to admit it.
        assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY);
    }

    /// The other half of the same fix: a non-matching IP must fall
    /// through to the login gate (so valid credentials still work)
    /// instead of 403ing immediately, whenever a login ACL is also
    /// configured on the host.
    #[tokio::test]
    async fn non_matching_ip_falls_through_to_the_login_gate_instead_of_403() {
        let state = test_state_with_access("example.com", vec!["192.168.1.0/24".parse().unwrap()], Some(viewer_auth())).await;
        let resp = send_test_request(state, "203.0.113.7".parse().unwrap(), "GET", "/", None, None).await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        let body = response_text(resp).await;
        assert!(body.contains("Sign in to example.com"), "a non-matching IP with a login ACL also configured must get the login page, not a 403");
    }

    fn viewer_auth() -> crate::config::HostAuth {
        crate::config::HostAuth {
            username: "viewer".into(),
            password_hash: crate::api::auth::hash_password("s3cret").unwrap(),
        }
    }

    #[tokio::test]
    async fn a_request_without_a_session_gets_the_login_page_instead_of_the_upstream() {
        let state = test_state_with_access("example.com", vec![], Some(viewer_auth())).await;
        let resp = send_test_request(
            state,
            "203.0.113.7".parse().unwrap(),
            "GET",
            "/dashboard",
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        assert_eq!(resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(), "text/html; charset=utf-8");
        let body = response_text(resp).await;
        assert!(body.contains("Sign in to example.com"));
        // The originally-requested path is threaded through as return_to
        // so a successful login lands the visitor back on it.
        assert!(body.contains("/dashboard"));
    }

    #[tokio::test]
    async fn login_submission_with_correct_credentials_sets_a_session_cookie() {
        let state = test_state_with_access("example.com", vec![], Some(viewer_auth())).await;
        let resp = send_test_request(
            state,
            "203.0.113.7".parse().unwrap(),
            "POST",
            login::LOGIN_SUBMIT_PATH,
            None,
            Some(serde_json::json!({"username": "viewer", "password": "s3cret", "return_to": "/"})),
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        let set_cookie = resp.headers().get(hyper::header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(set_cookie.starts_with(&format!("{}=", login::SESSION_COOKIE)));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("Secure"));
    }

    #[tokio::test]
    async fn login_submission_with_wrong_credentials_is_rejected_without_a_cookie() {
        let state = test_state_with_access("example.com", vec![], Some(viewer_auth())).await;
        let resp = send_test_request(
            state,
            "203.0.113.7".parse().unwrap(),
            "POST",
            login::LOGIN_SUBMIT_PATH,
            None,
            Some(serde_json::json!({"username": "viewer", "password": "wrong", "return_to": "/"})),
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get(hyper::header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn a_request_with_a_valid_session_cookie_passes_through_to_the_upstream_lookup() {
        let token = login::sign_session("test-secret", "example.com", "viewer");
        let state = test_state_with_access("example.com", vec![], Some(viewer_auth())).await;
        let resp = send_test_request(
            state,
            "203.0.113.7".parse().unwrap(),
            "GET",
            "/",
            Some(format!("{}={token}", login::SESSION_COOKIE)),
            None,
        )
        .await;
        // Upstream is unreachable (127.0.0.1:1) so this proves the
        // session cleared the login gate, not that it fully succeeded.
        assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn a_session_signed_for_a_different_domain_does_not_bypass_the_login_gate() {
        let token = login::sign_session("test-secret", "other.example.com", "viewer");
        let state = test_state_with_access("example.com", vec![], Some(viewer_auth())).await;
        let resp = send_test_request(
            state,
            "203.0.113.7".parse().unwrap(),
            "GET",
            "/",
            Some(format!("{}={token}", login::SESSION_COOKIE)),
            None,
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        assert!(response_text(resp).await.contains("Sign in to example.com"));
    }

    fn redirect_host(domain: &str, redirect: crate::config::RedirectTarget) -> ProxyHost {
        ProxyHost {
            id: Uuid::new_v4(),
            domain: domain.into(),
            bind_ip_v4: Some("10.0.0.2".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 443,
            upstream: String::new(),
            upstream_https: false,
            upstream_tls_verify: true,
            upstream_preserve_host: true,
            websockets: false,
            force_https: false,
            acme_enabled: false,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            acl_ids: vec![],
            dns_credential_id: None,
            redirect: Some(redirect),
            path_rewrite: None,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn a_redirect_host_serves_the_redirect_without_ever_touching_an_upstream() {
        let target = crate::config::RedirectTarget {
            target: "https://new.example.com".into(),
            preserve_path: true,
            status: crate::config::RedirectStatus::Permanent,
        };
        let state = test_state_with_host(redirect_host("example.com", target)).await;
        let resp = send_test_request(
            state,
            "203.0.113.7".parse().unwrap(),
            "GET",
            "/blog/post?x=1",
            None,
            None,
        )
        .await;
        // upstream is empty/invalid ("") -- a BAD_GATEWAY here would mean
        // the request fell through to resolve_upstream instead of being
        // answered as a redirect.
        assert_eq!(resp.status(), hyper::StatusCode::MOVED_PERMANENTLY);
        let location = resp.headers().get(hyper::header::LOCATION).unwrap().to_str().unwrap();
        assert_eq!(location, "https://new.example.com/blog/post?x=1");
    }

    #[tokio::test]
    async fn access_control_still_applies_to_a_redirect_host() {
        let target = crate::config::RedirectTarget {
            target: "https://new.example.com".into(),
            preserve_path: true,
            status: crate::config::RedirectStatus::Permanent,
        };
        let mut host = redirect_host("example.com", target);
        let state = test_state_with_cert("example.com").await;
        let acl_id = Uuid::new_v4();
        crate::db::create_acl_list(state.db(), acl_id, "test ip allow", crate::config::AclKind::IpAllow, chrono::Utc::now()).await.unwrap();
        crate::db::add_acl_ip_entries(state.db(), acl_id, &["192.168.1.0/24".to_string()]).await.unwrap();
        host.acl_ids = vec![acl_id];
        state.set_hosts(vec![host]);
        let resp = send_test_request(
            state,
            "203.0.113.7".parse().unwrap(),
            "GET",
            "/",
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::FORBIDDEN);
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
