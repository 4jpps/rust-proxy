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
pub mod client_cert;
pub mod http;
pub mod login;
pub mod passthrough;
pub mod revocation;
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
#[cfg(test)]
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

/// Backoff after a transient `listener.accept()` error (EMFILE/ENFILE
/// under fd-exhaustion, the case that actually bit production -- see
/// the call sites' comments) before the accept loop retries. 100ms is
/// short enough not to visibly delay recovery once fd pressure clears,
/// but caps a stuck condition at ~10 retries/sec instead of a tight
/// spin -- the difference between a few hundred log lines and hours of
/// runaway logging/CPU if the underlying cause takes a while to clear.
async fn accept_error_backoff() {
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

fn passthrough_keys(port_rules: &[crate::config::PortRule]) -> Vec<(IpAddr, u16, Protocol)> {
    let mut keys = Vec::new();
    for rule in port_rules
        .iter()
        .filter(|r| r.enabled && r.passthrough_target.is_some())
    {
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

        let config_with_client_auth = Arc::new(build_https_server_config(state.clone()));
        let config_no_client_auth =
            Arc::new(build_https_server_config_no_client_auth(state.clone()));

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "https listener accept failed");
                    // A transient accept() error (most commonly EMFILE/
                    // "too many open files" under a real connection spike)
                    // doesn't clear itself between one loop iteration and
                    // the next -- retrying with no backoff spins this loop
                    // as fast as the runtime allows, burning a full CPU
                    // core and flooding this log at whatever rate that
                    // achieves. Confirmed as a real incident: a single
                    // ~8-hour EMFILE spell logged 125M+ of these lines
                    // (15G compressed down to under 500M once cleaned up)
                    // and kept a core pegged the whole time. A short sleep
                    // gives fd pressure a chance to actually ease before
                    // trying again, the standard fix for this exact
                    // accept-loop shape.
                    accept_error_backoff().await;
                    continue;
                }
            };
            if wildcard_listener_got_dedicated_ip(&state, bind_ip, &stream) {
                continue;
            }
            let peer_ip = peer.ip();
            let config_with_client_auth = config_with_client_auth.clone();
            let config_no_client_auth = config_no_client_auth.clone();
            let state = state.clone();
            tokio::spawn(async move {
                // Two-phase accept: read just far enough to see the
                // ClientHello (which carries SNI) before committing to a
                // `ServerConfig`, so the choice of whether to solicit a
                // client cert can depend on which host this connection is
                // actually for -- see `should_request_client_cert`'s doc
                // comment for why this replaced a single config shared by
                // every connection on this listener.
                let start = match tokio_rustls::LazyConfigAcceptor::new(
                    rustls::server::Acceptor::default(),
                    stream,
                )
                .await
                {
                    Ok(s) => s,
                    Err(err) => {
                        tracing::debug!(error = %err, "tls clienthello read failed");
                        return;
                    }
                };
                let sni = start.client_hello().server_name().map(|s| s.to_string());
                let want_client_cert =
                    should_request_client_cert(&state, bind_ip, bind_port, peer_ip, sni.as_deref())
                        .await;
                let config = if want_client_cert {
                    config_with_client_auth
                } else {
                    config_no_client_auth
                };
                let tls_stream = match start.into_stream(config).await {
                    Ok(s) => s,
                    Err(err) => {
                        tracing::debug!(error = %err, "tls handshake failed");
                        return;
                    }
                };
                let client_cert_subject =
                    client_cert::client_cert_identity(tls_stream.get_ref().1.peer_certificates());
                let client_cert_leaf: Option<Vec<u8>> = tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| c.as_ref().to_vec());
                let io = TokioIo::new(tls_stream);
                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let state = state.clone();
                    let sni = sni.clone();
                    let client_cert_subject = client_cert_subject.clone();
                    let client_cert_leaf = client_cert_leaf.clone();
                    async move {
                        // A revoked certificate is treated as no certificate
                        // at all: the host falls back to its login page and
                        // no identity headers are forwarded.
                        let client_cert_subject = match (&client_cert_subject, &client_cert_leaf) {
                            (Some(_), Some(leaf)) if state.revocation().is_revoked(leaf).await => None,
                            _ => client_cert_subject,
                        };
                        match handle_https_request(
                            state,
                            bind_ip,
                            bind_port,
                            peer_ip,
                            sni,
                            client_cert_subject,
                            req,
                        )
                        .await
                        {
                            Ok(resp) => deliver(resp),
                            Err(never) => match never {},
                        }
                    }
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
    // Client-cert presentation is optional at the TLS layer (only
    // clients holding a cert whose issuer matches TrustBridge's root,
    // which this verifier is the only thing that advertises, will ever
    // offer one at all) -- but *soliciting* one at all (sending a TLS
    // CertificateRequest) is a per-connection choice made by
    // `should_request_client_cert` below, not applied to every
    // connection unconditionally. This function builds the config used
    // when that decision comes back true; see
    // `build_https_server_config_no_client_auth` for the other half.
    let client_cert_verifier = client_cert::build_optional_client_cert_verifier();
    let mut server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_cert_resolver(resolver);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    server_config
}

/// The other half of the pair above -- no CertificateRequest is ever
/// sent on a connection accepted with this config, so a browser never
/// shows its cert-picker prompt for it. Used for the overwhelming
/// majority of connections (every domain that doesn't actually use
/// client-cert login), which is the whole point of choosing between
/// the two per-connection instead of applying
/// `build_https_server_config` globally the way this used to work.
fn build_https_server_config_no_client_auth(state: AppState) -> rustls::ServerConfig {
    let resolver = Arc::new(tls::CertResolver::new(state));
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    server_config
}

/// Decides, from the SNI alone (all that's available before the TLS
/// handshake completes -- the HTTP request path isn't visible yet),
/// whether this connection should solicit a client cert at all.
///
/// True when either:
/// - the matched host forwards the verified subject to its upstream
///   (`pass_client_cert_header`) -- store/wiki/pki's admin-login
///   bypass all work this way, with no rust-proxy-level ACL selected
///   at all (the upstream app decides what to do with the header);
/// - the matched host has a `ClientCert`-kind ACL selected, unless it
///   *also* has an `IpAllow` ACL that this connection's peer IP
///   already satisfies -- Jeff's own spec: "should only be [requested]
///   on a login page, unless it's IP locked and I'm not on one of the
///   authorized IPs." A peer already let in by IP doesn't need to be
///   asked for a cert too.
///
/// **Known limitation, same one `tls::CertResolver`'s per-SNI cert
/// selection already has**: this is a one-time, connection-scoped
/// decision made from SNI alone. A single TLS connection can end up
/// carrying requests for a *different* host than its SNI named (HTTP/2
/// connection coalescing under a shared wildcard/SAN cert -- see
/// `handle_https_request`'s doc comment on `uri_host`/`host_header`
/// winning over `sni` for *routing*) -- if that happens, whether a
/// cert was solicited is fixed by the *first* host's setting, not the
/// coalesced request's own. Not worth solving: none of the domains
/// that actually use `pass_client_cert_header`/`ClientCert` ACLs today
/// share a wildcard cert with domains that don't, and getting this
/// exactly right in the general case needs re-running TLS negotiation
/// mid-connection, which TLS doesn't support.
async fn should_request_client_cert(
    state: &AppState,
    bind_ip: IpAddr,
    bind_port: u16,
    peer_ip: IpAddr,
    sni: Option<&str>,
) -> bool {
    let Some(sni) = sni else {
        return false;
    };
    let hosts = state.hosts();
    let Some(host) = router::match_host(&hosts, bind_ip, bind_port, sni) else {
        return false;
    };
    if host.pass_client_cert_header {
        return true;
    }
    if host.acl_ids.is_empty() {
        return false;
    }
    let acl_ids = host.acl_ids.clone();
    let resolved = match crate::db::resolve_acl_ids(state.db(), &acl_ids).await {
        Ok(resolved) => resolved,
        Err(err) => {
            tracing::error!(%sni, error = %err, "failed to resolve host ACLs while deciding whether to solicit a client cert");
            return false;
        }
    };
    if !resolved.has_client_cert_acl {
        return false;
    }
    let already_ip_allowed =
        resolved.has_ip_allow_acl && access::ip_allowed(&resolved.allow_ips, peer_ip);
    !already_ip_allowed
}

/// Thin wrapper that emits one SIEM `access` event per request (only when
/// that category is selected -- otherwise this is a single atomic load).
async fn handle_https_request(
    state: AppState,
    bind_ip: IpAddr,
    bind_port: u16,
    peer_ip: IpAddr,
    sni: Option<String>,
    client_cert_subject: Option<client_cert::ClientCertIdentity>,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, std::convert::Infallible> {
    if !crate::siem::wants(crate::siem::Category::Access) {
        return route_https_request(
            state,
            bind_ip,
            bind_port,
            peer_ip,
            sni,
            client_cert_subject,
            req,
        )
        .await;
    }
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let domain = req
        .uri()
        .host()
        .map(str::to_string)
        .or_else(|| {
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .or_else(|| sni.clone())
        .unwrap_or_else(|| "-".into());
    let query_present = if req.uri().query().is_some() { "1" } else { "0" };
    let user_agent: String = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(200).collect())
        .unwrap_or_else(|| "-".into());
    let start = std::time::Instant::now();
    let result = route_https_request(
        state,
        bind_ip,
        bind_port,
        peer_ip,
        sni,
        client_cert_subject,
        req,
    )
    .await;
    if let Ok(resp) = &result {
        let bytes = resp
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();
        let status = resp.status().as_u16().to_string();
        let elapsed = start.elapsed().as_millis().to_string();
        let client_ip = peer_ip.to_string();
        crate::siem::emit(
            crate::siem::Category::Access,
            crate::siem::Severity::Info,
            "http_request",
            "proxied request",
            &[
                ("client_ip", client_ip.as_str()),
                ("domain", domain.as_str()),
                ("method", method.as_str()),
                ("path", path.as_str()),
                ("http_status", status.as_str()),
                ("elapsed_ms", elapsed.as_str()),
                ("user_agent", user_agent.as_str()),
                ("bytes", bytes.as_str()),
                ("has_query", query_present),
            ],
        );
    }
    result
}

async fn route_https_request(
    state: AppState,
    bind_ip: IpAddr,
    bind_port: u16,
    peer_ip: IpAddr,
    sni: Option<String>,
    client_cert_subject: Option<client_cert::ClientCertIdentity>,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, std::convert::Infallible> {
    // With an org lock set, a cert from another org (or an old one with no
    // org-id) is treated as no certificate: login fallback, no identity headers.
    let required_org = state.required_client_cert_org();
    let client_cert_subject = client_cert_subject.filter(|id| {
        let ok = client_cert::org_allowed(id, required_org.as_deref());
        if !ok {
            tracing::info!(cn = %id.cn, org_id = ?id.org_id, "client cert ignored: org-id does not match the required org");
        }
        ok
    });
    // Same precedence as the routing decision below: the request's own
    // declared host beats the connection's SNI.
    let lookup_name = req
        .uri()
        .host()
        .map(|s| s.to_string())
        .or_else(|| {
            req.headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .or_else(|| sni.clone());
    let hsts = lookup_name.as_deref().and_then(|name| {
        router::match_host(&state.hosts(), bind_ip, bind_port, name).and_then(|h| h.hsts_header_value())
    });
    let mut result =
        route_https_request_inner(state, bind_ip, bind_port, peer_ip, sni, client_cert_subject, req)
            .await;
    if let (Some(value), Ok(resp)) = (hsts, result.as_mut()) {
        if let Ok(value) = hyper::header::HeaderValue::from_str(&value) {
            resp.headers_mut()
                .insert(hyper::header::STRICT_TRANSPORT_SECURITY, value);
        }
    }
    result
}

async fn route_https_request_inner(
    state: AppState,
    bind_ip: IpAddr,
    bind_port: u16,
    peer_ip: IpAddr,
    sni: Option<String>,
    client_cert_subject: Option<client_cert::ClientCertIdentity>,
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
    let lookup_name = uri_host
        .clone()
        .or_else(|| host_header.clone())
        .or_else(|| sni.clone());

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
        return Ok(default_site_response(&state.default_site()));
    };

    // Never let a client set this header itself -- only ever set below,
    // from a TLS-layer-verified cert, once we know whether this host
    // actually wants it forwarded. Stripped unconditionally (even for
    // hosts that never forward it) so a client can't probe the
    // difference between "stripped" and "never set" to tell whether an
    // upstream is watching for it.
    let mut req = req;
    client_cert::strip_identity_headers(req.headers_mut());

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
    // A verified TrustBridge client cert is a third way to satisfy this
    // gate, same OR-not-AND relationship as IP-allow-over-login above --
    // by the time client_cert_subject is `Some`, rustls has already
    // verified the cert chains to TrustBridge's root (see
    // client_cert.rs's module doc); this only checks whether the host
    // actually opted into treating that as sufficient, and the presented
    // subject must be one of the listed entries. A list with no entries
    // trusts no certificate (fail closed) -- see
    // `db::ResolvedAcls::allowed_client_cert_subjects`'s doc comment.
    let client_cert_ok = resolved_acls.has_client_cert_acl
        && client_cert_subject.as_ref().is_some_and(|id| {
            // The org lock was already applied at the top of this function.
            resolved_acls
                .allowed_client_cert_subjects
                .iter()
                .any(|s| *s == id.cn)
        });
    let ip_allowed = access::ip_allowed(&resolved_acls.allow_ips, peer_ip);
    if host.block_exploits {
        let path_and_query = req
            .uri()
            .path_and_query()
            .map_or("/", |pq| pq.as_str());
        let user_agent = req
            .headers()
            .get(hyper::header::USER_AGENT)
            .and_then(|v| v.to_str().ok());
        if let Some(reason) = access::exploit_check(req.method(), path_and_query, user_agent) {
            if crate::siem::wants(crate::siem::Category::Denied) {
                let client_ip = peer_ip.to_string();
                crate::siem::emit(
                    crate::siem::Category::Denied,
                    crate::siem::Severity::Warning,
                    "exploit_blocked",
                    "request refused: looks like an automated exploit probe",
                    &[
                        ("client_ip", client_ip.as_str()),
                        ("domain", host.domain.as_str()),
                        ("method", req.method().as_str()),
                        ("path", req.uri().path()),
                        ("reason", reason),
                    ],
                );
            }
            return Ok(forbidden_page(&host.domain));
        }
    }
    if let Some(fb) = host
        .deny_fallback
        .as_ref()
        .filter(|fb| fb.scope == crate::config::DenyScope::Everyone)
    {
        match access::deny_fallback_decision(fb, req.uri().path(), req.method()) {
            access::DenyDecision::PassThrough => {}
            access::DenyDecision::Redirect(path) => return Ok(fallback_redirect(&path)),
            access::DenyDecision::Forbidden => return Ok(not_found_page()),
        }
    }
    if !(client_cert_ok || (resolved_acls.has_ip_allow_acl && ip_allowed)) {
        if resolved_acls.has_login_acl {
            let has_valid_session = find_cookie(&req, login::SESSION_COOKIE)
                .zip(state.admin_identity())
                .map(|(token, identity)| {
                    login::verify_session(&identity.session_secret, &host.domain, &token)
                })
                .unwrap_or(false);
            if !has_valid_session {
                return Ok(handle_login_gate(
                    &state,
                    &host.domain,
                    &resolved_acls.credentials,
                    peer_ip,
                    req,
                )
                .await);
            }
        } else if resolved_acls.has_ip_allow_acl {
            let decision = match &host.deny_fallback {
                Some(fb) => access::deny_fallback_decision(fb, req.uri().path(), req.method()),
                None => access::DenyDecision::Forbidden,
            };
            if let access::DenyDecision::Redirect(path) = &decision {
                return Ok(fallback_redirect(path));
            }
            if decision == access::DenyDecision::Forbidden
                && crate::siem::wants(crate::siem::Category::Denied)
            {
                let client_ip = peer_ip.to_string();
                crate::siem::emit(
                    crate::siem::Category::Denied,
                    crate::siem::Severity::Warning,
                    "acl_ip_denied",
                    "request refused: source IP not in the host's allow list",
                    &[
                        ("client_ip", client_ip.as_str()),
                        ("domain", host.domain.as_str()),
                        ("method", req.method().as_str()),
                        ("path", req.uri().path()),
                    ],
                );
            }
            if decision == access::DenyDecision::Forbidden {
                return Ok(forbidden_page(&host.domain));
            }
        }
    }

    if let Some(fixed) = &host.fixed_response {
        return Ok(fixed_response_page(fixed));
    }

    if let Some(redirect) = &host.redirect {
        return Ok(http::redirect_target_response(&req, redirect));
    }

    if let Some(static_root) = &host.static_root {
        return Ok(http::serve_static_response(&req, static_root).await);
    }

    // Both headers or neither -- the subject alone is not proof the
    // request came through this proxy (see Config::
    // client_cert_forward_token's doc comment for the real threat this
    // closes: a co-located process reaching the upstream directly could
    // otherwise forge the subject header itself). No configured token
    // means this feature is silently inert regardless of any host's
    // pass_client_cert_header setting.
    if host.pass_client_cert_header {
        if let (Some(identity), Some(token)) =
            (&client_cert_subject, state.client_cert_forward_token())
        {
            client_cert::set_identity_headers(req.headers_mut(), identity, token);
        }
    }

    if let Some(path_rewrite) = &host.path_rewrite {
        apply_path_rewrite(&mut req, path_rewrite);
    }

    let location = crate::config::match_location(&host.locations, req.uri().path());
    let (upstream_host_port, upstream_https, upstream_tls_verify) = match location {
        Some(loc) => (loc.upstream.as_str(), loc.upstream_https, loc.upstream_tls_verify),
        None => (host.upstream.as_str(), host.upstream_https, host.upstream_tls_verify),
    };
    let Ok(upstream) = resolve_upstream(upstream_host_port) else {
        return Ok(bad_gateway());
    };

    let opts = http::UpstreamOptions {
        websockets_enabled: host.websockets,
        https: upstream_https,
        tls_verify: upstream_tls_verify,
        upstream_host_port,
        preserve_host: host.upstream_preserve_host,
        client_ip: peer_ip,
        rewrite_samesite_none_cookies: host.rewrite_samesite_none_cookies,
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
    let new_path = re
        .replace(original_path, rewrite.replacement.as_str())
        .into_owned();
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
    req.headers()
        .get(hyper::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
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
    peer_ip: IpAddr,
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    if req.method() == hyper::Method::POST && req.uri().path() == login::LOGIN_SUBMIT_PATH {
        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return login_page_response(
                    domain,
                    "/",
                    Some("invalid request"),
                    hyper::StatusCode::BAD_REQUEST,
                )
            }
        };
        let Ok(submission) = serde_json::from_slice::<login::LoginSubmission>(&body_bytes) else {
            return login_page_response(
                domain,
                "/",
                Some("invalid request"),
                hyper::StatusCode::BAD_REQUEST,
            );
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
            siem_login_event(true, domain, &submission.username, peer_ip);
            return login_success_response(&token);
        }
        siem_login_event(false, domain, &submission.username, peer_ip);
        return login_page_response(
            domain,
            &submission.return_to,
            Some("Invalid username or password"),
            hyper::StatusCode::UNAUTHORIZED,
        );
    }

    let return_to = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    login_page_response(domain, &return_to, None, hyper::StatusCode::OK)
}

/// Reports a host login-gate attempt. The submitted password is never
/// read here; the username is included (truncated) since it is the
/// useful signal for spotting credential stuffing.
fn siem_login_event(ok: bool, domain: &str, username: &str, peer_ip: IpAddr) {
    use crate::siem::{emit, wants, Category, Severity};
    let (cat, sev, event, msg) = if ok {
        (
            Category::Admin,
            Severity::Notice,
            "host_login_success",
            "host login gate: sign-in succeeded",
        )
    } else {
        (
            Category::Denied,
            Severity::Warning,
            "host_login_failure",
            "host login gate: invalid credentials",
        )
    };
    if !wants(cat) {
        return;
    }
    let client_ip = peer_ip.to_string();
    let user: String = username.chars().take(64).collect();
    emit(
        cat,
        sev,
        event,
        msg,
        &[
            ("client_ip", client_ip.as_str()),
            ("domain", domain),
            ("user", user.as_str()),
        ],
    );
}

fn login_page_response(
    domain: &str,
    return_to: &str,
    error: Option<&str>,
    status: hyper::StatusCode,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let html = login::render_login_page(domain, return_to, error);
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(
            http_body_util::Full::new(Bytes::from(html))
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
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
        .body(
            http_body_util::Empty::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
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
                    // Same reasoning as the HTTPS listener's identical
                    // accept-error handling above -- see that comment.
                    accept_error_backoff().await;
                    continue;
                }
            };
            if wildcard_listener_got_dedicated_ip(&state, bind_ip, &stream) {
                continue;
            }
            let io = TokioIo::new(stream);
            let state = state.clone();
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                async move {
                    if let Some(resp) = http::http01_challenge_response(&state, &req) {
                        return Ok::<_, ServiceError>(resp);
                    }
                    let known = req
                        .headers()
                        .get(hyper::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|h| router::host_is_known(&state.hosts(), h));
                    if known {
                        Ok(http::https_redirect_response(&req))
                    } else {
                        deliver(default_site_response(&state.default_site()))
                    }
                }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
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
        .find(|r| {
            r.enabled
                && crate::config::port_rule_bind_ips(r).contains(&bind_ip)
                && (r.port_start..=r.port_end).contains(&port)
                && r.protocol == protocol
        })
        .and_then(|r| r.passthrough_target.clone());

    let bind_addr = SocketAddr::from((bind_ip, port));
    tokio::spawn(async move {
        let Some(target) = target else {
            tracing::error!(%bind_addr, "passthrough listener spawned with no matching target rule");
            return;
        };
        let target = passthrough_target_for_port(&target, bind_addr.port());
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

/// A wildcard listener also receives connections addressed to a dedicated
/// IP (see `NetworkConfig::dedicated_ips`) if the firewall is not managing
/// the host. Those must only be served by listeners bound to that exact
/// address, so the wildcard one drops them.
fn wildcard_listener_got_dedicated_ip(
    state: &AppState,
    listener_ip: IpAddr,
    stream: &tokio::net::TcpStream,
) -> bool {
    if !listener_ip.is_unspecified() {
        return false;
    }
    let dedicated = &state.network().dedicated_ips;
    !dedicated.is_empty()
        && stream
            .local_addr()
            .map(|a| dedicated.contains(&a.ip()))
            .unwrap_or(false)
}

/// A target with no `:port` (bare host or IP, bracketed or bare IPv6) means
/// "same port the client connected to", which is what lets one range rule
/// forward 20100-22100 to the same ports on the backend.
fn passthrough_target_for_port(target: &str, port: u16) -> String {
    if target.parse::<SocketAddr>().is_ok() {
        return target.to_string();
    }
    if let Some((host, p)) = target.rsplit_once(':') {
        if !host.contains(':') && p.parse::<u16>().is_ok() {
            return target.to_string();
        }
    }
    if target.parse::<std::net::Ipv6Addr>().is_ok() {
        return format!("[{target}]:{port}");
    }
    format!("{target}:{port}")
}

fn resolve_upstream(upstream: &str) -> Result<SocketAddr, std::io::Error> {
    use std::net::ToSocketAddrs;
    upstream.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "upstream did not resolve to any address",
        )
    })
}

/// Marks a response that must not be sent: the connection is closed
/// instead (NPM's "No Response (444)").
#[derive(Clone, Copy)]
struct DropConnection;

type ServiceError = std::io::Error;

fn deliver(resp: Response<BoxBody<Bytes, hyper::Error>>) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ServiceError> {
    if resp.extensions().get::<DropConnection>().is_some() {
        return Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "default site: no response (444)"));
    }
    Ok(resp)
}

const HTML_RESPONSE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data: http: https:; font-src data: https:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const CONGRATULATIONS_HTML: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Congratulations</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:12vh auto;padding:0 1rem;color:#222}h1{font-size:1.6rem}</style></head><body><h1>Congratulations!</h1><p>RustProxy is running. No site is configured for this address yet.</p></body></html>\n";

pub(crate) fn default_site_response(site: &crate::config::DefaultSite) -> Response<BoxBody<Bytes, hyper::Error>> {
    use crate::config::DefaultSiteMode as M;
    let html = |status: hyper::StatusCode, body: String| {
        Response::builder()
            .status(status)
            .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(hyper::header::CACHE_CONTROL, "no-store")
            .header("x-content-type-options", "nosniff")
            .header("content-security-policy", HTML_RESPONSE_CSP)
            .body(
                http_body_util::Full::new(Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .expect("default site response is always valid")
    };
    match site.mode {
        M::NotFound => not_found_page(),
        M::Congratulations => html(hyper::StatusCode::OK, CONGRATULATIONS_HTML.to_string()),
        M::CustomHtml => html(hyper::StatusCode::OK, site.custom_html.clone()),
        M::Redirect => match hyper::header::HeaderValue::from_str(site.redirect_url.trim()) {
            Ok(loc) => Response::builder()
                .status(hyper::StatusCode::FOUND)
                .header(hyper::header::LOCATION, loc)
                .header(hyper::header::CACHE_CONTROL, "no-store")
                .body(
                    http_body_util::Empty::new()
                        .map_err(|e: std::convert::Infallible| match e {})
                        .boxed(),
                )
                .expect("default site redirect is always valid"),
            Err(_) => not_found_page(),
        },
        M::NoResponse => {
            let mut resp = not_found();
            resp.extensions_mut().insert(DropConnection);
            resp
        }
    }
}

fn not_found() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(hyper::StatusCode::NOT_FOUND)
        .body(
            http_body_util::Empty::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
        .expect("static response is always valid")
}

fn fixed_response_page(
    fixed: &crate::config::FixedResponse,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let status = hyper::StatusCode::from_u16(fixed.status).unwrap_or(hyper::StatusCode::NOT_FOUND);
    let body = if matches!(fixed.status, 204 | 205 | 304) {
        Bytes::new()
    } else {
        Bytes::from(fixed.body.clone())
    };
    Response::builder()
        .status(status)
        .header(
            hyper::header::CONTENT_TYPE,
            if fixed.html { "text/html; charset=utf-8" } else { "text/plain; charset=utf-8" },
        )
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("content-security-policy", HTML_RESPONSE_CSP)
        .body(
            http_body_util::Full::new(body)
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("fixed response is always valid")
}

fn bad_gateway() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(hyper::StatusCode::BAD_GATEWAY)
        .body(
            http_body_util::Empty::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
        .expect("static response is always valid")
}

fn fallback_redirect(path: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(hyper::StatusCode::FOUND)
        .header(hyper::header::LOCATION, path)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(
            http_body_util::Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static fallback redirect response is always valid")
}

fn not_found_page() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(hyper::StatusCode::NOT_FOUND)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(
            http_body_util::Full::new(Bytes::from_static(b"Not found\n"))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static not-found response is always valid")
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
        .body(
            http_body_util::Full::new(Bytes::from(html))
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
        .expect("static forbidden page response is always valid")
}

fn service_unavailable() -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
        .body(
            http_body_util::Empty::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
        .expect("static response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AcmeConfig, AdminConfig, Config, DnsProviderKind, NetworkConfig, PortRule, Protocol,
        ProxyHost,
    };
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName as RustlsServerName, UnixTime};
    use std::path::PathBuf;
    use uuid::Uuid;

    #[test]
    fn passthrough_target_without_port_uses_the_received_port() {
        assert_eq!(
            passthrough_target_for_port("172.16.233.2", 8080),
            "172.16.233.2:8080"
        );
        assert_eq!(
            passthrough_target_for_port("unifi.lan", 3478),
            "unifi.lan:3478"
        );
        assert_eq!(passthrough_target_for_port("fd00::2", 53), "[fd00::2]:53");
    }

    #[test]
    fn passthrough_target_with_port_is_left_alone() {
        assert_eq!(
            passthrough_target_for_port("172.16.233.2:9", 8080),
            "172.16.233.2:9"
        );
        assert_eq!(
            passthrough_target_for_port("unifi.lan:9", 3478),
            "unifi.lan:9"
        );
        assert_eq!(
            passthrough_target_for_port("[fd00::2]:9", 53),
            "[fd00::2]:9"
        );
    }

    fn path_rewrite(pattern: &str, replacement: &str) -> crate::config::PathRewrite {
        crate::config::PathRewrite {
            pattern: pattern.into(),
            replacement: replacement.into(),
        }
    }

    /// This is the exact pattern/replacement wiki.jpps.us uses in
    /// production, landing a bare `jpps/<project>` path directly on that
    /// project's wiki "Home" page slug in one hop. Two real production
    /// bugs shaped this exact pattern, both worth understanding:
    ///
    /// - An earlier version matched ANY two-segment-plus-rest path
    ///   (`^/([^/]+/[^/]+)(?:/(.*))?$`), trying to also preserve deeper
    ///   links. `regex` (RE2-based, no lookahead support) can't express
    ///   "doesn't already start with GitLab's own `-/` namespace", so it
    ///   also matched -- and mangled -- GitLab's own already-correct
    ///   `/-/wikis/<page>` URLs into `/-/wikis/-/wikis/<page>` the very
    ///   next click, a real 404 in production.
    /// - The next version narrowed that to exactly two segments
    ///   (`^/([^/]+/[^/]+)/?$`), which fixed the above but is still
    ///   dangerously broad on a real site: it also matches unrelated
    ///   top-level paths like `/assets/app.css` or `/api/v4/version`,
    ///   silently breaking GitLab's own static assets and API calls --
    ///   also hit for real in production.
    ///
    /// Anchoring to an explicit allowlist of this instance's real
    /// namespaces (alternation, not lookahead -- `regex` doesn't support
    /// lookahead at all) fixes both: it can only ever match a real
    /// `<namespace>/<project>` path for a namespace that's actually
    /// listed, never an already-rewritten wiki URL (those have more
    /// than two segments) and never an unrelated top-level path like
    /// `/assets/...` (not a listed namespace). An allowlist also stays
    /// correct automatically as GitLab adds new reserved top-level
    /// paths in the future -- nothing to update here unless a new real
    /// namespace is added.
    fn gitlab_wiki_rewrite() -> crate::config::PathRewrite {
        path_rewrite(r"^/((?:jpps|kb9gxk)/[^/]+)/?$", "/$1/-/wikis/Home")
    }

    #[test]
    fn apply_path_rewrite_sends_a_bare_project_path_straight_to_the_wiki_home_page() {
        let rw = gitlab_wiki_rewrite();
        let mut req = Request::builder().uri("/jpps/rust-proxy").body(()).unwrap();
        apply_path_rewrite(&mut req, &rw);
        assert_eq!(req.uri().path(), "/jpps/rust-proxy/-/wikis/Home");
    }

    #[test]
    fn apply_path_rewrite_does_not_touch_an_already_correct_gitlab_wiki_url() {
        // Regression test for the real production bug described above --
        // clicking a real wiki page link (already under /-/wikis/) must
        // never be rewritten a second time.
        let rw = gitlab_wiki_rewrite();
        let mut req = Request::builder()
            .uri("/jpps/rust-proxy/-/wikis/Getting-Started")
            .body(())
            .unwrap();
        apply_path_rewrite(&mut req, &rw);
        assert_eq!(req.uri().path(), "/jpps/rust-proxy/-/wikis/Getting-Started");
    }

    #[test]
    fn apply_path_rewrite_does_not_touch_gitlab_asset_or_api_paths() {
        // Regression test for the second real production bug described
        // above -- a pattern matching "any two segments" also matches
        // (and would break) GitLab's own site-wide static assets and API
        // calls, which aren't project paths at all.
        let rw = gitlab_wiki_rewrite();

        let mut assets_req = Request::builder()
            .uri("/assets/application-abc123.css")
            .body(())
            .unwrap();
        apply_path_rewrite(&mut assets_req, &rw);
        assert_eq!(assets_req.uri().path(), "/assets/application-abc123.css");

        let mut api_req = Request::builder().uri("/api/v4/version").body(()).unwrap();
        apply_path_rewrite(&mut api_req, &rw);
        assert_eq!(api_req.uri().path(), "/api/v4/version");
    }

    #[test]
    fn apply_path_rewrite_sends_a_second_allowlisted_namespace_to_its_own_wiki() {
        let rw = gitlab_wiki_rewrite();
        let mut req = Request::builder().uri("/kb9gxk/web").body(()).unwrap();
        apply_path_rewrite(&mut req, &rw);
        assert_eq!(req.uri().path(), "/kb9gxk/web/-/wikis/Home");
    }

    #[test]
    fn apply_path_rewrite_does_not_touch_a_namespace_outside_the_allowlist() {
        let rw = gitlab_wiki_rewrite();
        let mut req = Request::builder()
            .uri("/someone-else/their-project")
            .body(())
            .unwrap();
        apply_path_rewrite(&mut req, &rw);
        assert_eq!(req.uri().path(), "/someone-else/their-project");
    }

    #[test]
    fn apply_path_rewrite_preserves_the_query_string() {
        let rw = path_rewrite(r"^/old(/.*)?$", "/new$1");
        let mut req = Request::builder()
            .uri("/old/page?x=1&y=2")
            .body(())
            .unwrap();
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

    fn rule(
        bind_ip: &str,
        start: u16,
        end: u16,
        proto: Protocol,
        target: Option<&str>,
    ) -> PortRule {
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
        let rules = vec![rule(
            "10.0.0.4",
            21115,
            21119,
            Protocol::Tcp,
            Some("127.0.0.1:9000"),
        )];
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
            network: NetworkConfig {
                bind_ranges: vec![],
                dedicated_ips: vec![],
                dhcp_interfaces: vec![],
            },
            admin: AdminConfig {
                bind_ip_v4: Some("127.0.0.1".parse().unwrap()),
                bind_ip_v6: None,
                bind_port: 8080,
                allowed_ips: vec![],
                expose_admin_port: None,
                session_secret: Some("test-secret".into()),
                admin_username: Some("admin".into()),
                admin_password_hash: Some(
                    "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g".into(),
                ),
                db_path: PathBuf::from(":memory:"),
                log_dir: None,
                client_cert_subjects: vec![],
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
            client_cert_forward_token: None,
            siem: None,
            hosting: None,
        };
        let pool = crate::db::connect(&PathBuf::from(":memory:"))
            .await
            .unwrap();
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
            crate::db::create_acl_list(
                pool,
                acl_id,
                "test ip allow",
                crate::config::AclKind::IpAllow,
                chrono::Utc::now(),
            )
            .await
            .unwrap();
            let cidrs: Vec<String> = access_allow_ips.iter().map(|net| net.to_string()).collect();
            crate::db::add_acl_ip_entries(pool, acl_id, &cidrs)
                .await
                .unwrap();
            acl_ids.push(acl_id);
        }
        if let Some(auth) = access_login {
            let acl_id = Uuid::new_v4();
            crate::db::create_acl_list(
                pool,
                acl_id,
                "test login",
                crate::config::AclKind::Login,
                chrono::Utc::now(),
            )
            .await
            .unwrap();
            crate::db::add_acl_credentials(
                pool,
                acl_id,
                &[(auth.username.clone(), auth.password_hash.clone())],
            )
            .await
            .unwrap();
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
            static_root: None,
            rewrite_samesite_none_cookies: false,
            deny_fallback: None,
            locations: Vec::new(),
            block_exploits: false,
            fixed_response: None,
            hsts: false,
            hsts_subdomains: false,
            pass_client_cert_header: false,
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
                async move {
                    handle_https_request(state, bind_ip, bind_port, peer_ip, sni, None, req).await
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
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
        let req = builder
            .body(http_body_util::Full::new(Bytes::from(body_bytes)))
            .unwrap();
        sender.send_request(req).await.unwrap()
    }

    /// Same shape as `send_test_request`, but drives a connection that
    /// claims to have presented the given client-cert subject -- a
    /// dedicated helper rather than adding a parameter to
    /// `send_test_request` itself, since that would touch every one of
    /// its many existing call sites for a variant only the ClientCert
    /// ACL tests below need. Bypasses real TLS entirely (this crate's
    /// existing test suite already proves the TLS-level cert extraction
    /// separately in `client_cert.rs`) -- what's under test here is
    /// purely "does the gate logic in handle_https_request do the right
    /// thing with a given client_cert_subject value."
    async fn send_test_request_with_cert(
        state: AppState,
        peer_ip: IpAddr,
        client_cert_subject: Option<client_cert::ClientCertIdentity>,
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
                let client_cert_subject = client_cert_subject.clone();
                async move {
                    handle_https_request(
                        state,
                        bind_ip,
                        bind_port,
                        peer_ip,
                        sni,
                        client_cert_subject,
                        req,
                    )
                    .await
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);

        let req = Request::builder()
            .method("GET")
            .uri("/")
            .body(http_body_util::Full::new(Bytes::new()))
            .unwrap();
        sender.send_request(req).await.unwrap()
    }

    async fn response_text(resp: Response<Incoming>) -> String {
        String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
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
                async move {
                    handle_https_request(
                        state,
                        bind_ip,
                        bind_port,
                        "203.0.113.7".parse().unwrap(),
                        sni,
                        None,
                        req,
                    )
                    .await
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
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

        let location = resp
            .headers()
            .get(hyper::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            location, "https://b.example.com",
            "the request's real Host header must win over the connection's stale SNI"
        );
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
    async fn an_h2_requests_authority_wins_over_a_stale_connection_level_sni_with_no_host_header_at_all(
    ) {
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
                async move {
                    handle_https_request(
                        state,
                        bind_ip,
                        bind_port,
                        "203.0.113.7".parse().unwrap(),
                        sni,
                        None,
                        req,
                    )
                    .await
                }
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
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(&b"h2"[..]),
            "must actually be h2 -- that's the whole point of this test"
        );

        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(conn);

        // Absolute-form URI, no Host header at all -- hyper's h2 client
        // derives the :authority pseudo-header from the URI itself,
        // same as a real browser reusing a coalesced connection for a
        // different origin than the one it originally connected to.
        let req = Request::builder()
            .uri("https://second.example.com/")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();

        let location = resp
            .headers()
            .get(hyper::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            location, "https://b.example.com",
            "an h2 request's :authority (no Host header at all) must win over the connection's stale SNI"
        );
    }

    #[tokio::test]
    async fn request_from_an_ip_outside_the_allow_list_is_forbidden() {
        let state =
            test_state_with_access("example.com", vec!["192.168.1.0/24".parse().unwrap()], None)
                .await;
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
        assert_eq!(
            resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let body = response_text(resp).await;
        assert!(
            body.contains("Access denied"),
            "an IP-only-denied host must get a real page, not a bare empty 403"
        );
    }

    #[tokio::test]
    async fn request_from_an_allowed_ip_without_a_login_gate_configured_is_not_blocked() {
        let state =
            test_state_with_access("example.com", vec!["10.0.0.0/24".parse().unwrap()], None).await;
        let resp =
            send_test_request(state, "10.0.0.42".parse().unwrap(), "GET", "/", None, None).await;
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
    async fn matching_ip_admits_the_request_without_requiring_login_even_when_a_login_acl_is_also_configured(
    ) {
        let state = test_state_with_access(
            "example.com",
            vec!["10.0.0.0/24".parse().unwrap()],
            Some(viewer_auth()),
        )
        .await;
        let resp =
            send_test_request(state, "10.0.0.42".parse().unwrap(), "GET", "/", None, None).await;
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
        let state = test_state_with_access(
            "example.com",
            vec!["192.168.1.0/24".parse().unwrap()],
            Some(viewer_auth()),
        )
        .await;
        let resp = send_test_request(
            state,
            "203.0.113.7".parse().unwrap(),
            "GET",
            "/",
            None,
            None,
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        let body = response_text(resp).await;
        assert!(
            body.contains("Sign in to example.com"),
            "a non-matching IP with a login ACL also configured must get the login page, not a 403"
        );
    }

    fn viewer_auth() -> crate::config::HostAuth {
        crate::config::HostAuth {
            username: "viewer".into(),
            password_hash: crate::api::auth::hash_password("s3cret").unwrap(),
        }
    }

    /// A host with a `ClientCert`-kind ACL selected, plus (matching
    /// Jeff's own spec: "#2 but fallback with user/pass as is now") a
    /// `Login`-kind ACL as the fallback for a connection that didn't
    /// present a cert.
    async fn client_cert_host_with_login_fallback(
        pool: &sqlx::SqlitePool,
        domain: &str,
    ) -> ProxyHost {
        let cert_acl_id = Uuid::new_v4();
        crate::db::create_acl_list(
            pool,
            cert_acl_id,
            "test client cert",
            crate::config::AclKind::ClientCert,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        let login_acl_id = Uuid::new_v4();
        crate::db::create_acl_list(
            pool,
            login_acl_id,
            "test login fallback",
            crate::config::AclKind::Login,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        let auth = viewer_auth();
        crate::db::add_acl_credentials(pool, login_acl_id, &[(auth.username, auth.password_hash)])
            .await
            .unwrap();
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
            acl_ids: vec![cert_acl_id, login_acl_id],
            dns_credential_id: None,
            redirect: None,
            path_rewrite: None,
            static_root: None,
            rewrite_samesite_none_cookies: false,
            deny_fallback: None,
            locations: Vec::new(),
            block_exploits: false,
            fixed_response: None,
            hsts: false,
            hsts_subdomains: false,
            pass_client_cert_header: false,
            enabled: true,
        }
    }

    /// A host with a `ClientCert`-kind ACL *and* an `IpAllow`-kind ACL
    /// both selected -- for exercising Jeff's "unless it's IP locked
    /// and I'm not on one of the authorized IPs" exception in
    /// `should_request_client_cert`.
    async fn client_cert_host_with_ip_allow(
        pool: &sqlx::SqlitePool,
        domain: &str,
        allowed_cidr: &str,
    ) -> ProxyHost {
        let cert_acl_id = Uuid::new_v4();
        crate::db::create_acl_list(
            pool,
            cert_acl_id,
            "test client cert 2",
            crate::config::AclKind::ClientCert,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        let ip_acl_id = Uuid::new_v4();
        crate::db::create_acl_list(
            pool,
            ip_acl_id,
            "test ip allow 2",
            crate::config::AclKind::IpAllow,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        crate::db::add_acl_ip_entries(pool, ip_acl_id, &[allowed_cidr.to_string()])
            .await
            .unwrap();
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
            acl_ids: vec![cert_acl_id, ip_acl_id],
            dns_credential_id: None,
            redirect: None,
            path_rewrite: None,
            static_root: None,
            rewrite_samesite_none_cookies: false,
            deny_fallback: None,
            locations: Vec::new(),
            block_exploits: false,
            fixed_response: None,
            hsts: false,
            hsts_subdomains: false,
            pass_client_cert_header: false,
            enabled: true,
        }
    }

    fn pass_header_host(domain: &str) -> ProxyHost {
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
            acl_ids: vec![],
            dns_credential_id: None,
            redirect: None,
            path_rewrite: None,
            static_root: None,
            rewrite_samesite_none_cookies: false,
            deny_fallback: None,
            locations: Vec::new(),
            block_exploits: false,
            fixed_response: None,
            hsts: false,
            hsts_subdomains: false,
            pass_client_cert_header: true,
            enabled: true,
        }
    }

    const TEST_BIND_IP: &str = "10.0.0.2";
    const TEST_BIND_PORT: u16 = 443;

    /// Jeff's own ask, unit-tested directly against the decision
    /// function rather than through a real TLS handshake -- there's no
    /// way to construct a client cert that actually chains to
    /// TrustBridge's real embedded root in a test (its private key is
    /// deliberately offline, see `[[trustbridge_ca_portal]]`), so every
    /// other client-cert test in this file already works this way (see
    /// `send_test_request_with_cert`'s own doc comment on the same
    /// constraint) -- `should_request_client_cert` itself doesn't touch
    /// any cert material at all, only ACL/host config, so it's fully
    /// testable without one.
    #[tokio::test]
    async fn store_style_host_with_pass_client_cert_header_always_wants_a_cert_requested() {
        let state = test_state_with_cert("example.com").await;
        state.set_hosts(vec![pass_header_host("example.com")]);
        assert!(
            should_request_client_cert(
                &state,
                TEST_BIND_IP.parse().unwrap(),
                TEST_BIND_PORT,
                "203.0.113.7".parse().unwrap(),
                Some("example.com")
            )
            .await
        );
    }

    #[tokio::test]
    async fn a_host_with_no_client_cert_feature_enabled_never_wants_a_cert_requested() {
        let state = test_state_with_cert("example.com").await;
        state.set_hosts(vec![redirect_host(
            "example.com",
            crate::config::RedirectTarget {
                target: "https://a.example.com".into(),
                preserve_path: false,
                status: crate::config::RedirectStatus::Permanent,
            },
        )]);
        assert!(
            !should_request_client_cert(
                &state,
                TEST_BIND_IP.parse().unwrap(),
                TEST_BIND_PORT,
                "203.0.113.7".parse().unwrap(),
                Some("example.com")
            )
            .await
        );
    }

    #[tokio::test]
    async fn a_client_cert_acl_host_with_no_ip_allow_acl_always_wants_a_cert_requested() {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_login_fallback(state.db(), "example.com").await;
        state.set_hosts(vec![host]);
        assert!(
            should_request_client_cert(
                &state,
                TEST_BIND_IP.parse().unwrap(),
                TEST_BIND_PORT,
                "203.0.113.7".parse().unwrap(),
                Some("example.com")
            )
            .await
        );
    }

    /// The exception clause: an IP already covered by the host's own
    /// IpAllow ACL doesn't need to be asked for a cert too.
    #[tokio::test]
    async fn a_client_cert_acl_host_skips_the_cert_request_for_an_already_ip_allowed_peer() {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_ip_allow(state.db(), "example.com", "10.0.0.0/24").await;
        state.set_hosts(vec![host]);
        assert!(
            !should_request_client_cert(
                &state,
                TEST_BIND_IP.parse().unwrap(),
                TEST_BIND_PORT,
                "10.0.0.42".parse().unwrap(),
                Some("example.com")
            )
            .await
        );
    }

    /// Same host, but a peer IP outside the allow list -- back to
    /// wanting a cert requested, same as if there were no IpAllow ACL
    /// at all.
    #[tokio::test]
    async fn a_client_cert_acl_host_still_wants_a_cert_requested_for_a_peer_outside_the_ip_allow_list(
    ) {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_ip_allow(state.db(), "example.com", "10.0.0.0/24").await;
        state.set_hosts(vec![host]);
        assert!(
            should_request_client_cert(
                &state,
                TEST_BIND_IP.parse().unwrap(),
                TEST_BIND_PORT,
                "203.0.113.7".parse().unwrap(),
                Some("example.com")
            )
            .await
        );
    }

    #[tokio::test]
    async fn no_sni_never_wants_a_cert_requested() {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_login_fallback(state.db(), "example.com").await;
        state.set_hosts(vec![host]);
        assert!(
            !should_request_client_cert(
                &state,
                TEST_BIND_IP.parse().unwrap(),
                TEST_BIND_PORT,
                "203.0.113.7".parse().unwrap(),
                None
            )
            .await
        );
    }

    #[tokio::test]
    async fn sni_matching_no_host_never_wants_a_cert_requested() {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_login_fallback(state.db(), "example.com").await;
        state.set_hosts(vec![host]);
        assert!(
            !should_request_client_cert(
                &state,
                TEST_BIND_IP.parse().unwrap(),
                TEST_BIND_PORT,
                "203.0.113.7".parse().unwrap(),
                Some("unrelated.example.net")
            )
            .await
        );
    }

    /// A ClientCert ACL with no subject entries trusts no certificate: a
    /// valid cert alone does not skip the login gate.
    #[tokio::test]
    async fn a_client_cert_acl_with_no_entries_trusts_no_certificate() {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_login_fallback(state.db(), "example.com").await;
        state.set_hosts(vec![host]);

        let resp = send_test_request_with_cert(
            state,
            "203.0.113.7".parse().unwrap(),
            Some(client_cert::ClientCertIdentity::cn_only("Jeffs MacBook")),
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        let body = response_text(resp).await;
        assert!(
            body.contains("Sign in to example.com"),
            "an empty client-cert list must not let any certificate bypass the login page"
        );
    }

    /// Same host, but the ClientCert ACL now has one subject entry --
    /// Jeff's follow-up ask ("I need the ability to specify which certs
    /// to accept"). A cert whose subject matches the entry still
    /// bypasses the login gate.
    #[tokio::test]
    async fn a_client_cert_matching_an_allowed_subject_entry_bypasses_the_login_gate() {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_login_fallback(state.db(), "example.com").await;
        let cert_acl_id = host.acl_ids[0];
        crate::db::add_acl_client_cert_entry(state.db(), cert_acl_id, "Jeffs MacBook", None)
            .await
            .unwrap();
        state.set_hosts(vec![host]);

        let resp = send_test_request_with_cert(
            state,
            "203.0.113.7".parse().unwrap(),
            Some(client_cert::ClientCertIdentity::cn_only("Jeffs MacBook")),
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY);
    }

    /// With no org lock set, the allow-list is matched on CN alone.
    #[tokio::test]
    async fn without_an_org_lock_client_cert_matching_is_on_cn_only() {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_login_fallback(state.db(), "example.com").await;
        let cert_acl_id = host.acl_ids[0];
        crate::db::add_acl_client_cert_entry(state.db(), cert_acl_id, "Jeffs MacBook", None)
            .await
            .unwrap();
        state.set_hosts(vec![host]);

        let with_org = client_cert::ClientCertIdentity {
            cn: "Jeffs MacBook".into(),
            org: Some("Some Other Org".into()),
            org_id: Some("NOT-THE-ORG-ID".into()),
        };
        let resp = send_test_request_with_cert(
            state,
            "203.0.113.7".parse().unwrap(),
            Some(with_org),
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY);
    }

    /// With the org lock set, only a cert carrying that org-id passes; the
    /// same CN without it (an old cert) or from another org falls back to login.
    #[tokio::test]
    async fn an_org_lock_rejects_old_and_foreign_certs_and_accepts_the_right_one() {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_login_fallback(state.db(), "example.com").await;
        let cert_acl_id = host.acl_ids[0];
        crate::db::add_acl_client_cert_entry(state.db(), cert_acl_id, "Jeffs MacBook", None)
            .await
            .unwrap();
        state.set_hosts(vec![host]);
        state.set_required_client_cert_org(Some("TB-GOOD".into()));

        let ident = |org_id: Option<&str>| client_cert::ClientCertIdentity {
            cn: "Jeffs MacBook".into(),
            org: Some("Some Org".into()),
            org_id: org_id.map(str::to_string),
        };
        for (label, id, passes) in [
            ("old cert, no org-id", client_cert::ClientCertIdentity::cn_only("Jeffs MacBook"), false),
            ("other org", ident(Some("TB-OTHER")), false),
            ("right org", ident(Some("TB-GOOD")), true),
        ] {
            let resp = send_test_request_with_cert(
                state.clone(),
                "203.0.113.7".parse().unwrap(),
                Some(id),
            )
            .await;
            if passes {
                assert_eq!(resp.status(), hyper::StatusCode::BAD_GATEWAY, "{label}");
            } else {
                assert_eq!(resp.status(), hyper::StatusCode::OK, "{label}");
                assert!(response_text(resp).await.contains("Sign in to example.com"), "{label}");
            }
        }
    }

    /// A cert whose subject does NOT match any allowed entry falls back
    /// to the Login ACL instead of being treated as sufficient -- a
    /// valid TrustBridge cert alone is no longer enough once the
    /// operator has scoped the ACL down to specific subjects.
    #[tokio::test]
    async fn a_client_cert_not_matching_any_allowed_subject_entry_falls_through_to_the_login_gate()
    {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_login_fallback(state.db(), "example.com").await;
        let cert_acl_id = host.acl_ids[0];
        crate::db::add_acl_client_cert_entry(state.db(), cert_acl_id, "Jeffs MacBook", None)
            .await
            .unwrap();
        state.set_hosts(vec![host]);

        let resp = send_test_request_with_cert(
            state,
            "203.0.113.7".parse().unwrap(),
            Some(client_cert::ClientCertIdentity::cn_only("Someone Else's Phone")),
        )
        .await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        let body = response_text(resp).await;
        assert!(
            body.contains("Sign in to example.com"),
            "a cert not on the allow-list must fall back to the login page, not bypass it"
        );
    }

    /// The fallback half of the same spec: no cert presented falls
    /// through to the Login ACL exactly as today, not a hard block.
    #[tokio::test]
    async fn no_client_cert_falls_through_to_the_login_gate_fallback() {
        let state = test_state_with_cert("example.com").await;
        let host = client_cert_host_with_login_fallback(state.db(), "example.com").await;
        state.set_hosts(vec![host]);

        let resp = send_test_request_with_cert(state, "203.0.113.7".parse().unwrap(), None).await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        let body = response_text(resp).await;
        assert!(
            body.contains("Sign in to example.com"),
            "no client cert presented must fall back to the login page, not a bypass or a hard block"
        );
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
        assert_eq!(
            resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
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
        let set_cookie = resp
            .headers()
            .get(hyper::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
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
            static_root: None,
            rewrite_samesite_none_cookies: false,
            deny_fallback: None,
            locations: Vec::new(),
            block_exploits: false,
            fixed_response: None,
            hsts: false,
            hsts_subdomains: false,
            pass_client_cert_header: false,
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
        let location = resp
            .headers()
            .get(hyper::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
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
        crate::db::create_acl_list(
            state.db(),
            acl_id,
            "test ip allow",
            crate::config::AclKind::IpAllow,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        crate::db::add_acl_ip_entries(state.db(), acl_id, &["192.168.1.0/24".to_string()])
            .await
            .unwrap();
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

    #[tokio::test]
    async fn a_fixed_response_host_answers_without_an_upstream() {
        let target = crate::config::RedirectTarget {
            target: "https://unused.example.com".into(),
            preserve_path: true,
            status: crate::config::RedirectStatus::Permanent,
        };
        let mut host = redirect_host("example.com", target);
        host.redirect = None;
        host.fixed_response = Some(crate::config::FixedResponse {
            status: 404,
            body: "no such site".into(),
            html: false,
        });
        let state = test_state_with_host(host).await;
        let resp = send_test_request(state, "203.0.113.7".parse().unwrap(), "GET", "/x", None, None).await;
        assert_eq!(resp.status(), hyper::StatusCode::NOT_FOUND);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        assert_eq!(&body[..], b"no such site");
    }

    #[tokio::test]
    async fn a_parked_site_serves_its_html_landing_page_with_a_404() {
        let target = crate::config::RedirectTarget {
            target: "https://unused.example.com".into(),
            preserve_path: true,
            status: crate::config::RedirectStatus::Permanent,
        };
        let mut host = redirect_host("example.com", target);
        host.redirect = None;
        host.fixed_response = Some(crate::config::FixedResponse {
            status: 404,
            body: "<h1>Coming soon</h1>".into(),
            html: true,
        });
        let state = test_state_with_host(host).await;
        let resp = send_test_request(state, "203.0.113.7".parse().unwrap(), "GET", "/x", None, None).await;
        assert_eq!(resp.status(), hyper::StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        assert_eq!(&body[..], b"<h1>Coming soon</h1>");
    }

    #[tokio::test]
    async fn block_exploits_refuses_probes_but_not_ordinary_requests() {
        let target = crate::config::RedirectTarget {
            target: "https://new.example.com".into(),
            preserve_path: true,
            status: crate::config::RedirectStatus::Permanent,
        };
        let mut host = redirect_host("example.com", target);
        host.block_exploits = true;
        let state = test_state_with_host(host).await;
        let blocked = send_test_request(
            state.clone(),
            "203.0.113.7".parse().unwrap(),
            "GET",
            "/?q=%3Cscript%3E",
            None,
            None,
        )
        .await;
        assert_eq!(blocked.status(), hyper::StatusCode::FORBIDDEN);
        let ok = send_test_request(state, "203.0.113.7".parse().unwrap(), "GET", "/page", None, None).await;
        assert_eq!(ok.status(), hyper::StatusCode::MOVED_PERMANENTLY);
    }

    #[tokio::test]
    async fn a_custom_location_routes_its_path_to_its_own_upstream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let loc_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(|_req: Request<Incoming>| async {
                        Ok::<_, std::convert::Infallible>(Response::new(
                            http_body_util::Full::new(Bytes::from_static(b"from-location")),
                        ))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        let target = crate::config::RedirectTarget {
            target: "https://unused.example.com".into(),
            preserve_path: true,
            status: crate::config::RedirectStatus::Permanent,
        };
        let mut host = redirect_host("example.com", target);
        host.redirect = None;
        host.upstream = "127.0.0.1:1".into();
        host.locations = vec![crate::config::HostLocation {
            path: "/api".into(),
            upstream: loc_addr.to_string(),
            upstream_https: false,
            upstream_tls_verify: true,
        }];
        let state = test_state_with_host(host).await;
        let hit = send_test_request(state.clone(), "203.0.113.7".parse().unwrap(), "GET", "/api/users", None, None).await;
        assert_eq!(hit.status(), hyper::StatusCode::OK);
        let body = http_body_util::BodyExt::collect(hit.into_body()).await.unwrap().to_bytes();
        assert_eq!(&body[..], b"from-location");
        let miss = send_test_request(state, "203.0.113.7".parse().unwrap(), "GET", "/other", None, None).await;
        assert_eq!(miss.status(), hyper::StatusCode::BAD_GATEWAY);
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
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
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
                let body: BoxBody<Bytes, hyper::Error> = http_body_util::Empty::new()
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(200)
                        .header("x-h2-test", "yes")
                        .body(body)
                        .unwrap(),
                )
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
        assert_eq!(
            negotiated,
            Some(b"h2".to_vec()),
            "server should have negotiated h2 when the client offered it"
        );

        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .uri("/")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
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
                let body: BoxBody<Bytes, hyper::Error> = http_body_util::Empty::new()
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed();
                Ok::<_, std::convert::Infallible>(
                    Response::builder().status(200).body(body).unwrap(),
                )
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

    async fn default_site_body(resp: Response<BoxBody<Bytes, hyper::Error>>) -> String {
        use http_body_util::BodyExt;
        String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    fn site(mode: crate::config::DefaultSiteMode, url: &str, html: &str) -> crate::config::DefaultSite {
        crate::config::DefaultSite { mode, redirect_url: url.into(), custom_html: html.into() }
    }

    #[tokio::test]
    async fn default_site_not_found_is_a_plain_404() {
        use crate::config::DefaultSiteMode as M;
        let resp = default_site_response(&site(M::NotFound, "", ""));
        assert_eq!(resp.status(), hyper::StatusCode::NOT_FOUND);
        assert!(resp.extensions().get::<DropConnection>().is_none());
    }

    #[tokio::test]
    async fn default_site_congratulations_and_custom_html_are_200_pages() {
        use crate::config::DefaultSiteMode as M;
        let resp = default_site_response(&site(M::Congratulations, "", ""));
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        assert_eq!(
            resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert!(default_site_body(resp).await.contains("RustProxy is running"));

        let resp = default_site_response(&site(M::CustomHtml, "", "<h1>Mine</h1>"));
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        assert_eq!(default_site_body(resp).await, "<h1>Mine</h1>");
    }

    #[tokio::test]
    async fn default_site_redirect_sends_a_302_to_the_configured_url() {
        use crate::config::DefaultSiteMode as M;
        let resp = default_site_response(&site(M::Redirect, " https://www.example.com ", ""));
        assert_eq!(resp.status(), hyper::StatusCode::FOUND);
        assert_eq!(
            resp.headers().get(hyper::header::LOCATION).unwrap(),
            "https://www.example.com"
        );
        let bad = default_site_response(&site(M::Redirect, "bad\nurl", ""));
        assert_eq!(bad.status(), hyper::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn default_site_no_response_marks_the_connection_for_dropping() {
        use crate::config::DefaultSiteMode as M;
        let resp = default_site_response(&site(M::NoResponse, "", ""));
        assert!(resp.extensions().get::<DropConnection>().is_some());
    }
}
