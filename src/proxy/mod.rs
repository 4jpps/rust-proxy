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
use hyper_util::rt::TokioIo;
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
        spawn_redirect_listener(key.0, key.1)
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

        let resolver = Arc::new(tls::CertResolver::new(state.clone()));
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "https listener accept failed");
                    continue;
                }
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
                    async move { handle_https_request(state, bind_ip, bind_port, sni, req).await }
                });
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    tracing::debug!(error = %err, "https connection ended");
                }
            });
        }
    })
}

async fn handle_https_request(
    state: AppState,
    bind_ip: Ipv4Addr,
    bind_port: u16,
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

fn spawn_redirect_listener(bind_ip: Ipv4Addr, bind_port: u16) -> JoinHandle<()> {
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
            let service = hyper::service::service_fn(|req: Request<Incoming>| async move {
                Ok::<_, std::convert::Infallible>(http::https_redirect_response(&req))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PortRule, Protocol};
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
}
