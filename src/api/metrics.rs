//! `GET /metrics` (Prometheus text format) and `GET /api/limits`. Both sit
//! behind admin login or an API token: point a scraper at /metrics with a
//! Viewer token (`Authorization: Bearer rpx_...`).
//!
//! Written by hand instead of through a metrics crate: the values are a
//! handful of gauges read on demand and three totals.

use std::fmt::Write as _;

use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use super::health;
use crate::proxy::limits::{self, CONNECTIONS_REFUSED, RATE_LIMITED, TLS_HANDSHAKE_TIMEOUTS};
use crate::state::AppState;

pub async fn metrics(State(state): State<AppState>) -> Response {
    let report = health::report(&state).await;
    let mut out = String::new();
    let mut gauge = |name: &str, help: &str, value: f64| {
        let _ = writeln!(out, "# HELP rustproxy_{name} {help}");
        let _ = writeln!(out, "# TYPE rustproxy_{name} gauge");
        let _ = writeln!(out, "rustproxy_{name} {value}");
    };
    gauge("up", "1 while the daemon answers.", 1.0);
    gauge(
        "healthy",
        "1 when every /healthz check passes.",
        f64::from(u8::from(report.status == "ok")),
    );

    let certs = state.certs();
    gauge("certificates", "Certificates loaded.", certs.len() as f64);
    if let Some(soonest) = certs.values().map(|c| c.not_after).min() {
        gauge(
            "certificate_nearest_expiry_seconds",
            "Seconds until the soonest certificate expiry.",
            (soonest - chrono::Utc::now()).num_seconds() as f64,
        );
    }
    gauge("hosts", "Sites configured.", state.hosts().len() as f64);
    gauge(
        "port_rules",
        "Port rules configured.",
        state.port_rules().len() as f64,
    );

    let fw = state.firewall_status();
    gauge(
        "firewall_last_apply_ok",
        "1 if the last firewall apply succeeded.",
        f64::from(u8::from(fw.ok)),
    );
    if let Some(at) = fw.last_applied_at {
        gauge(
            "firewall_last_applied_age_seconds",
            "Seconds since the firewall was last applied successfully.",
            (chrono::Utc::now() - at).num_seconds() as f64,
        );
    }
    let (open, limit) = health::fd_usage();
    gauge("open_fds", "Open file descriptors.", open as f64);
    if let Some(limit) = limit {
        gauge("max_fds", "File descriptor soft limit.", limit as f64);
    }
    if let Some((free, total)) = health::disk_space(health::db_dir(&state.admin().db_path)) {
        gauge(
            "disk_free_bytes",
            "Free bytes where the database lives.",
            free,
        );
        gauge(
            "disk_total_bytes",
            "Size of the filesystem where the database lives.",
            total,
        );
    }
    gauge(
        "clients_connected",
        "Clients (address, or /64 for IPv6) holding at least one connection.",
        state.conn_limiter().clients() as f64,
    );

    for (name, help, counter) in [
        (
            "connections_refused_total",
            "Connections closed at accept for exceeding max_connections_per_ip.",
            &CONNECTIONS_REFUSED,
        ),
        (
            "tls_handshake_timeouts_total",
            "TLS handshakes abandoned after 10 s.",
            &TLS_HANDSHAKE_TIMEOUTS,
        ),
        (
            "rate_limited_total",
            "Requests answered 429 by a site's rate limit.",
            &RATE_LIMITED,
        ),
    ] {
        let _ = writeln!(out, "# HELP rustproxy_{name} {help}");
        let _ = writeln!(out, "# TYPE rustproxy_{name} counter");
        let _ = writeln!(out, "rustproxy_{name} {}", limits::total(counter));
    }
    let _ = writeln!(
        out,
        "# HELP rustproxy_check_ok 1 per /healthz check that passes."
    );
    let _ = writeln!(out, "# TYPE rustproxy_check_ok gauge");
    for c in &report.checks {
        let _ = writeln!(
            out,
            "rustproxy_check_ok{{check=\"{}\"}} {}",
            c.name,
            u8::from(c.ok)
        );
    }
    let _ = writeln!(
        out,
        "# HELP rustproxy_build_info Version of the running daemon."
    );
    let _ = writeln!(out, "# TYPE rustproxy_build_info gauge");
    let _ = writeln!(
        out,
        "rustproxy_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response()
}

#[derive(Debug, Serialize)]
pub struct ClientConnections {
    /// The address, or the /64 network address for IPv6.
    pub client: String,
    pub connections: usize,
}

#[derive(Debug, Serialize)]
pub struct LimitsView {
    pub max_connections_per_ip: usize,
    pub clients_connected: usize,
    /// The 50 clients holding the most connections, busiest first.
    pub top_clients: Vec<ClientConnections>,
    pub connections_refused_total: u64,
    pub tls_handshake_timeouts_total: u64,
    pub rate_limited_total: u64,
}

/// `GET /api/limits`: who is near the per-client connection cap, to tell a
/// false positive (an office behind one NAT) from a real flood.
pub async fn get_limits(State(state): State<AppState>) -> Json<LimitsView> {
    let limiter = state.conn_limiter();
    Json(LimitsView {
        max_connections_per_ip: limiter.limit(),
        clients_connected: limiter.clients(),
        top_clients: limiter
            .top(50)
            .into_iter()
            .map(|(ip, n)| ClientConnections {
                client: if ip.is_ipv6() {
                    format!("{ip}/64")
                } else {
                    ip.to_string()
                },
                connections: n,
            })
            .collect(),
        connections_refused_total: limits::total(&CONNECTIONS_REFUSED),
        tls_handshake_timeouts_total: limits::total(&TLS_HANDSHAKE_TIMEOUTS),
        rate_limited_total: limits::total(&RATE_LIMITED),
    })
}
