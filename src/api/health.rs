//! `GET /healthz` (no login, admin listener only -- that listener is
//! already firewalled to the admin allow-list) and the firewall preview.
//!
//! Health is read-only and cheap: it never triggers an nftables apply or
//! an ACME call, only reads what the background loops last recorded, and
//! the whole report is cached for a few seconds so a tight monitoring loop
//! can't turn it into load. Details name no domains or addresses.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::nftables::{self, DiffLine, Overrides};
use crate::state::AppState;

const CACHE_FOR: Duration = Duration::from_secs(5);
/// The sync loop runs at least every 5 minutes; three missed rounds is stale.
const FIREWALL_STALE_AFTER: Duration = Duration::from_secs(15 * 60);
const CERT_FAIL_DAYS: i64 = 7;
const DISK_FAIL_PERCENT: f64 = 5.0;
const FD_FAIL_PERCENT: f64 = 90.0;

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub status: &'static str,
    pub version: &'static str,
    pub checks: Vec<Check>,
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>) -> Check {
    Check {
        name,
        ok,
        detail: detail.into(),
    }
}

pub async fn healthz(State(state): State<AppState>) -> Response {
    static CACHE: OnceLock<Mutex<Option<(Instant, HealthReport)>>> = OnceLock::new();
    let mut cached = CACHE.get_or_init(|| Mutex::new(None)).lock().await;
    let report = match cached.as_ref() {
        Some((at, r)) if at.elapsed() < CACHE_FOR => r.clone(),
        _ => {
            let r = report(&state).await;
            *cached = Some((Instant::now(), r.clone()));
            r
        }
    };
    let code = if report.status == "ok" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(report)).into_response()
}

pub async fn report(state: &AppState) -> HealthReport {
    let mut checks = vec![
        database(state).await,
        firewall(&state.firewall_status(), chrono::Utc::now()),
        certificates(state),
        disk(&state.admin().db_path),
        file_descriptors(),
        check(
            "clients",
            true,
            format!("{} with open connections", state.conn_limiter().clients()),
        ),
    ];
    let hosting = state.hosting_status();
    if hosting.last_sync_at.is_some() && !hosting.inert {
        checks.push(check(
            "hosting",
            hosting.ok,
            if hosting.ok {
                "last sync ok".into()
            } else {
                "last sync failed".to_string()
            },
        ));
    }
    HealthReport {
        status: if checks.iter().all(|c| c.ok) {
            "ok"
        } else {
            "fail"
        },
        version: env!("CARGO_PKG_VERSION"),
        checks,
    }
}

async fn database(state: &AppState) -> Check {
    let q = sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(state.db());
    match tokio::time::timeout(Duration::from_secs(2), q).await {
        Ok(Ok(_)) => check("database", true, "reachable"),
        Ok(Err(_)) => check("database", false, "query failed"),
        Err(_) => check("database", false, "no answer within 2 s"),
    }
}

fn firewall(s: &nftables::FirewallStatus, now: chrono::DateTime<chrono::Utc>) -> Check {
    let Some(attempt) = s.last_attempt_at else {
        return check("firewall", false, "not applied yet");
    };
    let age = (now - attempt).to_std().unwrap_or_default();
    if !s.ok {
        check("firewall", false, "last apply failed")
    } else if age > FIREWALL_STALE_AFTER {
        check(
            "firewall",
            false,
            format!("last sync {} min ago", age.as_secs() / 60),
        )
    } else {
        check("firewall", true, format!("applied {} s ago", age.as_secs()))
    }
}

fn certificates(state: &AppState) -> Check {
    let certs = state.certs();
    let Some(soonest) = certs.values().map(|c| c.not_after).min() else {
        return check("certificates", true, "none loaded");
    };
    let days = (soonest - chrono::Utc::now()).num_days();
    check(
        "certificates",
        days >= CERT_FAIL_DAYS,
        format!("{} loaded, nearest expiry in {days} days", certs.len()),
    )
}

/// Directory holding the database (logs default there too).
pub(crate) fn db_dir(db_path: &Path) -> &Path {
    db_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// (free bytes available to the daemon, total bytes) on `dir`'s filesystem.
pub(crate) fn disk_space(dir: &Path) -> Option<(f64, f64)> {
    let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a properly
    // sized, writable statvfs struct.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let total = st.f_blocks as f64 * st.f_frsize as f64;
    let free = st.f_bavail as f64 * st.f_frsize as f64;
    Some((free, total))
}

/// (open descriptors, soft limit if known).
pub(crate) fn fd_usage() -> (usize, Option<u64>) {
    let open = std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count())
        .unwrap_or(0);
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit struct.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0;
    (open, (ok && lim.rlim_cur > 0).then_some(lim.rlim_cur))
}

/// Free space on the filesystem holding the database.
fn disk(db_path: &Path) -> Check {
    let Some((free, total)) = disk_space(db_dir(db_path)) else {
        return check("disk", false, "statvfs failed");
    };
    let pct = if total > 0.0 {
        free / total * 100.0
    } else {
        0.0
    };
    check(
        "disk",
        pct >= DISK_FAIL_PERCENT,
        format!("{pct:.0}% free ({:.1} GB)", free / 1e9),
    )
}

/// Open descriptors against the soft limit. Running out (EMFILE) is what
/// sent the accept loop into an 8-hour spin in 2026-08, so this fails well
/// before the limit and also fails if a fresh descriptor can't be opened.
fn file_descriptors() -> Check {
    if let Err(e) = std::fs::File::open("/dev/null") {
        return check(
            "file_descriptors",
            false,
            format!("cannot open a file: {e}"),
        );
    }
    match fd_usage() {
        (open, Some(limit)) => check(
            "file_descriptors",
            (open as f64 / limit as f64 * 100.0) < FD_FAIL_PERCENT,
            format!("{open} of {limit} open"),
        ),
        (open, None) => check("file_descriptors", true, format!("{open} open")),
    }
}

#[derive(Debug, Serialize)]
pub struct FirewallPreview {
    /// False when the generated ruleset matches what was last applied.
    pub changed: bool,
    pub added: usize,
    pub removed: usize,
    /// Changed lines with 3 lines of context; unchanged runs collapse to "…".
    pub diff: Vec<DiffLine>,
    pub last_applied_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_apply_ok: bool,
    /// Whether the address making this request could still reach the
    /// admin port under the previewed rules (allow-list and global blocks).
    pub admin_reachable_from_you: bool,
    pub your_ip: String,
}

/// `GET /api/firewall/preview`: pending changes versus what's applied.
pub async fn firewall_preview_get(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    preview(&state, peer, Overrides::default()).await
}

/// `POST /api/firewall/preview`: the same, with a what-if body
/// (`hosts`, `port_rules`, `admin_allowed_ips`). Nothing is saved or applied.
pub async fn firewall_preview_post(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(overrides): Json<Overrides>,
) -> Response {
    preview(&state, peer, overrides).await
}

async fn preview(state: &AppState, peer: SocketAddr, overrides: Overrides) -> Response {
    let ruleset = match nftables::build_ruleset_with(state, &overrides).await {
        Ok(r) => r,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };
    let status = state.firewall_status();
    let old = status
        .applied_ruleset
        .as_deref()
        .map(String::as_str)
        .unwrap_or("");
    let full = nftables::diff_lines(old, &ruleset);
    let added = full.iter().filter(|l| l.op == '+').count();
    let removed = full.iter().filter(|l| l.op == '-').count();

    let ip = peer.ip().to_canonical();
    let allowed = overrides
        .admin_allowed_ips
        .clone()
        .unwrap_or_else(|| state.admin_allowed_ips());
    let expose = overrides
        .expose_admin_port
        .unwrap_or_else(|| state.expose_admin_port());
    let reachable = admin_reachable(ip, &allowed, expose, state.block_index().global_nets());

    Json(FirewallPreview {
        changed: added + removed > 0,
        added,
        removed,
        diff: with_context(&full, 3),
        last_applied_at: status.last_applied_at,
        last_apply_ok: status.ok,
        admin_reachable_from_you: reachable,
        your_ip: ip.to_string(),
    })
    .into_response()
}

/// Whether the generated ruleset lets `ip` reach the admin port, in the
/// order its rules apply: loopback is accepted first; then global block
/// lists drop; then the admin rule exists only when the port is exposed,
/// limited to the allow list when one is set.
pub(crate) fn admin_reachable(
    ip: std::net::IpAddr,
    allowed: &[ipnet::IpNet],
    expose: bool,
    global_blocks: &[ipnet::IpNet],
) -> bool {
    if ip.is_loopback() {
        return true;
    }
    if global_blocks.iter().any(|n| n.contains(&ip)) || !expose {
        return false;
    }
    allowed.is_empty() || allowed.iter().any(|n| n.contains(&ip))
}

/// Keeps changed lines plus `ctx` lines either side; each skipped run of
/// unchanged lines becomes one `' '` line reading "…".
fn with_context(full: &[DiffLine], ctx: usize) -> Vec<DiffLine> {
    let keep: Vec<bool> = (0..full.len())
        .map(|i| {
            let lo = i.saturating_sub(ctx);
            let hi = (i + ctx + 1).min(full.len());
            full[lo..hi].iter().any(|l| l.op != ' ')
        })
        .collect();
    let mut out = Vec::new();
    let mut skipping = false;
    for (line, k) in full.iter().zip(keep) {
        if k {
            out.push(line.clone());
            skipping = false;
        } else if !skipping {
            out.push(DiffLine {
                op: ' ',
                text: "…".into(),
            });
            skipping = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn firewall_never_applied_is_unhealthy() {
        let c = firewall(&Default::default(), chrono::Utc::now());
        assert!(!c.ok);
    }

    #[test]
    fn firewall_recent_success_is_healthy_and_stale_is_not() {
        let now = chrono::Utc::now();
        let mut s = nftables::FirewallStatus {
            last_attempt_at: Some(now - chrono::Duration::seconds(30)),
            last_applied_at: Some(now - chrono::Duration::seconds(30)),
            ok: true,
            error: None,
            applied_ruleset: Some(Arc::new(String::new())),
        };
        assert!(firewall(&s, now).ok);
        s.last_attempt_at = Some(now - chrono::Duration::minutes(20));
        assert!(!firewall(&s, now).ok);
        s.last_attempt_at = Some(now);
        s.ok = false;
        assert!(!firewall(&s, now).ok);
    }

    #[test]
    fn disk_and_fds_report_on_a_real_system() {
        assert!(disk(Path::new("/tmp/x.db")).detail.contains("free"));
        assert!(file_descriptors().ok);
    }

    #[test]
    fn admin_reachability_follows_the_ruleset_order() {
        let me: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        let net = |s: &str| -> ipnet::IpNet { s.parse().unwrap() };
        // Open, or allow-listed: reachable.
        assert!(admin_reachable(me, &[], true, &[]));
        assert!(admin_reachable(me, &[net("203.0.113.0/24")], true, &[]));
        // A what-if allow list without me locks me out.
        assert!(!admin_reachable(me, &[net("10.9.9.9/32")], true, &[]));
        // Not exposed: only loopback gets in.
        assert!(!admin_reachable(me, &[], false, &[]));
        assert!(admin_reachable(
            "127.0.0.1".parse().unwrap(),
            &[],
            false,
            &[]
        ));
        // A global block wins over the allow list, never over loopback.
        assert!(!admin_reachable(
            me,
            &[net("203.0.113.0/24")],
            true,
            &[net("203.0.113.0/28")]
        ));
        assert!(admin_reachable(
            "::1".parse().unwrap(),
            &[],
            true,
            &[net("::/0")]
        ));
    }

    #[test]
    fn context_collapses_unchanged_runs() {
        let mut full: Vec<DiffLine> = (0..20)
            .map(|i| DiffLine {
                op: ' ',
                text: i.to_string(),
            })
            .collect();
        full[10].op = '+';
        let out = with_context(&full, 2);
        let text: Vec<_> = out.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(text, ["…", "8", "9", "10", "11", "12", "…"]);
    }
}
