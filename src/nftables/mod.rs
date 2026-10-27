//! Dynamic nftables firewall orchestration: default-DROP inbound, with an
//! explicit ACCEPT carve-out per active host/port-rule bind. Pure rule
//! text generation lives in `generator` (fully unit-tested, no `nft`
//! binary needed); this module is the thin, mostly-untested-by-design
//! layer that actually shells out to `nft` and keeps it in sync with
//! live state.

pub mod generator;

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::state::AppState;

/// Periodic fallback resync, in case a change notification is ever missed
/// (process restart racing a write, etc.) -- the `Notify`-driven path in
/// `run_sync_loop` is what makes updates feel real-time; this is just a
/// correctness backstop.
const FALLBACK_RESYNC_INTERVAL: Duration = Duration::from_secs(300);

/// Outcome of the most recent sync of the main table. `ok` stays false
/// until the first apply succeeds, so a daemon whose firewall has never
/// been enforced reports unhealthy rather than "fine".
#[derive(Debug, Clone, Serialize, Default)]
pub struct FirewallStatus {
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_applied_at: Option<DateTime<Utc>>,
    pub ok: bool,
    pub error: Option<String>,
    /// The exact text last handed to `nft -f -` successfully -- what the
    /// preview diffs against. Not serialized into health responses.
    #[serde(skip)]
    pub applied_ruleset: Option<Arc<String>>,
}

/// Checks that `nft` is actually present and invocable before the sync
/// loop starts silently retrying (and re-failing) forever. Called once
/// at startup (see `main.rs`) so a missing/broken nftables setup
/// produces one clear, actionable message right at boot -- not just an
/// `nftables sync failed` error line indistinguishable from any other
/// transient failure, appearing only once `run_sync_loop`'s first
/// iteration gets around to it and repeating every
/// `FALLBACK_RESYNC_INTERVAL` (or on every hosts/port_rules change)
/// after that with no clearer explanation.
///
/// Deliberately non-fatal: this returns a `String` describing the
/// problem for `main.rs` to log loudly, not a hard error that aborts
/// startup. Proxying/ACME/the admin API all work regardless of whether
/// the firewall layer is healthy -- crashing the whole daemon over a
/// missing `nft` binary would be strictly worse for, say, a container
/// or dev environment deliberately relying on an external firewall
/// instead of `CAP_NET_ADMIN`.
pub async fn validate_environment() -> Result<(), String> {
    let output = Command::new("nft")
        .arg("--version")
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "the `nft` binary was not found on PATH -- install the nftables package".to_string()
            } else {
                format!("couldn't run `nft --version`: {e}")
            }
        })?;
    if !output.status.success() {
        return Err(format!(
            "`nft --version` exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

pub async fn run_sync_loop(state: AppState) -> anyhow::Result<()> {
    loop {
        if let Err(err) = sync_once(&state).await {
            tracing::error!(error = %err, "nftables sync failed");
        }

        tokio::select! {
            _ = state.wait_for_change() => {}
            _ = tokio::time::sleep(FALLBACK_RESYNC_INTERVAL) => {}
        }
    }
}

async fn sync_once(state: &AppState) -> anyhow::Result<()> {
    let ruleset = build_ruleset(state).await?;
    let result = apply(&ruleset).await;
    let prev = state.firewall_status();
    let now = Utc::now();
    state.set_firewall_status(match &result {
        Ok(()) => FirewallStatus {
            last_attempt_at: Some(now),
            last_applied_at: Some(now),
            ok: true,
            error: None,
            applied_ruleset: Some(Arc::new(ruleset)),
        },
        Err(err) => FirewallStatus {
            last_attempt_at: Some(now),
            last_applied_at: prev.last_applied_at,
            ok: false,
            error: Some(err.to_string()),
            applied_ruleset: prev.applied_ruleset.clone(),
        },
    });
    result
}

/// What-if inputs for the firewall preview: any field that is set
/// replaces the live value when generating, nothing is saved or applied.
#[derive(Debug, Default, serde::Deserialize)]
pub struct Overrides {
    pub hosts: Option<Vec<crate::config::ProxyHost>>,
    pub port_rules: Option<Vec<crate::config::PortRule>>,
    pub admin_allowed_ips: Option<Vec<ipnet::IpNet>>,
}

/// The full ruleset `sync_once` would apply right now, from live state.
/// Read-only: used by the sync itself and by the firewall preview.
pub async fn build_ruleset(state: &AppState) -> anyhow::Result<String> {
    build_ruleset_with(state, &Overrides::default()).await
}

/// `build_ruleset`, with any of `overrides` swapped in for live state.
pub async fn build_ruleset_with(state: &AppState, overrides: &Overrides) -> anyhow::Result<String> {
    let hosts = match &overrides.hosts {
        Some(h) => Arc::new(h.clone()),
        None => state.hosts(),
    };
    let port_rules = match &overrides.port_rules {
        Some(r) => Arc::new(r.clone()),
        None => state.port_rules(),
    };

    // Hosts are handled entirely at the application layer (see
    // proxy::mod::handle_https_request's IP-over-login combination) --
    // it can show a login/block page, so their firewall rule never needs
    // a source restriction of its own. A raw TCP/UDP port rule has no
    // such application layer to fall back to, so an IP-allow ACL
    // selected on one *is* enforced here, directly at the firewall.
    // Only AclKind::IpAllow contributes here (IpBlock lists are handled
    // separately below); a Login-kind list selected on a port rule is
    // silently ignored (see PortRule::acl_ids' doc comment).
    let mut rule_allow_ips = std::collections::HashMap::new();
    for rule in port_rules
        .iter()
        .filter(|r| r.enabled && !r.acl_ids.is_empty())
    {
        let resolved = crate::db::resolve_acl_ids(state.db(), &rule.acl_ids).await?;
        if resolved.has_ip_allow_acl {
            rule_allow_ips.insert(rule.id, resolved.allow_ips);
        }
    }

    // IP/ASN block lists: global ones drop everything, and any selected on a
    // port rule drop just that rule's traffic. This is what covers raw
    // TCP/UDP passthrough and firewall-only rules, which have no
    // application layer to refuse a request.
    let index = state.block_index();
    let mut blocks = generator::NftBlocks {
        global: index.global_nets().to_vec(),
        rule: std::collections::HashMap::new(),
    };
    for rule in port_rules
        .iter()
        .filter(|r| r.enabled && !r.acl_ids.is_empty())
    {
        let nets = index.nets_for(&rule.acl_ids);
        if !nets.is_empty() {
            blocks.rule.insert(rule.id, nets);
        }
    }

    let mut admin = state.admin().clone();
    admin.allowed_ips = overrides
        .admin_allowed_ips
        .clone()
        .unwrap_or_else(|| state.admin_allowed_ips());
    let ruleset = generator::generate_ruleset(
        &hosts,
        &port_rules,
        &admin,
        state.expose_admin_port(),
        &rule_allow_ips,
        &state.network().dedicated_ips,
        &state.network().dhcp_interfaces,
        &blocks,
    );
    Ok(ruleset)
}

/// Asks `nft` to parse and validate a ruleset without loading it
/// (`nft -c`). Used by `rust-proxy check` before a restart.
pub async fn check(ruleset: &str) -> anyhow::Result<()> {
    run_nft(&["-c", "-f", "-"], ruleset).await
}

/// Applies a ruleset by piping it into `nft -f -`. Requires `CAP_NET_ADMIN`
/// (see the systemd unit) -- not exercised in unit tests, since that needs
/// a real Linux netfilter stack.
async fn apply(ruleset: &str) -> anyhow::Result<()> {
    run_nft(&["-f", "-"], ruleset).await?;
    tracing::info!("nftables ruleset applied");
    Ok(())
}

async fn run_nft(args: &[&str], ruleset: &str) -> anyhow::Result<()> {
    let mut child = Command::new("nft")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("the `nft` binary was not found on PATH -- install the nftables package")
            } else {
                anyhow::anyhow!("couldn't run `nft`: {e}")
            }
        })?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(ruleset.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        anyhow::bail!(
            "nft {} exited with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// One line of a ruleset diff: `' '` unchanged, `'-'` only in the old
/// text, `'+'` only in the new.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffLine {
    pub op: char,
    pub text: String,
}

/// Line diff (longest common subsequence). Rulesets are a few hundred
/// lines, so the quadratic table is small.
pub fn diff_lines(old: &str, new: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let mut lcs = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let line = |op, text: &str| DiffLine {
        op,
        text: text.to_string(),
    };
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            out.push(line(' ', a[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(line('-', a[i]));
            i += 1;
        } else {
            out.push(line('+', b[j]));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|t| line('-', t)));
    out.extend(b[j..].iter().map(|t| line('+', t)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops(d: &[DiffLine]) -> String {
        d.iter()
            .map(|l| format!("{}{}", l.op, l.text))
            .collect::<Vec<_>>()
            .join("|")
    }

    #[test]
    fn identical_rulesets_have_no_changes() {
        let d = diff_lines("a\nb\n", "a\nb\n");
        assert!(d.iter().all(|l| l.op == ' '));
    }

    #[test]
    fn added_and_removed_lines_are_marked() {
        let d = diff_lines("a\nb\nc", "a\nc\nd");
        assert_eq!(ops(&d), " a|-b| c|+d");
    }

    #[test]
    fn diff_against_nothing_is_all_additions() {
        let d = diff_lines("", "x\ny");
        assert_eq!(ops(&d), "+x|+y");
    }
}
