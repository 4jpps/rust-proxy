//! Dynamic nftables firewall orchestration: default-DROP inbound, with an
//! explicit ACCEPT carve-out per active host/port-rule bind. Pure rule
//! text generation lives in `generator` (fully unit-tested, no `nft`
//! binary needed); this module is the thin, mostly-untested-by-design
//! layer that actually shells out to `nft` and keeps it in sync with
//! live state.

pub mod generator;

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::state::AppState;

/// Periodic fallback resync, in case a change notification is ever missed
/// (process restart racing a write, etc.) -- the `Notify`-driven path in
/// `run_sync_loop` is what makes updates feel real-time; this is just a
/// correctness backstop.
const FALLBACK_RESYNC_INTERVAL: Duration = Duration::from_secs(300);

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
    let hosts = state.hosts();
    let port_rules = state.port_rules();

    // Hosts are handled entirely at the application layer (see
    // proxy::mod::handle_https_request's IP-over-login combination) --
    // it can show a login/block page, so their firewall rule never needs
    // a source restriction of its own. A raw TCP/UDP port rule has no
    // such application layer to fall back to, so an IP-allow ACL
    // selected on one *is* enforced here, directly at the firewall.
    // Only AclKind::IpAllow contributes; a Login-kind list selected on a
    // port rule is silently ignored (see PortRule::acl_ids' doc comment).
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

    let mut admin = state.admin().clone();
    admin.allowed_ips = state.admin_allowed_ips();
    let ruleset = generator::generate_ruleset(
        &hosts,
        &port_rules,
        &admin,
        state.expose_admin_port(),
        &rule_allow_ips,
        &state.network().dedicated_ips,
        &state.network().dhcp_interfaces,
    );
    apply(&ruleset).await
}

/// Applies a ruleset by piping it into `nft -f -`. Requires `CAP_NET_ADMIN`
/// (see the systemd unit) -- not exercised in unit tests, since that needs
/// a real Linux netfilter stack.
async fn apply(ruleset: &str) -> anyhow::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(ruleset.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        anyhow::bail!(
            "nft -f - exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    tracing::info!("nftables ruleset applied");
    Ok(())
}
