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
    let ruleset = generator::generate_ruleset(&hosts, &port_rules, state.admin());
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
