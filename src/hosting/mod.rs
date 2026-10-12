//! Public-address hosting: hands out addresses from routed pools and wires
//! each to a customer VM (1:1 DNAT in, SNAT out). The data model and rules
//! live in `model`, ruleset text in `generator`; this module applies them.
//!
//! Inert by default: with no pools and no allocations the sync loop does
//! nothing at all (no `ip`, no `nft`), so an existing install is unaffected
//! until an operator creates a pool.
//!
//! What a sync does, in order, each step idempotent:
//! 1. add a `/32` on `lo` for every active allocation (a local address beats
//!    the pool's blackhole route, which is what makes the address answer);
//! 2. `ip route replace blackhole <pool>` for each pool, so unallocated
//!    addresses stay silent;
//! 3. load the `ip rust_proxy_hosting` nftables table in one atomic call;
//! 4. remove `/32`s of addresses no longer allocated -- only ever inside a
//!    pool, never the proxy's own or `dedicated_ips` addresses.
//!
//! Needs `CAP_NET_ADMIN` (already granted by the systemd unit). Forwarded
//! traffic must also be admitted by whatever forward policy the host has
//! (e.g. an `ip proxy_router` table with policy drop); this module does not
//! override another table's drop.

pub mod generator;
pub mod model;

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::state::AppState;

const FALLBACK_RESYNC_INTERVAL: Duration = Duration::from_secs(300);

/// Set once anything has been applied, so that emptying the configuration
/// afterwards still clears the table instead of being skipped as "inert".
static EVER_APPLIED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Default)]
pub struct HostingStatus {
    pub last_sync_at: Option<DateTime<Utc>>,
    pub ok: bool,
    pub error: Option<String>,
    pub active_allocations: usize,
    /// True when the last sync found nothing configured and did nothing.
    pub inert: bool,
}

pub async fn run_sync_loop(state: AppState) -> anyhow::Result<()> {
    loop {
        let status = match sync_once(&state).await {
            Ok(status) => status,
            Err(err) => {
                tracing::error!(error = %err, "hosting sync failed");
                HostingStatus {
                    last_sync_at: Some(Utc::now()),
                    ok: false,
                    error: Some(err.to_string()),
                    active_allocations: state
                        .hosting_allocations()
                        .iter()
                        .filter(|a| a.is_active())
                        .count(),
                    inert: false,
                }
            }
        };
        state.set_hosting_status(status);

        tokio::select! {
            _ = state.hosting_changed() => {}
            _ = tokio::time::sleep(FALLBACK_RESYNC_INTERVAL) => {}
        }
    }
}

async fn sync_once(state: &AppState) -> anyhow::Result<HostingStatus> {
    let pools = state.hosting_pools();
    let allocations = state.hosting_allocations();

    if pools.is_empty() && allocations.is_empty() && !EVER_APPLIED.load(Ordering::Relaxed) {
        return Ok(HostingStatus {
            last_sync_at: Some(Utc::now()),
            ok: true,
            error: None,
            active_allocations: 0,
            inert: true,
        });
    }

    let pool_nets: Vec<Ipv4Net> = pools.iter().map(|p| p.cidr).collect();
    let desired: BTreeSet<Ipv4Addr> = allocations
        .iter()
        .filter(|a| a.is_active())
        .map(|a| a.public_ip)
        .collect();

    let current = generator::parse_lo_addresses(&run_capture("ip", &["-4", "-o", "addr", "show", "dev", "lo"]).await?);
    let (add, remove) = generator::plan_addresses(&desired, &current, &pool_nets);

    for ip in &add {
        run_checked("ip", &["addr", "add", &format!("{ip}/32"), "dev", "lo"]).await?;
        tracing::info!(address = %ip, "hosting: address added to lo");
    }
    for net in &pool_nets {
        run_checked("ip", &["route", "replace", "blackhole", &net.to_string()]).await?;
    }
    apply_ruleset(&generator::generate_ruleset(&allocations)).await?;
    EVER_APPLIED.store(true, Ordering::Relaxed);
    for ip in &remove {
        run_checked("ip", &["addr", "del", &format!("{ip}/32"), "dev", "lo"]).await?;
        tracing::info!(address = %ip, "hosting: address removed from lo");
    }

    tracing::info!(
        active = desired.len(),
        pools = pools.len(),
        "hosting ruleset applied"
    );
    Ok(HostingStatus {
        last_sync_at: Some(Utc::now()),
        ok: true,
        error: None,
        active_allocations: desired.len(),
        inert: false,
    })
}

async fn run_capture(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(program).args(args).output().await?;
    if !output.status.success() {
        anyhow::bail!(
            "`{program} {}` exited with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn run_checked(program: &str, args: &[&str]) -> anyhow::Result<()> {
    run_capture(program, args).await.map(|_| ())
}

async fn apply_ruleset(ruleset: &str) -> anyhow::Result<()> {
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
            "nft -f - (hosting) exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
