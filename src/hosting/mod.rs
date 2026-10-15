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
use uuid::Uuid;

use crate::state::AppState;
use model::Allocation;

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
    let hosts = state.hosts();
    let mut proxy_served: Vec<(Ipv4Addr, u16)> = Vec::new();
    for host in hosts.iter().filter(|h| h.enabled) {
        let Some(ip) = host.bind_ip_v4.filter(|ip| !ip.is_unspecified()) else { continue };
        proxy_served.push((ip, host.bind_port));
        if host.force_https || crate::acme::opens_port_80_for_acme(host) {
            proxy_served.push((ip, 80));
        }
    }
    apply_ruleset(&generator::generate_ruleset_with_served(&allocations, &proxy_served)).await?;
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CheckItem {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub id: Uuid,
    pub public_ip: Ipv4Addr,
    pub vm_ip: Option<Ipv4Addr>,
    pub state: &'static str,
    /// True only for an active allocation whose every check passed.
    pub ok: bool,
    pub checks: Vec<CheckItem>,
}

fn item(name: &'static str, ok: bool, detail: impl Into<String>) -> CheckItem {
    CheckItem { name, ok, detail: detail.into() }
}

/// Judges the live host state for one allocation. `lo` is the output of
/// `ip -4 -o addr show dev lo`, `ruleset` that of `nft list table ip
/// rust_proxy_hosting`; either is an error string when it could not be read.
pub fn evaluate_check(
    a: &Allocation,
    lo: Result<&str, &str>,
    ruleset: Result<&str, &str>,
    ping: Option<bool>,
) -> Vec<CheckItem> {
    let Some(vm) = a.vm_ip.filter(|_| a.is_active()) else {
        return vec![item(
            "active",
            false,
            format!("allocation is {}: nothing is forwarded", a.state()),
        )];
    };
    let public = a.public_ip;
    let mut out = vec![item("active", true, "enabled with a VM address")];

    out.push(match lo {
        Ok(text) if generator::parse_lo_addresses(text).contains(&public) => {
            item("address_on_lo", true, format!("{public}/32 is on lo"))
        }
        Ok(_) => item("address_on_lo", false, format!("{public}/32 is not on lo -- sync has not applied it")),
        Err(e) => item("address_on_lo", false, format!("could not read lo: {e}")),
    });

    let line_has = |text: &str, parts: &[String]| {
        text.lines().any(|l| parts.iter().all(|p| l.contains(p.as_str())))
    };
    match ruleset {
        Ok(text) => {
            let dnat = line_has(text, &[format!("ip daddr {public}"), format!("dnat to {vm}")]);
            out.push(item(
                "dnat_rule",
                dnat,
                if dnat { format!("{public} -> {vm}") } else { format!("no DNAT {public} -> {vm} in table {}", generator::TABLE) },
            ));
            let snat = line_has(text, &[format!("ip saddr {vm}"), format!("snat to {public}")]);
            out.push(item(
                "snat_rule",
                snat,
                if snat { format!("{vm} egresses as {public}") } else { format!("no SNAT {vm} -> {public} in table {}", generator::TABLE) },
            ));
        }
        Err(e) => {
            for name in ["dnat_rule", "snat_rule"] {
                out.push(item(name, false, format!("could not read table {}: {e}", generator::TABLE)));
            }
        }
    }

    out.push(match ping {
        Some(true) => item("vm_reachable", true, format!("{vm} answers ping")),
        Some(false) => item("vm_reachable", false, format!("{vm} did not answer ping (VM down, or blocks ICMP)")),
        None => item("vm_reachable", false, "ping could not be run"),
    });
    out
}

async fn ping_once(ip: Ipv4Addr) -> Option<bool> {
    let run = Command::new("ping")
        .args(["-n", "-c", "1", "-W", "2", &ip.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match tokio::time::timeout(Duration::from_secs(5), run).await {
        Ok(Ok(status)) => Some(status.success()),
        _ => None,
    }
}

/// Inspects the live host for one allocation. Read-only: runs `ip`, `nft
/// list` and a single ping, changes nothing.
pub async fn check_allocation(a: &Allocation) -> CheckReport {
    let checks = if a.is_active() {
        let lo = run_capture("ip", &["-4", "-o", "addr", "show", "dev", "lo"]).await;
        let rules = run_capture("nft", &["list", "table", "ip", generator::TABLE]).await;
        let ping = match a.vm_ip {
            Some(vm) => ping_once(vm).await,
            None => None,
        };
        let lo = lo.as_deref().map_err(|e| e.to_string());
        let rules = rules.as_deref().map_err(|e| e.to_string());
        evaluate_check(a, lo.as_deref().map_err(String::as_str), rules.as_deref().map_err(String::as_str), ping)
    } else {
        evaluate_check(a, Ok(""), Ok(""), None)
    };
    CheckReport {
        id: a.id,
        public_ip: a.public_ip,
        vm_ip: a.vm_ip,
        state: a.state(),
        ok: a.is_active() && checks.iter().all(|c| c.ok),
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::ForwardMode;

    fn active() -> Allocation {
        Allocation {
            id: Uuid::new_v4(),
            pool: "standard".into(),
            public_ip: "204.52.221.226".parse().unwrap(),
            name: "web".into(),
            customer: String::new(),
            notes: String::new(),
            vm_ip: Some("172.16.63.2".parse().unwrap()),
            vm_id: None,
            forward: ForwardMode::All,
            ports: vec![],
            enabled: true,
            created_at: Utc::now(),
        }
    }

    const LO: &str = "1: lo    inet 127.0.0.1/8 scope host lo\n1: lo    inet 204.52.221.226/32 scope global lo";

    #[test]
    fn healthy_allocation_passes_every_check() {
        let a = active();
        let rules = generator::generate_ruleset(std::slice::from_ref(&a));
        let checks = evaluate_check(&a, Ok(LO), Ok(&rules), Some(true));
        assert!(checks.iter().all(|c| c.ok), "{checks:?}");
        assert_eq!(checks.len(), 5);
    }

    #[test]
    fn missing_pieces_are_reported_individually() {
        let a = active();
        let checks = evaluate_check(&a, Ok("1: lo inet 127.0.0.1/8"), Ok("table ip x {}"), Some(false));
        let failed: Vec<_> = checks.iter().filter(|c| !c.ok).map(|c| c.name).collect();
        assert_eq!(failed, ["address_on_lo", "dnat_rule", "snat_rule", "vm_reachable"]);
        let checks = evaluate_check(&a, Err("boom"), Err("denied"), None);
        assert_eq!(checks.iter().filter(|c| !c.ok).count(), 5 - 1);
    }

    #[test]
    fn inactive_allocation_is_one_failed_check() {
        let mut a = active();
        a.vm_ip = None;
        let checks = evaluate_check(&a, Ok(""), Ok(""), None);
        assert_eq!(checks.len(), 1);
        assert!(!checks[0].ok);
        assert!(checks[0].detail.contains("reserved"));
    }
}
