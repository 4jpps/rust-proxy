//! Keeps the firewall's mobile-pass sets in step with `PassStore`.
//!
//! A port rule (main table) or hosted port (hosting table) restricted to an
//! IP-allow list with `mobile_pass_firewall` set also accepts sources in that
//! list's Login list's pass sets (`generator::pass_set_name`). The rulesets
//! only declare the sets; this module fills them. Every grant or revoke
//! rewrites each declared set from the live passes in one `nft` transaction,
//! and each element carries the pass's remaining lifetime as its timeout, so
//! a phone that stops checking in drops out of the kernel on its own.
//!
//! One lock covers applying either ruleset and refilling the sets, so a
//! refill never names a set a concurrent apply has just removed (which
//! would fail the whole transaction).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

use crate::proxy::mobile_pass::Pass;
use crate::state::AppState;

/// The pass sets each table declared in its last applied ruleset.
#[derive(Debug, Default)]
pub struct Declared {
    pub main: Vec<String>,
    pub hosting: Vec<String>,
}

static DECLARED: Mutex<Declared> = Mutex::const_new(Declared {
    main: Vec::new(),
    hosting: Vec::new(),
});

/// Held while applying a ruleset that declares pass sets, and while refilling them.
pub async fn lock() -> MutexGuard<'static, Declared> {
    DECLARED.lock().await
}

/// The pass set names a generated ruleset declares.
pub fn declared(ruleset: &str) -> Vec<String> {
    ruleset
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("set "))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter(|name| parse_name(name).is_some())
        .map(str::to_string)
        .collect()
}

/// `(login list, is IPv6)` from a name made by `generator::pass_set_name`.
fn parse_name(name: &str) -> Option<(Uuid, bool)> {
    let (family, id) = name.split_once('_')?;
    let v6 = match family {
        "mp4" => false,
        "mp6" => true,
        _ => return None,
    };
    Some((Uuid::try_parse(id).ok()?, v6))
}

/// The `nft` script that rewrites every declared set from `passes`. Empty
/// when nothing is declared.
pub fn refill_script(declared: &Declared, passes: &[Pass], now: DateTime<Utc>) -> String {
    let mut out = String::new();
    let tables = [
        (
            format!("inet {}", super::generator::TABLE_NAME),
            &declared.main,
        ),
        (
            format!("ip {}", crate::hosting::generator::TABLE),
            &declared.hosting,
        ),
    ];
    for (table, sets) in tables {
        for name in sets {
            let Some((login, v6)) = parse_name(name) else {
                continue;
            };
            let _ = writeln!(out, "flush set {table} {name}");
            // One element per IP: two phones behind the same address share
            // it, for as long as the later of their passes lasts.
            let mut left: BTreeMap<IpAddr, i64> = BTreeMap::new();
            for p in passes
                .iter()
                .filter(|p| p.login_list == login && p.ip.is_ipv6() == v6)
            {
                let ms = (p.expires_at - now).num_milliseconds();
                if ms > 0 {
                    let secs = (ms + 999) / 1000;
                    let e = left.entry(p.ip).or_insert(0);
                    *e = (*e).max(secs);
                }
            }
            if !left.is_empty() {
                let items: Vec<String> = left
                    .iter()
                    .map(|(ip, secs)| format!("{ip} timeout {secs}s"))
                    .collect();
                let _ = writeln!(out, "add element {table} {name} {{ {} }}", items.join(", "));
            }
        }
    }
    out
}

/// Rewrites the declared sets from the live passes. Failures are logged,
/// not returned: the next grant, revoke or ruleset apply tries again, and
/// meanwhile elements already loaded still lapse on their own timeouts.
pub async fn refill(state: &AppState, declared: &Declared) {
    let now = Utc::now();
    let script = refill_script(declared, &state.mobile_passes().list(now), now);
    if script.is_empty() {
        return;
    }
    if let Err(e) = super::run_nft(&["-f", "-"], &script).await {
        tracing::warn!(error = %e, "mobile pass firewall sets not updated");
    }
}

/// Refills the sets after every grant or revoke.
pub async fn run(state: AppState) -> anyhow::Result<()> {
    loop {
        state.mobile_passes().wait_for_change().await;
        let sets = lock().await;
        refill(&state, &sets).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nftables::generator::pass_set_name;

    fn pass(login: Uuid, device: &str, ip: &str, now: DateTime<Utc>, secs: i64) -> Pass {
        Pass {
            login_list: login,
            username: "jeff".into(),
            device: device.into(),
            ip: ip.parse().unwrap(),
            granted_at: now,
            expires_at: now + chrono::Duration::seconds(secs),
        }
    }

    #[test]
    fn set_names_round_trip_and_others_are_ignored() {
        let id = Uuid::new_v4();
        assert_eq!(parse_name(&pass_set_name(id, false)), Some((id, false)));
        assert_eq!(parse_name(&pass_set_name(id, true)), Some((id, true)));
        assert_eq!(parse_name("blocked_v4"), None);
        assert_eq!(parse_name("mp4_nothex"), None);
        let ruleset = format!(
            "table inet rust_proxy {{\n    set {} {{ type ipv4_addr; flags timeout; }}\n    set other {{ type ipv4_addr; }}\n",
            pass_set_name(id, false)
        );
        assert_eq!(declared(&ruleset), vec![pass_set_name(id, false)]);
    }

    #[test]
    fn refill_writes_each_family_and_drops_expired_passes() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let now = Utc::now();
        let sets = Declared {
            main: vec![pass_set_name(a, false), pass_set_name(a, true)],
            hosting: vec![pass_set_name(a, false), pass_set_name(b, false)],
        };
        let passes = vec![
            pass(a, "pixel", "203.0.113.5", now, 90),
            pass(a, "tablet", "203.0.113.5", now, 30),
            pass(a, "laptop", "2001:db8::7", now, 60),
            pass(a, "old", "198.51.100.1", now, -5),
            pass(b, "pixel", "198.51.100.9", now, 45),
        ];
        let out = refill_script(&sets, &passes, now);
        let (a4, a6, b4) = (
            pass_set_name(a, false),
            pass_set_name(a, true),
            pass_set_name(b, false),
        );
        assert!(out.contains(&format!("flush set inet rust_proxy {a4}\nadd element inet rust_proxy {a4} {{ 203.0.113.5 timeout 90s }}\n")), "{out}");
        assert!(
            out.contains(&format!(
                "add element inet rust_proxy {a6} {{ 2001:db8::7 timeout 60s }}"
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "add element ip rust_proxy_hosting {a4} {{ 203.0.113.5 timeout 90s }}"
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "add element ip rust_proxy_hosting {b4} {{ 198.51.100.9 timeout 45s }}"
            )),
            "{out}"
        );
        assert!(
            !out.contains("198.51.100.1"),
            "an expired pass must not be loaded: {out}"
        );
    }

    #[test]
    fn a_set_with_no_live_pass_is_only_flushed() {
        let a = Uuid::new_v4();
        let sets = Declared {
            main: vec![pass_set_name(a, false)],
            hosting: vec![],
        };
        let out = refill_script(&sets, &[], Utc::now());
        assert_eq!(
            out,
            format!("flush set inet rust_proxy {}\n", pass_set_name(a, false))
        );
        assert!(refill_script(&Declared::default(), &[], Utc::now()).is_empty());
    }
}
