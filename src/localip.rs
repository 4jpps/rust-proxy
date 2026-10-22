//! Enumerates this host's actual configured IPv4/IPv6 addresses via the
//! `ip` (iproute2) binary's `-json` output -- used only to populate the
//! admin UI's bind_ip dropdowns with real, pickable addresses instead of
//! requiring free-text entry. Best-effort: any failure (missing binary,
//! unparseable output, no addresses at all) just yields an empty list --
//! the UI always offers the unspecified address (0.0.0.0/::) and "None"
//! regardless, so a failure here narrows the picker, it never blocks
//! creating a host.

use std::net::IpAddr;
use std::process::Command;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LocalIp {
    pub address: IpAddr,
    pub interface: String,
}

pub fn list_local_ips() -> Vec<LocalIp> {
    let output = match Command::new("ip").args(["-json", "addr", "show"]).output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output) else {
        return Vec::new();
    };
    let Some(interfaces) = json.as_array() else {
        return Vec::new();
    };

    let mut ips = Vec::new();
    for iface in interfaces {
        let name = iface
            .get("ifname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let Some(addrs) = iface.get("addr_info").and_then(|v| v.as_array()) else {
            continue;
        };
        for addr_info in addrs {
            let Some(local) = addr_info.get("local").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok(address) = local.parse::<IpAddr>() else {
                continue;
            };
            // Skip link-local IPv6 (fe80::/10) -- not usable as a bind
            // address without an explicit scope id, which this UI has no
            // way to collect.
            if let IpAddr::V6(v6) = address
                && (v6.segments()[0] & 0xffc0) == 0xfe80
            {
                continue;
            }
            ips.push(LocalIp {
                address,
                interface: name.clone(),
            });
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not much to unit-test about a real `ip` binary invocation on
    /// arbitrary CI hosts -- this just proves the function never panics
    /// and always returns loopback at minimum on any real Linux box,
    /// which every dev/CI environment this runs in has.
    #[test]
    fn list_local_ips_includes_loopback_on_a_real_linux_host() {
        let ips = list_local_ips();
        assert!(
            ips.iter().any(|ip| ip.address.is_loopback()),
            "expected at least loopback among: {ips:?}"
        );
    }

    #[test]
    fn list_local_ips_never_returns_a_link_local_ipv6_address() {
        let ips = list_local_ips();
        assert!(!ips.iter().any(
            |ip| matches!(ip.address, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80)
        ));
    }
}
