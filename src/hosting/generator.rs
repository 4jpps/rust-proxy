//! Pure-text generation for the hosting apply layer, kept free of I/O so it
//! can be unit-tested without a netfilter stack (same split as
//! `nftables::generator`). Only typed values (addresses, port numbers) are
//! ever interpolated into the ruleset -- names, customers and notes never
//! reach nft, so there is nothing to inject through them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use uuid::Uuid;

use super::model::{Allocation, ForwardMode, PortSpec};
use crate::config::Protocol;

pub const TABLE: &str = "rust_proxy_hosting";

/// IPv4 source networks to refuse for hosted addresses: `global` for every
/// hosted VM, `acl` per block list, which a forwarded port can select.
#[derive(Debug, Default, Clone)]
pub struct HostingBlocks {
    pub global: Vec<Ipv4Net>,
    pub acl: HashMap<Uuid, Vec<Ipv4Net>>,
}

fn net_set(nets: &[Ipv4Net]) -> String {
    let items: Vec<String> = nets.iter().map(Ipv4Net::to_string).collect();
    format!("{{ {} }}", items.join(", "))
}

const PRIVATE_NETS: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10";

fn port_set(ports: &[&PortSpec], protocol: Protocol) -> Option<String> {
    let mut ranges: Vec<(u16, u16)> = ports
        .iter()
        .filter(|p| p.protocol == protocol)
        .map(|p| (p.port_start, p.port_end))
        .collect();
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_unstable();
    let items: Vec<String> = ranges
        .into_iter()
        .map(|(s, e)| if s == e { s.to_string() } else { format!("{s}-{e}") })
        .collect();
    Some(format!("{{ {} }}", items.join(", ")))
}

fn ip_set(ips: &[Ipv4Addr]) -> String {
    let items: Vec<String> = ips.iter().map(Ipv4Addr::to_string).collect();
    format!("{{ {} }}", items.join(", "))
}

/// Builds the whole `ip rust_proxy_hosting` table. `allocations` may hold
/// inactive entries; only active ones produce rules. The leading
/// `add`/`delete`/`table` sequence replaces the table atomically, whether or
/// not it already exists.
///
/// - `prerouting`: 1:1 DNAT of the public address (all protocols, or just the
///   listed ports) to the VM.
/// - `postrouting`: SNAT of the VM's egress to its public address, so the
///   address a customer is reached on is also the one they appear from.
///   Traffic to private ranges is left alone.
/// - `input`: anything still addressed to a hosted public address after DNAT
///   was not forwarded, so it would land on this host's own wildcard
///   listeners and rules (80/443, SSH carve-outs, the admin port). Dropped,
///   except ICMP.
/// - `forward`: a hosted VM may not open new connections to private or CGNAT ranges,
///   which keeps customer VMs off the internal networks.
#[cfg(test)]
pub fn generate_ruleset(allocations: &[Allocation]) -> String {
    generate_ruleset_with_served(allocations, &[])
}

/// As [`generate_ruleset`], plus `proxy_served`: `(public ip, tcp port)` pairs
/// that a rust-proxy host is deliberately bound to on a hosted address. Those
/// ports are accepted at `input` ahead of the blanket drop, so the proxy can
/// answer on an address whose other ports still belong to the VM.
#[cfg(test)]
pub fn generate_ruleset_with_served(allocations: &[Allocation], proxy_served: &[(Ipv4Addr, u16)]) -> String {
    generate_ruleset_full(allocations, proxy_served, &HashMap::new(), &HostingBlocks::default())
}

/// As [`generate_ruleset_with_served`], plus `acl_sources`: the IPv4 source
/// networks of each `IpAllow` ACL, keyed by ACL id. A forwarded port whose
/// `acl_ids` is non-empty is DNAT'd only for sources in the union of those
/// ACLs; an unknown ACL or one with no IPv4 entries contributes nothing, so a
/// port restricted to an empty list forwards to no one. Everything not
/// forwarded falls through to the `input` drop below, which is also what keeps
/// this host's own sshd from answering on a hosted address.
pub fn generate_ruleset_full(
    allocations: &[Allocation],
    proxy_served: &[(Ipv4Addr, u16)],
    acl_sources: &HashMap<Uuid, Vec<Ipv4Net>>,
    blocks: &HostingBlocks,
) -> String {
    let mut active: Vec<&Allocation> = allocations.iter().filter(|a| a.is_active()).collect();
    active.sort_by_key(|a| a.public_ip);

    let mut out = String::new();
    let _ = writeln!(out, "add table ip {TABLE}");
    let _ = writeln!(out, "delete table ip {TABLE}");
    let _ = writeln!(out, "table ip {TABLE} {{");

    let _ = writeln!(out, "    chain prerouting {{");
    let _ = writeln!(out, "        type nat hook prerouting priority dstnat; policy accept;");
    for a in &active {
        let (Some(vm), public) = (a.vm_ip, a.public_ip) else { continue };
        match a.forward {
            ForwardMode::All => {
                let _ = writeln!(out, "        ip daddr {public} dnat to {vm}");
            }
            ForwardMode::Ports => {
                let mut groups: BTreeMap<Vec<Uuid>, Vec<&PortSpec>> = BTreeMap::new();
                for p in &a.ports {
                    let mut key = p.acl_ids.clone();
                    key.sort();
                    key.dedup();
                    groups.entry(key).or_default().push(p);
                }
                for (acls, specs) in &groups {
                    let source = if acls.is_empty() {
                        String::new()
                    } else {
                        let mut nets: Vec<Ipv4Net> = acls
                            .iter()
                            .flat_map(|id| acl_sources.get(id).into_iter().flatten().copied())
                            .collect();
                        nets.sort();
                        nets.dedup();
                        if nets.is_empty() {
                            continue;
                        }
                        let items: Vec<String> = nets.iter().map(Ipv4Net::to_string).collect();
                        format!("ip saddr {{ {} }} ", items.join(", "))
                    };
                    let mut blocked: Vec<Ipv4Net> = acls
                        .iter()
                        .flat_map(|id| blocks.acl.get(id).into_iter().flatten().copied())
                        .collect();
                    blocked.sort();
                    blocked.dedup();
                    for (proto, name) in [(Protocol::Tcp, "tcp"), (Protocol::Udp, "udp")] {
                        if let Some(set) = port_set(specs, proto) {
                            if !blocked.is_empty() {
                                let _ = writeln!(
                                    out,
                                    "        ip daddr {public} ip saddr {} {name} dport {set} drop",
                                    net_set(&blocked)
                                );
                            }
                            let _ = writeln!(
                                out,
                                "        ip daddr {public} {source}{name} dport {set} dnat to {vm}"
                            );
                        }
                    }
                }
            }
        }
    }
    let _ = writeln!(out, "    }}");

    let _ = writeln!(out, "    chain postrouting {{");
    let _ = writeln!(out, "        type nat hook postrouting priority srcnat; policy accept;");
    for a in &active {
        if let Some(vm) = a.vm_ip {
            let _ = writeln!(
                out,
                "        ip saddr {vm} ip daddr != {{ {PRIVATE_NETS} }} snat to {}",
                a.public_ip
            );
        }
    }
    let _ = writeln!(out, "    }}");

    let _ = writeln!(out, "    chain input {{");
    let _ = writeln!(out, "        type filter hook input priority -10; policy accept;");
    if !active.is_empty() {
        let publics: Vec<Ipv4Addr> = active.iter().map(|a| a.public_ip).collect();
        let mut served: Vec<&(Ipv4Addr, u16)> = proxy_served.iter().filter(|(ip, _)| publics.contains(ip)).collect();
        served.sort();
        served.dedup();
        for (ip, port) in served {
            let _ = writeln!(out, "        ip daddr {ip} tcp dport {port} accept");
        }
        let _ = writeln!(
            out,
            "        ip daddr {} meta l4proto != icmp drop",
            ip_set(&publics)
        );
    }
    let _ = writeln!(out, "    }}");

    let _ = writeln!(out, "    chain forward {{");
    let _ = writeln!(out, "        type filter hook forward priority -10; policy accept;");
    if !active.is_empty() {
        let vms: Vec<Ipv4Addr> = active.iter().filter_map(|a| a.vm_ip).collect();
        if !blocks.global.is_empty() && !vms.is_empty() {
            let _ = writeln!(
                out,
                "        ip saddr {} ip daddr {} drop",
                net_set(&blocks.global),
                ip_set(&vms)
            );
        }
        let _ = writeln!(
            out,
            "        ip saddr {} ip daddr {{ {PRIVATE_NETS} }} ct state new drop",
            ip_set(&vms)
        );
    }
    let _ = writeln!(out, "    }}");

    let _ = writeln!(out, "}}");
    out
}

/// Which `/32`s to add to / remove from `lo`. Only addresses inside one of
/// the hosting pools are ever considered for removal, so the proxy's own
/// addresses (dedicated IPs, the egress address) are never touched.
pub fn plan_addresses(
    desired: &BTreeSet<Ipv4Addr>,
    current_lo: &BTreeSet<Ipv4Addr>,
    pools: &[Ipv4Net],
) -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>) {
    let add = desired.difference(current_lo).copied().collect();
    let remove = current_lo
        .iter()
        .filter(|ip| !desired.contains(ip) && pools.iter().any(|p| p.contains(*ip)))
        .copied()
        .collect();
    (add, remove)
}

/// Extracts the `/32` IPv4 addresses from `ip -4 -o addr show dev lo`.
pub fn parse_lo_addresses(output: &str) -> BTreeSet<Ipv4Addr> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            while let Some(f) = fields.next() {
                if f == "inet" {
                    let cidr = fields.next()?;
                    let (ip, len) = cidr.split_once('/')?;
                    return (len == "32").then(|| ip.parse().ok()).flatten();
                }
            }
            None
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn alloc(public_ip: &str, vm_ip: Option<&str>, forward: ForwardMode, ports: Vec<PortSpec>) -> Allocation {
        Allocation {
            id: Uuid::new_v4(),
            pool: "standard".into(),
            public_ip: public_ip.parse().unwrap(),
            name: "evil\"; flush ruleset; #".into(),
            customer: "x".into(),
            notes: String::new(),
            vm_ip: vm_ip.map(|s| s.parse().unwrap()),
            vm_id: None,
            forward,
            ports,
            enabled: true,
            created_at: Utc::now(),
        }
    }

    fn spec(protocol: Protocol, s: u16, e: u16) -> PortSpec {
        PortSpec { protocol, port_start: s, port_end: e, acl_ids: vec![] }
    }

    #[test]
    fn empty_input_yields_an_empty_but_valid_table() {
        let out = generate_ruleset(&[]);
        assert!(out.starts_with("add table ip rust_proxy_hosting\ndelete table ip rust_proxy_hosting\n"));
        assert!(!out.contains("dnat"));
        assert!(!out.contains("drop"), "no set means no rule referencing it: {out}");
        assert_eq!(out.matches('{').count(), out.matches('}').count());
    }

    #[test]
    fn full_forward_is_one_to_one_dnat_with_matching_snat() {
        let out = generate_ruleset(&[alloc("204.52.221.226", Some("172.16.63.10"), ForwardMode::All, vec![])]);
        assert!(out.contains("ip daddr 204.52.221.226 dnat to 172.16.63.10\n"));
        assert!(out.contains(
            "ip saddr 172.16.63.10 ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } snat to 204.52.221.226\n"
        ));
        assert!(out.contains("ip daddr { 204.52.221.226 } meta l4proto != icmp drop\n"));
        assert!(out.contains(
            "ip saddr { 172.16.63.10 } ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } ct state new drop\n"
        ));
    }

    #[test]
    fn proxy_served_ports_are_accepted_before_the_blanket_drop() {
        let hosted = alloc("44.30.51.254", Some("100.64.244.254"), ForwardMode::All, vec![]);
        let other = alloc("204.52.221.226", Some("172.16.63.10"), ForwardMode::All, vec![]);
        let served = [
            ("44.30.51.254".parse().unwrap(), 443),
            ("44.30.51.254".parse().unwrap(), 80),
            ("44.30.51.254".parse().unwrap(), 443),
            ("9.9.9.9".parse().unwrap(), 443),
        ];
        let out = generate_ruleset_with_served(&[hosted, other], &served);
        let accept80 = out.find("ip daddr 44.30.51.254 tcp dport 80 accept\n").unwrap();
        let accept443 = out.find("ip daddr 44.30.51.254 tcp dport 443 accept\n").unwrap();
        let drop = out.find("meta l4proto != icmp drop").unwrap();
        assert!(accept80 < accept443 && accept443 < drop);
        assert_eq!(out.matches("tcp dport 443 accept").count(), 1, "duplicates collapse: {out}");
        assert!(!out.contains("9.9.9.9"), "only addresses that are actually hosted: {out}");
        assert!(!out.contains("ip daddr 204.52.221.226 tcp dport"), "unserved hosted IPs stay fully dropped");
    }

    #[test]
    fn port_forward_emits_sorted_per_protocol_sets() {
        let ports = vec![
            spec(Protocol::Tcp, 443, 443),
            spec(Protocol::Tcp, 22, 22),
            spec(Protocol::Udp, 20100, 20200),
            spec(Protocol::Tcp, 8000, 8100),
        ];
        let out = generate_ruleset(&[alloc("204.52.221.226", Some("172.16.63.10"), ForwardMode::Ports, ports)]);
        assert!(out.contains(
            "ip daddr 204.52.221.226 tcp dport { 22, 443, 8000-8100 } dnat to 172.16.63.10\n"
        ));
        assert!(out.contains(
            "ip daddr 204.52.221.226 udp dport { 20100-20200 } dnat to 172.16.63.10\n"
        ));
    }

    #[test]
    fn only_active_allocations_produce_rules() {
        let reserved = alloc("204.52.221.226", None, ForwardMode::All, vec![]);
        let mut disabled = alloc("204.52.221.227", Some("172.16.63.11"), ForwardMode::All, vec![]);
        disabled.enabled = false;
        let active = alloc("204.52.221.228", Some("172.16.63.12"), ForwardMode::All, vec![]);
        let out = generate_ruleset(&[reserved, disabled, active]);
        assert!(!out.contains("204.52.221.226"));
        assert!(!out.contains("204.52.221.227"));
        assert!(!out.contains("172.16.63.11"));
        assert!(out.contains("204.52.221.228"));
    }

    #[test]
    fn free_text_never_reaches_the_ruleset() {
        let out = generate_ruleset(&[alloc("204.52.221.226", Some("172.16.63.10"), ForwardMode::All, vec![])]);
        assert!(!out.contains("flush"));
        assert!(!out.contains("evil"));
    }

    #[test]
    fn multiple_allocations_are_sorted_and_grouped_in_one_set() {
        let out = generate_ruleset(&[
            alloc("204.52.221.228", Some("172.16.63.12"), ForwardMode::All, vec![]),
            alloc("204.52.221.226", Some("172.16.63.10"), ForwardMode::All, vec![]),
        ]);
        let first = out.find("ip daddr 204.52.221.226 dnat").unwrap();
        let second = out.find("ip daddr 204.52.221.228 dnat").unwrap();
        assert!(first < second);
        assert!(out.contains("ip daddr { 204.52.221.226, 204.52.221.228 } meta l4proto != icmp drop"));
    }

    #[test]
    fn global_block_drops_forwarded_traffic_to_hosted_vms() {
        let blocks = HostingBlocks { global: vec!["203.0.113.0/24".parse().unwrap()], acl: HashMap::new() };
        let a = alloc("204.52.221.226", Some("172.16.63.10"), ForwardMode::All, vec![]);
        let out = generate_ruleset_full(&[a], &[], &HashMap::new(), &blocks);
        assert!(out.contains("ip saddr { 203.0.113.0/24 } ip daddr { 172.16.63.10 } drop"), "{out}");
    }

    #[test]
    fn address_plan_adds_missing_and_removes_only_stale_pool_addresses() {
        let pools: Vec<Ipv4Net> = vec!["204.52.221.224/28".parse().unwrap()];
        let ip = |s: &str| -> Ipv4Addr { s.parse().unwrap() };
        let desired: BTreeSet<Ipv4Addr> = [ip("204.52.221.226"), ip("204.52.221.227")].into_iter().collect();
        let current: BTreeSet<Ipv4Addr> = [
            ip("127.0.0.1"),
            ip("204.52.221.227"),
            ip("204.52.221.228"),
            ip("204.52.221.250"),
        ]
        .into_iter()
        .collect();
        let (add, remove) = plan_addresses(&desired, &current, &pools);
        assert_eq!(add, vec![ip("204.52.221.226")]);
        assert_eq!(remove, vec![ip("204.52.221.228")], "the dedicated .250 and 127.0.0.1 must survive");
    }

    #[test]
    fn lo_output_parses_only_slash_32_ipv4() {
        let out = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n\
                   1: lo    inet 204.52.221.249/32 scope global lo\\       valid_lft forever preferred_lft forever\n\
                   1: lo    inet 204.52.221.226/32 scope global lo\\       valid_lft forever preferred_lft forever\n";
        let got = parse_lo_addresses(out);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&"204.52.221.226".parse().unwrap()));
        assert!(!got.contains(&"127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn acl_restricted_port_is_dnat_only_for_acl_sources() {
        let acl = Uuid::new_v4();
        let mut ssh = spec(Protocol::Tcp, 22, 22);
        ssh.acl_ids = vec![acl];
        let open = spec(Protocol::Tcp, 443, 443);
        let a = alloc("44.30.51.254", Some("100.64.244.254"), ForwardMode::Ports, vec![ssh, open]);
        let mut sources = HashMap::new();
        sources.insert(acl, vec!["172.16.0.0/16".parse().unwrap(), "10.1.2.3/32".parse().unwrap()]);
        let out = generate_ruleset_full(&[a], &[], &sources, &HostingBlocks::default());
        assert!(out.contains(
            "ip daddr 44.30.51.254 ip saddr { 10.1.2.3/32, 172.16.0.0/16 } tcp dport { 22 } dnat to 100.64.244.254\n"
        ), "{out}");
        assert!(out.contains("ip daddr 44.30.51.254 tcp dport { 443 } dnat to 100.64.244.254\n"), "{out}");
    }

    #[test]
    fn acl_restricted_port_with_no_resolvable_sources_forwards_nothing() {
        let acl = Uuid::new_v4();
        let mut ssh = spec(Protocol::Tcp, 22, 22);
        ssh.acl_ids = vec![acl];
        let a = alloc("44.30.51.254", Some("100.64.244.254"), ForwardMode::Ports, vec![ssh]);
        for sources in [HashMap::new(), HashMap::from([(acl, vec![])])] {
            let out = generate_ruleset_full(&[a.clone()], &[], &sources, &HostingBlocks::default());
            assert!(!out.contains("dnat"), "fail closed: {out}");
            assert!(out.contains("meta l4proto != icmp drop"), "own sshd stays shut: {out}");
        }
    }
}
