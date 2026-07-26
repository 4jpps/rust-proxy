//! Pure nftables ruleset generation -- no I/O, no `nft` binary, nothing
//! that needs root. `nftables::apply` is the only thing that actually
//! shells out; keeping generation separate means the rule logic is fully
//! unit-testable in CI without a real Linux firewall.
//!
//! Posture: default-DROP on the `input` chain. Every rule this module
//! emits is an explicit ACCEPT carve-out for one bind_ip/port(s)/protocol
//! that a configured host or port rule actually uses -- nothing else in
//! the /29 is reachable.

use std::fmt::Write as _;

use crate::config::{AdminConfig, PortRule, Protocol, ProxyHost};

pub const TABLE_NAME: &str = "rust_proxy";

pub fn generate_ruleset(hosts: &[ProxyHost], port_rules: &[PortRule], admin: &AdminConfig) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "flush table inet {TABLE_NAME}");
    let _ = writeln!(out, "table inet {TABLE_NAME} {{");
    let _ = writeln!(out, "    chain inbound {{");
    let _ = writeln!(out, "        type filter hook input priority 0; policy drop;");
    let _ = writeln!(out);
    let _ = writeln!(out, "        ct state established,related accept");
    let _ = writeln!(out, "        iif \"lo\" accept");
    let _ = writeln!(
        out,
        "        icmp type {{ echo-request, destination-unreachable, time-exceeded }} accept"
    );
    let _ = writeln!(out);

    write_admin_rule(&mut out, admin);

    for host in hosts.iter().filter(|h| h.enabled) {
        write_host_rules(&mut out, host);
    }

    for rule in port_rules.iter().filter(|r| r.enabled) {
        write_port_rule(&mut out, rule);
    }

    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}");
    out
}

fn write_admin_rule(out: &mut String, admin: &AdminConfig) {
    let _ = writeln!(out, "        # admin UI");
    if admin.allowed_ips.is_empty() {
        // No explicit allowlist configured -- fail safe to loopback-only
        // rather than leaving the admin UI reachable from the whole /29.
        let _ = writeln!(
            out,
            "        tcp dport {} ip daddr {} iif \"lo\" accept",
            admin.bind_port, admin.bind_ip
        );
    } else {
        let sources = admin
            .allowed_ips
            .iter()
            .map(|net| net.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "        tcp dport {} ip daddr {} ip saddr {{ {} }} accept",
            admin.bind_port, admin.bind_ip, sources
        );
    }
    let _ = writeln!(out);
}

fn write_host_rules(out: &mut String, host: &ProxyHost) {
    let _ = writeln!(out, "        # host: {}", host.domain);
    let _ = writeln!(
        out,
        "        tcp dport {} ip daddr {} accept",
        host.bind_port, host.bind_ip
    );
    if host.force_https || crate::acme::opens_port_80_for_acme(host) {
        // The force_https redirect listener and/or an http-01 challenge
        // listener (see `acme::opens_port_80_for_acme`) both need port
        // 80 open.
        let _ = writeln!(out, "        tcp dport 80 ip daddr {} accept", host.bind_ip);
    }
    let _ = writeln!(out);
}

fn write_port_rule(out: &mut String, rule: &PortRule) {
    let proto = match rule.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    let port_expr = if rule.is_range() {
        format!("{}-{}", rule.port_start, rule.port_end)
    } else {
        rule.port_start.to_string()
    };
    if !rule.description.is_empty() {
        let _ = writeln!(out, "        # port rule: {}", rule.description);
    }
    let _ = writeln!(
        out,
        "        {proto} dport {port_expr} ip daddr {} accept",
        rule.bind_ip
    );
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn admin() -> AdminConfig {
        AdminConfig {
            bind_ip: "10.0.0.1".parse().unwrap(),
            bind_port: 8080,
            allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
            session_secret: "test".into(),
            admin_username: "admin".into(),
            admin_password_hash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g".into(),
            db_path: std::path::PathBuf::from(":memory:"),
        }
    }

    fn host(domain: &str, bind_ip: &str, port: u16, force_https: bool) -> ProxyHost {
        ProxyHost {
            id: Uuid::new_v4(),
            domain: domain.into(),
            bind_ip: bind_ip.parse().unwrap(),
            bind_port: port,
            upstream: "127.0.0.1:8000".into(),
            websockets: false,
            force_https,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            access_allow_ips: vec![],
            access_login: None,
            enabled: true,
        }
    }

    fn port_rule(bind_ip: &str, start: u16, end: u16, proto: Protocol, desc: &str) -> PortRule {
        PortRule {
            id: Uuid::new_v4(),
            bind_ip: bind_ip.parse().unwrap(),
            port_start: start,
            port_end: end,
            protocol: proto,
            description: desc.into(),
            passthrough_target: None,
            enabled: true,
        }
    }

    #[test]
    fn default_policy_is_drop() {
        let out = generate_ruleset(&[], &[], &admin());
        assert!(out.contains("policy drop;"));
    }

    #[test]
    fn single_port_rule_emits_bare_port_not_a_range() {
        let rule = port_rule("10.0.0.3", 22, 22, Protocol::Tcp, "ssh");
        let out = generate_ruleset(&[], &[rule], &admin());
        assert!(out.contains("tcp dport 22 ip daddr 10.0.0.3 accept"));
        assert!(!out.contains("22-22"));
    }

    #[test]
    fn port_range_rule_emits_dash_syntax() {
        let rule = port_rule("10.0.0.4", 21115, 21119, Protocol::Tcp, "rustdesk tcp");
        let out = generate_ruleset(&[], &[rule], &admin());
        assert!(out.contains("tcp dport 21115-21119 ip daddr 10.0.0.4 accept"));
    }

    #[test]
    fn udp_and_tcp_rules_use_distinct_protocol_keywords() {
        let tcp_rule = port_rule("10.0.0.4", 21115, 21119, Protocol::Tcp, "rustdesk tcp");
        let udp_rule = port_rule("10.0.0.4", 21116, 21116, Protocol::Udp, "rustdesk udp");
        let out = generate_ruleset(&[], &[tcp_rule, udp_rule], &admin());
        assert!(out.contains("tcp dport 21115-21119 ip daddr 10.0.0.4 accept"));
        assert!(out.contains("udp dport 21116 ip daddr 10.0.0.4 accept"));
    }

    #[test]
    fn rule_targets_only_its_own_bind_ip() {
        let a = port_rule("10.0.0.3", 22, 22, Protocol::Tcp, "ssh");
        let b = port_rule("10.0.0.4", 21116, 21116, Protocol::Udp, "rustdesk udp");
        let out = generate_ruleset(&[], &[a, b], &admin());
        // 10.0.0.5 was never assigned anything -- must not appear at all.
        assert!(!out.contains("10.0.0.5"));
        assert!(out.contains("ip daddr 10.0.0.3"));
        assert!(out.contains("ip daddr 10.0.0.4"));
    }

    #[test]
    fn disabled_port_rule_is_not_emitted() {
        let mut rule = port_rule("10.0.0.3", 22, 22, Protocol::Tcp, "ssh");
        rule.enabled = false;
        let out = generate_ruleset(&[], &[rule], &admin());
        assert!(!out.contains("dport 22"));
    }

    #[test]
    fn disabled_host_is_not_emitted() {
        let mut h = host("example.com", "10.0.0.2", 443, false);
        h.enabled = false;
        let out = generate_ruleset(&[h], &[], &admin());
        assert!(!out.contains("example.com"));
        assert!(!out.contains("10.0.0.2"));
    }

    #[test]
    fn host_with_force_https_also_opens_port_80() {
        let h = host("example.com", "10.0.0.2", 443, true);
        let out = generate_ruleset(&[h], &[], &admin());
        assert!(out.contains("tcp dport 443 ip daddr 10.0.0.2 accept"));
        assert!(out.contains("tcp dport 80 ip daddr 10.0.0.2 accept"));
    }

    #[test]
    fn host_without_force_https_does_not_open_port_80() {
        let h = host("example.com", "10.0.0.2", 443, false);
        let out = generate_ruleset(&[h], &[], &admin());
        assert!(out.contains("tcp dport 443 ip daddr 10.0.0.2 accept"));
        assert!(!out.contains("tcp dport 80 ip daddr 10.0.0.2 accept"));
    }

    #[test]
    fn host_with_http01_challenge_type_opens_port_80_without_force_https() {
        let mut h = host("example.com", "10.0.0.2", 443, false);
        h.acme_challenge_type = crate::config::AcmeChallengeType::Http01;
        let out = generate_ruleset(&[h], &[], &admin());
        assert!(out.contains("tcp dport 80 ip daddr 10.0.0.2 accept"));
    }

    #[test]
    fn admin_ui_restricted_to_allowed_source_ips() {
        let out = generate_ruleset(&[], &[], &admin());
        assert!(out.contains("tcp dport 8080 ip daddr 10.0.0.1 ip saddr { 10.0.0.1/32 } accept"));
    }

    #[test]
    fn admin_ui_falls_back_to_loopback_only_when_no_allowlist_configured() {
        let mut a = admin();
        a.allowed_ips = vec![];
        let out = generate_ruleset(&[], &[], &a);
        assert!(out.contains("iif \"lo\" accept") && out.contains(&format!("dport {}", a.bind_port)));
    }

    #[test]
    fn unassigned_ips_in_the_29_never_appear_in_output() {
        let h = host("example.com", "10.0.0.2", 443, false);
        let rule = port_rule("10.0.0.4", 21115, 21119, Protocol::Tcp, "rustdesk");
        let out = generate_ruleset(&[h], &[rule], &admin());
        for unused in ["10.0.0.5", "10.0.0.6"] {
            assert!(!out.contains(unused), "unassigned ip {unused} leaked into ruleset");
        }
    }
}
