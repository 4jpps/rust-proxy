//! Pure nftables ruleset generation -- no I/O, no `nft` binary, nothing
//! that needs root. `nftables::apply` is the only thing that actually
//! shells out; keeping generation separate means the rule logic is fully
//! unit-testable in CI without a real Linux firewall.
//!
//! Posture: default-DROP on the `input` chain. Every rule this module
//! emits is an explicit ACCEPT carve-out for one bind_ip/port(s)/protocol
//! that a configured host or port rule actually uses -- nothing else in
//! the /29 is reachable, EXCEPT for a small, fixed set of ports this
//! module always keeps open regardless of configuration (see
//! `write_always_open_rules`): SSH, HTTP, HTTPS, and the admin UI. A
//! default-DROP firewall that can also lock an operator out of SSH, or
//! out of the admin UI needed to fix the firewall itself, is a bricked
//! box waiting to happen -- these are a deliberate safety net, not
//! something a host/port-rule config omission should ever be able to
//! close.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::config::{AdminConfig, PortRule, Protocol, ProxyHost};

pub const TABLE_NAME: &str = "rust_proxy";

pub fn generate_ruleset(hosts: &[ProxyHost], port_rules: &[PortRule], admin: &AdminConfig) -> String {
    let mut out = String::new();

    // `add table` is idempotent (a no-op if it already exists, creates
    // it if not) -- required before `flush table` below, which errors
    // outright if the table doesn't exist yet. Without this, the very
    // first sync ever run on a genuinely fresh host (nothing has ever
    // created `inet rust_proxy`) would fail on its first statement, and
    // `nft -f -` aborts the rest of the script on that first error --
    // meaning the `table { ... }` block that actually creates
    // everything below would never run either, and every subsequent
    // sync would keep failing the exact same way forever. Confirmed via
    // nftables' own documented `flush table` semantics, not assumed.
    let _ = writeln!(out, "add table inet {TABLE_NAME}");
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

    write_always_open_rules(&mut out);
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

/// `ip daddr X` only matches a packet whose *actual* destination
/// address is literally `X` -- for a listener bound to a real, single
/// IP that's exactly right, but 0.0.0.0 (`Ipv4Addr::UNSPECIFIED`) never
/// appears as a real packet's destination on the wire (it means "every
/// interface" to the *bind()* call, not a literal address to match).
/// Emitting `ip daddr 0.0.0.0` would silently produce a rule that can
/// never match anything, firewalling off a listener that's actually
/// live on every real interface -- so this clause is omitted entirely
/// (matching any destination) whenever the bind address is unspecified.
fn daddr_clause(ip: Ipv4Addr) -> String {
    if ip.is_unspecified() {
        String::new()
    } else {
        format!("ip daddr {ip} ")
    }
}

/// SSH, HTTP, and HTTPS are always reachable, unconditionally -- not
/// tied to any host/port-rule configuration existing at all. SSH is a
/// completely separate daemon this project has no visibility into or
/// control over; a fresh install with no port rules yet must never be
/// able to firewall off the very access an operator needs to configure
/// it in the first place. 80/443 are the two ports this whole proxy
/// exists to serve -- a host that hasn't been created yet (or one an
/// operator only half-finished configuring) must not leave the network
/// unable to reach them; per-host rules below add narrower carve-outs
/// on top, but never need to re-open these two.
fn write_always_open_rules(out: &mut String) {
    let _ = writeln!(out, "        # always reachable -- see this module's own doc comment");
    let _ = writeln!(out, "        tcp dport 22 accept");
    let _ = writeln!(out, "        tcp dport 80 accept");
    let _ = writeln!(out, "        tcp dport 443 accept");
    let _ = writeln!(out);
}

fn write_admin_rule(out: &mut String, admin: &AdminConfig) {
    let _ = writeln!(out, "        # admin UI");
    let daddr = daddr_clause(admin.bind_ip);
    if admin.allowed_ips.is_empty() {
        // No explicit allowlist configured -- open to any source, same
        // "reachable out of the box" reasoning as write_always_open_rules
        // above. Matches admin.bind_ip's own default of 0.0.0.0 (see
        // AdminConfig): a fresh install's first-launch setup wizard must
        // actually be reachable from the network without any config.toml
        // edits at all. Set admin.allowed_ips once you know your real
        // management network/IP to narrow this down -- the source-IP
        // restriction below is what actually enforces it, at the
        // firewall layer, not just at the application layer.
        let _ = writeln!(out, "        tcp dport {} {daddr}accept", admin.bind_port);
    } else {
        let sources = admin
            .allowed_ips
            .iter()
            .map(|net| net.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "        tcp dport {} {daddr}ip saddr {{ {} }} accept", admin.bind_port, sources);
    }
    let _ = writeln!(out);
}

fn write_host_rules(out: &mut String, host: &ProxyHost) {
    let _ = writeln!(out, "        # host: {}", host.domain);
    let daddr = daddr_clause(host.bind_ip);
    let _ = writeln!(out, "        tcp dport {} {daddr}accept", host.bind_port);
    if host.force_https || crate::acme::opens_port_80_for_acme(host) {
        // Redundant with write_always_open_rules's unconditional port 80
        // accept above, but kept: this rule's own bind_ip-scoped comment
        // is useful context when reading the generated ruleset, and
        // nftables rule evaluation order means either one matching is
        // sufficient regardless of which is "the" one actually doing the
        // work.
        let _ = writeln!(out, "        tcp dport 80 {daddr}accept");
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
    let daddr = daddr_clause(rule.bind_ip);
    let _ = writeln!(out, "        {proto} dport {port_expr} {daddr}accept");
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
            session_secret: Some("test".into()),
            admin_username: Some("admin".into()),
            admin_password_hash: Some("$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g".into()),
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
            upstream_https: false,
            upstream_tls_verify: true,
            upstream_preserve_host: true,
            websockets: false,
            force_https,
            acme_enabled: true,
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            acl_ids: vec![],
            dns_credential_id: None,
            redirect: None,
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
    fn table_is_created_before_being_flushed() {
        // `flush table` errors outright if the table doesn't exist yet
        // -- `add table` (idempotent) must come first, or a genuinely
        // fresh host (the table has never been created) would fail its
        // very first sync forever, since nft -f - aborts the rest of
        // the script on that first error.
        let out = generate_ruleset(&[], &[], &admin());
        let add_pos = out.find(&format!("add table inet {TABLE_NAME}")).expect("must add the table");
        let flush_pos = out.find(&format!("flush table inet {TABLE_NAME}")).expect("must still flush it too");
        assert!(add_pos < flush_pos, "add table must come before flush table");
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
        // Port 22 is always open unconditionally (see
        // write_always_open_rules), so "dport 22" alone would appear in
        // every ruleset regardless -- assert the specific, bind_ip-scoped
        // rule this disabled config would have produced is absent instead.
        let mut rule = port_rule("10.0.0.3", 22, 22, Protocol::Tcp, "ssh");
        rule.enabled = false;
        let out = generate_ruleset(&[], &[rule], &admin());
        assert!(!out.contains("dport 22 ip daddr 10.0.0.3"));
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
    fn admin_ui_falls_back_to_open_when_no_allowlist_configured() {
        // Deliberately NOT loopback-only -- admin.bind_ip now defaults to
        // 0.0.0.0 specifically so a fresh install's setup wizard is
        // reachable from the network with zero config.toml edits; an
        // unset allowed_ips must match that, not silently firewall the
        // admin port back down to loopback underneath it.
        let mut a = admin();
        a.allowed_ips = vec![];
        let out = generate_ruleset(&[], &[], &a);
        assert!(out.contains(&format!("tcp dport {} ip daddr {} accept", a.bind_port, a.bind_ip)));
    }

    #[test]
    fn admin_rule_omits_the_daddr_clause_when_bind_ip_is_unspecified() {
        let mut a = admin();
        a.bind_ip = Ipv4Addr::UNSPECIFIED;
        a.allowed_ips = vec![];
        let out = generate_ruleset(&[], &[], &a);
        assert!(out.contains(&format!("tcp dport {} accept", a.bind_port)), "got: {out}");
        assert!(!out.contains("ip daddr 0.0.0.0"), "0.0.0.0 never appears as a real packet's destination -- this rule would never match anything");
    }

    #[test]
    fn ssh_http_and_https_are_always_accepted_unconditionally() {
        let out = generate_ruleset(&[], &[], &admin());
        assert!(out.contains("tcp dport 22 accept"));
        assert!(out.contains("tcp dport 80 accept"));
        assert!(out.contains("tcp dport 443 accept"));
    }

    #[test]
    fn ssh_stays_open_even_when_a_real_port_rule_also_claims_port_22() {
        // Proves the always-open rule isn't merely "there happens to be
        // no conflicting config yet" -- it's unconditional even alongside
        // a real, unrelated rule that also targets port 22.
        let rule = port_rule("10.0.0.3", 22, 22, Protocol::Tcp, "some other ssh-like service");
        let out = generate_ruleset(&[], &[rule], &admin());
        assert!(out.contains("tcp dport 22 accept"));
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
