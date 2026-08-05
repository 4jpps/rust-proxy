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

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;

use ipnet::IpNet;
use uuid::Uuid;

use crate::config::{host_bind_ips, port_rule_bind_ips, AdminConfig, PortRule, Protocol, ProxyHost};

pub const TABLE_NAME: &str = "rust_proxy";

/// `expose_admin_port` is the already-resolved effective value (config.toml's
/// `AdminConfig.expose_admin_port` if set, else the DB-backed fallback --
/// see `state::AppState::expose_admin_port`), passed in explicitly rather
/// than read off `admin` directly since resolving that precedence needs
/// `AppState`, which this module deliberately has no dependency on (pure
/// generation, no I/O -- see this module's own doc comment).
///
/// `rule_allow_ips` maps a port rule's id to the CIDRs its firewall
/// entry should be restricted to -- present only when that rule has an
/// `AclKind::IpAllow` ACL selected (see `PortRule::acl_ids`, and
/// `nftables::sync_once`, which resolves this from the DB before calling
/// here). Hosts never appear in this map -- a `ProxyHost`'s own
/// `acl_ids` is enforced entirely at the application layer (see
/// `proxy::mod::handle_https_request`), which can show a login/block
/// page; a raw TCP/UDP port rule has no such layer to fall back to, so
/// its ACL is enforced directly at the firewall instead. A rule absent
/// from this map gets no source restriction at all, same as before this
/// map existed.
pub fn generate_ruleset(hosts: &[ProxyHost], port_rules: &[PortRule], admin: &AdminConfig, expose_admin_port: bool, rule_allow_ips: &HashMap<Uuid, Vec<IpNet>>) -> String {
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
    write_admin_rule(&mut out, admin, expose_admin_port);

    for host in hosts.iter().filter(|h| h.enabled) {
        write_host_rules(&mut out, host);
    }

    for rule in port_rules.iter().filter(|r| r.enabled) {
        write_port_rule(&mut out, rule, rule_allow_ips.get(&rule.id));
    }

    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}");
    out
}

/// `ip daddr X`/`ip6 daddr X` only matches a packet whose *actual*
/// destination address is literally `X` -- for a listener bound to a
/// real, single IP that's exactly right, but an unspecified address
/// (`0.0.0.0`/`::`) never appears as a real packet's destination on the
/// wire (it means "every interface" to the *bind()* call, not a literal
/// address to match). Emitting `ip daddr 0.0.0.0` would silently produce
/// a rule that can never match anything, firewalling off a listener
/// that's actually live on every real interface -- so this clause is
/// omitted entirely (matching any destination) whenever the bind address
/// is unspecified. `ip`/`ip6` is chosen by `ip`'s own family -- nftables
/// requires the matching keyword for each address family, they aren't
/// interchangeable.
fn daddr_clause(ip: IpAddr) -> String {
    if ip.is_unspecified() {
        String::new()
    } else if ip.is_ipv4() {
        format!("ip daddr {ip} ")
    } else {
        format!("ip6 daddr {ip} ")
    }
}

/// `ip saddr { ... }`/`ip6 saddr { ... }` for whichever of `allowed`
/// matches `ip`'s family -- nftables rejects mixing v4 and v6 addresses
/// in one `saddr` set, and a rule scoped to a v4 `daddr` only ever needs
/// v4 sources checked against it anyway (a v6 client could never reach a
/// v4-only bind in the first place). Returns `None` when there are no
/// allowed sources of the matching family, so the caller can fall back
/// to its own "no restriction" rule for that family.
fn saddr_clause(ip: IpAddr, allowed: &[IpNet]) -> Option<String> {
    let sources: Vec<String> = allowed.iter().filter(|net| net.addr().is_ipv4() == ip.is_ipv4()).map(|net| net.to_string()).collect();
    if sources.is_empty() {
        None
    } else {
        let keyword = if ip.is_ipv4() { "ip" } else { "ip6" };
        Some(format!("{keyword} saddr {{ {} }} ", sources.join(", ")))
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

fn admin_bind_ips(admin: &AdminConfig) -> Vec<IpAddr> {
    let mut ips = Vec::with_capacity(2);
    if let Some(v4) = admin.bind_ip_v4 {
        ips.push(IpAddr::V4(v4));
    }
    if let Some(v6) = admin.bind_ip_v6 {
        ips.push(IpAddr::V6(v6));
    }
    ips
}

fn write_admin_rule(out: &mut String, admin: &AdminConfig, expose_admin_port: bool) {
    if !expose_admin_port {
        // Deliberately no accept rule at all -- default-DROP then keeps
        // the admin port unreachable from the network entirely (only
        // `iif "lo" accept`, already unconditional above, can still
        // reach it). See `AdminConfig::expose_admin_port`'s doc comment.
        let _ = writeln!(out, "        # admin UI -- not exposed via the firewall (expose_admin_port = false); reachable via loopback only");
        let _ = writeln!(out);
        return;
    }
    let _ = writeln!(out, "        # admin UI");
    for bind_ip in admin_bind_ips(admin) {
        let daddr = daddr_clause(bind_ip);
        if admin.allowed_ips.is_empty() {
            // No explicit allowlist configured -- open to any source,
            // same "reachable out of the box" reasoning as
            // write_always_open_rules above. Matches the admin bind
            // fields' own default of unspecified (see AdminConfig): a
            // fresh install's first-launch setup wizard must actually be
            // reachable from the network without any config.toml edits
            // at all. Set admin.allowed_ips once you know your real
            // management network/IP to narrow this down -- the
            // source-IP restriction below is what actually enforces it,
            // at the firewall layer, not just at the application layer.
            let _ = writeln!(out, "        tcp dport {} {daddr}accept", admin.bind_port);
        } else if let Some(saddr) = saddr_clause(bind_ip, &admin.allowed_ips) {
            let _ = writeln!(out, "        tcp dport {} {daddr}{saddr}accept", admin.bind_port);
        }
        // An allowlist was configured but has no entries of this bind's
        // family -- deliberately emit no accept rule for it at all
        // (default-DROP then blocks it), rather than falling back to
        // "open": an operator who configured a v4-only allowlist almost
        // certainly didn't mean "and leave v6 wide open by omission."
    }
    let _ = writeln!(out);
}

/// `ProxyHost.acl_ids` is deliberately never consulted here -- a host's
/// access control is enforced entirely at the application layer (see
/// `proxy::mod::handle_https_request`), which can show a login/block
/// page and combines IP-allow/login ACLs by OR ("IP over login").
/// Restricting the firewall too would block the login fallback before a
/// request ever reached the app. See `write_port_rule` for the one place
/// an ACL *is* enforced at the firewall layer (a raw port rule has no
/// application layer to fall back to).
fn write_host_rules(out: &mut String, host: &ProxyHost) {
    let _ = writeln!(out, "        # host: {}", host.domain);
    for bind_ip in host_bind_ips(host) {
        let daddr = daddr_clause(bind_ip);
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
    }
    let _ = writeln!(out);
}

fn write_port_rule(out: &mut String, rule: &PortRule, allow_ips: Option<&Vec<IpNet>>) {
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
    for bind_ip in port_rule_bind_ips(rule) {
        let daddr = daddr_clause(bind_ip);
        match allow_ips {
            Some(allow) => {
                if let Some(saddr) = saddr_clause(bind_ip, allow) {
                    let _ = writeln!(out, "        {proto} dport {port_expr} {daddr}{saddr}accept");
                }
                // else: this rule's IP-allow ACL has no entries of this
                // bind's family -- deliberately no accept rule for it
                // (default-DROP blocks it), same reasoning as the admin
                // rule's identical case.
            }
            None => {
                let _ = writeln!(out, "        {proto} dport {port_expr} {daddr}accept");
            }
        }
    }
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn admin() -> AdminConfig {
        AdminConfig {
            bind_ip_v4: Some("10.0.0.1".parse().unwrap()),
            bind_ip_v6: None,
            bind_port: 8080,
            allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
            expose_admin_port: None,
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
            bind_ip_v4: Some(bind_ip.parse().unwrap()),
            bind_ip_v6: None,
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
            path_rewrite: None,
            static_root: None,
            enabled: true,
        }
    }

    fn port_rule(bind_ip: &str, start: u16, end: u16, proto: Protocol, desc: &str) -> PortRule {
        PortRule {
            id: Uuid::new_v4(),
            bind_ip_v4: Some(bind_ip.parse().unwrap()),
            bind_ip_v6: None,
            port_start: start,
            port_end: end,
            protocol: proto,
            description: desc.into(),
            passthrough_target: None,
            acl_ids: vec![],
            enabled: true,
        }
    }

    #[test]
    fn default_policy_is_drop() {
        let out = generate_ruleset(&[], &[], &admin(), true, &HashMap::new());
        assert!(out.contains("policy drop;"));
    }

    #[test]
    fn table_is_created_before_being_flushed() {
        // `flush table` errors outright if the table doesn't exist yet
        // -- `add table` (idempotent) must come first, or a genuinely
        // fresh host (the table has never been created) would fail its
        // very first sync forever, since nft -f - aborts the rest of
        // the script on that first error.
        let out = generate_ruleset(&[], &[], &admin(), true, &HashMap::new());
        let add_pos = out.find(&format!("add table inet {TABLE_NAME}")).expect("must add the table");
        let flush_pos = out.find(&format!("flush table inet {TABLE_NAME}")).expect("must still flush it too");
        assert!(add_pos < flush_pos, "add table must come before flush table");
    }

    #[test]
    fn single_port_rule_emits_bare_port_not_a_range() {
        let rule = port_rule("10.0.0.3", 22, 22, Protocol::Tcp, "ssh");
        let out = generate_ruleset(&[], &[rule], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 22 ip daddr 10.0.0.3 accept"));
        assert!(!out.contains("22-22"));
    }

    #[test]
    fn port_range_rule_emits_dash_syntax() {
        let rule = port_rule("10.0.0.4", 21115, 21119, Protocol::Tcp, "rustdesk tcp");
        let out = generate_ruleset(&[], &[rule], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 21115-21119 ip daddr 10.0.0.4 accept"));
    }

    #[test]
    fn udp_and_tcp_rules_use_distinct_protocol_keywords() {
        let tcp_rule = port_rule("10.0.0.4", 21115, 21119, Protocol::Tcp, "rustdesk tcp");
        let udp_rule = port_rule("10.0.0.4", 21116, 21116, Protocol::Udp, "rustdesk udp");
        let out = generate_ruleset(&[], &[tcp_rule, udp_rule], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 21115-21119 ip daddr 10.0.0.4 accept"));
        assert!(out.contains("udp dport 21116 ip daddr 10.0.0.4 accept"));
    }

    #[test]
    fn rule_targets_only_its_own_bind_ip() {
        let a = port_rule("10.0.0.3", 22, 22, Protocol::Tcp, "ssh");
        let b = port_rule("10.0.0.4", 21116, 21116, Protocol::Udp, "rustdesk udp");
        let out = generate_ruleset(&[], &[a, b], &admin(), true, &HashMap::new());
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
        let out = generate_ruleset(&[], &[rule], &admin(), true, &HashMap::new());
        assert!(!out.contains("dport 22 ip daddr 10.0.0.3"));
    }

    #[test]
    fn disabled_host_is_not_emitted() {
        let mut h = host("example.com", "10.0.0.2", 443, false);
        h.enabled = false;
        let out = generate_ruleset(&[h], &[], &admin(), true, &HashMap::new());
        assert!(!out.contains("example.com"));
        assert!(!out.contains("10.0.0.2"));
    }

    #[test]
    fn host_with_force_https_also_opens_port_80() {
        let h = host("example.com", "10.0.0.2", 443, true);
        let out = generate_ruleset(&[h], &[], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 443 ip daddr 10.0.0.2 accept"));
        assert!(out.contains("tcp dport 80 ip daddr 10.0.0.2 accept"));
    }

    #[test]
    fn host_without_force_https_does_not_open_port_80() {
        let h = host("example.com", "10.0.0.2", 443, false);
        let out = generate_ruleset(&[h], &[], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 443 ip daddr 10.0.0.2 accept"));
        assert!(!out.contains("tcp dport 80 ip daddr 10.0.0.2 accept"));
    }

    #[test]
    fn host_with_http01_challenge_type_opens_port_80_without_force_https() {
        let mut h = host("example.com", "10.0.0.2", 443, false);
        h.acme_challenge_type = crate::config::AcmeChallengeType::Http01;
        let out = generate_ruleset(&[h], &[], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 80 ip daddr 10.0.0.2 accept"));
    }

    #[test]
    fn admin_ui_restricted_to_allowed_source_ips() {
        let out = generate_ruleset(&[], &[], &admin(), true, &HashMap::new());
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
        let out = generate_ruleset(&[], &[], &a, true, &HashMap::new());
        assert!(out.contains(&format!("tcp dport {} ip daddr {} accept", a.bind_port, a.bind_ip_v4.unwrap())));
    }

    #[test]
    fn admin_rule_omits_the_daddr_clause_when_bind_ip_is_unspecified() {
        let mut a = admin();
        a.bind_ip_v4 = Some(std::net::Ipv4Addr::UNSPECIFIED);
        a.bind_ip_v6 = None;
        a.allowed_ips = vec![];
        let out = generate_ruleset(&[], &[], &a, true, &HashMap::new());
        assert!(out.contains(&format!("tcp dport {} accept", a.bind_port)), "got: {out}");
        assert!(!out.contains("ip daddr 0.0.0.0"), "0.0.0.0 never appears as a real packet's destination -- this rule would never match anything");
    }

    #[test]
    fn ssh_http_and_https_are_always_accepted_unconditionally() {
        let out = generate_ruleset(&[], &[], &admin(), true, &HashMap::new());
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
        let out = generate_ruleset(&[], &[rule], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 22 accept"));
    }

    #[test]
    fn unassigned_ips_in_the_29_never_appear_in_output() {
        let h = host("example.com", "10.0.0.2", 443, false);
        let rule = port_rule("10.0.0.4", 21115, 21119, Protocol::Tcp, "rustdesk");
        let out = generate_ruleset(&[h], &[rule], &admin(), true, &HashMap::new());
        for unused in ["10.0.0.5", "10.0.0.6"] {
            assert!(!out.contains(unused), "unassigned ip {unused} leaked into ruleset");
        }
    }

    #[test]
    fn ipv6_only_host_emits_ip6_daddr_not_ip_daddr() {
        let mut h = host("example.com", "10.0.0.2", 443, false);
        h.bind_ip_v4 = None;
        h.bind_ip_v6 = Some("2001:db8::1".parse().unwrap());
        let out = generate_ruleset(&[h], &[], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 443 ip6 daddr 2001:db8::1 accept"));
        assert!(!out.contains("ip daddr 2001:db8::1"), "an IPv6 address must never be matched with the v4-only `ip daddr` keyword");
    }

    #[test]
    fn dual_stack_host_emits_a_rule_for_each_family() {
        let mut h = host("example.com", "10.0.0.2", 443, true);
        h.bind_ip_v6 = Some("2001:db8::1".parse().unwrap());
        let out = generate_ruleset(&[h], &[], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 443 ip daddr 10.0.0.2 accept"));
        assert!(out.contains("tcp dport 443 ip6 daddr 2001:db8::1 accept"));
        assert!(out.contains("tcp dport 80 ip daddr 10.0.0.2 accept"));
        assert!(out.contains("tcp dport 80 ip6 daddr 2001:db8::1 accept"));
    }

    #[test]
    fn ipv6_port_rule_uses_ip6_daddr() {
        let mut rule = port_rule("10.0.0.3", 22, 22, Protocol::Tcp, "ssh");
        rule.bind_ip_v4 = None;
        rule.bind_ip_v6 = Some("2001:db8::5".parse().unwrap());
        let out = generate_ruleset(&[], &[rule], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 22 ip6 daddr 2001:db8::5 accept"));
    }

    #[test]
    fn admin_allowlist_with_only_v4_entries_leaves_a_v6_bind_unopened() {
        // A configured allowlist that only lists v4 sources must not
        // silently fall back to "wide open" for a v6 bind that has no
        // matching entries -- default-DROP should keep it closed instead.
        let mut a = admin();
        a.bind_ip_v6 = Some(std::net::Ipv6Addr::UNSPECIFIED);
        let out = generate_ruleset(&[], &[], &a, true, &HashMap::new());
        assert!(out.contains("tcp dport 8080 ip daddr 10.0.0.1 ip saddr { 10.0.0.1/32 } accept"));
        assert!(!out.contains("ip6 daddr"), "no v6 accept rule should have been emitted since allowed_ips has no v6 entries");
    }

    #[test]
    fn admin_allowlist_with_a_v6_entry_opens_the_v6_bind_to_it() {
        let mut a = admin();
        a.bind_ip_v6 = Some(std::net::Ipv6Addr::UNSPECIFIED);
        a.allowed_ips.push("2001:db8::/32".parse().unwrap());
        let out = generate_ruleset(&[], &[], &a, true, &HashMap::new());
        assert!(out.contains("tcp dport 8080 ip6 saddr { 2001:db8::/32 } accept"));
    }

    #[test]
    fn expose_admin_port_false_emits_no_accept_rule_for_the_admin_port() {
        let a = admin();
        let out = generate_ruleset(&[], &[], &a, false, &HashMap::new());
        assert!(!out.contains("dport 8080"), "no accept rule should mention the admin port at all when expose_admin_port is false");
    }

    #[test]
    fn expose_admin_port_false_does_not_affect_host_or_port_rule_firewall_entries() {
        let a = admin();
        let h = host("example.com", "10.0.0.2", 443, false);
        let out = generate_ruleset(&[h], &[], &a, false, &HashMap::new());
        assert!(out.contains("tcp dport 443 ip daddr 10.0.0.2 accept"));
    }

    /// The new feature this whole map exists for: a port rule with an
    /// IP-allow ACL selected gets its firewall entry source-restricted
    /// directly, since a raw TCP/UDP passthrough rule has no application
    /// layer to gate on the way a host does.
    #[test]
    fn port_rule_with_an_ip_allow_acl_gets_a_source_restricted_firewall_entry() {
        let rule = port_rule("10.0.0.3", 21115, 21115, Protocol::Tcp, "rustdesk");
        let mut rule_allow_ips = HashMap::new();
        rule_allow_ips.insert(rule.id, vec!["192.168.1.0/24".parse().unwrap()]);
        let out = generate_ruleset(&[], &[rule], &admin(), true, &rule_allow_ips);
        assert!(out.contains("tcp dport 21115 ip daddr 10.0.0.3 ip saddr { 192.168.1.0/24 } accept"));
    }

    /// A port rule absent from the map (no IP-allow ACL selected) is
    /// unrestricted, exactly as before this feature existed.
    #[test]
    fn port_rule_without_an_acl_is_unrestricted() {
        let rule = port_rule("10.0.0.3", 21115, 21115, Protocol::Tcp, "rustdesk");
        let out = generate_ruleset(&[], &[rule], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 21115 ip daddr 10.0.0.3 accept"), "got: {out}");
    }

    /// An IP-allow ACL selected but with no entries of the rule's own
    /// bind family emits no accept rule at all for it -- default-DROP
    /// then blocks it, same as the admin rule's identical case.
    #[test]
    fn port_rule_with_an_acl_that_has_no_matching_family_entries_is_not_emitted() {
        let rule = port_rule("10.0.0.3", 21115, 21115, Protocol::Tcp, "rustdesk");
        let mut rule_allow_ips = HashMap::new();
        rule_allow_ips.insert(rule.id, vec!["2001:db8::/32".parse().unwrap()]);
        let out = generate_ruleset(&[], &[rule], &admin(), true, &rule_allow_ips);
        assert!(!out.contains("dport 21115"), "no accept rule should exist for a family the ACL has no entries for");
    }

    /// A host's own acl_ids must never influence the firewall -- it's
    /// application-layer-only (see write_host_rules' doc comment).
    #[test]
    fn host_acl_ids_never_affect_the_firewall_rule() {
        let mut h = host("example.com", "10.0.0.2", 443, false);
        h.acl_ids = vec![Uuid::new_v4()]; // a real acl_id, deliberately not in any allow_ips map
        let out = generate_ruleset(&[h], &[], &admin(), true, &HashMap::new());
        assert!(out.contains("tcp dport 443 ip daddr 10.0.0.2 accept"), "a host must never be source-restricted at the firewall layer regardless of its own acl_ids: got {out}");
    }
}
