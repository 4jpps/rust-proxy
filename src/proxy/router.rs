//! Pure host-matching logic: given the live `hosts` list and a listener's
//! `(bind_ip, bind_port)` plus the request's SNI/Host name, find which
//! `ProxyHost` should handle it. No I/O -- fully unit-testable, and kept
//! separate so listener code never has to duplicate matching rules.

use std::net::Ipv4Addr;

use crate::config::ProxyHost;

/// Case-insensitive per RFC 4343 -- DNS names/SNI/Host headers aren't
/// case-sensitive, and a client (or a misbehaving upstream) may send
/// either case.
pub fn match_host<'a>(hosts: &'a [ProxyHost], bind_ip: Ipv4Addr, bind_port: u16, name: &str) -> Option<&'a ProxyHost> {
    let name = strip_port_suffix(name);
    hosts
        .iter()
        .find(|h| h.enabled && h.bind_ip == bind_ip && h.bind_port == bind_port && h.domain.eq_ignore_ascii_case(name))
}

/// `Host:` headers (unlike SNI) may carry a `:port` suffix.
fn strip_port_suffix(name: &str) -> &str {
    match name.rsplit_once(':') {
        // Only strip if what follows really is a port number -- otherwise
        // this would mangle a bare IPv6 literal host header.
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => name,
    }
}

/// Every unique `(bind_ip, bind_port)` an enabled host wants a TLS/HTTP
/// listener on -- what the supervisor diffs against currently-running
/// listeners to decide what to spawn/stop.
pub fn https_listener_keys(hosts: &[ProxyHost]) -> Vec<(Ipv4Addr, u16)> {
    let mut keys: Vec<(Ipv4Addr, u16)> = hosts
        .iter()
        .filter(|h| h.enabled)
        .map(|h| (h.bind_ip, h.bind_port))
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Every unique `(bind_ip, 80)` an enabled `force_https` host needs a
/// plain-HTTP redirect listener on.
pub fn redirect_listener_keys(hosts: &[ProxyHost]) -> Vec<(Ipv4Addr, u16)> {
    let mut keys: Vec<(Ipv4Addr, u16)> = hosts
        .iter()
        .filter(|h| h.enabled && h.force_https)
        .map(|h| (h.bind_ip, 80u16))
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn host(domain: &str, bind_ip: &str, bind_port: u16, force_https: bool, enabled: bool) -> ProxyHost {
        ProxyHost {
            id: Uuid::new_v4(),
            domain: domain.into(),
            bind_ip: bind_ip.parse().unwrap(),
            bind_port,
            upstream: "127.0.0.1:8000".into(),
            websockets: false,
            force_https,
            acme_enabled: true,
            enabled,
        }
    }

    #[test]
    fn matches_exact_domain_bind_ip_and_port() {
        let hosts = vec![host("example.com", "10.0.0.2", 443, true, true)];
        let found = match_host(&hosts, "10.0.0.2".parse().unwrap(), 443, "example.com").unwrap();
        assert_eq!(found.domain, "example.com");
    }

    #[test]
    fn does_not_match_wrong_bind_ip() {
        let hosts = vec![host("example.com", "10.0.0.2", 443, true, true)];
        assert!(match_host(&hosts, "10.0.0.3".parse().unwrap(), 443, "example.com").is_none());
    }

    #[test]
    fn domain_matching_is_case_insensitive() {
        let hosts = vec![host("Example.COM", "10.0.0.2", 443, true, true)];
        let found = match_host(&hosts, "10.0.0.2".parse().unwrap(), 443, "example.com").unwrap();
        assert_eq!(found.domain, "Example.COM");
    }

    #[test]
    fn disabled_host_never_matches() {
        let hosts = vec![host("example.com", "10.0.0.2", 443, true, false)];
        assert!(match_host(&hosts, "10.0.0.2".parse().unwrap(), 443, "example.com").is_none());
    }

    #[test]
    fn two_domains_share_one_ip_port_disambiguated_by_sni() {
        let hosts = vec![
            host("a.example.com", "10.0.0.2", 443, true, true),
            host("b.example.com", "10.0.0.2", 443, true, true),
        ];
        let a = match_host(&hosts, "10.0.0.2".parse().unwrap(), 443, "a.example.com").unwrap();
        let b = match_host(&hosts, "10.0.0.2".parse().unwrap(), 443, "b.example.com").unwrap();
        assert_eq!(a.domain, "a.example.com");
        assert_eq!(b.domain, "b.example.com");
    }

    #[test]
    fn host_header_port_suffix_is_stripped_before_matching() {
        let hosts = vec![host("example.com", "10.0.0.2", 8443, true, true)];
        let found = match_host(&hosts, "10.0.0.2".parse().unwrap(), 8443, "example.com:8443").unwrap();
        assert_eq!(found.domain, "example.com");
    }

    #[test]
    fn https_listener_keys_are_deduplicated_across_shared_ip_port() {
        let hosts = vec![
            host("a.example.com", "10.0.0.2", 443, true, true),
            host("b.example.com", "10.0.0.2", 443, true, true),
            host("c.example.com", "10.0.0.3", 8443, false, true),
        ];
        let keys = https_listener_keys(&hosts);
        assert_eq!(keys, vec![("10.0.0.2".parse().unwrap(), 443), ("10.0.0.3".parse().unwrap(), 8443)]);
    }

    #[test]
    fn redirect_listener_keys_only_include_force_https_hosts() {
        let hosts = vec![
            host("a.example.com", "10.0.0.2", 443, true, true),
            host("b.example.com", "10.0.0.3", 443, false, true),
        ];
        let keys = redirect_listener_keys(&hosts);
        assert_eq!(keys, vec![("10.0.0.2".parse().unwrap(), 80)]);
    }

    #[test]
    fn disabled_hosts_excluded_from_listener_keys() {
        let hosts = vec![host("a.example.com", "10.0.0.2", 443, true, false)];
        assert!(https_listener_keys(&hosts).is_empty());
        assert!(redirect_listener_keys(&hosts).is_empty());
    }
}
