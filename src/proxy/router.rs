//! Pure host-matching logic: given the live `hosts` list and a listener's
//! `(bind_ip, bind_port)` plus the request's SNI/Host name, find which
//! `ProxyHost` should handle it. No I/O -- fully unit-testable, and kept
//! separate so listener code never has to duplicate matching rules.

use std::net::Ipv4Addr;

use crate::config::ProxyHost;

/// Case-insensitive per RFC 4343 -- DNS names/SNI/Host headers aren't
/// case-sensitive, and a client (or a misbehaving upstream) may send
/// either case. Tries an exact match first, then falls back to a
/// `*.parent` wildcard host covering exactly one label under `parent` --
/// the same single-level semantics as an X.509 wildcard cert (`*.a.com`
/// matches `x.a.com`, never `x.y.a.com`).
pub fn match_host<'a>(hosts: &'a [ProxyHost], bind_ip: Ipv4Addr, bind_port: u16, name: &str) -> Option<&'a ProxyHost> {
    let name = strip_port_suffix(name);
    let is_candidate = |h: &&ProxyHost, domain: &str| h.enabled && h.bind_ip == bind_ip && h.bind_port == bind_port && h.domain.eq_ignore_ascii_case(domain);

    if let Some(host) = hosts.iter().find(|h| is_candidate(h, name)) {
        return Some(host);
    }
    let (_, parent) = name.split_once('.')?;
    let wildcard = format!("*.{parent}");
    hosts.iter().find(|h| is_candidate(h, &wildcard))
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

/// Every unique `(bind_ip, 80)` an enabled host needs a plain-HTTP
/// listener on -- either a `force_https` redirect, or purely to serve an
/// http-01 challenge (see `acme::opens_port_80_for_acme`) for a host
/// that doesn't otherwise force HTTPS. The listener itself (`proxy::mod`)
/// always checks for a pending challenge before falling back to the
/// redirect response, so one listener per bind_ip serves both purposes.
pub fn redirect_listener_keys(hosts: &[ProxyHost]) -> Vec<(Ipv4Addr, u16)> {
    let mut keys: Vec<(Ipv4Addr, u16)> = hosts
        .iter()
        .filter(|h| h.enabled && (h.force_https || crate::acme::opens_port_80_for_acme(h)))
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
            acme_challenge_type: crate::config::AcmeChallengeType::Auto,
            access_allow_ips: vec![],
            access_login: None,
            redirect: None,
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
    fn wildcard_host_matches_any_single_label_subdomain() {
        let hosts = vec![host("*.pages.example.com", "10.0.0.2", 443, false, true)];
        let bind_ip = "10.0.0.2".parse().unwrap();
        assert!(match_host(&hosts, bind_ip, 443, "myproject.pages.example.com").is_some());
        assert!(match_host(&hosts, bind_ip, 443, "other-project.pages.example.com").is_some());
    }

    #[test]
    fn wildcard_host_does_not_match_two_levels_deep() {
        let hosts = vec![host("*.pages.example.com", "10.0.0.2", 443, false, true)];
        let bind_ip = "10.0.0.2".parse().unwrap();
        assert!(match_host(&hosts, bind_ip, 443, "a.b.pages.example.com").is_none());
    }

    #[test]
    fn wildcard_host_does_not_match_the_bare_parent_domain() {
        let hosts = vec![host("*.pages.example.com", "10.0.0.2", 443, false, true)];
        let bind_ip = "10.0.0.2".parse().unwrap();
        assert!(match_host(&hosts, bind_ip, 443, "pages.example.com").is_none());
    }

    #[test]
    fn exact_match_wins_over_wildcard_when_both_are_configured() {
        let hosts = vec![
            host("myproject.pages.example.com", "10.0.0.2", 443, false, true),
            host("*.pages.example.com", "10.0.0.2", 443, false, true),
        ];
        let bind_ip = "10.0.0.2".parse().unwrap();
        let found = match_host(&hosts, bind_ip, 443, "myproject.pages.example.com").unwrap();
        assert_eq!(found.domain, "myproject.pages.example.com");
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
    fn redirect_listener_keys_include_http01_only_hosts_without_force_https() {
        let mut h = host("a.example.com", "10.0.0.3", 443, false, true);
        h.acme_challenge_type = crate::config::AcmeChallengeType::Http01;
        let keys = redirect_listener_keys(&[h]);
        assert_eq!(keys, vec![("10.0.0.3".parse().unwrap(), 80)]);
    }

    #[test]
    fn redirect_listener_keys_exclude_wildcard_hosts_forced_to_dns01() {
        // Explicit Http01 is ignored for a wildcard domain --
        // `acme::resolve_challenge_type` always resolves it to dns-01,
        // so no port-80 listener is needed for ACME purposes here.
        let mut h = host("*.pages.example.com", "10.0.0.3", 443, false, true);
        h.acme_challenge_type = crate::config::AcmeChallengeType::Http01;
        assert!(redirect_listener_keys(&[h]).is_empty());
    }

    #[test]
    fn disabled_hosts_excluded_from_listener_keys() {
        let hosts = vec![host("a.example.com", "10.0.0.2", 443, true, false)];
        assert!(https_listener_keys(&hosts).is_empty());
        assert!(redirect_listener_keys(&hosts).is_empty());
    }
}
