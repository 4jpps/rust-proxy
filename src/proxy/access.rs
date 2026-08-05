//! Per-host IP allow list, checked by `proxy::mod`'s request handler
//! before a request ever reaches the upstream. Pure logic -- no I/O --
//! so it's fully unit-testable without a real listener or a real
//! client. The other half of a host's access control, the login-page
//! gate, lives in `proxy::login` -- it needs session-cookie signing and
//! HTML rendering, enough machinery of its own to warrant a separate
//! module.

use std::net::IpAddr;

use ipnet::IpNet;

/// `allow_ips` empty means unrestricted (the default) -- every source IP
/// passes. Otherwise `addr` must fall inside at least one configured
/// range of the *same family* -- a v4 range never matches a v6 `addr`
/// and vice versa, same reasoning as `config::validate_bind_ip`.
pub fn ip_allowed(allow_ips: &[IpNet], addr: IpAddr) -> bool {
    allow_ips.is_empty() || allow_ips.iter().any(|net| net.contains(&addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(cidr: &str) -> IpNet {
        cidr.parse().unwrap()
    }

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    #[test]
    fn empty_allow_list_permits_any_ip() {
        assert!(ip_allowed(&[], ip("203.0.113.7")));
    }

    #[test]
    fn ip_inside_an_allowed_range_passes() {
        let allow = vec![net("10.0.0.0/24")];
        assert!(ip_allowed(&allow, ip("10.0.0.42")));
    }

    #[test]
    fn ip_outside_every_allowed_range_is_rejected() {
        let allow = vec![net("10.0.0.0/24")];
        assert!(!ip_allowed(&allow, ip("192.168.1.1")));
    }

    #[test]
    fn ip_matching_any_one_of_several_ranges_passes() {
        let allow = vec![net("10.0.0.0/24"), net("192.168.1.0/24")];
        assert!(ip_allowed(&allow, ip("192.168.1.50")));
    }

    #[test]
    fn ipv6_address_matches_an_ipv6_range() {
        let allow = vec![net("2001:db8::/32")];
        assert!(ip_allowed(&allow, ip("2001:db8::1")));
    }

    #[test]
    fn ipv6_address_never_matches_an_ipv4_range_and_vice_versa() {
        let allow = vec![net("10.0.0.0/24")];
        assert!(!ip_allowed(&allow, ip("::1")));
        let allow = vec![net("2001:db8::/32")];
        assert!(!ip_allowed(&allow, ip("10.0.0.5")));
    }
}
