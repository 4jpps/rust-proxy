//! Per-host access control: an IP allow list and/or an HTTP Basic Auth
//! gate, checked by `proxy::mod`'s request handler before a request ever
//! reaches the upstream. Pure logic -- no I/O -- so it's fully
//! unit-testable without a real listener or a real client.

use std::net::Ipv4Addr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ipnet::Ipv4Net;

use crate::config::BasicAuth;

/// `allow_ips` empty means unrestricted (the default) -- every source IP
/// passes. Otherwise `addr` must fall inside at least one configured
/// range.
pub fn ip_allowed(allow_ips: &[Ipv4Net], addr: Ipv4Addr) -> bool {
    allow_ips.is_empty() || allow_ips.iter().any(|net| net.contains(&addr))
}

/// `auth` `None` means no gate -- always passes. Otherwise `header_value`
/// must be a well-formed `Authorization: Basic <base64(user:pass)>`
/// header whose credentials match. Constant-time-safe against timing
/// attacks in the same way the rest of this daemon's auth already is --
/// `verify_password` (argon2) never short-circuits on a partial match.
pub fn check_basic_auth(auth: &Option<BasicAuth>, header_value: Option<&str>) -> bool {
    let Some(auth) = auth else { return true };
    let Some((username, password)) = header_value.and_then(decode_basic_auth) else {
        return false;
    };
    username == auth.username && crate::api::auth::verify_password(&password, &auth.password_hash)
}

fn decode_basic_auth(header_value: &str) -> Option<(String, String)> {
    let encoded = header_value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(cidr: &str) -> Ipv4Net {
        cidr.parse().unwrap()
    }

    fn ip(addr: &str) -> Ipv4Addr {
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

    fn basic_auth_header(username: &str, password: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{username}:{password}")))
    }

    #[test]
    fn no_gate_passes_regardless_of_header() {
        assert!(check_basic_auth(&None, None));
    }

    #[test]
    fn correct_credentials_pass() {
        let auth = Some(BasicAuth {
            username: "viewer".into(),
            password_hash: crate::api::auth::hash_password("s3cret").unwrap(),
        });
        let header = basic_auth_header("viewer", "s3cret");
        assert!(check_basic_auth(&auth, Some(&header)));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let auth = Some(BasicAuth {
            username: "viewer".into(),
            password_hash: crate::api::auth::hash_password("s3cret").unwrap(),
        });
        let header = basic_auth_header("viewer", "wrong");
        assert!(!check_basic_auth(&auth, Some(&header)));
    }

    #[test]
    fn wrong_username_is_rejected() {
        let auth = Some(BasicAuth {
            username: "viewer".into(),
            password_hash: crate::api::auth::hash_password("s3cret").unwrap(),
        });
        let header = basic_auth_header("someone-else", "s3cret");
        assert!(!check_basic_auth(&auth, Some(&header)));
    }

    #[test]
    fn missing_header_is_rejected_when_a_gate_is_configured() {
        let auth = Some(BasicAuth {
            username: "viewer".into(),
            password_hash: crate::api::auth::hash_password("s3cret").unwrap(),
        });
        assert!(!check_basic_auth(&auth, None));
    }

    #[test]
    fn malformed_header_is_rejected_not_panicking() {
        let auth = Some(BasicAuth {
            username: "viewer".into(),
            password_hash: crate::api::auth::hash_password("s3cret").unwrap(),
        });
        assert!(!check_basic_auth(&auth, Some("not-basic-auth")));
        assert!(!check_basic_auth(&auth, Some("Basic not-valid-base64!!")));
        assert!(!check_basic_auth(&auth, Some("Basic")));
    }
}
