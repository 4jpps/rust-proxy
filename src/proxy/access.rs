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

/// What to do with a request from a source that failed the host's
/// IP-allow ACL, when the host has a `DenyFallback` configured.
#[derive(Debug, PartialEq, Eq)]
pub enum DenyDecision {
    /// Standard 403 block page.
    Forbidden,
    /// 302 to this same-site path.
    Redirect(String),
    /// Let the request through to the host's normal handling (it is the
    /// fallback page itself or one of its allowed resource paths).
    PassThrough,
}

fn path_is_safe(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    !(path.split('/').any(|seg| seg == "..")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || path.contains('\\'))
}

fn prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix.ends_with('/') {
        path.starts_with(prefix)
    } else {
        path == prefix || (path.starts_with(prefix) && path[prefix.len()..].starts_with('/'))
    }
}

pub fn deny_fallback_decision(
    fb: &crate::config::DenyFallback,
    path: &str,
    method: &hyper::Method,
) -> DenyDecision {
    if path_is_safe(path) {
        let allowed = std::iter::once(fb.redirect_path.as_str())
            .chain(fb.allow_paths.iter().map(String::as_str))
            .filter(|p| !p.is_empty())
            .any(|p| prefix_matches(p, path));
        if allowed {
            return DenyDecision::PassThrough;
        }
    }
    if fb.redirect_path.is_empty() {
        return DenyDecision::Forbidden;
    }
    let safe_method = method == hyper::Method::GET || method == hyper::Method::HEAD;
    if !safe_method {
        return DenyDecision::Forbidden;
    }
    // `/live` (no trailing slash) for a `/live/` fallback: bounce it
    // ourselves instead of letting the upstream answer with its own,
    // possibly scheme-wrong, redirect.
    let bare = fb.redirect_path.trim_end_matches('/');
    if path == "/" || path == bare || fb.lock {
        return DenyDecision::Redirect(fb.redirect_path.clone());
    }
    DenyDecision::Forbidden
}

/// Decodes `%XX` escapes (leaving malformed ones as-is) into a lossy
/// UTF-8 string.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const EXPLOIT_URL_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "\0",
    "<script",
    "</script",
    "base64_encode(",
    "base64_decode(",
    "$globals",
    "_request[",
    "_server[",
    "proc/self/environ",
    "/etc/passwd",
    "/etc/shadow",
    "mosconfig",
    "union select",
    "union all select",
    "information_schema",
    "<?php",
    "eval(",
    "${jndi:",
];

const EXPLOIT_USER_AGENTS: &[&str] = &[
    "sqlmap", "nikto", "havij", "acunetix", "nessus", "wpscan", "masscan", "nmap scripting",
];

/// The opt-in `block_exploits` check: returns the reason a request looks
/// like a common automated exploit probe, or `None` if it looks ordinary.
/// The URL is percent-decoded twice (to catch double encoding) and
/// matched case-insensitively. Deliberately a short, conservative list --
/// this trims scanner noise, it is not a web application firewall.
pub fn exploit_check(
    method: &hyper::Method,
    path_and_query: &str,
    user_agent: Option<&str>,
) -> Option<&'static str> {
    if method.as_str().eq_ignore_ascii_case("TRACE") || method.as_str().eq_ignore_ascii_case("TRACK") {
        return Some("TRACE/TRACK method");
    }
    let decoded = percent_decode(&percent_decode(path_and_query)).to_ascii_lowercase();
    let decoded = decoded.replace('+', " ");
    if EXPLOIT_URL_PATTERNS.iter().any(|p| decoded.contains(p)) {
        return Some("exploit pattern in URL");
    }
    if let Some(ua) = user_agent {
        let ua = ua.to_ascii_lowercase();
        if EXPLOIT_USER_AGENTS.iter().any(|p| ua.contains(p)) {
            return Some("scanner user agent");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DenyFallback;
    use hyper::Method;

    fn fb(lock: bool) -> DenyFallback {
        DenyFallback {
            scope: Default::default(),
            redirect_path: "/live/".into(),
            lock,
            allow_paths: vec!["/css/".into(), "/js".into()],
        }
    }

    #[test]
    fn fallback_page_and_resources_pass_through() {
        for p in ["/live/", "/live/x.json", "/css/a.css", "/js", "/js/app.js"] {
            assert_eq!(deny_fallback_decision(&fb(false), p, &Method::GET), DenyDecision::PassThrough, "{p}");
        }
    }

    #[test]
    fn unlocked_redirects_only_the_root() {
        assert_eq!(deny_fallback_decision(&fb(false), "/", &Method::GET), DenyDecision::Redirect("/live/".into()));
        assert_eq!(deny_fallback_decision(&fb(false), "/admin/", &Method::GET), DenyDecision::Forbidden);
    }

    #[test]
    fn locked_redirects_everything_else_for_get_only() {
        assert_eq!(deny_fallback_decision(&fb(true), "/admin/", &Method::GET), DenyDecision::Redirect("/live/".into()));
        assert_eq!(deny_fallback_decision(&fb(true), "/admin/", &Method::HEAD), DenyDecision::Redirect("/live/".into()));
        assert_eq!(deny_fallback_decision(&fb(true), "/admin/", &Method::POST), DenyDecision::Forbidden);
        assert_eq!(deny_fallback_decision(&fb(true), "/live/x", &Method::POST), DenyDecision::PassThrough);
    }

    #[test]
    fn bare_fallback_path_is_bounced_to_the_slash_form() {
        assert_eq!(deny_fallback_decision(&fb(false), "/live", &Method::GET), DenyDecision::Redirect("/live/".into()));
    }

    #[test]
    fn prefix_lookalikes_and_traversal_do_not_pass() {
        assert_eq!(deny_fallback_decision(&fb(true), "/livex", &Method::GET), DenyDecision::Redirect("/live/".into()));
        assert_eq!(deny_fallback_decision(&fb(true), "/jsx/a", &Method::GET), DenyDecision::Redirect("/live/".into()));
        for p in ["/live/../admin/", "/css/%2e%2e/admin/", "/css/..%2fadmin"] {
            assert_ne!(deny_fallback_decision(&fb(true), p, &Method::GET), DenyDecision::PassThrough, "{p}");
        }
    }

    #[test]
    fn empty_redirect_is_a_pure_allow_list() {
        let f = DenyFallback { scope: Default::default(), redirect_path: String::new(), lock: true, allow_paths: vec!["/guest/".into()] };
        assert!(f.validate().is_ok());
        assert_eq!(deny_fallback_decision(&f, "/guest/s/x", &Method::GET), DenyDecision::PassThrough);
        assert_eq!(deny_fallback_decision(&f, "/", &Method::GET), DenyDecision::Forbidden);
        assert_eq!(deny_fallback_decision(&f, "/api/", &Method::GET), DenyDecision::Forbidden);
        let empty = DenyFallback { scope: Default::default(), redirect_path: String::new(), lock: false, allow_paths: vec![] };
        assert!(empty.validate().is_err());
    }

    #[test]
    fn validate_rejects_offsite_paths() {
        let mut f = fb(false);
        assert!(f.validate().is_ok());
        for bad in ["//evil.com", "live", "http://x", "/a?b", "/a b"] {
            f.redirect_path = bad.into();
            assert!(f.validate().is_err(), "{bad}");
        }
    }

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

    #[test]
    fn exploit_check_flags_common_probes() {
        use hyper::Method;
        assert!(exploit_check(&Method::GET, "/a/../../etc/passwd", None).is_some());
        assert!(exploit_check(&Method::GET, "/a/%2e%2e/%2e%2e/x", None).is_some());
        assert!(exploit_check(&Method::GET, "/a/%252e%252e%252fx", None).is_some());
        assert!(exploit_check(&Method::GET, "/?q=%3Cscript%3Ealert(1)", None).is_some());
        assert!(exploit_check(&Method::GET, "/?id=1+UNION+SELECT+1", None).is_some());
        assert!(exploit_check(&Method::GET, "/?x=${jndi:ldap://x}", None).is_some());
        assert!(exploit_check(&Method::TRACE, "/", None).is_some());
        assert!(exploit_check(&Method::GET, "/", Some("sqlmap/1.7")).is_some());
    }

    #[test]
    fn exploit_check_passes_ordinary_requests() {
        use hyper::Method;
        assert!(exploit_check(&Method::GET, "/", Some("Mozilla/5.0")).is_none());
        assert!(exploit_check(&Method::POST, "/api/v1/items?page=2&sort=name", None).is_none());
        assert!(exploit_check(&Method::GET, "/files/my%20report.pdf", None).is_none());
        assert!(exploit_check(&Method::GET, "/100%25/done", None).is_none());
        assert!(exploit_check(&Method::GET, "/trailing%", None).is_none());
    }
}
