//! Mobile passes: lets a phone through IP-allow lists while it is away from the allowed networks.
//!
//! An IP-allow list can name a Login list ("Mobile pass logins"). A phone app signs in at
//! `POST /.rust-proxy/mobile-pass` on any host this proxy serves, with a username and password
//! from that Login list. Its current source IP then counts as inside every IP-allow list linked to
//! that Login list, for `PASS_SECS` (90 s). The app checks in again before the pass runs out and whenever
//! the phone changes networks, so the pass follows the phone. `DELETE` on the same path ends it.
//!
//! Only a phone's current IP counts: each check-in replaces the IP of that login + device, and
//! passes live in memory only, so no list of past IPs is ever kept.
//!
//! Off unless turned on in Settings (`mobile_pass_settings`); while off the path is a plain 404.
//! Only the HTTP/HTTPS access check honors a pass, not the nftables firewall. Failed sign-ins are
//! limited per source IP and reported to the SIEM like the host login gate's.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;

/// Where the phone app checks in.
pub const PATH: &str = "/.rust-proxy/mobile-pass";
/// How long one check-in keeps a phone's IP inside the linked lists: a short lease, so a phone
/// that goes offline, is switched off without reaching the proxy, or whose public IP changes
/// underneath it drops out within this time. The app (0.2.0 and later) reads `expires_in` and
/// checks in three times per lease, so every 30 s at this length. App 0.1.0 checked in every
/// 4 minutes and would see its pass lapse between check-ins: update the app before this.
pub const PASS_SECS: i64 = 90;
/// Failed sign-ins allowed per source IP in `FAIL_WINDOW` before it is refused outright.
const MAX_FAILS: u32 = 10;
const FAIL_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Most passes kept at once; the oldest goes first past this.
const MAX_PASSES: usize = 200;
const MAX_BODY: usize = 4096;

#[derive(Debug, Clone, Serialize)]
pub struct Pass {
    pub login_list: Uuid,
    pub username: String,
    pub device: String,
    pub ip: IpAddr,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// The live passes and the per-IP failure counts. In memory only: after a restart each phone
/// signs in again at its next check-in.
#[derive(Default)]
pub struct PassStore {
    passes: Mutex<Vec<Pass>>,
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl PassStore {
    /// Records (or refreshes) the pass for this login + device on `ip`.
    pub fn grant(
        &self,
        login_list: Uuid,
        username: &str,
        device: &str,
        ip: IpAddr,
        now: DateTime<Utc>,
    ) {
        let mut passes = self.passes.lock().unwrap_or_else(|e| e.into_inner());
        passes.retain(|p| {
            p.expires_at > now
                && !(p.login_list == login_list && p.username == username && p.device == device)
        });
        passes.push(Pass {
            login_list,
            username: username.to_string(),
            device: device.to_string(),
            ip,
            granted_at: now,
            expires_at: now + chrono::Duration::seconds(PASS_SECS),
        });
        let extra = passes.len().saturating_sub(MAX_PASSES);
        passes.drain(..extra);
    }

    /// Ends every pass this login holds for this device; how many there were.
    pub fn revoke(&self, logins: &[Uuid], username: &str, device: &str) -> usize {
        let mut passes = self.passes.lock().unwrap_or_else(|e| e.into_inner());
        let before = passes.len();
        passes.retain(|p| {
            !(logins.contains(&p.login_list) && p.username == username && p.device == device)
        });
        before - passes.len()
    }

    /// Whether `ip` holds a fresh pass from any of `login_lists`.
    pub fn allows(&self, login_lists: &[Uuid], ip: IpAddr, now: DateTime<Utc>) -> bool {
        if login_lists.is_empty() {
            return false;
        }
        let passes = self.passes.lock().unwrap_or_else(|e| e.into_inner());
        passes
            .iter()
            .any(|p| p.ip == ip && p.expires_at > now && login_lists.contains(&p.login_list))
    }

    /// The fresh passes, newest first.
    pub fn list(&self, now: DateTime<Utc>) -> Vec<Pass> {
        let mut passes = self.passes.lock().unwrap_or_else(|e| e.into_inner());
        passes.retain(|p| p.expires_at > now);
        let mut out = passes.clone();
        out.reverse();
        out
    }

    pub fn clear(&self) {
        self.passes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Ends every pass granted under this Login list, e.g. because its credentials changed or it
    /// stopped being accepted for mobile passes. A pass never outlives the login it was granted on.
    pub fn revoke_login_list(&self, login_list: Uuid) {
        self.passes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|p| p.login_list != login_list);
    }

    /// Takes one attempt slot for `ip` before its password is checked, so parallel guesses can't
    /// all slip past the limit; false once `MAX_FAILS` are used in `FAIL_WINDOW`. A successful
    /// sign-in gives the slots back (`succeeded`).
    fn try_attempt(&self, ip: IpAddr, now: Instant) -> bool {
        let mut f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        f.retain(|_, (_, since)| now.duration_since(*since) < FAIL_WINDOW);
        let entry = f.entry(ip).or_insert((0, now));
        if entry.0 >= MAX_FAILS {
            return false;
        }
        entry.0 += 1;
        true
    }

    fn succeeded(&self, ip: IpAddr) {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&ip);
    }
}

#[derive(Deserialize)]
struct SignIn {
    username: String,
    password: String,
    /// A name for the phone ("Jeff's Pixel"), so its pass can be told apart and ended.
    #[serde(default)]
    device: String,
}

/// Answers `POST`/`DELETE` on `PATH`. Called before any host access check.
pub async fn handle(
    state: &AppState,
    peer_ip: IpAddr,
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    if !state.mobile_pass_enabled() {
        return json(
            StatusCode::NOT_FOUND,
            serde_json::json!({ "error": "not found" }),
        );
    }
    let method = req.method().clone();
    if method != hyper::Method::POST && method != hyper::Method::DELETE {
        return json(
            StatusCode::METHOD_NOT_ALLOWED,
            serde_json::json!({ "error": "use POST to sign in, DELETE to sign out" }),
        );
    }
    let now = Instant::now();
    let store = state.mobile_passes();
    if !store.try_attempt(peer_ip, now) {
        report(false, "", "", peer_ip, "too many failed sign-ins");
        return json(
            StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({ "error": "too many failed sign-ins, try again later" }),
        );
    }
    let body = match http_body_util::Limited::new(req.into_body(), MAX_BODY)
        .collect()
        .await
    {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "error": "invalid request" }),
            );
        }
    };
    let Ok(sign_in) = serde_json::from_slice::<SignIn>(&body) else {
        return json(
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": "invalid request" }),
        );
    };
    let device: String = sign_in.device.trim().chars().take(64).collect();
    let device = if device.is_empty() {
        "phone".to_string()
    } else {
        device
    };
    let logins = match crate::db::mobile_pass_logins(state.db()).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "loading mobile pass logins failed");
            return json(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({ "error": "try again later" }),
            );
        }
    };
    let matched: Vec<Uuid> = logins
        .iter()
        .filter(|(_, creds)| {
            super::login::verify_credentials_any(creds, &sign_in.username, &sign_in.password)
        })
        .map(|(id, _)| *id)
        .collect();
    if matched.is_empty() {
        report(
            false,
            &sign_in.username,
            &device,
            peer_ip,
            "invalid credentials",
        );
        return json(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({ "error": "invalid username or password" }),
        );
    }
    store.succeeded(peer_ip);
    if method == hyper::Method::DELETE {
        store.revoke(&matched, &sign_in.username, &device);
        report(true, &sign_in.username, &device, peer_ip, "signed out");
        return json(StatusCode::OK, serde_json::json!({ "ok": true }));
    }
    let utc = Utc::now();
    for login in &matched {
        store.grant(*login, &sign_in.username, &device, peer_ip, utc);
    }
    report(true, &sign_in.username, &device, peer_ip, "pass granted");
    json(
        StatusCode::OK,
        serde_json::json!({ "ok": true, "ip": peer_ip.to_string(), "expires_in": PASS_SECS }),
    )
}

fn json(status: StatusCode, v: serde_json::Value) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(
            Full::new(Bytes::from(v.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static JSON response is always valid")
}

/// SIEM event for a check-in; the password is never read here.
fn report(ok: bool, username: &str, device: &str, peer_ip: IpAddr, what: &str) {
    use crate::siem::{Category, Severity, emit, wants};
    let (cat, sev, event) = if ok {
        (Category::Admin, Severity::Notice, "mobile_pass_success")
    } else {
        (Category::Denied, Severity::Warning, "mobile_pass_failure")
    };
    if !wants(cat) {
        return;
    }
    let client_ip = peer_ip.to_string();
    let user: String = username.chars().take(64).collect();
    emit(
        cat,
        sev,
        event,
        &format!("mobile pass: {what}"),
        &[
            ("client_ip", client_ip.as_str()),
            ("username", user.as_str()),
            ("device", device),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_pass_follows_the_phone_and_runs_out() {
        let store = PassStore::default();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let t0 = Utc::now();
        store.grant(a, "jeff", "pixel", ip("203.0.113.5"), t0);
        assert!(store.allows(&[a], ip("203.0.113.5"), t0));
        // Only for the Login lists it was granted under.
        assert!(!store.allows(&[b], ip("203.0.113.5"), t0));
        assert!(!store.allows(&[], ip("203.0.113.5"), t0));
        // The phone moves networks and checks in again: the old IP is out, the new one in.
        store.grant(a, "jeff", "pixel", ip("198.51.100.9"), t0);
        assert!(!store.allows(&[a], ip("203.0.113.5"), t0));
        assert!(store.allows(&[a], ip("198.51.100.9"), t0));
        // And without a check-in it lapses.
        let later = t0 + chrono::Duration::seconds(PASS_SECS + 1);
        assert!(!store.allows(&[a], ip("198.51.100.9"), later));
        assert!(store.list(later).is_empty());
    }

    #[test]
    fn two_phones_and_signing_out() {
        let store = PassStore::default();
        let a = Uuid::new_v4();
        let t0 = Utc::now();
        store.grant(a, "jeff", "pixel", ip("203.0.113.5"), t0);
        store.grant(a, "jeff", "tablet", ip("203.0.113.6"), t0);
        assert_eq!(store.list(t0).len(), 2);
        assert_eq!(store.revoke(&[a], "jeff", "pixel"), 1);
        assert!(!store.allows(&[a], ip("203.0.113.5"), t0));
        assert!(store.allows(&[a], ip("203.0.113.6"), t0));
        store.clear();
        assert!(store.list(t0).is_empty());
    }

    #[test]
    fn attempts_are_counted_before_checking_and_lock_out_that_ip() {
        let store = PassStore::default();
        let now = Instant::now();
        for _ in 0..MAX_FAILS {
            assert!(store.try_attempt(ip("192.0.2.1"), now));
        }
        assert!(!store.try_attempt(ip("192.0.2.1"), now));
        assert!(store.try_attempt(ip("192.0.2.2"), now));
        assert!(store.try_attempt(ip("192.0.2.1"), now + FAIL_WINDOW + Duration::from_secs(1)));
        // A success gives the slots back.
        store.succeeded(ip("192.0.2.2"));
        for _ in 0..MAX_FAILS {
            assert!(store.try_attempt(ip("192.0.2.2"), now));
        }
    }

    #[test]
    fn changing_a_login_list_ends_its_passes() {
        let store = PassStore::default();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let t0 = Utc::now();
        store.grant(a, "jeff", "pixel", ip("203.0.113.5"), t0);
        store.grant(b, "mike", "iphone", ip("203.0.113.6"), t0);
        store.revoke_login_list(a);
        assert!(!store.allows(&[a], ip("203.0.113.5"), t0));
        assert!(store.allows(&[b], ip("203.0.113.6"), t0));
    }
}
