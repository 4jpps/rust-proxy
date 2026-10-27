//! Connection-level protection shared by every listener: a cap on
//! concurrent connections per client, and the timeouts that stop a
//! client from holding a connection (and its file descriptor) open
//! without ever completing a request.
//!
//! IPv6 clients are counted per /64, since one subscriber normally gets a
//! whole /64 and could otherwise rotate addresses to dodge the cap.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;

/// ClientHello plus the full TLS handshake must finish within this.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// HTTP/1 request headers must arrive within this -- also bounds how long
/// an idle keep-alive connection waits for its next request.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// HTTP/2 pings an idle connection this often and drops it if a ping
/// goes unanswered for `H2_KEEPALIVE_TIMEOUT`.
pub const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
pub const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// Totals since start, for `/metrics` and `/api/limits`.
pub static CONNECTIONS_REFUSED: AtomicU64 = AtomicU64::new(0);
pub static TLS_HANDSHAKE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
pub static RATE_LIMITED: AtomicU64 = AtomicU64::new(0);

/// Bumps one of the totals above.
pub fn count(counter: &AtomicU64) {
    counter.fetch_add(1, AtomicOrdering::Relaxed);
}

/// Reads one of the totals above.
pub fn total(counter: &AtomicU64) -> u64 {
    counter.load(AtomicOrdering::Relaxed)
}

/// Concurrent-connection counter keyed by client (address, or /64 for
/// IPv6). `limit == 0` turns the cap off.
#[derive(Debug, Default)]
pub struct ConnLimiter {
    limit: usize,
    counts: Mutex<HashMap<IpAddr, usize>>,
}

/// Holds one slot for as long as the connection lives.
#[derive(Debug)]
pub struct ConnGuard {
    limiter: Arc<ConnLimiter>,
    key: IpAddr,
}

impl ConnLimiter {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            counts: Mutex::new(HashMap::new()),
        })
    }

    /// A slot for `ip`, or `None` if it already has `limit` connections.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        let key = client_key(ip);
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let n = counts.entry(key).or_insert(0);
        if self.limit > 0 && *n >= self.limit {
            return None;
        }
        *n += 1;
        Some(ConnGuard {
            limiter: self.clone(),
            key,
        })
    }

    /// Connections currently held by `ip`'s client key.
    #[cfg(test)]
    pub fn current(&self, ip: IpAddr) -> usize {
        let counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        counts.get(&client_key(ip)).copied().unwrap_or(0)
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The `n` clients holding the most connections, busiest first.
    pub fn top(&self, n: usize) -> Vec<(IpAddr, usize)> {
        let counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let mut all: Vec<(IpAddr, usize)> = counts.iter().map(|(k, v)| (*k, *v)).collect();
        all.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        all.truncate(n);
        all
    }

    /// Distinct clients currently holding at least one connection.
    pub fn clients(&self) -> usize {
        self.counts.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(n) = counts.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

/// Per-site request rate limit (`ProxyHost::rate_limit_per_minute`): a
/// token bucket per (site, client), refilled at the per-minute rate. Its
/// size is the site's `rate_limit_burst`, or by default a sixth of a
/// minute's allowance (at least 10).
#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<(Uuid, IpAddr), Bucket>>,
    checks: AtomicUsize,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Buckets untouched this long are full again and get dropped.
const BUCKET_IDLE: Duration = Duration::from_secs(600);
/// How often (in checks) idle buckets are swept.
const SWEEP_EVERY: usize = 4096;

fn burst(per_minute: u32, configured: u32) -> f64 {
    if configured > 0 {
        configured as f64
    } else {
        (per_minute as f64 / 6.0).max(10.0)
    }
}

impl RateLimiter {
    /// `Ok` to let the request through, or `Err(wait)` with how long until
    /// the client has a token again (for `Retry-After`).
    pub fn check(
        &self,
        site: Uuid,
        ip: IpAddr,
        per_minute: u32,
        burst_size: u32,
    ) -> Result<(), Duration> {
        self.check_at(site, ip, per_minute, burst_size, Instant::now())
    }

    fn check_at(
        &self,
        site: Uuid,
        ip: IpAddr,
        per_minute: u32,
        burst_size: u32,
        now: Instant,
    ) -> Result<(), Duration> {
        if per_minute == 0 {
            return Ok(());
        }
        let rate = per_minute as f64 / 60.0; // tokens per second
        let cap = burst(per_minute, burst_size);
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if self.checks.fetch_add(1, AtomicOrdering::Relaxed) % SWEEP_EVERY == SWEEP_EVERY - 1 {
            buckets.retain(|_, b| now.saturating_duration_since(b.last) < BUCKET_IDLE);
        }
        let b = buckets.entry((site, client_key(ip))).or_insert(Bucket {
            tokens: cap,
            last: now,
        });
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * rate).min(cap);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - b.tokens) / rate))
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

/// IPv4 (and IPv4-mapped IPv6) by address; IPv6 by its /64.
fn client_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut seg = v6.segments();
            seg[4..].fill(0);
            IpAddr::V6(seg.into())
        }
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn caps_per_client_and_releases_on_drop() {
        let l = ConnLimiter::new(2);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let g1 = l.try_acquire(a).unwrap();
        let _g2 = l.try_acquire(a).unwrap();
        assert!(l.try_acquire(a).is_none());
        assert!(l.try_acquire(b).is_some(), "other clients are unaffected");
        assert_eq!(l.top(5), vec![(a, 2)], "b's guard was dropped right away");
        drop(g1);
        assert!(l.try_acquire(a).is_some());
    }

    #[test]
    fn ipv6_counts_per_64_and_mapped_v4_counts_as_v4() {
        let l = ConnLimiter::new(1);
        let _g = l.try_acquire("2001:db8:1:2::1".parse().unwrap()).unwrap();
        assert!(
            l.try_acquire("2001:db8:1:2:ffff::9".parse().unwrap())
                .is_none()
        );
        assert!(l.try_acquire("2001:db8:1:3::1".parse().unwrap()).is_some());
        let _v4 = l.try_acquire("198.51.100.7".parse().unwrap()).unwrap();
        assert!(
            l.try_acquire("::ffff:198.51.100.7".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn zero_means_unlimited() {
        let l = ConnLimiter::new(0);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let guards: Vec<_> = (0..1000).map(|_| l.try_acquire(ip).unwrap()).collect();
        assert_eq!(l.current(ip), 1000);
        drop(guards);
        assert_eq!(l.clients(), 0);
    }

    proptest! {
        /// Any interleaving of opens and closes: the count never exceeds
        /// the limit, matches the guards alive, and returns to empty.
        #[test]
        fn count_tracks_live_guards(limit in 1usize..6, ops in proptest::collection::vec((0u8..3, any::<bool>()), 0..200)) {
            let l = ConnLimiter::new(limit);
            let ips: Vec<IpAddr> = ["192.0.2.1", "192.0.2.2", "2001:db8::1"].iter().map(|s| s.parse().unwrap()).collect();
            let mut held: Vec<Vec<ConnGuard>> = vec![vec![], vec![], vec![]];
            for (who, open) in ops {
                let w = who as usize;
                if open {
                    match l.try_acquire(ips[w]) {
                        Some(g) => held[w].push(g),
                        None => prop_assert_eq!(held[w].len(), limit),
                    }
                } else {
                    held[w].pop();
                }
                for (i, ip) in ips.iter().enumerate() {
                    prop_assert_eq!(l.current(*ip), held[i].len());
                    prop_assert!(held[i].len() <= limit);
                }
            }
            drop(held);
            prop_assert_eq!(l.clients(), 0);
        }
    }

    fn site() -> Uuid {
        Uuid::from_u128(1)
    }

    #[test]
    fn rate_limit_allows_the_burst_then_refills_at_the_rate() {
        let r = RateLimiter::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();
        // 120/min: burst 20, then 2 per second.
        for _ in 0..20 {
            assert!(r.check_at(site(), ip, 120, 0, t0).is_ok());
        }
        let wait = r.check_at(site(), ip, 120, 0, t0).unwrap_err();
        assert!(
            wait > Duration::from_millis(400) && wait <= Duration::from_millis(500),
            "{wait:?}"
        );
        assert!(
            r.check_at(site(), ip, 120, 0, t0 + Duration::from_millis(500))
                .is_ok()
        );
        assert!(
            r.check_at(site(), ip, 120, 0, t0 + Duration::from_millis(500))
                .is_err()
        );
        // Other sites and other clients have their own buckets.
        assert!(r.check_at(Uuid::from_u128(2), ip, 120, 0, t0).is_ok());
        assert!(
            r.check_at(site(), "192.0.2.2".parse().unwrap(), 120, 0, t0)
                .is_ok()
        );
        // Same /64 shares a bucket.
        for _ in 0..10 {
            r.check_at(site(), "2001:db8::1".parse().unwrap(), 30, 0, t0)
                .unwrap();
        }
        assert!(
            r.check_at(site(), "2001:db8::2".parse().unwrap(), 30, 0, t0)
                .is_err()
        );
    }

    #[test]
    fn a_configured_burst_lets_a_login_flow_through() {
        let r = RateLimiter::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();
        // 60/min alone allows 10 back to back; burst 25 allows 25.
        for i in 0..25 {
            assert!(
                r.check_at(site(), ip, 60, 25, t0 + Duration::from_millis(i * 80))
                    .is_ok(),
                "{i}"
            );
        }
        assert!(
            r.check_at(site(), ip, 60, 25, t0 + Duration::from_secs(2))
                .is_ok()
        );
        assert!(
            r.check_at(site(), ip, 60, 25, t0 + Duration::from_secs(2))
                .is_err()
        );
    }

    #[test]
    fn zero_is_unlimited_and_idle_buckets_are_swept() {
        let r = RateLimiter::default();
        let t0 = Instant::now();
        for i in 0..(SWEEP_EVERY as u32 - 1) {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(i));
            r.check_at(site(), ip, 60, 0, t0).unwrap();
            assert!(r.check_at(site(), ip, 0, 0, t0).is_ok());
        }
        assert_eq!(r.tracked(), SWEEP_EVERY - 1);
        // The next check comes long after: every idle bucket goes.
        r.check_at(
            site(),
            "203.0.113.9".parse().unwrap(),
            60,
            0,
            t0 + BUCKET_IDLE * 2,
        )
        .unwrap();
        assert_eq!(r.tracked(), 1);
    }

    proptest! {
        /// Over any window, a client never gets more than the burst plus
        /// what the rate earns in that window.
        #[test]
        fn never_more_than_burst_plus_rate(per_minute in 1u32..2000, gaps in proptest::collection::vec(0u64..3000, 1..300)) {
            let r = RateLimiter::default();
            let ip: IpAddr = "192.0.2.1".parse().unwrap();
            let t0 = Instant::now();
            let mut t = t0;
            let mut allowed = 0u32;
            for g in gaps {
                t += Duration::from_millis(g);
                if r.check_at(site(), ip, per_minute, 0, t).is_ok() {
                    allowed += 1;
                }
            }
            let window = (t - t0).as_secs_f64();
            let ceiling = burst(per_minute, 0) + window * per_minute as f64 / 60.0;
            prop_assert!(allowed as f64 <= ceiling + 1e-6, "allowed {} > {}", allowed, ceiling);
        }
    }
}
