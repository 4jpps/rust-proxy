//! Connection-level protection shared by every listener: a cap on
//! concurrent connections per client, and the timeouts that stop a
//! client from holding a connection (and its file descriptor) open
//! without ever completing a request.
//!
//! IPv6 clients are counted per /64, since one subscriber normally gets a
//! whole /64 and could otherwise rotate addresses to dodge the cap.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// ClientHello plus the full TLS handshake must finish within this.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// HTTP/1 request headers must arrive within this -- also bounds how long
/// an idle keep-alive connection waits for its next request.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// HTTP/2 pings an idle connection this often and drops it if a ping
/// goes unanswered for `H2_KEEPALIVE_TIMEOUT`.
pub const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
pub const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

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
}
