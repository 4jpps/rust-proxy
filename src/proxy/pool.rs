//! Keep-alive pool for upstream HTTP/1.1 connections. Without it every
//! proxied request paid a fresh TCP handshake (plus TLS for
//! `upstream_https` hosts) and a file descriptor, even in a burst of page
//! assets to the same backend.
//!
//! Connections are pooled per `PoolKey`: the resolved upstream address,
//! whether TLS is spoken, the verification mode and the upstream
//! `host:port` (the TLS SNI and certificate name). Nothing is shared
//! across those, so one site's connection is never reused with another
//! site's TLS settings. WebSocket upgrades never use the pool.
//!
//! A connection only goes back into the pool once it can carry another
//! request (its response body fully read), and it is dropped after
//! `network.upstream_keepalive_seconds` idle. Upstreams may still close an
//! idle connection at any moment, so a reused connection is sent with
//! `try_send_request`: if hyper reports the request was never written, it
//! is retried once on a fresh connection; once any of it was sent it is
//! never retried.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;

/// Fresh upstream connections opened (handshake done).
pub static UPSTREAM_CONNECTS: AtomicU64 = AtomicU64::new(0);
/// Requests sent on a pooled, already-open connection.
pub static UPSTREAM_REUSES: AtomicU64 = AtomicU64::new(0);
/// Pooled connections found closed by the upstream before the request was
/// written; the request went out on a fresh connection instead.
pub static UPSTREAM_STALE_RETRIES: AtomicU64 = AtomicU64::new(0);

/// Idle connections kept per key and in total, so the pool itself can
/// never hold more than a bounded number of descriptors.
const MAX_IDLE_PER_KEY: usize = 16;
const MAX_IDLE_TOTAL: usize = 256;

pub const DEFAULT_UPSTREAM_KEEPALIVE_SECONDS: u64 = 4;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub addr: SocketAddr,
    pub https: bool,
    pub tls_verify: bool,
    pub upstream_host_port: String,
}

struct Idle {
    sender: SendRequest<Incoming>,
    since: Instant,
}

pub struct UpstreamPool {
    idle_timeout: Duration,
    idle: Mutex<HashMap<PoolKey, Vec<Idle>>>,
}

impl UpstreamPool {
    /// `keepalive_seconds == 0` disables pooling: every request gets its
    /// own connection, exactly as before the pool existed.
    pub fn new(keepalive_seconds: u64) -> Self {
        Self {
            idle_timeout: Duration::from_secs(keepalive_seconds),
            idle: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.idle_timeout.is_zero()
    }

    /// The most recently used idle connection for `key` that is still open
    /// and inside the idle timeout, if any. Expired ones met on the way are
    /// dropped (closing them).
    pub fn take(&self, key: &PoolKey) -> Option<SendRequest<Incoming>> {
        if !self.enabled() {
            return None;
        }
        let mut map = self.idle.lock().unwrap();
        let list = map.get_mut(key)?;
        let mut found = None;
        while let Some(idle) = list.pop() {
            if idle.since.elapsed() < self.idle_timeout && idle.sender.is_ready() {
                found = Some(idle.sender);
                break;
            }
        }
        if list.is_empty() {
            map.remove(key);
        }
        found
    }

    /// Returns a connection that is ready for its next request. Every
    /// expired or closed entry is swept first; past the per-key or total
    /// cap the connection is simply dropped.
    pub fn put(&self, key: PoolKey, sender: SendRequest<Incoming>) {
        if !self.enabled() || !sender.is_ready() {
            return;
        }
        let timeout = self.idle_timeout;
        let mut map = self.idle.lock().unwrap();
        map.retain(|_, list| {
            list.retain(|i| i.since.elapsed() < timeout && !i.sender.is_closed());
            !list.is_empty()
        });
        let total: usize = map.values().map(Vec::len).sum();
        let list = map.entry(key).or_default();
        if list.len() >= MAX_IDLE_PER_KEY || total >= MAX_IDLE_TOTAL {
            return;
        }
        list.push(Idle {
            sender,
            since: Instant::now(),
        });
    }

    /// Puts `sender` back once its connection can take another request,
    /// i.e. after the response body has been fully read. Waits in its own
    /// task so a long download never holds anything else up; a connection
    /// the upstream closes (or `Connection: close`) never comes back.
    pub fn release_when_ready(self: &Arc<Self>, key: PoolKey, mut sender: SendRequest<Incoming>) {
        if !self.enabled() {
            return;
        }
        let pool = self.clone();
        tokio::spawn(async move {
            if sender.ready().await.is_ok() {
                pool.put(key, sender);
            }
        });
    }

    pub fn idle_count(&self) -> usize {
        self.idle.lock().unwrap().values().map(Vec::len).sum()
    }
}

pub fn count(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}
