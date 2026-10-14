# Architecture

A map of the code for contributors. User-facing behavior is covered in the
other pages.

## Modules

- **`config`**: TOML parsing and validation (bind IPs inside `network.bind_ranges` if any are configured, valid ports, no duplicate binds, `deny_fallback` paths).
- **`state`**: `AppState`. Hosts, port rules and certificates live in `ArcSwap` for lock-free reads on hot reload. A `Mutex` per resource serializes the admin API's write path so concurrent edits cannot drop each other. A `Notify` wakes the nftables sync loop and the listener supervisor immediately on change, with a periodic fallback in case a notification is ever missed.
- **`nftables::generator`**: pure ruleset-text generation (default-DROP, one explicit ACCEPT per active host or port-rule bind). **`nftables::apply`** is the thin layer that shells out to `nft -f -`.
- **`acme`**: a native RFC 8555 client. `jws` (framing), `types` (wire types), `client` (the HTTP state machine), `dns01` (a `DnsProvider` trait with one implementation per provider), `http01` (serves the key authorization from an in-memory map on the port-80 listener), and `cert` (CSR and certificate handling). `resolve_challenge_type` picks which one a host uses. `run_renewal_loop` checks every ACME-enabled host every 12 hours and re-issues anything within `acme.renew_before_days` of expiry. `load_certs_from_disk` restores every issued or uploaded certificate from `acme.cert_dir` at startup.
- **`proxy`**: the data plane.
  - `router`: pure host matching. An exact domain beats a wildcard.
  - `tls`: SNI certificate dispatch reading live state, falling back from an exact match to a covering `*.parent`.
  - `http`: forwarding, WebSocket upgrade passthrough, and the redirect and static-file responses.
  - `access`: pure IP-allow checks, the `deny_fallback` decision function and the `exploit_check` filter.
  - `login`: the login-ACL session-cookie gate (credential check, HMAC session signing, the login page).
  - `client_cert`: optional mTLS client-certificate verification.
  - `passthrough`: raw TCP/UDP for non-HTTP port rules.
  
  Access and login run before a matched request is forwarded, or before a redirect or static response is built.
- **`api`**: the Axum admin REST API (`routes`, `hosting`) behind dual authentication (`auth`): argon2/HMAC session cookies for the web UI, or SHA-256-hashed-at-rest bearer tokens for everything else. The cookie proves identity only; `require_admin` resolves the role (`auth::Role`) from the database on every request and enforces the per-path rules, so a role change or a disabled user takes effect immediately. Also serves the embedded single-page UI at `web/index.html` (included with `include_str!`).
- **`hosting`**: pool and allocation model, plus the generator for the `rust_proxy_hosting` nftables table, loopback addresses and blackhole routes.
- **`siem`**: the bounded event queue and the syslog senders.
- **`db`**: sqlite persistence via `sqlx`.

## Protocol notes

ALPN offers `h2` then `http/1.1`. The HTTPS listener uses `hyper-util`'s
auto builder to speak whichever a client negotiates, with HTTP/1 upgrades
still enabled for WebSocket passthrough. HTTP/2 extended CONNECT (RFC
8441) is deliberately not enabled: a client will not try a WebSocket
handshake over h2 without confirming it is supported, so leaving it off
makes WebSocket clients fall back to HTTP/1.1 instead of failing.
Everything else gets real HTTP/2 multiplexing. This is the same split
nginx makes.

A listener supervisor diffs the desired listener set against what is
running on every state change and only starts or stops the difference.
Editing a route's upstream never restarts its listener.

## Request flow for a host

1. Match the host by SNI and `Host` (exact, then wildcard).
2. With `block_exploits`, refuse probe requests (`access::exploit_check`).
3. For `deny_fallback` with `scope: everyone`, apply the path decision.
4. Evaluate the ACL gate: client certificate, IP allow, then login (OR).
5. For a visitor who fails an IP-only gate, apply `deny_fallback` with `scope: blocked`, or return 403.
6. Answer from `fixed_response`, then `redirect`, then `static_root`, otherwise forward upstream.
7. Forwarding adds `X-Forwarded-*`, applies `path_rewrite`, picks the upstream from the longest matching `locations` entry (or the host's own), and optionally passes the client-cert subject headers.

## Building and testing

```sh
cargo build
cargo test
```

No external services are needed for the test suite. ACME and DNS-provider
calls run against mock HTTP servers (`wiremock`), and persistence tests
use an in-memory sqlite database.
