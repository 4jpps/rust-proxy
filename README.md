# rust-proxy

A lightweight L7 reverse proxy daemon in Rust for an LXC container with
a dedicated `/29` IPv4 block: HTTP/WebSocket reverse proxying with
SNI-based TLS, a native RFC 8555 ACME client (dns-01 via Cloudflare),
dynamic default-DROP nftables firewall orchestration, arbitrary
TCP/UDP port passthrough, and a small embedded web admin UI.

## Building and testing

```sh
cargo build
cargo test
```

No external services are required for the test suite -- ACME/Cloudflare
calls are exercised against mock HTTP servers (`wiremock`), and
persistence tests run against an in-memory sqlite database.

## Configuration

Copy `deploy/config.toml.example` to `/etc/rust-proxy/config.toml` and
fill in `admin.session_secret` (`openssl rand -hex 32`),
`admin.admin_password_hash` (`rust-proxy hash-password '...'`), and
`acme.cloudflare_api_token`. `network.subnet` must be the LXC's assigned
subnet -- every `bind_ip` used anywhere has to fall inside it.

`hosts`/`port_rules` in the TOML file only seed an empty database on
first boot. After that, sqlite (`admin.db_path`) is the source of
truth and everything is managed from the admin UI, not by re-editing
the file.

## Architecture

- `config` -- TOML parsing + validation (bind IPs inside the subnet,
  non-zero/well-ordered ports, no duplicate binds).
- `state` -- `AppState`: hosts/port_rules/certs live in `ArcSwap` for
  lock-free hot-reload reads; a `Mutex` per resource serializes the
  admin API's write path so concurrent edits can't race and drop each
  other; a `Notify` wakes the nftables sync loop and the proxy listener
  supervisor immediately on change (plus a periodic fallback in case a
  notification is ever missed).
- `nftables::generator` -- pure ruleset-text generation (default-DROP,
  one explicit ACCEPT per active host/port-rule bind); `nftables::apply`
  is the thin layer that actually shells out to `nft -f -`.
- `acme` -- native RFC 8555 client: JWS framing (`jws`), wire types
  (`types`), the HTTP state machine (`client`), Cloudflare dns-01
  (`dns01`), and CSR/certificate handling (`cert`). `run_renewal_loop`
  checks every ACME-enabled host every 12h and re-issues anything
  within `acme.renew_before_days` of expiry.
- `proxy` -- the data plane: `router` (pure host-matching), `tls`
  (SNI cert dispatch reading live state), `http` (forwarding +
  WebSocket upgrade passthrough), `passthrough` (raw TCP/UDP for
  non-HTTP port rules). A supervisor diffs the desired listener set
  against what's running on every state change and only starts/stops
  the delta -- editing a route's upstream never restarts its listener.
  A host's `domain` may be a single leading wildcard label
  (`*.pages.example.com`) to cover every one-level subdomain under one
  route/cert -- e.g. a GitLab instance's Pages feature, which serves
  each project at its own subdomain. Exact matches always win over a
  wildcard when both are configured. dns-01 (required for wildcard
  certs -- CAs never offer http-01 for them) already covers this; no
  ACME changes were needed beyond record-name handling.
- `api` -- Axum admin REST API (`routes`) behind argon2/HMAC session
  auth (`auth`), plus the embedded (`include_str!`) single-page web UI
  at `web/index.html`.
- `db` -- sqlite persistence for hosts/port_rules via `sqlx`.

## Deployment

Target is a Proxmox LXC with a `/29` assigned. `deploy/rust-proxy.service`
runs the daemon as a non-root `rust-proxy` user with just
`CAP_NET_BIND_SERVICE` (privileged ports) and `CAP_NET_ADMIN` (nftables)
via `AmbientCapabilities`/`CapabilityBoundingSet`, plus
`NoNewPrivileges`/`ProtectSystem=strict`/`ProtectHome` for defense in
depth. The admin UI's own port is additionally restricted to
`admin.allowed_ips` at the firewall layer, not just by session auth.

```sh
sudo install -d -m 750 -o rust-proxy -g rust-proxy /etc/rust-proxy
sudo install -m 640 -o root -g rust-proxy deploy/config.toml.example /etc/rust-proxy/config.toml
# edit /etc/rust-proxy/config.toml -- see Configuration above
sudo install -m 644 deploy/rust-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rust-proxy
```

No `.deb`/CI packaging pipeline yet -- add one (mirroring
`jpps/store`'s `.gitlab-ci.yml` + `cargo-deb` approach) once this is
ready for a real rollout.

## Status

Scaffolded per the initial spec's implementation checklist; TLS
listener behavior end-to-end (real handshake, SNI dispatch, a real
Let's Encrypt + Cloudflare issuance) has not been verified against a
real deployment yet -- only unit/mock/loopback-integration tested. See
git log for what's been built in what order.
