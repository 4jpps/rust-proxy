# rust-proxy

A lightweight L7 reverse proxy daemon in Rust, built as an open,
self-hostable alternative to Nginx Proxy Manager: HTTP/1.1+HTTP/2 and
WebSocket reverse proxying with SNI-based TLS, a native RFC 8555 ACME
client (dns-01 via a
pluggable DNS provider -- Cloudflare, DigitalOcean, or Hetzner today --
or http-01, needing no DNS credentials at all), dynamic default-DROP
nftables firewall orchestration, arbitrary TCP/UDP port passthrough,
and a small embedded web admin UI. Runs on anything from a single
dedicated IP to a full subnet block -- see Configuration below.

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
`acme.dns_api_token` for whichever `acme.dns_provider` you use
(`cloudflare`, the default if omitted; `digitalocean`; or `hetzner` --
all three take a single bearer/header API token, see the comments in
`deploy/config.toml.example`). Adding another provider means one new
file under `src/acme/dns01/` implementing the `DnsProvider` trait
(`find_zone`/`create_txt_record`/`delete_txt_record`) plus a new
`DnsProviderKind` variant -- PRs for more providers welcome.
`network.bind_ranges` is optional
and empty by default -- unrestricted, bind to whatever address the
environment actually has, whether that's a single dedicated IP, a full
LXC /29 block, or several disjoint ranges. Populate it only if you want
config-validation-time hardening against bind_ip typos for a known
range you control.

`hosts`/`port_rules` in the TOML file only seed an empty database on
first boot. After that, sqlite (`admin.db_path`) is the source of
truth and everything is managed from the admin UI, not by re-editing
the file.

Each host picks its own ACME challenge type via `acme_challenge_type`:
`auto` (the default) uses http-01 when the host has `force_https` on
(port 80 is already open for the redirect, so no DNS provider
credentials are needed) and falls back to dns-01 otherwise; `http01`
and `dns01` force one or the other explicitly. A wildcard domain
(`*.example.com`) always uses dns-01 regardless of this setting -- CAs
never offer http-01 for a wildcard identifier. Choosing `http01`
without `force_https` still opens a port-80 listener/firewall rule for
that host, just to answer the challenge.

## API

Every route under `/api/*` except `/api/login`/`/api/logout` requires
authentication, and accepts either of two independent credentials:

- **Session cookie** -- what the web UI uses. `POST /api/login` with
  `{"username": "...", "password": "..."}` sets an HTTP-only,
  `SameSite=Lax` cookie good for 12 hours; `POST /api/logout` clears it.
- **API token** -- `Authorization: Bearer <token>`, for scripts, CI
  pipelines, or any other tool driving this instance without a browser.
  A token is exactly as privileged as the admin session that created it
  (there's no scope/permission system, matching this daemon's one-admin-
  account model) and can reach every endpoint below, including token
  management itself -- **treat a token like a password**: anyone holding
  one can reconfigure the proxy and the firewall behind it.

### Managing tokens

Bootstrapping requires the web UI (or `curl` against `/api/login` with
the admin password) once, to mint the first token -- there's no way to
create a token without already having a valid credential.

```sh
# Sign in, keeping the session cookie, then mint a token:
curl -c /tmp/cookies -X POST https://proxy.example.com/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}'

curl -b /tmp/cookies -X POST https://proxy.example.com/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci pipeline"}'
# -> {"id":"...","name":"ci pipeline","token":"rpx_...","created_at":"..."}
# The "token" field is shown exactly once -- save it now. Only its
# SHA-256 hash is ever persisted (see db::create_api_token), so a lost
# token means minting a new one, not recovering the old one.
```

| Method | Path             | Body                | Notes |
|--------|------------------|----------------------|-------|
| GET    | `/api/tokens`    | --                   | Lists `{id, name, created_at, last_used_at}` -- never the token or its hash. `last_used_at` is `null` until first use, so unused tokens are easy to spot and revoke. |
| POST   | `/api/tokens`    | `{"name": "..."}`   | Creates a token; response includes the plaintext once. |
| DELETE | `/api/tokens/:id`| --                   | Revokes immediately -- any request already using it fails on its very next call. |

### Managing proxy hosts and firewall rules

The same token works for everything the admin UI does. The request/
response shapes match the `HostRequest`/`PortRuleRequest` fields in
`src/api/routes.rs` (also visible in the web UI's own forms):

| Method | Path                    | Body                                                                                     |
|--------|-------------------------|-------------------------------------------------------------------------------------------|
| GET    | `/api/dashboard`        | -- (host/port-rule/cert counts, configured `bind_ranges`)                                 |
| GET    | `/api/hosts`            | --                                                                                         |
| POST   | `/api/hosts`            | `{"domain","bind_ip","bind_port","upstream","websockets","force_https","acme_enabled","acme_challenge_type","enabled"}` |
| PUT    | `/api/hosts/:id`        | same shape as POST                                                                         |
| DELETE | `/api/hosts/:id`        | --                                                                                         |
| GET    | `/api/port-rules`       | --                                                                                         |
| POST   | `/api/port-rules`       | `{"bind_ip","port_start","port_end","protocol","description","passthrough_target","enabled"}` |
| PUT    | `/api/port-rules/:id`   | same shape as POST                                                                          |
| DELETE | `/api/port-rules/:id`   | --                                                                                         |
| GET    | `/api/certs`            | -- (`{domain, not_after, days_remaining}` per issued cert)                                |

```sh
curl -X POST https://proxy.example.com/api/hosts \
  -H "Authorization: Bearer rpx_..." \
  -H 'Content-Type: application/json' \
  -d '{"domain":"app.example.com","bind_ip":"10.0.0.2","bind_port":443,"upstream":"127.0.0.1:8000","websockets":true}'
```

Errors are `{"error": "message"}` with `400`/`404`/`500` as appropriate;
`bind_ip` is validated against `network.bind_ranges` the same way the
web UI's own submissions are -- there's no separate, looser code path
for the token-authenticated API.

## Architecture

- `config` -- TOML parsing + validation (bind IPs inside the configured
  `network.bind_ranges`, if any are configured; non-zero/well-ordered
  ports; no duplicate binds).
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
  (`types`), the HTTP state machine (`client`), pluggable dns-01
  (`dns01` -- a `DnsProvider` trait plus one implementation per provider:
  `dns01::cloudflare`, `dns01::digitalocean`, `dns01::hetzner`), http-01
  (`http01` -- serves the key authorization from an in-memory map on
  `proxy::mod`'s port-80 listener, no third-party credentials needed),
  and CSR/certificate handling (`cert`). `resolve_challenge_type` picks
  which one a given host actually uses (see Configuration above).
  `run_renewal_loop` checks every ACME-enabled host every 12h and
  re-issues anything within `acme.renew_before_days` of expiry.
- `proxy` -- the data plane: `router` (pure host-matching), `tls`
  (SNI cert dispatch reading live state), `http` (forwarding +
  WebSocket upgrade passthrough), `passthrough` (raw TCP/UDP for
  non-HTTP port rules). ALPN offers `h2` then `http/1.1`; the HTTPS
  listener uses `hyper-util`'s auto builder to actually speak whichever
  one a client negotiates, with HTTP/1 upgrades (what WebSocket
  passthrough needs) still enabled. Deliberately doesn't enable HTTP/2
  Extended CONNECT (RFC 8441) -- per that RFC, a client won't attempt a
  WebSocket handshake over h2 without confirming that's supported, so
  leaving it off means WebSocket clients cleanly fall back to HTTP/1.1
  instead of failing; everything else gets real HTTP/2 multiplexing.
  Same split Nginx itself makes. A supervisor diffs the desired listener set
  against what's running on every state change and only starts/stops
  the delta -- editing a route's upstream never restarts its listener.
  A host's `domain` may be a single leading wildcard label
  (`*.pages.example.com`) to cover every one-level subdomain under one
  route/cert -- e.g. a GitLab instance's Pages feature, which serves
  each project at its own subdomain. Exact matches always win over a
  wildcard when both are configured. dns-01 (required for wildcard
  certs -- CAs never offer http-01 for them) already covers this; no
  ACME changes were needed beyond record-name handling.
- `api` -- Axum admin REST API (`routes`) behind dual auth (`auth`):
  argon2/HMAC session cookies for the web UI, or a SHA-256-hashed-at-rest
  bearer API token for everything else -- see the API section above.
  Plus the embedded (`include_str!`) single-page web UI at
  `web/index.html`.
- `db` -- sqlite persistence for hosts/port_rules/api_tokens via `sqlx`.

## Deployment

Runs on any Linux host, from a Proxmox LXC with a dedicated subnet to a
single-IP VPS or home server -- see `network.bind_ranges` above.
`deploy/rust-proxy.service` runs the daemon as a non-root `rust-proxy` user
with just
`CAP_NET_BIND_SERVICE` (privileged ports) and `CAP_NET_ADMIN` (nftables)
via `AmbientCapabilities`/`CapabilityBoundingSet`, plus
`NoNewPrivileges`/`ProtectSystem=strict`/`ProtectHome` for defense in
depth. The admin UI's own port is additionally restricted to
`admin.allowed_ips` at the firewall layer, not just by session auth.

### Installing the `.deb`

Every `vX.Y.Z` tag is built and published by CI (`.gitlab-ci.yml`) to
this project's [Releases](../../releases) page and to a small
self-hosted apt repo:

```sh
echo 'deb [trusted=yes] https://repo.jpps.us/stable /' | sudo tee /etc/apt/sources.list.d/jpps.list
sudo apt update
sudo apt install rust-proxy
```

(`[trusted=yes]` because this repo isn't GPG-signed yet -- it's a
small, flat, single-maintainer repo, not a general-purpose
distribution; download over HTTPS still protects the transfer, just
not the publisher's identity the way a signed repo would.)

`postinst` creates the `rust-proxy` system user and, on first install,
either interactively prompts for initial configuration (admin
credentials, DNS provider/token) or -- if run non-interactively, e.g.
`apt-get install -y` in a script -- generates a random admin password
and prints it once. Either way you get a real `/etc/rust-proxy/config.toml`
and a running service; edit the file and `systemctl restart rust-proxy`
to change anything afterward. An unattended install without ACME
credentials on hand still works -- it just can't issue certs until
`acme.dns_api_token` is filled in.

Or download a specific release's `.deb` directly and `dpkg -i` it, or
build/install manually:

```sh
sudo install -d -m 750 -o rust-proxy -g rust-proxy /etc/rust-proxy
sudo install -m 640 -o root -g rust-proxy deploy/config.toml.example /etc/rust-proxy/config.toml
# edit /etc/rust-proxy/config.toml -- see Configuration above
sudo install -m 644 deploy/rust-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rust-proxy
```

## Status

Scaffolded per the initial spec's implementation checklist; TLS
listener behavior end-to-end (real handshake, SNI dispatch, a real
Let's Encrypt issuance against a live DNS provider) has not been
verified against a real deployment yet -- only unit/mock/loopback-
integration tested. See git log for what's been built in what order.

## License

MIT -- see [LICENSE](LICENSE). Contributions (new DNS providers
especially) welcome.
