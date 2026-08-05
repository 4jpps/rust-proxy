# Changelog

## [Unreleased]

- Admin UI redesign -- the single long scrolling page is now organized
  into tabs (Hosts, Firewall Rules, Certificates, DNS Credentials, API
  Tokens), and every form field gets a real `<label>` grouped into
  `<fieldset>`s (Basics/TLS-ACME/Access control/Redirect for the host
  form) instead of one dense row of placeholder-only inputs. Hosts can
  now be edited after creation (an "Edit" button per row prefills the
  form and switches it to `PUT /api/hosts/:id`) -- the backend endpoint
  already existed but the UI never used it. Fixed a real usability trap
  this surfaced: a host's login-gate password is never returned by the
  API (only the username), so an edit that touched any *other* field
  used to force re-entering the password too or fail outright; `PUT
  /api/hosts/:id` now treats an explicitly-blank password as "keep the
  existing one" (`api::routes::build_host_login_for_update`), same
  convention the placeholder text already promised.
- Multiple DNS-01 providers, DB-backed and multi-credential -- Namecheap
  and AWS Route53 (a from-scratch AWS SigV4 request signer, verified
  against AWS's own published test vectors) join the existing
  Cloudflare/DigitalOcean/Hetzner/DuckDNS/GoDaddy set, for seven total.
  `acme.dns_provider`/`acme.dns_api_token` in config.toml now only ever
  seed a single optional "default" credential; DNS credentials
  otherwise live in a new `dns_credentials` sqlite table, managed from
  the admin UI's "DNS credentials" section (create/list/delete, one
  named credential per row) or the first-launch setup wizard. Each
  proxy host picks a credential explicitly via `dns_credential_id`, or
  falls back to the sole configured credential when there's exactly
  one and no explicit choice was made -- ambiguous/dangling references
  are rejected at host-creation time rather than failing silently at
  the next renewal. See `acme::dns01::{namecheap,route53,sigv4}`,
  `acme::resolve_dns_credential`, and `api::routes`'s
  `*_dns_credential` handlers.
- Admin identity (username/password/session secret) is now optional in
  config.toml -- omitting all three (a partial set is rejected at
  startup) means the daemon serves a first-launch setup wizard from the
  admin UI instead (`GET /api/setup-status`, `POST /api/setup`), which
  creates the admin account -- and optionally an initial DNS
  credential -- through the browser and stores it in a new
  `admin_identity` sqlite table. config.toml's own identity fields, if
  set, always take precedence over the DB on every read, not just at
  first boot, so an operator who prefers managing this in the config
  file isn't affected. Existing single-provider/single-credential
  config.toml deployments keep working unchanged. See
  `state::AppState::admin_identity`, `db::create_admin_identity_if_absent`,
  and `web/index.html`'s setup wizard screen.
- `postinst` no longer interactively prompts for or randomly generates
  admin credentials -- the web setup wizard above covers that now, so a
  fresh install just gets a working default `config.toml` (loopback-only
  admin UI, no admin account or DNS credential yet) and a running
  service. Visit the admin UI once to finish setup.
- "Multiple SSL certificates" was already supported (per-domain
  `ArcSwap<HashMap<String, CertEntry>>` in `state.rs`) -- no change
  needed there, confirmed while scoping this release.

- HTTP/2 support -- ALPN now offers `h2` alongside `http/1.1`, and the
  HTTPS listener uses `hyper-util`'s auto h1/h2 connection builder.
  Deliberately doesn't enable HTTP/2 Extended CONNECT (RFC 8441), so
  WebSocket clients cleanly negotiate HTTP/1.1 instead (same split
  Nginx makes) -- see `proxy/mod.rs`'s `build_https_server_config`.
- http-01 ACME challenges as an alternative to dns-01 -- no DNS provider
  credentials needed for a plain (non-wildcard) domain. New per-host
  `acme_challenge_type` setting (`auto`/`http01`/`dns01`; `auto` uses
  http-01 whenever `force_https` already has port 80 open, dns-01
  otherwise). Wildcard domains always use dns-01 regardless of this
  setting, since no CA offers http-01 for them. See `acme::http01` and
  `acme::resolve_challenge_type`.
- Per-host access lists -- an IP allow list (`access_allow_ips`) and/or
  a login gate (`access_login`), enforced at the application layer
  before a request reaches the upstream, independent of
  `network.bind_ranges` and the nftables firewall. The most-cited
  real-world use of Nginx Proxy Manager's raw config-injection escape
  hatch, covered here as a structured feature instead. `access_login`
  serves a real HTML login page (`proxy::login`) and a signed,
  `HttpOnly`/`Secure` session cookie scoped to that one host, rather
  than an HTTP Basic Auth prompt -- password managers reliably recognize
  and offer to save a real login form, unlike Basic Auth's browser-
  native dialog. Passwords are argon2-hashed server-side and never
  stored or returned in plaintext. See `proxy::access`/`proxy::login`.
- Redirection hosts -- a host can now be a pure redirect (`redirect`:
  `{"target", "preserve_path", "status"}`) instead of a reverse proxy;
  `upstream` becomes ignored/optional. `preserve_path` (default `true`)
  appends the visited path/query onto `target`; `status` is
  `"permanent"` (301, default) or `"temporary"` (302). Same as Nginx
  Proxy Manager's Redirection Hosts, it still gets its own ACME cert and
  its own `access_allow_ips`/`access_login` -- only the final response
  differs from a normal proxy host. See `config::RedirectTarget` and
  `proxy::http::redirect_target_response`.
- Custom/uploaded certificates -- `POST /api/certs` publishes a
  manually-provided cert/key pair for a domain, bypassing ACME entirely
  (an internal CA's cert, a wildcard bought elsewhere). Rejected if a
  host for that domain still has `acme_enabled = true`, since the next
  renewal check would otherwise overwrite it. Also fixes a real gap this
  surfaced: certs previously lived only in memory, so a restart forgot
  every uploaded cert permanently and needlessly re-issued every
  ACME-issued one against Let's Encrypt's rate limits; every cert is now
  reloaded from `acme.cert_dir` at startup. See `acme::load_certs_from_disk`
  and `api::routes::upload_cert`/`delete_cert`.

## [0.1.0] - 2026-07-26

First public release. A lightweight L7 reverse proxy daemon in Rust,
built as an open, self-hostable alternative to Nginx Proxy Manager.

- HTTP/WebSocket reverse proxying with SNI-based TLS dispatch, and
  arbitrary TCP/UDP port passthrough (e.g. RustDesk). A host's domain
  may be a single leading wildcard label (`*.example.com`) to cover
  every subdomain under one route/cert.
- Native RFC 8555 ACME v2 client (its own JWS framing and HTTP state
  machine, no `instant-acme`/`lego`) -- dns-01 validation via a
  pluggable DNS provider: Cloudflare, DigitalOcean, or Hetzner today,
  one new file plus one enum variant to add another.
- Dynamic default-DROP nftables firewall orchestration -- only the
  proxy hosts/port rules actually configured get an explicit ACCEPT,
  everything else is dropped by default.
- Axum admin REST API plus a small embedded single-page web UI, behind
  dual auth: argon2/HMAC session cookies for the UI, or bearer API
  tokens (SHA-256-hashed at rest, `rpx_`-prefixed) for scripts, CI, or
  any other tooling -- everything the UI can do, the API can do too.
- sqlite persistence (hosts, port rules, API tokens) via `sqlx`.
- Flexible network binding (`network.bind_ranges`) -- a single
  dedicated IP, a full subnet block, or several disjoint ranges; no
  assumption of a dedicated `/29`.
- MIT licensed.
