# Changelog

## [Unreleased]

- **Standalone DNS-01 certificates, decoupled from any host.** Built
  for wildcards -- issuing `*.example.com` used to require creating a
  throwaway `ProxyHost` just to get ACME to issue against that domain.
  `POST /api/dns01-certs` (new "Standalone DNS-01 certificates" section
  on the Certificates tab) issues a cert for any domain with no host at
  all, synchronously within the request (the real ACME flow, DNS
  propagation wait included, so it can take up to a minute -- the UI
  disables the button and shows progress text meanwhile). Once issued,
  every subdomain host under that wildcard just uses it automatically
  with no separate "attach" step: `proxy::tls::select_cert_for_sni`
  already falls back from an exact-domain match to a covering wildcard
  cert, which this feature leans on rather than duplicating. The
  tracking row (`standalone_certs` table) is only persisted after a
  real successful issuance, so a failed one-off attempt doesn't linger
  being silently retried against a domain that never got a cert;
  `run_renewal_loop` renews every tracked standalone cert the same way
  it renews a host's own. Verified against a real Let's Encrypt staging
  round trip in a real browser (account registration reached, a real
  ACME error returned and displayed, form re-enabled correctly). See
  `acme::issue_standalone_dns01_certificate`, `db::StandaloneCert`, and
  `api::routes`'s `/api/dns01-certs` handlers.
- **Reusable, named ACLs replace per-host inline access control.** A
  host used to carry its own `access_allow_ips`/`access_login` fields
  directly -- sharing the same office IP range or login across five
  hosts meant retyping (and re-hashing) it five times, and there was no
  way to update one shared rule in one place. Access control is now a
  first-class resource: create a named **IP allow** list (one or more
  CIDRs/bare IPs) or **Login** list (one or more username/password
  pairs, argon2-hashed) once from the new ACLs tab, then select none,
  one, or several of them per host. A host with multiple selected lists
  of the same kind unions them -- any selected IP range is enough, any
  selected list's credentials work -- while the IP-gate and login-gate
  remain the same two independent sequential checks as before (an
  allowed IP still doesn't bypass a configured login). Resolution
  happens live from sqlite on every request (`db::resolve_acl_ids`),
  the same precedent already set by bearer-token auth's live DB lookup,
  rather than hot-reloaded state -- ACL definitions change rarely
  enough that this is the simpler design. Deleting an ACL still
  selected by a live host is refused, same guard already used for DNS
  credentials. Existing hosts' inline `access_allow_ips`/`access_login`
  data is migrated automatically and losslessly into an auto-created,
  per-host-named ACL the first time the daemon starts on the new schema
  (`db::migrate_legacy_host_access`) -- no manual re-entry needed on
  upgrade. See `config::{AclList,AclKind}`, `db::resolve_acl_ids`, and
  `api::routes`'s `/api/acls` handlers.
- **`main.rs` startup sequencing pulled into a new `bootstrap` module.**
  DB connect + seed/load hosts+port_rules+the default DNS credential +
  resolve the admin identity + load certs from disk used to all be
  inlined in `main()`; each step is now its own small, independently
  named, independently unit-tested function
  (`bootstrap::load_or_seed_hosts_and_port_rules`,
  `seed_default_dns_credential_if_configured`,
  `load_persisted_admin_identity`, `build_app_state`), so reviewing "did
  startup seed/load things correctly" means reading one focused
  function instead of tracing mutable state through `main()`'s whole
  body. `main()` itself is now purely: parse args, init logging, load
  config, call `bootstrap::build_app_state`, validate nftables, spawn
  the service tasks. Every DNS-01 provider was already its own module
  (`src/acme/dns01/{cloudflare,digitalocean,hetzner,duckdns,godaddy,namecheap,route53}.rs`)
  from earlier work this cycle -- confirmed, not something this change
  needed to add.
- **Per-provider DNS credential fields, not a hand-packed token
  string.** The DNS Credentials form (and the setup wizard's optional
  DNS step) used to have one generic "token" text box, with Namecheap
  (`api_user:api_key:client_ip`) and Route53
  (`access_key_id:secret_access_key`) requiring the operator to
  manually construct a correctly-ordered, colon-delimited string --
  explained only in the provider dropdown's option text. Both forms now
  render dedicated, labeled inputs per provider (2 for Route53, 3 for
  Namecheap, a single clearly-labeled token field for the other five)
  and pack them into the exact string `acme::dns01::{namecheap,route53}`
  expect entirely client-side -- no more error-prone manual construction.
- **Admin defaults to `0.0.0.0:8084`** (was a required field with no
  default; 8084 to cut down on port collisions with the many
  self-hosted tools defaulting to 8080), reachable from the network out
  of the box so the first-launch setup wizard doesn't need any
  config.toml edits to reach. nftables mirrors this: SSH (22), HTTP
  (80), and HTTPS (443) are now always accepted unconditionally,
  regardless of what hosts/port rules are (or aren't yet) configured --
  a default-DROP firewall that could lock an operator out of SSH, or
  out of the admin UI needed to fix the firewall itself, was a bricked
  box waiting to happen. The admin port itself is open to any source
  until `admin.allowed_ips` narrows it down. Fixed a real, previously
  latent bug this work surfaced: the generated ruleset started with
  `flush table inet rust_proxy`, which errors outright if that table
  has never been created -- meaning a genuinely fresh host (nftables
  has never seen this table before) would fail its very first sync
  forever, since `nft -f -` aborts the rest of the script on that first
  error and the `table { ... }` block that actually creates everything
  never got to run. Fixed by emitting an idempotent `add table` first.
  Verified against a real `nft` binary, not just the unit tests: the
  bug reproduces exactly as described, and the fix resolves it.
  `Config::load` also now writes a working default config.toml
  automatically if the given path doesn't exist at all (not just via
  `postinst`), and `nftables::validate_environment` checks `nft` is
  actually usable once at startup with one clear, actionable error
  message instead of that only surfacing buried in repeating sync
  failures.
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
- Per-host access lists -- an IP allow list and/or a login gate,
  enforced at the application layer before a request reaches the
  upstream, independent of `network.bind_ranges` and the nftables
  firewall. The most-cited real-world use of Nginx Proxy Manager's raw
  config-injection escape hatch, covered here as a structured feature
  instead. (Originally per-host inline fields; superseded by the
  reusable ACL system above -- this bullet describes the underlying
  mechanism, which the ACL rewrite kept, not the now-removed inline
  fields.) The login gate serves a real HTML login page (`proxy::login`)
  and a signed, `HttpOnly`/`Secure` session cookie scoped to that one
  host, rather than an HTTP Basic Auth prompt -- password managers
  reliably recognize and offer to save a real login form, unlike Basic
  Auth's browser-native dialog. Passwords are argon2-hashed server-side
  and never stored or returned in plaintext. See
  `proxy::access`/`proxy::login`.
- Redirection hosts -- a host can now be a pure redirect (`redirect`:
  `{"target", "preserve_path", "status"}`) instead of a reverse proxy;
  `upstream` becomes ignored/optional. `preserve_path` (default `true`)
  appends the visited path/query onto `target`; `status` is
  `"permanent"` (301, default) or `"temporary"` (302). Same as Nginx
  Proxy Manager's Redirection Hosts, it still gets its own ACME cert and
  its own ACL selection -- only the final response
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
