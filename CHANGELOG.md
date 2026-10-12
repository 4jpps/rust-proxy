# Changelog

## [Unreleased]

- **Multi-IP readiness: dedicated addresses, listeners that coexist with
  wildcard ones, and same-port passthrough.** (1) Every listener now sets
  `SO_REUSEPORT`, so a listener bound to one specific address (for example
  a public IP added to give one site its own address) can run beside the
  wildcard `0.0.0.0:443` listeners; Linux otherwise refuses it with
  "Address already in use", and the kernel delivers to the exact-address
  socket first. (2) New `network.dedicated_ips`: an address listed there
  serves only hosts and port rules explicitly bound to it. The generated
  firewall emits those accepts first, then drops everything else addressed
  to the dedicated IP before the wildcard rules and the always-open
  22/80/443 can match, and wildcard HTTP(S) listeners refuse connections
  that arrived on it. (3) A port rule's `passthrough_target` may now be a
  bare host or IP with no port, meaning "forward to the same port the
  client connected to", so one range rule (for example UDP 20100-22100)
  maps each port to the same port on the backend.

- **Fixed a real production incident: the HTTPS/redirect accept loops
  could busy-spin for hours on a transient `accept()` error, pegging a
  CPU core and flooding the log.** Root-caused from a real 15G,
  126M-line `proxy.log` on `sites.tech.lan`'s instance: 125.9M of
  those lines were `https listener accept failed error=Too many open
  files (os error 24)`, continuously from 00:53 to 09:17 one day — the
  loop retried `accept()` immediately on every failure with no
  backoff, so once the process hit its file-descriptor limit (no
  `LimitNOFILE` was set, so it ran under systemd's own default,
  commonly 1024), every subsequent iteration failed immediately too,
  as fast as the runtime could spin. Two-part fix: `accept_error_backoff()`
  (a 100ms sleep before retrying on any accept error, both the HTTPS
  and plain-HTTP redirect listeners) caps a stuck condition at ~10
  retries/sec instead of a tight spin, and `LimitNOFILE=65536` in the
  systemd unit makes actually hitting the fd limit under real load
  much less likely in the first place.
- **Added `admin.log_dir` config option** to split `proxy.log`/
  `access.log`/`server.log` out from the state directory (previously
  hardcoded to the same directory as `admin.db_path`, e.g.
  `/var/lib/rust-proxy` on a systemd-packaged install, no way to
  change it without touching `db_path` too). `None` (the default,
  unset in config.toml) keeps the original behavior exactly, so an
  existing install with no config edit sees no change. Deployed on
  `sites.tech.lan`'s instance to relocate logs to a dedicated
  `/var/log/rust-proxy`, after noticing `/var/lib/rust-proxy` had
  grown to 15G from the incident above.

- **Fixed a real production bug: adding/editing/removing an IP entry
  on an `AclList` didn't take effect for a port rule enforcing it at
  the firewall until the 5-minute fallback resync caught up.** A
  host's HTTP-level access check resolves `acl_ids` live from the DB
  on every request, so that path updated instantly -- but a raw
  TCP/UDP port rule's IP allow list is enforced by the generated
  nftables ruleset, which only regenerates when `state.set_hosts`/
  `set_port_rules` fires (or the periodic fallback timer). Editing an
  ACL's IP entries does neither, so a port rule (e.g. SSH, gated by a
  "Default IP ACL") kept enforcing the *old* address list until the
  next fallback resync, up to 5 minutes later -- confirmed as a real
  incident: adding a new IP to an in-use ACL didn't grant access,
  requiring a fallback to an already-allowed address in the meantime.
  Added `AppState::notify_config_change`, called by the
  add/update/delete-IP-entry admin routes after a successful write, so
  `nftables::run_sync_loop` wakes and re-syncs immediately, the same
  way it already does for a host or port-rule edit.
- **An ACL's IP entries now list sorted by parsed address, not
  insertion order or raw CIDR text.** Plain text sort put e.g.
  `10.0.0.0/24` before `2.2.2.2/32` (`'1' < '2'` lexicographically),
  which read as broken to an operator scanning the list for a specific
  address. `db::list_acl_ip_entries` now sorts by the parsed
  `ipnet::IpNet` value (IPv4 before IPv6, ascending within each); a
  CIDR that somehow fails to parse sorts last instead of panicking.
- **Fixed a real production bug: HTTP/2-split `Cookie` headers were
  forwarded to the upstream as multiple separate `Cookie:` lines
  instead of being merged into one.** RFC 7540 §8.1.2.5 permits an
  HTTP/2 client to split its `Cookie` header into several HTTP/2
  header fields for better HPACK compression -- real Chromium and
  Firefox both do this; curl, httpx, and Node's `fetch` do not, which
  is why this went undetected by every scripted test. Rack/Rails (and
  most HTTP/1.1 server frameworks) only read the first `Cookie:` line
  off the wire, silently discarding the rest. Confirmed as a real
  production bug against a GitLab instance behind this proxy: every
  real browser hit a 100%-reproducible 422 `InvalidAuthenticityToken`
  on login, because the session cookie (which happened to land second
  of four split fields) was completely invisible to GitLab -- it saw
  no session at all and rejected the CSRF token issued for it. A raw
  TCP byte capture of this proxy's own forwarded request confirmed the
  four separate `cookie:` lines on the wire; bypassing this proxy with
  a minimal from-scratch HTTP/2 proxy that merges cookies correctly
  fixed the same request instantly. `forward_http` now merges all
  `cookie` header values into one `Cookie: a; b; c` line, per spec,
  before forwarding to any HTTP/1.1 upstream. See
  `proxy::http::merge_split_cookie_headers`.
- **Added a per-host `rewrite_samesite_none_cookies` option**,
  downgrading `SameSite=None` to `SameSite=Lax` on every `Set-Cookie`
  response header for hosts that opt in. Real incident this exists
  for: an upstream application set `SameSite=None` unconditionally on
  its session cookie (an obsolete Chrome-v80-era compatibility
  workaround baked into that application, not anything this proxy
  controls), which modern browsers can silently drop even in ordinary
  first-party use -- confirmed via server-side logging showing a valid
  session cookie in the response but completely absent from the
  client's next request. Deliberately a generic proxy-level feature
  rather than a patch to the specific upstream application, so any
  operator hitting the same issue with a different backend can use it
  too. See `config::ProxyHost::rewrite_samesite_none_cookies` and
  `proxy::http::rewrite_samesite_none_to_lax`.
- **The real client IP is now forwarded to every upstream** via
  `X-Forwarded-For` (appended to, never replacing, any existing chain,
  since this proxy's own hop is the only one it can vouch for),
  `X-Forwarded-Proto: https`, and `X-Forwarded-Host` (the client's
  original declared host, captured before any `preserve_host: false`
  rewriting). Previously upstream applications saw every request as
  coming from the proxy's own address, which broke per-client IP
  logging, rate limiting, and access control at the application layer.
  See `proxy::http::forward_http` and `UpstreamOptions::client_ip`.
- **Fixed a real production bug: an HTTP/2 request's absolute-form URI
  was forwarded verbatim to an HTTP/1.1 upstream.** A real HTTP/2
  client's request target is absolute-form (scheme + authority +
  path); forwarding that unchanged produces an HTTP/1.1 request line
  meant for a forward proxy, not an origin server. Confirmed as a real
  bug via a Proxmox upstream (`pveproxy`) correctly rejecting it with
  "invalid proxy uri", while nginx (a different upstream) silently
  tolerated the malformed request line -- meaning this had been
  quietly working by accident for every nginx-backed host and only
  surfaced once a stricter upstream was added. `forward_http` now
  downgrades any absolute-form request URI to origin-form (path +
  query only) before forwarding. New test drives a real h2 connection
  through a raw-TCP-listening mock upstream and confirms the exact
  wire-level request line.

- **Fixed a real production bug: a genuine HTTP/2 request forwarded to
  the upstream with no `Host` header at all.** Real HTTP/2 clients
  (every modern browser) declare their target host via the `:authority`
  pseudo-header, never a literal `Host:` header -- confirmed live via a
  real upstream that correctly rejected the resulting Host-less
  forwarded request with its own 400 "missing required Host header".
  The connection to the upstream is always plain HTTP/1.1, which
  requires a literal `Host` header on the wire; `preserve_host: true`
  (the default) now synthesizes one from the request's own declared
  authority when no literal header exists, instead of forwarding
  nothing. `preserve_host: false` (rewrite to the upstream's own
  host:port) is unaffected. New test drives a real h2 connection with
  no Host header through a real upstream and confirms it receives one.
  See `proxy::http::forward_http`.
- **`acme_challenge_type: auto` now prefers dns-01 over http-01.**
  http-01 depends on this daemon's own port 80 actually being publicly
  reachable for the exact domain being issued -- NAT, a firewall, or
  the domain's own DNS not routing here yet can all silently break it
  in ways invisible from this end. Confirmed live: a real host's
  http-01 authorization failed outright, fast, with nothing on this
  side to explain why. dns-01 only depends on a working DNS provider
  credential, already required for any wildcard host anyway. `auto`
  previously picked http-01 whenever `force_https` was already on;
  it's dns-01 unconditionally now. Explicit `http01` remains available
  for anyone who genuinely wants the old behavior. Also fixed a related
  gap this exposed: a host with ACME disabled was still being forced to
  have a DNS credential configured, since the validation only checked
  what challenge type `auto` would resolve to, not whether ACME was
  even enabled -- previously masked because `auto` often resolved to
  http-01, which needs no credential.
- **Per-standalone-cert Organization/Organizational Unit**, overriding
  the global `acme.organization`/`acme.organizational_unit` config.toml
  default for one specific standalone DNS-01 cert (new optional fields
  on `POST /api/dns01-certs` and the Certificates tab's issuance form).
  Whatever's actually used is persisted (not just the override) so a
  later automatic renewal requests the exact same Subject even if the
  global default changes afterward.
- **Fixed a real production routing bug: a request's own `Host` header
  now always wins over the TLS connection's SNI when they disagree.**
  `sni` is captured once per TLS connection at handshake time, but a
  single connection can carry requests for more than one domain -- HTTP/2
  connection coalescing (RFC 7540 §9.1.1) lets a browser reuse an
  existing connection for a *different* origin whenever the connection's
  certificate also covers it (exactly what a wildcard/SAN cert does),
  and each request on that connection still carries its own real
  `:authority`/`Host`. Routing by SNI first sent every request after the
  first to whichever host the connection originally happened to be for.
  Confirmed as a real production bug: visiting store.jpps.us right after
  proxy.jpps.us (both under the same `*.jpps.us` wildcard cert, same
  bind_ip:port) served proxy.jpps.us's admin login page instead of the
  store. `sni` is still what `proxy::tls::CertResolver` uses to pick the
  TLS certificate itself; this only changes which *host* a request
  routes to. New regression test reproduces the exact scenario (two
  hosts, one stale connection-level SNI, a `Host` header for the other)
  and confirms the fix. See `proxy::handle_https_request`.
- **A wildcard cert now also covers its own bare apex** (`*.example.com`
  automatically requests `example.com` too, as a second SAN in the same
  certificate) -- matching how certbot/acme.sh commonly issue combined
  wildcard+apex certs, and how most operators expect a wildcard cert to
  behave. A wildcard alone never covers its own apex (standard X.509
  semantics), so this used to require a second, separately-managed
  certificate. Applies to both per-host ACME issuance and the standalone
  DNS-01 feature. Both authorizations validate via dns-01 against the
  *same* TXT record name (`_acme-challenge.example.com` -- a wildcard
  authorization's identifier is already the bare apex per RFC 8555) but
  with different content per challenge token; real DNS "create record"
  APIs add rather than overwrite, so both coexist and are independently
  cleaned up by their own record ids, with whatever was already created
  cleaned up even if a later record's creation fails partway through.
  The issued cert is published under *both* domain keys -- publishing
  only under the wildcard would leave the apex SAN practically
  unreachable, since `proxy::tls::select_cert_for_sni`'s wildcard
  fallback deliberately never matches the bare parent either. See
  `acme::domains_for_issuance` and `acme::issue_via_dns01`.
- **Organization/Organizational Unit requested in every issued CSR's
  Subject**, via new `acme.organization`/`acme.organizational_unit`
  config.toml fields. Only ever a *request*, not a guarantee -- Let's
  Encrypt and virtually every public CA issue Domain Validated certs,
  which by definition can't vouch for organizational identity, so these
  fields are silently discarded by their CAs; they only actually land in
  the issued certificate against a private/enterprise ACME CA that
  performs real organization vetting. See `acme::cert::generate_csr`.
- **HTTPS upstreams, including self-signed ones.** A host's `upstream`
  was always plain HTTP, even when the internal service behind it spoke
  TLS itself. Three new per-host settings: `upstream_https` (default
  `false`, unchanged behavior) makes `forward_http` speak TLS to the
  upstream over a real `tokio-rustls` client connection instead of
  plain TCP; `upstream_tls_verify` (default `true`) verifies the
  upstream's certificate chain against the bundled Mozilla root store
  (`webpki-roots`, no OpenSSL/system cert store needed) -- set `false`
  to accept a self-signed or otherwise untrusted upstream cert (the
  connection is still encrypted, just not authenticated, so this only
  makes sense for an upstream already reached over a network this proxy
  otherwise trusts); `upstream_preserve_host` (default `true`) forwards
  the client's original `Host` header unmodified as before, or `false`
  rewrites it to the upstream's own `host:port` for a backend that
  expects to see its own hostname rather than the public-facing one.
  Verified with real TLS handshakes end-to-end: a real self-signed
  upstream is reached when verification is off, genuinely rejected when
  it's on, and the `Host` rewrite is confirmed against what the
  upstream actually receives -- not just that the code compiles. See
  `proxy::upstream_tls` and `proxy::http::UpstreamOptions`.
- **The admin UI now surfaces an existing certificate when adding or
  editing a host.** Certs are keyed purely by domain
  (`proxy::tls::select_cert_for_sni`), decoupled from hosts entirely --
  a cert issued/uploaded beforehand, or left over from a host that was
  deleted and is now being re-added, was already usable with ACME left
  off, but there was no way to know that from the host form. Typing a
  domain that already has a matching cert now shows its expiry and a
  hint that "Issue/renew a certificate automatically" can safely stay
  unchecked, instead of leaving the operator to guess or re-issue
  needlessly.
- **Split logging into `proxy.log`/`access.log`/`server.log`, plus a
  real per-request admin audit trail.** Everything used to go to one
  interleaved stdout/journald stream. `logging::init` now additionally
  writes three purpose-scoped files (daily-rotated, non-blocking) next
  to the sqlite DB (no new config field or packaging change --
  `/var/lib/rust-proxy` is already read-write for this daemon): `proxy.log`
  (the data plane -- listeners, TLS, forwarding, WebSocket/passthrough,
  plus ACME issuance/renewal) accepts `debug`-level events too, since
  real `tracing::debug!` calls already exist on the connection-handling
  hot paths and that's exactly the detail "especially for debugging"
  wants -- without changing stdout/journald's own default verbosity;
  `access.log` (new) is a dedicated admin API audit trail -- every
  request through method, path, status, latency, and how it
  authenticated (`session`/`token`/`unauthenticated`), which didn't
  exist in any form before; `server.log` catches everything else
  (startup/bootstrap, nftables sync, config loading). stdout/journald
  keeps behaving exactly as before, unified and `info`-level by
  default, still overridable via `RUST_LOG` -- these files are
  additive. See `logging.rs` and `api::routes::access_log`.
- **ACME contact email is now settable from the admin UI, not just
  config.toml.** Same "config.toml wins if set, else DB-backed and
  mutable via the API" precedence as the admin identity/setup wizard --
  set it in the setup wizard's new optional field, or later from the
  Certificates tab's new "ACME settings" section (`GET`/`PUT
  /api/acme-settings`), disabled with an explanatory note when
  config.toml already supplies it. A changed value takes effect the
  next time an `AcmeClient` is built (a restart, or the next init retry
  after an earlier failure) -- there's no RFC 8555 account-contact-update
  call here, so an already-running client keeps using whatever email it
  registered with until then; the UI's hint text says so.
  `acme.contact_email` is also no longer a required config.toml field
  (`toml::from_str` used to fail outright if it was missing) -- same
  "config.toml is only ever a seed, the DB-backed value takes over from
  there" precedence the admin identity fields already use, not a
  required setting. See
  `state::AppState::acme_contact_email`/`set_acme_contact_email` and
  `db::{load,set}_acme_contact_email`.
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
