# Changelog

## [Unreleased]

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
