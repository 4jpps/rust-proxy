# API

Everything the admin UI does is available over a REST API. Every route
under `/api/*` except `/api/login`, `/api/logout`, `/api/setup-status`,
`/api/setup` and `/api/version` requires authentication, and accepts
either of two independent credentials:

- **Session cookie**: what the web UI uses. `POST /api/login` with `{"username","password"}` sets an HTTP-only, `SameSite=Lax` cookie good for 12 hours. `POST /api/logout` clears it.
- **API token**: `Authorization: Bearer <token>`, for scripts, CI and other tools.

`GET /api/setup-status` returns `{configured, client_ip}` (`client_ip` only
while unconfigured). `POST /api/setup` (only until an admin exists) takes
`{username, password, acme_contact_email?, dns_credential?, admin_allowed_ips?,
expose_admin_port?}`. `admin_allowed_ips` lists IPs or CIDRs allowed to reach
the admin port and is rejected if it excludes the caller. Anything
`config.toml` already sets is left alone.

Every credential carries a **role** (`admin`, `operator` or `viewer`, see
[Users and roles](users-and-roles.md)) and the role limits what it can
reach. A token's role is chosen when it is minted and defaults to
`admin`, which is what every token was before roles existed. **Treat an
admin token like a password.** Anyone holding one can reconfigure the
proxy and the firewall behind it. For a script that only reads, mint a
`viewer` token.

A request the role does not allow gets `403` with
`{"error": "..."}` and is recorded as an `admin_access_denied` SIEM event.

The admin API is on the admin port (default 8084). That port is
firewalled by `admin.allowed_ips`, so call it from an allowed address or
from the host itself (`http://127.0.0.1:8084`).

## Tokens

You need one valid credential to mint the first token, so sign in once
with the password:

```sh
curl -c /tmp/cookies -X POST https://proxy.example.com/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}'

curl -b /tmp/cookies -X POST https://proxy.example.com/api/tokens \
  -H 'Content-Type: application/json' -d '{"name":"ci pipeline","role":"operator"}'
# -> {"id":"...","name":"ci pipeline","role":"operator","token":"rpx_...","created_at":"..."}
```

The `token` field is shown **once**. Only its SHA-256 hash is stored, so a
lost token means minting a new one.

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/tokens` | `{id, name, role, created_at, last_used_at}`. Never the token or its hash. `last_used_at` is `null` until first use, so unused tokens are easy to spot. |
| POST | `/api/tokens` | Body `{"name", "role"}`; `role` is optional and defaults to `admin`. Response includes the plaintext once. |
| DELETE | `/api/tokens/:id` | Revokes immediately. |

Token management is admin-only, for every method.

## Users and roles

Admin-only, for every method. Full explanation in
[Users and roles](users-and-roles.md).

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/users` | The owner first (`primary: true`, always admin, not editable), then every stored user: `{id, username, role, disabled, primary, created_at, last_login_at}`. |
| POST | `/api/users` | Body `{"username", "password", "role"}`. Username is 1-64 characters of letters, digits, `.`, `_`, `@` or `-`; password at least 8 characters. `409` if the name is taken (case-insensitive) or is the owner's. |
| PUT | `/api/users/:id` | Body with any of `role`, `disabled`, `password` (an admin reset). Takes effect on the user's next request, even with a cookie that is still valid. |
| DELETE | `/api/users/:id` | Removes the user immediately. |

Open to every signed-in role:

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/me` | `{username, role, via, primary}`. `via` is `session`, `token` or `cert`. The web UI uses it to hide what the role cannot use. |
| POST | `/api/me/password` | Body `{"current_password", "new_password"}`. Only for users stored in the database, signed in with a session. The owner, tokens and client certificates get `400`. |

## Endpoints

Errors are `{"error": "message"}` with `400`, `404`, `409`, `500` or `502` (the license store was unreachable).
`bind_ip_v4`/`bind_ip_v6` are checked against `network.bind_ranges`
exactly as the UI's own submissions are. There is no separate, looser path
for the API.

### Hosts and port rules

| Method | Path | Body or notes |
|--------|------|---------------|
| GET | `/api/dashboard` | Counts of hosts, port rules and certificates, plus the configured `bind_ranges` |
| GET | `/api/hosts` | |
| POST | `/api/hosts` | See the field table in [Configuration](configuration.md#hosts): `domain`, `bind_ip_v4`, `bind_ip_v6`, `bind_port`, `upstream`, `upstream_https`, `upstream_tls_verify`, `upstream_preserve_host`, `websockets`, `force_https`, `acme_enabled`, `acme_challenge_type`, `acl_ids`, `dns_credential_id`, `redirect`, `path_rewrite`, `static_root`, `rewrite_samesite_none_cookies`, `pass_client_cert_header`, `deny_fallback`, `locations`, `block_exploits`, `fixed_response`, `hsts`, `hsts_subdomains`, `rate_limit_per_minute`, `enabled` |
| PUT | `/api/hosts/:id` | Same shape as POST |
| DELETE | `/api/hosts/:id` | |
| GET | `/api/port-rules` | |
| POST | `/api/port-rules` | `{"bind_ip_v4","bind_ip_v6","port_start","port_end","protocol","description","passthrough_target","acl_ids","enabled"}` |
| PUT, DELETE | `/api/port-rules/:id` | PUT takes the same shape as POST |

```sh
curl -X POST https://proxy.example.com/api/hosts \
  -H "Authorization: Bearer rpx_..." -H 'Content-Type: application/json' \
  -d '{"domain":"app.example.com","bind_ip_v4":"10.0.0.2","bind_port":443,
       "upstream":"127.0.0.1:8000","websockets":true}'
```

### Certificates and DNS

| Method | Path | Body or notes |
|--------|------|---------------|
| GET | `/api/certs` | `{domain, not_after, days_remaining}` per issued or uploaded certificate |
| POST | `/api/certs` | `{"domain","fullchain_pem","private_key_pem"}`: upload your own |
| DELETE | `/api/certs/:domain` | |
| GET | `/api/dns01-certs` | Tracked standalone certificates |
| POST | `/api/dns01-certs` | `{"domain","dns_credential_id","organization","organizational_unit"}`. Issues synchronously (up to a minute) and persists only on success |
| DELETE | `/api/dns01-certs/:id` | Stops renewal tracking. The issued certificate keeps working |
| GET, POST | `/api/dns-credentials` | POST body `{"name","provider","token"}`. List never returns the token |
| DELETE | `/api/dns-credentials/:id` | |
| GET, PUT | `/api/acme-settings` | `{contact_email, from_config}`. PUT is refused (409) if `config.toml` supplies it |

### Access control

| Method | Path | Body or notes |
|--------|------|---------------|
| GET | `/api/acls` | `{id, name, kind, created_at, global}`, plus `asn_status` for block lists. Never entries or credentials |
| POST | `/api/acls` | `{"name","kind"}` with `kind` one of `ip_allow`, `ip_block`, `login`, `client_cert`, plus `ip_entries` (IPs, CIDRs, and `AS<n>` for `ip_block`) or `credentials` |
| GET, DELETE | `/api/acls/:id` | DELETE is refused (409) while any host selects it |
| POST | `/api/acls/:id/ip-entries` | `{"cidr","description"}`. For an `ip_block` list `cidr` may be `AS<n>` |
| PUT | `/api/acls/:id/global` | `{"global":true}` makes an `ip_block` list apply to every host and the whole firewall |
| PUT | `/api/acls/:id/mobile-login` | `{"login_acl_id":"<login list id>"}` lets that login list's phones hold [mobile passes](access-control.md#mobile-passes-getting-past-ip-allow-lists-while-mobile) for this `ip_allow` list; `null` unlinks |
| GET, PUT | `/api/mobile-pass` | `{enabled, path, pass_secs, passes:[{login_list, login_list_name, username, device, ip, granted_at, expires_at}]}`; PUT `{"enabled":bool}` (admin), off also ends every pass |
| DELETE | `/api/mobile-pass/passes` | Ends every mobile pass now (admin) |
| POST | `/api/acls/:id/credentials` | `{"username","password"}` |
| POST | `/api/acls/:id/client-cert-entries` | `{"subject","description"}` |

Entries are removed with `DELETE` on the same path plus `/:entry_id` (or
`/:credential_id`), and client-cert entries can be edited with `PUT`.

### Settings, SIEM and hosting

| Method | Path | Notes |
|--------|------|-------|
| GET, PUT | `/api/firewall-settings` | GET returns `{expose_admin_port, admin_allowed_ips, allowed_ips_from_config, from_config}`. PUT takes `{expose_admin_port?, admin_allowed_ips?}` (both optional, admin only). `admin_allowed_ips` is a list of IPs or CIDRs; empty allows any address. A list that excludes the caller's own non-loopback address is refused with 400. A value that `config.toml` sets is refused with 409. |
| GET, PUT | `/api/default-site` | `{mode, redirect_url, custom_html}`. See [Default site](configuration.md#default-site) |
| GET, PUT, DELETE | `/api/license` | PUT `{"license_key"}` validates once against the store. GET returns `{licensed, licensee, key_hint, expires_at, lifetime, validated_at}`, never the full key. See [Commercial license](configuration.md#commercial-license) |
| GET, PUT | `/api/siem` | See [Logging and SIEM](logging-and-siem.md) |
| POST | `/api/siem/test` | Sends a `siem_test` event |
| | `/api/hosting/*` | See [Hosting](hosting.md) |
| GET | `/api/firewall/preview` | The ruleset that would be applied now, diffed against the last one applied: `{changed, added, removed, diff: [{op, text}], last_applied_at, last_apply_ok, admin_reachable_from_you, your_ip}`. `op` is `" "`, `"-"` or `"+"`; unchanged runs collapse to `…` |
| POST | `/api/firewall/preview` | Same, for a what-if: any of `{hosts, port_rules, admin_allowed_ips}` replaces the live value. Nothing is saved or applied. `admin_reachable_from_you` says whether your address could still reach the admin port |
| GET | `/api/version` | No authentication needed |
| GET | `/healthz` | No authentication needed. See [Deployment](deployment.md#health-check) |

## Audit trail

Every admin API request is recorded in `access.log` with its method,
path, status, latency, how it authenticated (`session`, `token` or
`unauthenticated`) and, once signed in, the `user` and `role`. Non-GET
calls are also emitted to SIEM as `admin_change` events, and a request
refused for its role as `admin_access_denied`, both carrying the same
`user` and `role` fields.
