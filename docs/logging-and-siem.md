# Logging and SIEM

## Log files

stdout (the systemd journal) behaves as you would expect: unified,
`info` level by default, overridable with `RUST_LOG`. In addition,
rust-proxy writes three purpose-scoped, daily-rotated files. By default
they sit alongside the sqlite database; set `admin.log_dir` in
`config.toml` to move them elsewhere.

| File | Contents |
|------|----------|
| `proxy.log` | The data plane: listeners, TLS, forwarding, WebSocket and passthrough, plus ACME issuance and renewal. Also accepts `debug`-level events without changing the journal's verbosity. |
| `access.log` | Every **admin API** request: method, path, status, latency, and how it authenticated (`session`, `token` or `unauthenticated`) and the `user` and `role` once signed in. The daemon's only per-request admin audit trail. It does not log proxied visitor traffic. |
| `server.log` | Everything else: startup, nftables sync, config loading. |

For per-request records of proxied traffic, use SIEM forwarding with the
`access` category below.

## SIEM / syslog forwarding (optional)

rust-proxy can forward security-relevant events to any syslog collector
or SIEM (Wazuh, Graylog, Splunk, rsyslog, Elastic and so on). It is **off
by default**, needs no particular product, and costs nothing unless
enabled.

Configure it in `config.toml` (read-only in the UI/API when present), or
at runtime from the UI's "SIEM / syslog forwarding" panel or
`PUT /api/siem`. Runtime settings are stored in the database and applied
live, with no restart.

```toml
[siem]
enabled        = true
host           = "siem.example.com"
port           = 514                # default 514
protocol       = "udp"              # udp | tcp | tls
syslog_format  = "rfc5424"          # rfc5424 | rfc3164
message_format = "json"             # json | kv | cef
facility       = "local0"           # name or 0-23
app_name       = "rust-proxy"
# hostname     = "proxy"            # default: this machine's hostname
categories     = ["denied", "admin", "cert", "system"]   # add "access" for every request
# tls_ca_file  = "/etc/ssl/siem-ca.pem"   # extra CA, on top of the public roots
queue_size     = 4096
```

### Events

| Category | Events |
|----------|--------|
| `denied` | `acl_ip_denied`, `ip_blocked`, `host_login_failure` |
| `admin` | `admin_auth_failure`, `admin_login`, `admin_access_denied` (a role was refused), `admin_change` (every non-GET admin API call, warning severity when it fails), `host_login_success` |
| `cert` | `cert_issued`, `cert_issue_failed` |
| `system` | `daemon_start`, `siem_test` |
| `access` | `http_request` (one per proxied HTTPS request; high volume, opt-in) |

Every event carries `event`, `category`, `severity` and `message`, plus
event-specific fields (`client_ip`, `domain`, `method`, `path`,
`http_status` and so on). `access` events also carry `user_agent`, `bytes`
and `has_query`.

### What is kept out of events

- Query strings are never logged.
- Any field whose name suggests a secret (password, token, cookie, authorization) is replaced with `[redacted]`, and passwords and tokens are never read into events.
- Control characters are stripped so a request cannot forge extra log lines.
- Values are capped at 1024 characters.

### Delivery

Delivery never blocks traffic. Events go through a bounded queue and are
**dropped** (and counted) when it is full or the collector is down. TCP and
TLS reconnect with 1 s to 60 s backoff; UDP re-resolves the hostname
every 5 minutes. `GET /api/siem` shows `sent`, `dropped`, `errors` and
`last_error`; `POST /api/siem/test` sends a `siem_test` event so you can
confirm the path end to end.

### Limitations

- Connections dropped by the kernel firewall never reach the daemon, so they are not forwarded.
- Port-forward passthrough has no application-level access list, so it produces no events.
- With TCP, the first event written to a connection the collector has silently closed may be lost before the reconnect.

## Wazuh

Use `syslog_format = "rfc3164"` and `message_format = "json"`. In Wazuh,
add a `<remote>` block with `<connection>syslog</connection>`, your chosen
port, and `<allowed-ips>` set to the proxy's address. Then install the
bundled decoders and rules from `deploy/wazuh/`:

- `rustproxy_decoders.xml` into `/var/ossec/etc/decoders`
- `rustproxy_rules.xml` into `/var/ossec/etc/rules`

The rules use IDs 100300 to 100399 and cover brute force, repeated
denials, scanner and probe activity, exploit paths, 5xx bursts,
unknown-host requests and request rate, with MITRE mappings. Normal
`access` traffic stays at level 2, so it is archived but does not alert.
Edit the hostname suffix list in rule 100371 to match your own domains.
`install-retention.sh` adds an optional log-retention cron job.
