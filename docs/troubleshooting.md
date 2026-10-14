# Troubleshooting

Start with the service log. It lists each listener the daemon opened, ACME
progress, and nftables sync results:

```sh
systemctl status rust-proxy
journalctl -u rust-proxy --no-pager | tail -50
```

For more detail, `proxy.log` accepts `debug` events (see
[Logging](logging-and-siem.md#log-files)).

## I can't reach the admin UI

- **From another machine:** the admin port is firewalled by `admin.allowed_ips`. If it is set, connect from an allowed address, or use an SSH tunnel: `ssh -L 8084:127.0.0.1:8084 you@host`.
- **From the host itself:** `curl -s http://127.0.0.1:8084/api/version` should return JSON. If it does not, the service is not running; check the journal.
- **`expose_admin_port` is off:** by design, the port is reachable only over loopback. Use the tunnel.
- **A lockout you caused:** SSH on port 22 is never closed by rust-proxy. Log in over SSH and edit `/etc/rust-proxy/config.toml`, then restart.

## A certificate is not issuing

1. Look at the journal for the ACME error. Failures are logged with the domain and the stage.
2. **dns-01:** confirm the credential has permission to create and delete TXT records in that zone, and that the domain's zone is in that account. Issuance waits for DNS propagation, so allow up to a minute.
3. **http-01:** the CA must reach port 80 on this host for that exact domain from the internet. NAT, an upstream firewall, or DNS not yet pointing here all break it silently. Try `curl http://app.example.com/.well-known/acme-challenge/x` from outside. A 404 from rust-proxy means you reached it.
4. **Wildcard:** needs dns-01; there is no http-01 for wildcards.
5. **Let's Encrypt rate limits** apply to repeated failures. Wait before retrying a domain that has failed many times.
6. With `auto`, the daemon tries dns-01 and then http-01 once. If you know which will work, set the type explicitly to make the failure clearer.

If you uploaded your own certificate, the host must have `acme_enabled`
off, or the upload is rejected.

## A site returns 502 Bad Gateway

The proxy could not reach or talk to the upstream.

- Check `upstream` is `host:port` and reachable **from the proxy host**: `curl -v http://<upstream>/`.
- Upstream speaks TLS but `upstream_https` is off (or the reverse). A mismatch gives connection resets or garbage.
- Self-signed upstream certificate: set `upstream_tls_verify` to `false`.
- If the app complains about the wrong hostname, try `upstream_preserve_host`. It is on by default (the app sees your public domain); turn it off if the app expects its own `host:port`.

## WebSockets don't work

Enable `websockets` on the host. WebSocket clients negotiate HTTP/1.1; the
proxy deliberately does not enable HTTP/2 extended CONNECT, so clients fall
back to HTTP/1.1 cleanly.

## Login loops, or the app says "CSRF" or "session invalid"

Some applications hard-code `SameSite=None` on their session cookie. Modern
browsers increasingly drop those cookies even in ordinary first-party use.
Turn on the host's `rewrite_samesite_none_cookies`, which downgrades them to
`Lax`. Leave it off for apps that really need cross-site cookies.

## "Access denied" (403) or a plain "Not found" (404)

- **403 "Access denied"** on a host with an IP allow list: your source address is not in the list. If the proxy is behind another proxy or NAT, the address it sees may not be yours. Check `acl_ip_denied` events or the `client_ip` in SIEM output.
- **404 "Not found"** on a host with a `deny_fallback` of `scope: everyone`: the path is not in `allow_paths`. See [deny_fallback](deny-fallback.md).
- A page that loads without styles or scripts behind `deny_fallback` is missing `allow_paths` entries for its assets.

## A port or service isn't reachable

- Everything is default-DROP. A TCP/UDP service needs a [port rule](firewall.md#port-rules-tcpudp-passthrough). A host opens only its own `bind_port`.
- Inspect the generated ruleset: `sudo nft list ruleset`.
- If `nft` is missing, the journal logs one clear error at startup (the rest of the daemon keeps running).

## The firewall conflicts with something else

rust-proxy writes its own table and leaves other tables alone, but a
default-DROP table still applies alongside them. If another tool also
manages nftables, check both rulesets with `sudo nft list ruleset`.

## Hosting allocations don't forward

Use `POST /api/hosting/allocations/:id/check` to verify an allocation's
live state, and `GET /api/hosting/status` for the last apply result. Make
sure the host's forward policy accepts the VM network, since rust-proxy
never edits tables other than its own. See [Hosting](hosting.md).

## After an upgrade

Read [`CHANGELOG.md`](../CHANGELOG.md). rust-proxy is pre-1.0, so
configuration and API details can change. Nightly database backups are in
`/var/lib/rust-proxy/backups/`, so you can roll the database back along
with the binary.

## Still stuck

Open an issue at
[gitlab.jpps.us/jpps/rust-proxy/-/issues](https://gitlab.jpps.us/jpps/rust-proxy/-/issues)
with the version (`curl -s http://127.0.0.1:8084/api/version`), the
relevant journal lines, and your host configuration with secrets removed.
