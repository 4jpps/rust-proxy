# Migrating from Nginx Proxy Manager

rust-proxy covers the same core job as Nginx Proxy Manager (NPM): a web
UI in front of a reverse proxy, with automatic certificates. This page
maps NPM's concepts onto rust-proxy and lists what has no equivalent, so
you can decide whether to move before you start.

There is **no automatic importer**. You recreate hosts by hand or with a
short script against the [API](api.md).

## What is different

- **No Docker, no nginx.** rust-proxy is one native daemon with an embedded sqlite database, installed from a `.deb` and run by systemd.
- **It owns the host's firewall.** It builds a default-DROP nftables table from your hosts and port rules. If something else already manages nftables on the machine, read [Firewall](firewall.md) first.
- **Ports 22, 80, 443 and the admin port are always open.** See [Firewall](firewall.md#always-open).
- **Users have three fixed roles** (admin, operator, viewer) rather than NPM's per-section permissions. See [Users and roles](users-and-roles.md). Your NPM users are not imported; recreate them in the Users tab.

## Concept map

| NPM | rust-proxy |
|-----|------------|
| Proxy Host | A host with an `upstream` |
| Redirection Host | A host with a [`redirect`](configuration.md#redirect-hosts) |
| Streams (TCP/UDP) | A [port rule](firewall.md#port-rules-tcpudp-passthrough) with a `passthrough_target` |
| Access List (IP allow) | An [IP allow ACL](access-control.md#ip-allow) |
| Access List (username and password) | A [login ACL](access-control.md#login). It shows an HTML login page, not a browser Basic Auth prompt |
| Access List (deny addresses) | An [IP block list](access-control.md#ip-and-asn-block). It also takes AS numbers and can be made global |
| Access List "Satisfy Any" | The default. IP allow, client cert and login are alternatives (OR) |
| Let's Encrypt certificate (HTTP challenge) | `acme_enabled` with `acme_challenge_type: http01` |
| Let's Encrypt certificate (DNS challenge) | `dns01`, with a [DNS credential](configuration.md#dns-providers) |
| Custom certificate | `POST /api/certs` with `acme_enabled` off |
| Force SSL | `force_https` (on by default) |
| Websockets Support | `websockets` |
| Scheme / Forward host and port | `upstream`, `upstream_https` |
| Block Common Exploits | `block_exploits` (see [Configuration](configuration.md#block-common-exploits)) |
| Client certificates (hand-written nginx config) | A [client-certificate ACL](access-control.md#client-certificate), with issuing, revocation and an organization lock in System, Client certificates |
| Advanced tab (custom nginx config) | No equivalent. Closest are `path_rewrite` and `rewrite_samesite_none_cookies` |
| Custom Locations (different upstream per path) | `locations` (see [Configuration](configuration.md#custom-locations)) |
| 404 Hosts | **Hosts, Add 404 host** (or the **Maintenance / 404** site type) in the UI, or `fixed_response` in the API (see [Configuration](configuration.md#fixed-response-hosts)) |
| Settings, Default Site | **System, Default site**: not found, congratulations page, no response, redirect or custom HTML (see [Configuration](configuration.md#default-site)). TLS connections for names with no certificate are refused before this applies |
| HSTS Enabled, HSTS Sub-domains | `hsts`, `hsts_subdomains` (see [Configuration](configuration.md#hsts)). No `preload` flag |
| Users and roles | Users tab with `admin`, `operator` and `viewer` roles (see [Users and roles](users-and-roles.md)). NPM's finer per-section permissions have no equivalent |

rust-proxy also does things NPM does not: [ASN blocking and global block lists](access-control.md#ip-and-asn-block) (also enforced in the [firewall](firewall.md#block-lists)), built-in [client certificates](access-control.md#client-certificate) with revocation checking, [`deny_fallback`](deny-fallback.md) path locks and the firewall itself; the [README](../README.md#how-it-compares-to-nginx-proxy-manager) summarizes the differences.

## Before you move

1. **Check you do not depend on the Advanced tab's custom Nginx config.** Custom Locations are supported (`locations`), but raw Nginx directives are not and will not be. Keep a site that needs them on NPM.
2. **List your DNS provider.** dns-01 supports Cloudflare, DigitalOcean, Hetzner, DuckDNS, GoDaddy, Namecheap and Route53. If you use another provider, use http-01 or upload certificates yourself.
3. **Plan the cutover for ports 80 and 443.** Only one thing can listen on them. Move one host at a time using a second IP or a test hostname, or schedule a short window.

## A migration path

1. Install rust-proxy on a spare IP or host, and finish [Getting started](getting-started.md).
2. For each NPM proxy host, create the equivalent host. Start with the least important one.
3. Let certificates issue. With dns-01 this works before DNS points here; with http-01, DNS must already reach the new host.
4. Test with `curl --resolve app.example.com:443:<new-ip> https://app.example.com/` before changing any DNS.
5. Move DNS or the port-forward for that host, and watch `journalctl -u rust-proxy`.
6. Repeat, then retire NPM.

Reusable ACLs are a good place to save time: create one `office` IP-allow
list once and select it on every host that used the same NPM access list.
