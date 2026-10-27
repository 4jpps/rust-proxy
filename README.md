<p align="center">
  <img src="docs/logo.svg" alt="RustProxy" width="280">
</p>

# rust-proxy

**A self-hosted reverse proxy with built-in ACME, a default-deny firewall, and per-host access control.**

Primary home: https://gitlab.jpps.us/jpps/rust-proxy (issues, merge requests and releases live there). The GitHub copy at https://github.com/4jpps/rust-proxy is a read-only mirror, updated automatically from GitLab.

rust-proxy is a single Rust daemon that terminates TLS, gets and renews
its own certificates, routes traffic to your internal services, and
manages the host's nftables firewall to match. It has a small embedded
web UI and a REST API, and it installs from a signed `.deb`.

- **HTTP/1.1, HTTP/2 and WebSocket** reverse proxying with SNI-based TLS (rustls, no OpenSSL).
- **Native ACME client** (RFC 8555): dns-01 through Cloudflare, DigitalOcean, Hetzner, DuckDNS, GoDaddy, Namecheap or Route53, or http-01 with no DNS credentials. Wildcards supported.
- **Default-DROP nftables firewall** generated from your hosts and port rules. Only what you configure is reachable.
- **TCP/UDP port passthrough** for non-HTTP services.
- **Per-host access control**: IP allow lists, a built-in login page, and client-certificate auth, combined with OR.
- **Mobile passes**: get past your own IP allow lists from a phone on cellular. The RustProxy Mobile Pass app signs in with a login you choose, and while its switch is on the phone's *current* IP is let in for 10 minutes per check-in. See [Access control](docs/access-control.md#mobile-passes-getting-past-ip-allow-lists-while-mobile).
- **IP and ASN blocking**: deny lists that take IPs, CIDRs or whole AS numbers (`AS13238`), per host or global, enforced in the web layer *and* the firewall. See [Access control](docs/access-control.md#ip-and-asn-block).
- **Client certificates, managed for you**: issue and revoke them from the admin UI through TrustBridge, with OCSP revocation checking and an organization lock that rejects certificates from anyone else.
- **Per-host `deny_fallback`**: send blocked visitors to a public page, or lock a host to a path allow-list (for example only `/guest/`). See [deny_fallback](docs/deny-fallback.md).
- **Redirect hosts, static-file hosts, fixed-response hosts and path rewrites** alongside normal proxy hosts, plus **custom locations** (different upstreams per path) and an optional **block-common-exploits** filter.
- **Public-address hosting** (optional): 1:1 forward a routed public IP to a private customer VM.
- **SIEM/syslog forwarding** (optional), with Wazuh rules included.

![The Sites page lists every host with its upstream, bind address, certificate status and access lists.](docs/screenshots/hosts-list.png)

> **The first person to open a new instance becomes its admin.** A fresh
> install has no accounts. Browsing to `http://<host-ip>:8084/` shows a
> setup page, and whoever completes it first owns the instance. The admin
> port is open to any source until then, so open it yourself right after
> installing, and in the setup page choose which addresses may reach the
> admin UI (or reach the port through an SSH tunnel instead).

## Install

```sh
sudo mkdir -p /etc/apt/keyrings
sudo curl -fsSL https://repo.jpps.us/repo-signing-key.asc -o /etc/apt/keyrings/jpps-repo.asc
echo 'deb [signed-by=/etc/apt/keyrings/jpps-repo.asc] https://repo.jpps.us/stable /' | sudo tee /etc/apt/sources.list.d/jpps.list
sudo apt update
sudo apt install rust-proxy
```

Then open `http://<host-ip>:8084/`. A new instance takes you straight to the
setup page (there is no default password); the first person there becomes the
admin. The
full walkthrough, from install to your first HTTPS host, is in
[Getting started](docs/getting-started.md).

rust-proxy runs as a systemd service and manages the host's nftables
rules. It is not distributed as a Docker image and Docker support is not
planned.

## A quick example: lock a captive-portal port to one path

A UniFi Hosted Controller exposes its guest portal on port 8444. Nothing
else on that port should ever be reachable from the internet. One host
setting does it:

```json
{
  "domain": "guest.unifi.example.com",
  "bind_ip_v4": "0.0.0.0",
  "bind_port": 8444,
  "upstream": "10.0.0.20:8444",
  "upstream_https": true,
  "deny_fallback": { "scope": "everyone", "allow_paths": ["/guest/"] }
}
```

Every request outside `/guest/` gets a plain 404 and never reaches the
upstream. More on this, including redirecting blocked visitors to a
public page, in [deny_fallback](docs/deny-fallback.md) and the
[cookbook](docs/cookbook.md).

## How it compares to Nginx Proxy Manager

rust-proxy aims at the same job: a web UI in front of a reverse proxy
with automatic certificates. The differences, stated plainly:

- **Different shape.** One native binary and sqlite, installed from a `.deb` and run by systemd. No Docker, no separate nginx, no MariaDB.
- **It manages the firewall.** The host's nftables ruleset is generated from your configuration, default-DROP.
- **Access lists are reusable and named**, and a host can combine IP allow, login and client-certificate lists.
- **ASN blocking.** Enter an AS number and every prefix it announces is blocked, refreshed daily from RIPEstat. NPM has no ASN support; its access lists take individual addresses and ranges only.
- **Blocking reaches past HTTP.** NPM's access lists can deny addresses on a proxy host. rust-proxy's block lists can also be global (one switch covers every site) and are enforced in the firewall, so they stop TCP/UDP passthrough, SSH and hosted VMs too, with a SIEM event for every refused web request.
- **Client certificates are built in.** NPM has no client-certificate option in its UI or access lists (mutual TLS there means hand-written nginx config and your own CA). rust-proxy issues certificates for you through TrustBridge, checks revocation by OCSP, can lock every certificate-protected site to your organization, and can pass the verified identity to the backend.
- **Users have three fixed roles**: admin, operator (changes proxy config, cannot touch users, tokens or system settings) and viewer (read-only). API tokens carry a role too. See [Users and roles](docs/users-and-roles.md).
- **What NPM has that rust-proxy does not:** per-section permissions finer than those three roles, and a larger community.

If you are moving over, see [Migrating from Nginx Proxy Manager](docs/migration-from-npm.md).

## Documentation

| Page | What it covers |
|------|----------------|
| [Getting started](docs/getting-started.md) | Install, first-run wizard, DNS credential, first host, verifying it works |
| [Configuration](docs/configuration.md) | `config.toml`, every host field, ACME, DNS providers, redirect/static hosts |
| [Access control](docs/access-control.md) | IP allow, IP/ASN block, login and client-cert ACLs, and how they combine |
| [deny_fallback](docs/deny-fallback.md) | Blocked-visitor redirects, path locks and allow-lists |
| [Firewall](docs/firewall.md) | What the nftables ruleset does, always-open ports, port rules |
| [Hosting](docs/hosting.md) | Public IP pools and 1:1 forwards to customer VMs |
| [Users and roles](docs/users-and-roles.md) | Admin, operator and viewer roles, adding users, token roles |
| [API](docs/api.md) | Authentication, tokens and the endpoint reference |
| [Logging and SIEM](docs/logging-and-siem.md) | Log files, syslog forwarding, Wazuh rules |
| [Cookbook](docs/cookbook.md) | Worked recipes |
| [Troubleshooting](docs/troubleshooting.md) | Common problems and how to check them |
| [Architecture](docs/architecture.md) | Module layout, for contributors |
| [Deployment](docs/deployment.md) | systemd unit, capabilities, manual install, building from source |

## Status

rust-proxy fronts all of JPPS's public `*.jpps.us` sites, handling TLS
termination, SNI dispatch, Let's Encrypt issuance over DNS-01 and
dynamic firewalling, so it is used in production every day. It is
maintained by one person and is still pre-1.0: configuration and API
details can change between releases. Read [`CHANGELOG.md`](CHANGELOG.md)
before upgrading.

## Support

- **Bugs and questions:** [open an issue](https://gitlab.jpps.us/jpps/rust-proxy/-/issues).
- **Chip in:** rust-proxy is free under the AGPL-3.0. If it saves you time, you can [buy me a coffee](https://buymeacoffee.com/kb9gxk).

## License

rust-proxy is dual-licensed by Jeff Parrish PC Services LLC. Pick whichever fits:

- **AGPL-3.0**, free, see [LICENSE](LICENSE). If you modify rust-proxy and let others use it over a network, you must offer them your modified source.
- **Commercial License**, a one-time **$10** for a lifetime license with no source-sharing conditions, see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md) and buy it at [store.jpps.us](https://store.jpps.us/products/rust-proxy).

Running unmodified rust-proxy, or modified rust-proxy for yourself, needs nothing but the AGPL. Releases up to 0.1.3 were published under MIT and stay MIT.

Code contributions are welcome under a short [contributor agreement](CLA.md) that lets the project stay dual-licensed; see [CONTRIBUTING.md](CONTRIBUTING.md). You can also support the project with [Buy Me a Coffee](https://buymeacoffee.com/kb9gxk).
