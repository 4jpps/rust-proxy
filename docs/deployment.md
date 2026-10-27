# Deployment

rust-proxy runs on any Linux host with systemd and nftables, from a
Proxmox LXC with its own subnet to a single-IP VPS or a home server. The
installed `.deb` is the supported path. The signed apt repository
instructions are in [Getting started](getting-started.md#1-install).

## What the package does

`postinst` creates the `rust-proxy` system user, installs a working default
`/etc/rust-proxy/config.toml` on first install (admin UI on
`0.0.0.0:8084`, no admin account or DNS credential yet), starts the
service, and enables a nightly backup timer. Open the admin UI once to
finish setup.

## The systemd unit

`deploy/rust-proxy.service` runs the daemon as the non-root `rust-proxy`
user with exactly three capabilities, through `AmbientCapabilities` and
`CapabilityBoundingSet`:

| Capability | Used for |
|------------|----------|
| `CAP_NET_BIND_SERVICE` | Listening on privileged ports (80, 443) |
| `CAP_NET_ADMIN` | Managing nftables, and the hosting feature's addresses and routes |
| `CAP_NET_RAW` | The hosting reachability check's single ICMP ping |

It also sets `NoNewPrivileges`, `ProtectSystem=strict` and `ProtectHome`,
and gives the daemon write access only to `/var/lib/rust-proxy` (state,
certificates, logs) and its log directory. `LimitNOFILE=65536` allows many
concurrent connections. The admin port is additionally restricted to
`admin.allowed_ips` at the firewall layer, not just by session
authentication.

## Backups

`rust-proxy-backup.timer` runs nightly at 03:00. It takes a consistent
snapshot of the sqlite database while the daemon is running (using sqlite's
`VACUUM INTO`, not a raw file copy), compacts the live database, and
deletes backups older than 14 days. Backups go to
`/var/lib/rust-proxy/backups/`. You can run the same operation by hand:

```sh
sudo -u rust-proxy rust-proxy --config /etc/rust-proxy/config.toml \
  backup-and-compact /var/lib/rust-proxy/backups/manual.db
```

The destination must not already exist.

## Hashing a password for `config.toml`

```sh
rust-proxy hash-password 'your-real-password'
```

Use the output as `admin.admin_password_hash`. See
[Configuration](configuration.md#admin-identity-in-configtoml).

## Releases

Every `vX.Y.Z` tag is built and published by CI to the project's Releases
page and to the signed apt repository. You can also download a release
`.deb` and install it with `dpkg -i`.

## Manual install

```sh
cargo build --release
sudo install -m 755 target/release/rust-proxy /usr/bin/rust-proxy
sudo useradd --system --home /var/lib/rust-proxy --shell /usr/sbin/nologin rust-proxy
sudo install -d -m 750 -o rust-proxy -g rust-proxy /etc/rust-proxy
sudo install -m 640 -o root -g rust-proxy deploy/config.toml.example /etc/rust-proxy/config.toml
sudo install -m 644 deploy/rust-proxy.service deploy/rust-proxy-backup.service \
  deploy/rust-proxy-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rust-proxy rust-proxy-backup.timer
```

Then edit `/etc/rust-proxy/config.toml` as described in
[Configuration](configuration.md).

## Upgrading

```sh
sudo apt update && sudo apt install --only-upgrade rust-proxy
journalctl -u rust-proxy --no-pager | tail -20
```

For a manual binary swap, check the new binary against the live
configuration before restarting:

```sh
/tmp/rust-proxy-new check --config /etc/rust-proxy/config.toml
```

`check` validates the config, upgrades a private snapshot of the
database (the live file is never written), loads hosts and certificates,
and has `nft -c` validate the firewall ruleset without loading it. It
exits non-zero if anything would fail. Add `--print-ruleset` to see the
ruleset. Run it as root so `nft -c` can run.

## Health check

`GET /healthz` on the admin port needs no login (the admin port is
already limited by the admin allow list). It returns `200` when every
check passes and `503` otherwise, with one entry per check: database,
firewall (last apply succeeded within 15 minutes), certificates (nearest
expiry at least 7 days away), disk (at least 5% free where the database
lives), file descriptors (under 90% of the limit), hosting (when used),
and how many clients hold connections. It never changes anything and
answers from a 5-second cache.

```sh
curl -s http://127.0.0.1:8084/healthz
```

Read [`CHANGELOG.md`](../CHANGELOG.md) first. The project is pre-1.0 and
configuration or API details can change between releases.

## Docker

rust-proxy is not distributed as a Docker image, and Docker support is not
planned. It manages the host's nftables rules (`CAP_NET_ADMIN`) and is
built to run as a normal systemd service.
