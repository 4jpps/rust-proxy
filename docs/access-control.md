# Access control

Each host can gate who reaches it, at the application layer, on top of
the [firewall](firewall.md). Gates are built from **named, reusable ACLs**.
You create an ACL once, add entries to it, and any number of hosts can
select it. Changing an entry (adding an IP, rotating a password) happens
once, in the ACL, not once per host.

A host selects zero or more ACLs through `acl_ids`. A host with none is
open to everyone.

![The Access lists tab with an IP allow list and a login list.](screenshots/access-lists.png)

![Managing the entries of an IP allow list.](screenshots/access-list-entries.png)

## ACL kinds

### IP allow

A list of CIDRs (`"10.0.0.0/24"`) or bare IPv4 addresses (treated as
`/32`).

```sh
curl -X POST https://proxy.example.com/api/acls \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"office","kind":"ip_allow","ip_entries":["203.0.113.0/28","198.51.100.7"]}'

# add one later
curl -X POST https://proxy.example.com/api/acls/$ID/ip-entries \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"cidr":"192.0.2.0/24","description":"branch office"}'
```

### Login

A list of username and password pairs. A visitor without a valid session
gets a real HTML login page in place of the upstream, rather than an HTTP
Basic Auth prompt, so password managers can offer to save the credential.
A successful login sets a signed, `HttpOnly`, `Secure` session cookie
scoped to that one host; a session for one domain is never accepted on
another. Passwords are hashed with argon2 when the ACL is created and are
never stored or returned in plaintext.

```sh
curl -X POST https://proxy.example.com/api/acls \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"staff","kind":"login","credentials":[{"username":"alice","password":"..."}]}'
```

### Client certificate

A client-certificate ACL lets a visitor who presents a valid client
certificate skip the login page. Add the allowed certificate subjects with
`POST /api/acls/:id/client-cert-entries`, body `{"subject","description"}`.
A verified certificate passes only if its subject is listed. **A list with
no entries trusts no certificate.**

> **Current limitation:** the client-certificate verifier trusts a single
> built-in root, the JPPS TrustBridge CA. It is not yet configurable, so
> this kind is only useful if you use TrustBridge.

**Revocation.** Besides the chain and expiry, each certificate is checked
against TrustBridge's OCSP responder (`https://ocsp.pki.jpps.us` by default;
set `RUST_PROXY_OCSP_URL` to change it, or to an empty value to turn the
check off). A revoked certificate is treated as if the visitor had presented
none, so the host falls back to its login page and no identity headers are
forwarded. If the responder cannot be reached, the certificate is allowed
(fail open) and the check is retried shortly after. A revocation, once seen,
is remembered in the database and stays in force even if the responder later
fails to answer.

If you want to hand the verified subject to your upstream (so an app can
skip its own login), turn on a host's `pass_client_cert_header` and set
the top-level `client_cert_forward_token` in `config.toml`
(`openssl rand -hex 32`). The proxy then sends `X-Client-Cert-Subject`
plus `X-RustProxy-Client-Cert-Token`. The upstream must check that **both**
are present and the token matches, otherwise a process that can reach the
upstream directly could forge the subject header. With no token
configured, the option does nothing.

## How the gates combine

For a host that selects ACLs, a visitor gets through if **any** of these
is true:

1. Their source IP is in a selected IP-allow list.
2. They presented an accepted client certificate (client-cert ACL selected).
3. They hold a valid login session (login ACL selected), after the login page.

In other words IP allow, client cert and login are alternatives (OR), not
a chain. The common pattern is IP allow plus login: people on the trusted
network walk straight in, everyone else sees the login page.

What a visitor who fails every gate sees depends on what is selected:

| Selected | A visitor who does not match |
|----------|------------------------------|
| IP allow only | The "Access denied" page (HTTP 403), or the host's [`deny_fallback`](deny-fallback.md) if one is set |
| Login (with or without IP allow) | The login page. Login always takes precedence over `deny_fallback` |

Several lists of the same kind combine by union: any selected IP list's
range is enough, and any selected login list's credentials work.

Deleting an ACL that a host still selects is refused (HTTP 409). Remove
it from every host first.

## Port rules

A port rule (TCP/UDP passthrough) can also select ACLs, but only IP-allow
lists have any effect there. A login list is accepted but contributes
nothing, because passthrough has no HTTP layer to show a login page on.
Passthrough produces no application-level events either.

## Denials are logged

Refused requests are emitted as `acl_ip_denied` and `host_login_failure`
events when [SIEM forwarding](logging-and-siem.md) is on.
