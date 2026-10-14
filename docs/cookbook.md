# Cookbook

Worked recipes. They use the [API](api.md) so they are copy-pasteable;
every one can also be done in the web UI. Set `TOKEN` to an API token and
`API` to the admin URL first:

```sh
API=http://127.0.0.1:8084      # run on the proxy host itself
TOKEN=rpx_...
H=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')
```

## 1. Wildcard certificate with DNS-01

One certificate for `*.example.com` (and `example.com`), shared by every
subdomain host.

```sh
# 1. a DNS credential (Cloudflare shown)
curl -s "${H[@]}" -X POST $API/api/dns-credentials \
  -d '{"name":"cloudflare","provider":"cloudflare","token":"<API token>"}'

# 2. issue the wildcard (takes up to a minute)
curl -s "${H[@]}" -X POST $API/api/dns01-certs \
  -d '{"domain":"*.example.com","dns_credential_id":"<id from step 1>"}'

# 3. subdomain hosts reuse it, with ACME off
curl -s "${H[@]}" -X POST $API/api/hosts \
  -d '{"domain":"app.example.com","bind_ip_v4":"0.0.0.0","bind_port":443,"upstream":"127.0.0.1:8000","acme_enabled":false}'
```

If you have only one DNS credential, `dns_credential_id` can be left out.
It demonstrates: standalone certificates, and SNI falling back from an
exact match to a covering wildcard.

## 2. A public page with a private admin (deny_fallback)

Everything behind your home network, except a status page the world may
see.

```sh
# an IP allow list for your network
ACL=$(curl -s "${H[@]}" -X POST $API/api/acls \
  -d '{"name":"home","kind":"ip_allow","ip_entries":["203.0.113.0/28"]}' | jq -r .id)

curl -s "${H[@]}" -X POST $API/api/hosts -d "{
  \"domain\":\"hotspot.example.com\",\"bind_ip_v4\":\"0.0.0.0\",\"bind_port\":443,\"upstream\":\"10.0.0.50:80\",
  \"acl_ids\":[\"$ACL\"],
  \"deny_fallback\":{\"scope\":\"blocked\",\"redirect_path\":\"/live/\",\"lock\":true,
    \"allow_paths\":[\"/css/\",\"/js/\",\"/images/\"]}}"
```

People on the allowed network get the full site. Everyone else lands on
`/live/` and cannot go anywhere else. Full reference:
[deny_fallback](deny-fallback.md).

## 3. Lock one port to one path

A captive-portal or API port that must expose a single path.

```sh
curl -s "${H[@]}" -X POST $API/api/hosts -d '{
  "domain":"guest.example.com","bind_ip_v4":"0.0.0.0","bind_port":8444,
  "upstream":"10.0.0.20:8444","upstream_https":true,"upstream_tls_verify":false,
  "deny_fallback":{"scope":"everyone","allow_paths":["/guest/"]}}'
```

`upstream_tls_verify: false` is for an upstream with a self-signed
certificate. Anything outside `/guest/` returns `404` without reaching it.

## 4. Put the admin UI itself behind HTTPS and an allow list

Instead of leaving port 8084 open, serve the admin UI on a normal HTTPS
hostname with access control, and take the raw port off the wire.

```sh
ACL=$(curl -s "${H[@]}" -X POST $API/api/acls \
  -d '{"name":"admins","kind":"ip_allow","ip_entries":["203.0.113.0/28"]}' | jq -r .id)

curl -s "${H[@]}" -X POST $API/api/hosts -d "{
  \"domain\":\"proxy.example.com\",\"bind_ip_v4\":\"0.0.0.0\",\"bind_port\":443,\"upstream\":\"127.0.0.1:8084\",
  \"acl_ids\":[\"$ACL\"]}"

# only after you have confirmed the HTTPS URL works from an allowed address:
curl -s "${H[@]}" -X PUT $API/api/firewall-settings -d '{"expose_admin_port":false}'
```

The admin UI still requires its own login, so this is two layers. Test the
new URL from an allowed address **before** the last command, so you cannot
lock yourself out. SSH on port 22 remains open as your way back in.

## 5. Give a customer VM its own public IP

```sh
curl -s "${H[@]}" -X POST $API/api/hosting/pools \
  -d '{"name":"standard","cidr":"204.52.221.224/28","reserved":["204.52.221.225"],
       "vm_cidr":"172.16.63.0/24","gateway":"172.16.63.1"}'

curl -s "${H[@]}" -X POST $API/api/hosting/allocations \
  -d '{"class":"standard","name":"web01","customer":"Acme"}'
```

Configure the VM with the `provision` values from the response. Details
and the other endpoints are in [Hosting](hosting.md).

## 6. Migrate an NPM host

For each NPM proxy host, one request:

```sh
curl -s "${H[@]}" -X POST $API/api/hosts -d '{
  "domain":"app.example.com","bind_ip_v4":"0.0.0.0","bind_port":443,"upstream":"192.168.1.20:3000",
  "websockets":true,"force_https":true,"acme_challenge_type":"auto"}'
```

Test with `curl --resolve app.example.com:443:<proxy-ip> https://app.example.com/`
before moving DNS. The full concept map is in
[Migrating from Nginx Proxy Manager](migration-from-npm.md).
