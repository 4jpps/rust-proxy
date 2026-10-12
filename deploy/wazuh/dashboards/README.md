# Wazuh dashboards

OpenSearch Dashboards saved objects for the Wazuh dashboard.

- `rust-proxy.ndjson`: "Rust-Proxy" dashboard (alerts index plus an archives index pattern for access traffic; needs `logall` and filebeat archives enabled).
- `unifi.ndjson`: "UniFi Network" dashboard (needs the UniFi decoders/rules, rule group `unifi`, in `../`).

Import: Dashboard management > Saved objects > Import, or `POST /api/saved_objects/_import?overwrite=true` (multipart `file`).
Both default to the last 24 hours with a 1 minute refresh.
