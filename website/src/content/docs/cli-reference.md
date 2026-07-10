---
title: "CLI Reference"
description: "flareover <phase [args] flareover"
---

```
flareover <phase> [args]
flareover version
```

All credentials are read from **environment variables**, never passed on the command line. See [Security](/docs/security/) for the full list.

## Phases

### `zones`
List every zone the token can see (an account-scoped read-only token can migrate any or all of them). Needs `CLOUDFLARE_API_TOKEN`.

### `extract <domain|zone-id>`
Read a live zone (read-only API) into a snapshot JSON on stdout. Needs `CLOUDFLARE_API_TOKEN`.
```bash
flareover extract example.com > zone.snapshot.json
```

### `assess <snapshot.json>`
Classify a snapshot into an honest AUTO/ASK/MANUAL coverage report.

| Flag | Effect |
|------|--------|
| `--md` | Emit the report as Markdown (a migration-report fragment) |
| `--json` | Emit the raw findings as JSON |
| `--html` | Emit a self-contained, shareable HTML report |

**Exit codes:** `0` = all AUTO · `11` = has ASK items · `10` = has MANUAL items. (Useful as a CI gate.)

### `resolve <snapshot.json>`
Walk the ASK questions into a `decisions.lock`. Interactive on a TTY.

| Flag | Effect |
|------|--------|
| `--defaults` | Accept the safe default for every ASK |
| `--merge <file>` | Layer answers onto an existing lock |

### `cost <snapshot.json>`
Estimate managed-edge tier/add-on cost vs a flat EU sovereign stack.

| Flag | Effect |
|------|--------|
| `--vps <eur/mo>` | Override the assumed EU VPS monthly price |

### `prepare <snapshot.json>`
Generate the target-stack artifacts (Caddyfile, caddy-waf rules, PowerDNS zone, …) for the AUTO + answered-ASK surface, **plus a `MIGRATION.md`** report.

| Flag | Effect |
|------|--------|
| `--decisions <file>` | JSON map of ASK question id → answer (`decisions.lock`) |
| `--edge-ip <ip>` | Public IP of the new Caddy edge (proxied records repoint here) |
| `--ca <name>` | Default cert CA: `letsencrypt` (default) \| `actalis` (EU CA) |
| `--stack <id>` | Target stack profile (default: `caddy`) |
| `--dns <id>` | Authoritative DNS target — see [DNS Targets](/docs/dns-targets/) |
| `--out <dir>` | Write artifacts under `<dir>` (default: stdout preview) |
| `--validate` | Prove the generated Caddyfile + zone parse (`caddy validate`) |
| `--mesh-edge [name=]<host:port>` | WireGuard tunnel to keep an existing origin unchanged; repeat for an HA edge front |
| `--edge-provider <key>` | Emit a cloud-init to boot each edge on that provider (requires `--mesh-edge`) |

### `provision …`
Stand the target up via APIs (DNS zone + DNSSEC, CertMate DNS-01 certs).

| Flag | Effect |
|------|--------|
| `--snapshot <file>` / `--decisions <file>` | Inputs |
| `--edge-ip <ip>` | The edge IP proxied records point at |
| `--pdns-url <url>` | Self-hosted PowerDNS API (auth: `PDNS_API_KEY` env) |
| `--dns <id>` | Managed DNS target instead of PowerDNS — see [DNS Targets](/docs/dns-targets/) |
| `--nameservers a,b` | Delegation NS to record for the registrar step |
| `--certmate-url <url>` | CertMate API (auth: `CERTMATE_TOKEN` env) |
| `--certmate-dns <provider>` | DNS provider CertMate solves DNS-01 against (pre-cutover, use the source) |
| `--ca <name>` | `letsencrypt` \| `actalis` |

### `present …`
Parity gate: probe the live edge vs the staged edge (`--after-addr <host:port>`) and diff status / redirects / headers / body. **Exit `12`** on a HARD divergence.

### `execute …`
Orchestrate the phases live up to the gated cutover. The DNS flip stays your explicit step. **Exit `12`** if the cutover is blocked.

### `storage <buckets.json>`
Migrate object storage (R2/S3) → self-hosted MinIO (default) or managed EU S3. See [Object Storage](/docs/object-storage/).

| Flag | Effect |
|------|--------|
| `--dest <id>` | `minio` (default) \| `scaleway` \| `ovh` \| `contabo` \| `aruba` |
| `--region <r>` | Provider region (EU-scoped) |
| `--minio-endpoint <url>` | S3 endpoint (required for `--dest aruba`; also the self-host MinIO endpoint) |
| `--extract-r2` / `--extract-s3` | Extract buckets from R2 / S3 first |

### `doctor …`
Read-only pre-flight — is every target reachable, authorized, and configured? GO/NO-GO before you provision (exit `0` only when ready).

| Flag | Effect |
|------|--------|
| `--pdns-url <url>` | Probe the PowerDNS API + auth (`PDNS_API_KEY` env) |
| `--certmate-url <url>` | Probe CertMate health + DNS-provider config (`CERTMATE_TOKEN` env) |
| `--minio-endpoint <url>` | Probe MinIO/S3 reachability |
| `--spm-url <url>` | Probe secure-proxy-manager readiness |
| `--check-caddy` | Check the local Caddy build (caddy-waf + souin present) |

### `guard --url <url> …`
Failguards watchdog: health-watch + rollback/failover trigger.

| Flag | Effect |
|------|--------|
| `--on-unhealthy "<cmd>"` | Command to run on an unhealthy result |
| `--interval <dur>` | Poll interval (e.g. `30s`) |
| `--once` | Run a single check and exit |

### `providers`
List EU edge providers with their honest sovereignty tier (EU-owned vs US-operator/EU-region). Use a key with `prepare --edge-provider <key>`. See [Sovereignty Tiers](/docs/sovereignty-tiers/).

### `version`
Print the build version.

## Exit-code summary

| Code | Where | Meaning |
|------|-------|---------|
| `0` | all | Success / clean |
| `1` | all | Runtime error |
| `2` | all | Usage / bad arguments |
| `10` | `assess`, `storage` | MANUAL items present |
| `11` | `assess`, `storage` | ASK items present (no MANUAL) |
| `12` | `present`, `execute` | Parity divergence / cutover blocked |
