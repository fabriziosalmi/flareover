---
title: "Troubleshooting"
description: "Common errors and what they mean. If your issue isn't here, open one on the repository with the relevant assess --json output"
---

Common errors and what they mean. If your issue isn't here, open one on the [repository](https://github.com/fabriziosalmi/flareover/issues) with the relevant `assess --json` output (scrubbed).

## Extraction & assessment

### `extract` fails with an auth error
`CLOUDFLARE_API_TOKEN` isn't set, or lacks read access to the zone. Use a **read-only** token that can see the zone (and, for `zones`, the account). flareover never needs write access to the source.

### `assess` exits non-zero on a "successful" run
That's by design — it's a CI gate:
- `0` = everything AUTO
- `11` = there are **ASK** items to answer
- `10` = there are **MANUAL** items to handle

Answer the ASKs with `resolve`; handle the MANUALs by hand. A non-zero exit is information, not failure.

### An item I expected to migrate is marked MANUAL
Check its rationale in `assess` — flareover names *why*. Common cases: a compound firewall expression (`and`/`or`), a Worker, a country/ASN **allowlist** (only IP allowlists map), Automatic HTTPS Rewrites, or a lifecycle transition. These have no faithful deterministic mapping and are surfaced rather than guessed. See the [Coverage Matrix](/docs/coverage-matrix/).

## Preparation

### An answered ASK didn't change the output
Make sure `--decisions decisions.lock` points at the file you actually answered, and that the answer key matches. Re-run `resolve` to regenerate the lock. Unanswered questions are intentionally not generated.

### `prepare --validate` fails
The generated Caddyfile or zone didn't parse. This usually means `caddy` isn't on `PATH` (validation shells out to it) — install the Caddy binary, or drop `--validate` to skip the parse check. If Caddy *is* installed and it still fails, that's a bug worth reporting with the generated `out/caddy/Caddyfile`.

## Provisioning

### `provision: --pdns-key is no longer accepted …`
Secrets are read from the environment only. Set `PDNS_API_KEY` / `CERTMATE_TOKEN` and drop the `--pdns-key` / `--certmate-token` flags:
```bash
export PDNS_API_KEY=… CERTMATE_TOKEN=…
```

### `unknown --dns "…"`
Typo in the DNS target. Valid values: `powerdns | scaleway | ovh | gandi | leaseweb | hetzner | route53 | clouddns | azure` for `provision` (plus `bunny` for `prepare`, which is preview-only). See [DNS Targets](/docs/dns-targets/).

### `--dns <provider>` needs an env var
Each managed backend reads its credentials from the environment — the error names the exact variable(s). See the [Security](/docs/security/) table.

### `no zone found for "…" (create it first)`
flareover manages *records*, not zones. Create the zone with your DNS provider first, then re-run `provision` — it never auto-creates the zone.

### `--dns bunny` is rejected by `provision`
bunny.net is **preview-only**: `prepare --dns bunny` emits a records file plus an `apply.sh` that uses the bunny.net CLI. Run that script to apply; there's no native `provision` path for bunny.

### `--dns route53 / clouddns / azure` prints a sovereignty note
That's intentional — these are US-operated and not sovereign. The note nudges you toward the EU-owned options. It doesn't stop provisioning.

## Object storage

### `--dest aruba needs --minio-endpoint …`
Aruba's S3 endpoint is account-specific (the *Service Point URL* from your account page). flareover won't guess it — pass it explicitly:
```bash
flareover storage buckets.json --dest aruba --minio-endpoint https://<your-service-point> --out ./out
```

### `unknown <provider> --region "…"`
Only EU regions are accepted, to keep the migration EU-scoped. The error lists the valid regions for that provider.

### A lifecycle rule didn't migrate
If it only tiers objects (a transition) or has no positive expiry (e.g. multipart-abort / noncurrent-version only), it's MANUAL — MinIO has no equivalent to emit. Only expiry rules with `> 0` days map.

## Cutover & guard

### `present` exits `12`
A **HARD** parity divergence between the live and staged edge (status code, redirect, header, or body). Fix the difference before cutting over — that's the gate doing its job. SOFT divergences are surfaced but don't block.

### `execute` exits `12`
The cutover was blocked (a gate didn't pass). Re-run `present` to see the specific divergence.

## General

### Which version am I running?
```bash
flareover version
```

### Verifying a downloaded binary
See [Installation](/docs/installation/) — verify the cosign-signed `checksums.txt`, then `sha256sum -c`.
