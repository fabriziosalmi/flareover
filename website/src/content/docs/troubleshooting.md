---
title: "Troubleshooting"
description: "flareover error messages and what to do about them: auth failures, non-zero exit codes, missing env vars, DNS and storage targets, port 53 conflicts, parity failures."
---

Common errors and what they mean. If your issue isn't here, open one on the [repository](https://github.com/fabriziosalmi/flareover/issues) with the relevant `assess --json` output (scrubbed), or ask in [Discussions](https://github.com/fabriziosalmi/flareover/discussions) if you're not sure it's a bug.

## Extraction & assessment

### `extract` fails with an auth error
`CLOUDFLARE_API_TOKEN` isn't set, or lacks read access to the zone. Use a **read-only** token that can see the zone (and, for `zones`, the account). flareover never needs write access to the source.

### `assess` exits non-zero on a "successful" run
That's by design. It's a CI gate:
- `0` = everything AUTO
- `11` = there are **ASK** items to answer
- `10` = there are **MANUAL** items to handle

Answer the ASKs with `resolve`; handle the MANUALs by hand. A non-zero exit is information, not failure.

### An item I expected to migrate is marked MANUAL
Check its rationale in `assess`: flareover names *why*. Common cases: a compound firewall expression (`and`/`or`), a Worker, a country/ASN **allowlist** (only IP allowlists map), Automatic HTTPS Rewrites, or a lifecycle transition. These have no faithful deterministic mapping and are surfaced rather than guessed. See the [Coverage Matrix](/docs/coverage-matrix/).

## Preparation

### An answered ASK didn't change the output
Make sure `--decisions decisions.lock` points at the file you actually answered, and that the answer key matches. Re-run `resolve` to regenerate the lock. Unanswered questions are intentionally not generated.

### `prepare --validate` fails
The generated Caddyfile or zone didn't parse. This usually means `caddy` isn't on `PATH` (validation shells out to it): install the Caddy binary, or drop `--validate` to skip the parse check. If Caddy *is* installed and it still fails, that's a bug worth reporting with the generated `out/caddy/Caddyfile`.

## Provisioning

### `provision: --pdns-key is no longer accepted …`
Secrets are read from the environment only. Set `PDNS_API_KEY` / `CERTMATE_TOKEN` and drop the `--pdns-key` / `--certmate-token` flags:
```bash
export PDNS_API_KEY=… CERTMATE_TOKEN=…
```

### `unknown --dns "…"`
Typo in the DNS target. Valid values: `powerdns | scaleway | ovh | gandi | leaseweb | hetzner | route53 | clouddns | azure` for `provision` (plus `bunny` for `prepare`, which is preview-only). See [DNS Targets](/docs/dns-targets/).

### `--dns <provider>` needs an env var
Each managed backend reads its credentials from the environment: the error names the exact variable(s). See the [Security](/docs/security/) table.

### `no zone found for "…" (create it first)`
flareover manages *records*, not zones. Create the zone with your DNS provider first, then re-run `provision`: it never auto-creates the zone.

### `--dns bunny` is rejected by `provision`
bunny.net is **preview-only**: `prepare --dns bunny` emits a records file plus an `apply.sh` that uses the bunny.net CLI. Run that script to apply; there's no native `provision` path for bunny.

### `--dns route53 / clouddns / azure` prints a sovereignty note
That's intentional: these are US-operated and not sovereign. The note nudges you toward the EU-owned options. It doesn't stop provisioning.

## Object storage

### `--dest aruba needs --minio-endpoint …`
Aruba's S3 endpoint is account-specific (the *Service Point URL* from your account page). flareover won't guess it. Pass it explicitly:
```bash
flareover storage buckets.json --dest aruba --minio-endpoint https://<your-service-point> --out ./out
```

### `unknown <provider> --region "…"`
Only EU regions are accepted, to keep the migration EU-scoped. The error lists the valid regions for that provider.

### A lifecycle rule didn't migrate
If it only tiers objects (a transition) or has no positive expiry (e.g. multipart-abort / noncurrent-version only), it's MANUAL on every destination: there is no equivalent to emit. Only expiry rules with `> 0` days map.

### `storage` exits `10` on a bucket with versioning
Expected on the default destination. Garage answers `NotImplemented` to `PutBucketVersioning`, so versioning is MANUAL there: the bucket migrates without it and older versions are not copied. Pick a destination that versions (`--dest minio|scaleway|ovh|contabo|aruba`), or accept the loss explicitly.

### `set S3_REGION to the signing region of your … endpoint`
`provision.sh` for `--dest contabo` and `--dest aruba` needs the signing region in `S3_REGION`; it is not guessed. Set it to the region your provider documents for the endpoint and re-run. On any destination, `S3_REGION` overrides the default.

### `set GARAGE_KEY to the name or ID of the Garage key …`
The Garage `provision.sh` grants every bucket to a Garage key and needs its name or ID. With the `deploy/` stack, `./garage-init.sh` creates the key `flareover`; export `GARAGE_KEY=flareover` together with its `GARAGE_ACCESS_KEY` / `GARAGE_SECRET_KEY`. If the `garage` binary is not on `PATH`, also set `GARAGE_CLI="docker compose exec -T garage /garage"`.

### A Garage bucket exists but the web endpoint or another key cannot see it
It was created over S3 (`CreateBucket`), which gives it only an alias local to the key that created it. Buckets from the generated `provision.sh` are created with `garage bucket create` (a global alias) for exactly this reason. For a bucket created some other way, find its ID with `garage bucket list`, add a global alias with `garage bucket alias <bucket-id> <bucket>`, and grant it with `garage bucket allow --read --write --owner <bucket> --key <key>`.

### A public Garage bucket answers `403`
Anonymous S3 GETs stay `403` on Garage by design. A bucket confirmed public is served by the **web endpoint** (port `3902` in the `deploy/` stack) as `<bucket>.<web root domain>`, not by the S3 API. Set the web root domain in `garage.toml` to your own domain and route it to `3902` from Caddy.

## Cutover & guard

### `present` exits `12`
A **HARD** parity divergence between the live and staged edge (status code, redirect, header, or body). Fix the difference before cutting over: that's the gate doing its job. SOFT divergences are surfaced but don't block.

### `execute` exits `12`
The cutover was blocked (a gate didn't pass). Re-run `present` to see the specific divergence.

## General

### `docker compose up` fails with `address already in use` on port 53
Your host is already running a DNS listener — on Ubuntu, Debian and Fedora that
is `systemd-resolved`, whose stub holds `127.0.0.53:53`, and publishing the
stack's DNS on `0.0.0.0` collides with it:

```
failed to bind host port for 0.0.0.0:53: address already in use
```

Either bind only the address that will actually serve DNS — `DNS_BIND=203.0.113.10`
in `deploy/.env` — or free port 53 on the host, which is what an edge dedicated
to this stack wants:

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

### Garage `/health` answers `503`
A fresh Garage node serves nothing until it has a cluster layout. Run `./garage-init.sh` once in `deploy/` after `docker compose up -d`: it applies the layout and creates the migration key, and `/health` on `127.0.0.1:3903` then answers `200`. The script is safe to re-run.

### `docker compose up` fails to pull a MinIO image
MinIO is archived upstream and `quay.io/minio/minio` answers `401`. The current `deploy/docker-compose.yml` runs Garage instead (`GARAGE_IMAGE`); an older copy of the compose file or `.env` still references MinIO. Update both from the repository and set `GARAGE_RPC_SECRET` and `GARAGE_ADMIN_TOKEN` in `.env`.

### Which version am I running?
```bash
flareover version
# flareover 0.4.0 (efa6ed3ac5d8, 2026-09-16T07:33:20Z)
```
The commit is in there too, and a `dirty` marker if the binary was built from a
modified tree — so a bug report names an exact build.

### Verifying a downloaded binary
See [Installation](/docs/installation/): verify the cosign-signed `checksums.txt`, then `sha256sum -c`.
