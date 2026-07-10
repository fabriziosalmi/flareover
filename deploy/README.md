# deploy/: turnkey EU landing zone

The #1 friction in a migration is *"where do I run the target?"*. This is a
`docker compose` stack that stands the whole EU target up in one command and
consumes the artifacts `flareover prepare` generates, so `provision` has
something to talk to.

It is the containerized twin of [`../docs/deploy-hardened.md`](../docs/deploy-hardened.md)
(the bare-metal / Proxmox hardening guide).

## What it runs

| Service | Role | Port (localhost) |
|---------|------|------------------|
| **PowerDNS** | authoritative DNS + REST API | `8081` (API), `53` (DNS) |
| **Caddy** | reverse proxy · caddy-waf · souin · HTTP/3 (custom build) | `80`, `443` |
| **CertMate** | DNS-01 wildcard certificates | `8000` (API) |
| **MinIO** | S3-compatible object storage | `9000` (S3), `9001` (console) |
| **secure-proxy-manager** | outbound egress shield (optional) | `3128` |

Caddy (`80`/`443`) and PowerDNS (`53`, authoritative: it must be publicly
reachable to serve the zone) are internet-facing; every admin/API surface
(PowerDNS `8081`, CertMate `8000`, MinIO `9000`/`9001`, SPM `3128`) is bound to
`127.0.0.1`.

## Use it

```sh
# 1. generate the target config
flareover prepare snap.json --decisions decisions.lock --edge-ip <public-ip> --out ./out

# 2. secrets
cp .env.example .env && $EDITOR .env      # PDNS_API_KEY, CERTMATE_TOKEN, MinIO creds

# 3. stand it up (the --build compiles the custom Caddy once)
docker compose up -d --build

# 4. provision your target (the DNS zone + certs) via its APIs.
#    Secrets come from the environment only, never argv (the .env already
#    defines PDNS_API_KEY / CERTMATE_TOKEN):
set -a; . ./.env; set +a
flareover provision --snapshot snap.json --decisions decisions.lock \
  --pdns-url http://localhost:8081 \
  --certmate-url http://localhost:8000

# object storage, if any:
flareover storage buckets.json --out ./out && sh ./out/minio/provision.sh
```

Caddy live-reloads the bind-mounted Caddyfile; re-run `prepare --out ./out` and it
picks up the change.

## Confirm before you trust it (the live-proof)

This compose is structurally validated but not yet run end-to-end in CI (no Docker
there). Bring it up in your lab and confirm: the same Tier-A bar the rest of
flareover meets (see [`../docs/live-proof.md`](../docs/live-proof.md)):

- **PowerDNS backend.** The `gsqlite3` schema must exist on first boot. If the
  image does not auto-create it, initialize once:
  `docker compose exec powerdns pdnsutil create-zone <zone>` (or load the gsqlite3
  schema), then re-run `provision`.
- **CertMate image + certbot plugins.** Point `CERTMATE_IMAGE` at your published
  image; it must carry `certbot` and the matching DNS plugin
  (`certbot-dns-rfc2136` for PowerDNS) on `PATH`, or issuance fails.
- **secure-proxy-manager image.** Set `SPM_IMAGE`, or comment the `spm` service out.
- **Wildcards need DNS-01.** Pre-cutover the zone still answers at the source, so
  issue against it first: `provision --certmate-dns cloudflare`; switch to
  `powerdns` after the nameservers have moved.

`docker compose config` validates the file; `docker compose up` proves it.
