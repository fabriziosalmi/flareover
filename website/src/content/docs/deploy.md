---
title: "Deploy / Landing Zone"
description: "Where to run the target: a one-command docker compose stack, a cloud-init edge on an EU provider, Terraform for Hetzner, or a WireGuard mesh that keeps your origin."
---

The most common friction in a migration is *"where do I run the target?"*. flareover ships a one-command landing zone so you don't have to assemble the stack by hand.

## One-command stack (`deploy/`)

The [`deploy/`](https://github.com/fabriziosalmi/flareover/tree/main/deploy) directory is a `docker compose` project that stands up the full target stack and consumes the `prepare --out` artifacts directly:

- **PowerDNS**: authoritative DNS (+ DNSSEC)
- **Caddy**: reverse proxy / TLS / HTTP/3, built with **caddy-waf** + **souin**
- **CertMate**: certificates via DNS-01 (wildcard; Let's Encrypt or Actalis)
- **Garage**: S3-compatible object storage (replaces MinIO, which is archived upstream)
- **secure-proxy-manager**: the optional egress shield

```bash
cd deploy
cp .env.example .env          # set PDNS_API_KEY, CERTMATE_TOKEN, GARAGE_RPC_SECRET, GARAGE_ADMIN_TOKEN
docker compose up -d --build  # --build compiles the custom Caddy once
./garage-init.sh              # once: Garage cluster layout + the `flareover` key
```

`GARAGE_RPC_SECRET` must be 32 bytes as hex (`openssl rand -hex 32`). A fresh
Garage node serves nothing until it has a cluster layout: until
`./garage-init.sh [capacity]` has run (default capacity `100G`), its `/health`
answers `503`. The script applies the layout, creates the key `flareover`
(override the name with `GARAGE_KEY`) with permission to create buckets, and
prints the exports the generated `garage/provision.sh` needs. It is safe to
re-run. The key's secret is read with
`docker compose exec -T garage /garage key info flareover --show-secret`.

:::caution[Port 53 is probably already taken]
Ubuntu, Debian and Fedora run `systemd-resolved`, whose stub listener holds
`127.0.0.53:53`, so publishing the stack's DNS on `0.0.0.0` fails to bind and
the container never starts. Set `DNS_BIND` in `.env` to the address that will
actually serve DNS, or free port 53 on the host — both are in
[Troubleshooting](/docs/troubleshooting/).
:::

Then point `provision` at it, loading the secrets from the environment (never the command line):

```bash
set -a; . ./.env; set +a
flareover provision --snapshot snap.json --decisions decisions.lock \
  --pdns-url http://localhost:8081 \
  --certmate-url http://localhost:8000

# object storage, if any (after exporting what garage-init.sh printed):
flareover storage buckets.json --minio-endpoint http://127.0.0.1:3900 --out ./out
bash ./out/garage/provision.sh
```

Garage's config is `deploy/garage.toml`: one node, `replication_factor = 1`,
S3 signing region `garage`. Buckets confirmed public are served by Garage's web
endpoint as `<bucket>.<web root domain>`; the shipped web root domain is
`.web.garage.localhost`, so change it to your own domain and route that domain
to port `3902` from Caddy. See [Object Storage](/docs/object-storage/).

### Exposure

- **Caddy** (`80`/`443`) and **PowerDNS** (`53`, authoritative: it must be publicly reachable to serve the zone) are internet-facing.
- Every **admin/API** surface (PowerDNS `8081`, CertMate `8000`, Garage `3900` S3 API / `3902` web endpoint / `3903` admin, secure-proxy-manager `3128`) binds to `127.0.0.1`.
- The PowerDNS control API additionally refuses any source outside the compose
  network: the restriction is in the setting, not only in the port binding, so
  exposing `8081` later does not silently remove it.
- Every service runs with `no-new-privileges` and `cap_drop: ALL`, with
  capabilities added back only where the image's entrypoint needs them.

Put your own firewall in front regardless. See [Security](/docs/security/).

### Back it up

The eight volumes are not equal. The five in this table hold state that cannot be regenerated:

| Volume | Holds | If you lose it |
|--------|-------|----------------|
| `pdns-data` | the authoritative zone **and the DNSSEC signing keys** | the zone stops resolving, and the DS record at your registrar points at keys that no longer exist |
| `certmate-data` + `certs` | issued certificates and issuance state | re-issuance, and rate limits at the CA |
| `garage-meta` + `garage-data` | the migrated objects and the index that finds them (back up both, together) | possibly the only remaining copy, once the source bucket is gone |

`caddy-data`, `caddy-config` and `spm-data` are disposable — re-running
`prepare` plus a restart rebuilds them. The commands, and what a *good* restore
looks like (the zone back **and its original DNSSEC key**), are in
[`deploy/README.md`](https://github.com/fabriziosalmi/flareover/blob/main/deploy/README.md).

### Pinned, and proven

Image versions are pinned in `.env` rather than floating on `:latest`: these
services hold the authoritative zone, the DNSSEC keys and the migrated objects,
so an upgrade should be a reviewed change and a rollback should be possible.

A CI job brings this stack up on every change to `deploy/` and asserts that the
PowerDNS API answers, that a zone can be created and signed, and that it
survives a backup/restore round trip with the same signing key. It also runs
`garage-init.sh`, waits for Garage's `/health` to answer `200`, and does an S3
put/get round trip with the key the script created.

## Boot an edge on a provider

`prepare --edge-provider <key>` emits a cloud-init that installs and configures a Caddy + WireGuard edge on a specific provider (see [Sovereignty Tiers](/docs/sovereignty-tiers/)). For **Scaleway** and **OVHcloud** it also emits a script that creates and boots the instance from that cloud-init.

```bash
flareover prepare snap.json --decisions decisions.lock \
  --edge-provider hetzner --mesh-edge 203.0.113.10:51820 --out ./out
#   → ./out/edge/cloud-init.yaml   (installs Caddy + WireGuard, writes the config)
```

> The cloud-init carries the mesh WireGuard **private key**, so treat `./out/` as a secret.

### Terraform (Hetzner)

[`terraform/hetzner/`](https://github.com/fabriziosalmi/flareover/tree/main/terraform/hetzner) is a module that boots the edge on Hetzner Cloud straight from the generated cloud-init (`hcloud_server` + firewall + SSH key; outputs the edge IP). Point `cloud_init_path` at `out/edge/cloud-init.yaml`, `terraform apply`, and feed the printed IP back into `prepare --edge-ip` / `present`.

## Keep your origin exactly where it is (WireGuard mesh)

The lowest-risk shape leaves your origin unchanged and just re-tunnels it: flareover stands up your own edge node(s) and a **WireGuard** tunnel, and the origin only swaps its managed tunnel daemon for `wg-quick`. Add `--mesh-edge` (repeat it for an HA edge front). The origin keeps **zero public inbound**. Full walkthrough: [Keep your origin](/docs/keep-your-origin/).

## Bare-metal / Proxmox

The `deploy/` compose file is the fast path; the [Hardened Proxmox landing zone](/docs/hardened-deploy/) covers the hardened bare-metal / Proxmox blueprint: isolated origin bridge, edge on the routable bridge, origin reachable only through the edge/tunnel.
