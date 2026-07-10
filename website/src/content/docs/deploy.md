---
title: "Deploy / Landing Zone"
description: "The most common friction in a migration is 'where do I run the target?'. flareover ships a one-command landing zone so you don't have to assemble the"
---

The most common friction in a migration is *"where do I run the target?"*. flareover ships a one-command landing zone so you don't have to assemble the stack by hand.

## One-command stack (`deploy/`)

The [`deploy/`](https://github.com/fabriziosalmi/flareover/tree/main/deploy) directory is a `docker compose` project that stands up the full target stack and consumes the `prepare --out` artifacts directly:

- **PowerDNS**: authoritative DNS (+ DNSSEC)
- **Caddy**: reverse proxy / TLS / HTTP/3, built with **caddy-waf** + **souin**
- **CertMate**: certificates via DNS-01 (wildcard; Let's Encrypt or Actalis)
- **MinIO**: S3-compatible object storage
- **secure-proxy-manager**: the optional egress shield

```bash
cd deploy
cp .env.example .env          # set PDNS_API_KEY, CERTMATE_TOKEN, etc.
docker compose up -d --build  # --build compiles the custom Caddy once
```

Then point `provision` at it, loading the secrets from the environment (never the command line):

```bash
set -a; . ./.env; set +a
flareover provision --snapshot snap.json --decisions decisions.lock \
  --pdns-url http://localhost:8081 \
  --certmate-url http://localhost:8000
```

### Exposure

- **Caddy** (`80`/`443`) and **PowerDNS** (`53`, authoritative: it must be publicly reachable to serve the zone) are internet-facing.
- Every **admin/API** surface (PowerDNS `8081`, CertMate `8000`, MinIO `9000`/`9001`, secure-proxy-manager `3128`) binds to `127.0.0.1`.

Put your own firewall in front regardless. See [Security](/docs/security/).

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

The lowest-risk shape leaves your origin unchanged and just re-tunnels it: flareover stands up your own edge node(s) and a **WireGuard** tunnel, and the origin only swaps its managed tunnel daemon for `wg-quick`. Add `--mesh-edge` (repeat it for an HA edge front). The origin keeps **zero public inbound**.

## Bare-metal / Proxmox

The `deploy/` compose file is the fast path; the repository's `docs/deploy-hardened.md` covers the hardened bare-metal / Proxmox blueprint: isolated origin bridge, edge on the routable bridge, origin reachable only through the edge/tunnel.
