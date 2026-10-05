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
- **MinIO**: S3-compatible object storage
- **secure-proxy-manager**: the optional egress shield

```bash
cd deploy
cp .env.example .env          # set PDNS_API_KEY, CERTMATE_TOKEN, etc.
docker compose up -d --build  # --build compiles the custom Caddy once
```

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
```

### Exposure

- **Caddy** (`80`/`443`) and **PowerDNS** (`53`, authoritative: it must be publicly reachable to serve the zone) are internet-facing.
- Every **admin/API** surface (PowerDNS `8081`, CertMate `8000`, MinIO `9000`/`9001`, secure-proxy-manager `3128`) binds to `127.0.0.1`.
- The PowerDNS control API additionally refuses any source outside the compose
  network: the restriction is in the setting, not only in the port binding, so
  exposing `8081` later does not silently remove it.
- Every service runs with `no-new-privileges` and `cap_drop: ALL`, with
  capabilities added back only where the image's entrypoint needs them.

Put your own firewall in front regardless. See [Security](/docs/security/).

### Back it up

The seven volumes are not equal. Three hold state that cannot be regenerated:

| Volume | Holds | If you lose it |
|--------|-------|----------------|
| `pdns-data` | the authoritative zone **and the DNSSEC signing keys** | the zone stops resolving, and the DS record at your registrar points at keys that no longer exist |
| `certmate-data` + `certs` | issued certificates and issuance state | re-issuance, and rate limits at the CA |
| `minio-data` | the migrated objects | possibly the only remaining copy, once the source bucket is gone |

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
survives a backup/restore round trip with the same signing key.

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
