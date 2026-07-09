# flareover — Hetzner Cloud edge (Terraform)

Stand up a **Caddy + WireGuard edge node on Hetzner Cloud** (EU-owned, sovereign)
that boots straight from the cloud-init flareover generates. The edge fronts your
site; the origin stays inbound-free behind the WireGuard mesh.

## Flow

```bash
# 1. Generate the edge cloud-init (+ mesh config) with flareover:
flareover prepare zone.snapshot.json \
  --edge-provider hetzner --mesh-edge PLACEHOLDER:51820 --out ./out
#    → ./out/edge/cloud-init.yaml   (installs Caddy + WireGuard, writes config)
#    NOTE: it carries the mesh private key — treat ./out/ as a secret.

# 2. Boot the edge:
cd terraform/hetzner
cp terraform.tfvars.example terraform.tfvars   # set cloud_init_path + ssh_public_key
export TF_VAR_hcloud_token=…                    # project-scoped Hetzner Cloud token
terraform init
terraform apply                                 # prints edge_ipv4

# 3. Feed the real edge IP back into flareover for the parity gate + cutover:
flareover present zone.snapshot.json --after-addr <edge_ipv4>:443
```

`--mesh-edge` wants the edge's public IP, which you only learn after `apply`. Two
options: run `terraform apply` first with a placeholder and re-run `prepare` with
the real `edge_ipv4`, or reserve a Hetzner floating IP up front and use that.

## Inputs

| Variable | Default | Notes |
|----------|---------|-------|
| `hcloud_token` | — | Hetzner Cloud API token. Prefer `TF_VAR_hcloud_token`; never commit it. |
| `cloud_init_path` | — | Path to `out/edge/cloud-init.yaml`. **Secret** (mesh key). |
| `ssh_public_key` | — | Break-glass admin key. |
| `server_type` | `cx22` | Hetzner server type. |
| `image` | `debian-12` | Debian/Ubuntu family (the cloud-init uses apt). |
| `location` | `fsn1` | Keep it EU: `nbg1`/`fsn1` (DE), `hel1` (FI). |
| `wireguard_port` | `51820` | Match `--mesh-edge <ip>:<port>`. |
| `ssh_source_ips` | `[]` | CIDRs allowed to SSH; empty = 22/tcp closed. |

The firewall opens 80/tcp, 443/tcp, 443/udp (HTTP/3) and the WireGuard port to
the world; SSH only to `ssh_source_ips`. No origin ports are exposed — origin
traffic rides the tunnel.

## Verification status (honest tier)

This module is **validated offline** — `terraform fmt`, `terraform init`, and
`terraform validate` pass against the real `hetznercloud/hcloud` provider schema,
so the resources and attributes are correct. It has **not yet been
`terraform apply`-tested against a live Hetzner account** (that needs your token
and spends real money). Once someone runs a full apply → boot → mesh → parity
gate, this note gets upgraded to live-proven, matching the standard the rest of
the project holds itself to. Treat it as a correct-but-unbooted reference until
then, and review the plan before you apply.
