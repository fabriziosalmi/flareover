---
title: "Security"
description: "flareover handles credentials for your DNS, certificates, storage, and edge. Its security posture is deliberately"
---

flareover handles credentials for your DNS, certificates, storage, and edge. Its security posture is deliberately conservative.

## Auth from the environment only, never on argv

**Every** credential is read from an environment variable. flareover never accepts a secret as a command-line flag, because anything on the command line leaks via `ps auxww`, `/proc/<pid>/cmdline`, shell history, and CI job logs.

```bash
export PDNS_API_KEY=…
export CERTMATE_TOKEN=…
flareover provision --pdns-url http://pdns:8081 --certmate-url http://certmate:8000 …
```

Passing `--pdns-key` or `--certmate-token` is refused with a pointer to the env var: the invariant is enforced, not just documented.

### Environment variables by purpose

| Purpose | Variable(s) |
|---------|-------------|
| Read the source zone (`extract`, `zones`) | `CLOUDFLARE_API_TOKEN` (read-only) |
| PowerDNS | `PDNS_API_KEY` |
| CertMate | `CERTMATE_TOKEN` |
| Scaleway DNS / S3 | `SCW_SECRET_KEY`, `SCW_DEFAULT_PROJECT_ID` / `SCW_ACCESS_KEY`, `SCW_SECRET_KEY` |
| OVH DNS / S3 | `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY` / `OVH_S3_ACCESS_KEY`, `OVH_S3_SECRET_KEY` |
| Gandi | `GANDI_PAT` |
| Leaseweb | `LEASEWEB_API_KEY` |
| Hetzner DNS | `HETZNER_DNS_TOKEN` |
| Route 53 | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| Cloud DNS | `GOOGLE_APPLICATION_CREDENTIALS` |
| Azure DNS | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP` |
| Contabo / Aruba S3 | `CONTABO_S3_*` / `ARUBA_S3_*` |
| bunny.net | `BUNNYNET_API_KEY` |

Use a **read-only** source token: flareover never writes to the source.

## Least privilege at the edges

- **The engine never touches your source provider or your registrar.** The DS publish and the final NS move are explicit human steps.
- **The origin stays inbound-free.** The recommended shape puts a WireGuard mesh between the edge and the origin, so the origin has zero public inbound; the edge dials nothing the origin didn't initiate.
- **Egress shield (optional).** `secure-proxy-manager` enforces default-deny outbound with an allowlist, fail-closed, so a compromised edge can't phone home to arbitrary hosts.

## Supply chain

- **Zero external Go dependencies**: standard library only. A small, auditable surface with no third-party module tree to vet.
- **Signed releases.** Every release ships an **SBOM** and a `checksums.txt` **signed keyless via Sigstore/cosign**. Verify before you run (see [Installation](/docs/installation/)).
- **AGPL-3.0-only.** Network use counts as distribution, so any derivative service must offer its source under the same terms.

## Handle generated artifacts as secrets

Some generated outputs contain key material:

- The **edge cloud-init** (`out/edge/cloud-init.yaml`) embeds the mesh **WireGuard private key**.
- A `decisions.lock` may encode operational choices you'd rather not publish.

Keep `out/` and `decisions.lock` out of public version control. The repository's `.gitignore` already excludes them for in-repo runs, and Terraform state / `*.tfvars` are excluded too.

## Certificates

CertMate issues real, publicly-trusted certificates via **DNS-01** (wildcard-capable), from **Let's Encrypt** or **Actalis** (an EU CA) with `--ca actalis`. Pre-cutover, solve DNS-01 against the **source** DNS (`--certmate-dns <provider>`), since the NS haven't moved yet.
