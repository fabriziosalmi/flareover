---
title: "DNS Targets"
description: "Authoritative DNS is the one swappable part of the target stack: self-host it, or point --dns at a managed provider. The de-proxied records map"
---

Authoritative DNS is the one swappable part of the target stack: self-host it, or point `--dns` at a managed provider. The de-proxied records map deterministically either way (a shared BIND renderer serializes them), and every provisioner is **idempotent** — re-running converges with no duplicate records.

All credentials come from the **environment**, never the command line.

## Self-hosted (default)

| Target | `--dns` | How | Env |
|--------|---------|-----|-----|
| **PowerDNS** | `powerdns` (default) | Full BIND zone + live REST provisioning, DNSSEC automated | `PDNS_API_KEY` (+ `--pdns-url`) |

## Managed — EU-owned (sovereign)

| Target | `--dns` | How | Env |
|--------|---------|-----|-----|
| **bunny.net** | `bunny` | *Preview only:* emits a records BIND file + an `apply.sh` using the bunny.net CLI (there is no native provisioner) | `BUNNYNET_API_KEY` |
| **Scaleway** | `scaleway` | Idempotent `set` per rrset | `SCW_SECRET_KEY`, `SCW_DEFAULT_PROJECT_ID` |
| **OVHcloud** | `ovh` | REPLACE per rrset + zone refresh (stdlib signed auth) | `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY` |
| **Gandi** | `gandi` | Idempotent PUT per rrset (LiveDNS) | `GANDI_PAT` |
| **Leaseweb** | `leaseweb` | Delete-then-create REPLACE | `LEASEWEB_API_KEY` |
| **Hetzner** | `hetzner` | Create-if-absent per record | `HETZNER_DNS_TOKEN` |

## Managed — US-operated (honestly tiered, **not** sovereign)

These live under US CLOUD Act / FISA reach. flareover offers them as the pragmatic "keep your existing account" bridge and says so every time — it will never label them sovereign, and prints a nudge back to the EU-owned options. See [Sovereignty Tiers](/docs/sovereignty-tiers/).

| Target | `--dns` | How | Env |
|--------|---------|-----|-----|
| **AWS Route 53** | `route53` | UPSERT per rrset (hand-rolled SigV4) | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| **Google Cloud DNS** | `clouddns` | Create-or-patch per rrset (service-account RS256 JWT → OAuth2) | `GOOGLE_APPLICATION_CREDENTIALS` (+ optional `GOOGLE_CLOUD_PROJECT`) |
| **Azure DNS** | `azure` | PUT recordset per type (AAD client-credentials) | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP` |

## How to use one

```bash
# 1. Preview the zone that will be applied
flareover prepare zone.snapshot.json --decisions decisions.lock --dns hetzner --out ./out

# 2. Apply it live (creds in the environment)
export HETZNER_DNS_TOKEN=…
flareover provision --snapshot zone.snapshot.json --decisions decisions.lock --dns hetzner
#    → prints the delegation nameservers; set them at your registrar, then let old TTLs expire.
```

Re-running `provision` is the idempotency check: a correct adapter converges with no duplicate records.

## Notes

- **The zone must already exist** with the provider. flareover manages *records*; it never auto-creates the zone (that stays an explicit operator step).
- **Record encoding** is shared across the BIND-style providers: `TXT` values are quoted, `MX`/`SRV` priority is embedded, `CNAME`/`NS` targets are dotted. This is proven against each provider's documented API.
- **DNSSEC** is automated only on PowerDNS today. On a managed provider the DNSSEC request is surfaced with instructions (enable it in the provider console, publish the DS at the registrar) — never silently assumed.
- **The registrar NS cutover is always a human step.** flareover prints the delegation set; you make the move.

## Verification tier

PowerDNS is proven live. The managed backends are verified against each vendor's **documented API** and a mocked test harness (Tier B), and promoted to live-proven after a real run. See [Coverage Matrix](/docs/coverage-matrix/) and the Status note on [Home](/docs/).
