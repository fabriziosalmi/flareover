---
title: "DNS Targets"
description: "Authoritative DNS is the one swappable part of the target stack: self-host it, or point --dns at a managed provider. The de-proxied records map"
---

Authoritative DNS is the one swappable part of the target stack: self-host it, or point `--dns` at a managed provider. The de-proxied records map deterministically either way (a shared BIND renderer serializes them), and every provisioner is **idempotent**: re-running converges with no duplicate records.

All credentials come from the **environment**, never the command line.

## Self-hosted (default)

| Target | `--dns` | How | Env |
|--------|---------|-----|-----|
| **PowerDNS** | `powerdns` (default) | Full BIND zone + live REST provisioning, DNSSEC automated | `PDNS_API_KEY` (+ `--pdns-url`) |

## Managed: EU-owned (sovereign)

| Target | `--dns` | How | Env |
|--------|---------|-----|-----|
| **bunny.net** | `bunny` | *Preview only:* emits a records BIND file + an `apply.sh` using the bunny.net CLI (there is no native provisioner) | `BUNNYNET_API_KEY` |
| **Scaleway** | `scaleway` | Idempotent `set` per rrset | `SCW_SECRET_KEY`, `SCW_DEFAULT_PROJECT_ID` |
| **OVHcloud** | `ovh` | REPLACE per rrset + zone refresh (stdlib signed auth) | `OVH_APPLICATION_KEY`, `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY` |
| **Gandi** | `gandi` | Idempotent PUT per rrset (LiveDNS) | `GANDI_PAT` |
| **Leaseweb** | `leaseweb` | Delete-then-create REPLACE | `LEASEWEB_API_KEY` |
| **Hetzner** | `hetzner` | Create-if-absent per record | `HETZNER_DNS_TOKEN` |

## Pointing a backend somewhere else

Each backend's API endpoint is compiled in, and each can be overridden from the
environment. Nothing prints the endpoint it used, so **a stale value in your
shell silently redirects a live `provision --dns` at a different host, with real
credentials** — check these before a cutover if you have ever pointed the tool
at a sandbox.

| Target | Override | Overrides |
|--------|----------|-----------|
| Scaleway | `SCW_API_URL` | API base URL |
| OVHcloud | `OVH_ENDPOINT` | API base URL (default `https://eu.api.ovh.com/1.0`) |
| Gandi | `GANDI_ENDPOINT` | LiveDNS base URL |
| Leaseweb | `LEASEWEB_ENDPOINT` | API base URL |
| Hetzner | `HETZNER_DNS_ENDPOINT` | API base URL |
| Route 53 | `AWS_ENDPOINT_URL_ROUTE53` | API endpoint |
| Cloud DNS | `CLOUDDNS_ENDPOINT` · `GOOGLE_TOKEN_URI` | API base URL · OAuth token endpoint |
| Azure DNS | `AZURE_ARM_ENDPOINT` · `AZURE_AUTH_HOST` | ARM base URL · AAD login host |

An empty or unset variable leaves the compiled-in default in place. These exist
for testing against a sandbox or a private endpoint; they are not needed for
normal use.

## What this does to your API quota

Extraction and provisioning are one request per item, so the cost grows with the
size of your account. The ceilings the tool imposes on itself:

| Limit | Value | What it protects |
|-------|-------|------------------|
| Concurrent bucket reads (`storage`) | 8 | your object-storage provider's request budget |
| Concurrent Access-policy reads (`extract`) | 6 | the Cloudflare API's request budget |
| Retry attempts on `429`/`5xx` | 4, exponential backoff from 1s | retrying harder into a rate limit is amplification |
| Response size | 32 MiB | a pathological or hostile response |
| Any single string in a snapshot | 8192 bytes | a value inflated to carry a payload into a generated file |

A rate limit is not fatal: the retry absorbs a brief one, and a persistent one
becomes a MANUAL item saying to wait and re-run rather than a silent gap. None
of these is configurable yet; if you need them lower for a stricter provider,
open an issue.

## Managed: US-operated (honestly tiered, **not** sovereign)

These live under US CLOUD Act / FISA reach. flareover offers them as the pragmatic "keep your existing account" bridge and says so every time. It will never label them sovereign, and prints a nudge back to the EU-owned options. See [Sovereignty Tiers](/docs/sovereignty-tiers/).

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
- **DNSSEC** is automated only on PowerDNS today. On a managed provider the DNSSEC request is surfaced with instructions (enable it in the provider console, publish the DS at the registrar), never silently assumed.
- **The registrar NS cutover is always a human step.** flareover prints the delegation set; you make the move.

## Verification tier

PowerDNS is proven live. The managed backends are verified against each vendor's **documented API** and a mocked test harness (Tier B), and promoted to live-proven after a real run. See [Coverage Matrix](/docs/coverage-matrix/) and the Status note on [Home](/docs/).
