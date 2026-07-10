---
title: Overview
description: "Move your site off the orange cloud onto your own EU servers, without changing how it behaves. A deterministic, 0% false-positive migration engine."
---

**Move your site off the orange cloud onto your own EU servers, without changing how it behaves.**

`flareover` is an [AGPL-3.0](https://github.com/fabriziosalmi/flareover/blob/main/LICENSE), single-binary Go engine that reads a live managed-edge zone and rebuilds the equivalent configuration for an open-source, self-hosted stack (Caddy, PowerDNS, CertMate, …) on EU-sovereign infrastructure.

Its one rule (the whole reason the project exists) is a **0% false-positive contract**: it never emits configuration that silently changes behavior.

- Where it can **prove** an exact equivalent, it applies it (**AUTO**).
- Where a choice is genuinely ambiguous, it asks you one yes/no (**ASK**).
- Where nothing maps faithfully, it flags the item for you and **never guesses** (**MANUAL**).

That is the difference between a migration you can trust and a migration you have to re-audit by hand.

---

## Why this exists

Leaving a big managed edge means rebuilding, by hand, everything the dashboard quietly did for you (DNS, TLS certificates, redirects, firewall/WAF rules, caching) and hoping you didn't miss something that silently breaks the site. flareover does that rebuild deterministically and tells you, honestly, exactly what it could and could not carry over.

## The 30-second tour

```bash
flareover extract example.com > zone.snapshot.json   # read-only, needs CLOUDFLARE_API_TOKEN
flareover assess  zone.snapshot.json                 # honest AUTO/ASK/MANUAL report
flareover resolve zone.snapshot.json --defaults > decisions.lock
flareover prepare zone.snapshot.json --decisions decisions.lock \
  --edge-ip 203.0.113.10 --out ./out                 # generate the target-stack config
```

Everything up to the DNS flip is a review artifact you can read in `git` before anything goes live. See **[Quick Start](/docs/quick-start/)** for a full walkthrough.

## What's in the box

| Concern | Tool |
|---------|------|
| Authoritative DNS | Self-hosted **PowerDNS**, or a managed target via `--dns` (see **[DNS Targets](/docs/dns-targets/)**) |
| Reverse proxy / CDN / TLS | **Caddy** (native ACME, HTTP/3) |
| WAF | **caddy-waf** (OWASP, rate-limit, IP/ASN/country, blocklists) |
| Edge cache | **souin** (Caddy module) |
| Certificates | **CertMate**: DNS-01, wildcard, Let's Encrypt or **Actalis** (EU CA) |
| Object storage | Self-hosted **MinIO**, or managed EU S3 (see **[Object Storage](/docs/object-storage/)**) |
| Sovereign origin link | **WireGuard** mesh (replaces the managed tunnel; origin stays inbound-free) |
| Egress shield (optional) | **secure-proxy-manager** (default-deny + allowlist, fail-closed) |

## Where to go next

- **New here?** → [Installation](/docs/installation/) → [Quick Start](/docs/quick-start/)
- **Want the guarantees?** → [The Contract](/docs/the-contract/)
- **What actually maps?** → [Coverage Matrix](/docs/coverage-matrix/)
- **Which providers?** → [DNS Targets](/docs/dns-targets/) · [Sovereignty Tiers](/docs/sovereignty-tiers/)
- **Questions?** → [FAQ / Q&A](/docs/faq/)

---

> **Status.** All five phases are implemented; the five core adapters (PowerDNS, CertMate, MinIO, WireGuard mesh, secure-proxy-manager) are proven live against real services. The managed DNS/storage backends and the Terraform edge module are verified against each vendor's documented API and test harness (Tier B) and promoted to live-proven after a real run. Nothing claims a proof it hasn't earned. See [Coverage Matrix](/docs/coverage-matrix/).
