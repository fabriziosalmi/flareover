---
title: "Quick Start"
description: "This walks a single zone from read-only assessment all the way to a gated cutover. Every step before the DNS flip is non-destructive and produces"
---

This walks a single zone from **read-only assessment** all the way to a **gated cutover**. Every step before the DNS flip is non-destructive and produces artifacts you can review in `git`.

> **You will need:** a running edge host (its public IP), and a target stack to point at. No box yet? The **[Deploy / Landing Zone](/docs/deploy/)** page stands one up with a single `docker compose up`.

## 1. Extract the zone (read-only)

```bash
export CLOUDFLARE_API_TOKEN=…            # a read-only token
flareover extract example.com > zone.snapshot.json
```

`extract` only reads. The snapshot is a faithful, provider-native capture of the zone: DNS records, TLS/SSL settings, WAF and rate-limit rules, page rules, transforms, redirects, object-storage buckets, and more.

Migrating a whole account? `flareover zones` lists every zone the token can see.

## 2. Assess: the honest coverage report

```bash
flareover assess zone.snapshot.json          # human-readable
flareover assess zone.snapshot.json --md      # Markdown (drop into a PR)
flareover assess zone.snapshot.json --json     # machine-readable findings
flareover assess zone.snapshot.json --html      # self-contained shareable report
```

Every setting gets exactly one verdict: **AUTO**, **ASK**, or **MANUAL** (see **[The Contract](/docs/the-contract/)**). `assess` is CI-friendly:

| Exit code | Meaning |
|-----------|---------|
| `0` | Everything is AUTO: a clean, fully-deterministic migration |
| `11` | There are **ASK** items to answer (no MANUAL) |
| `10` | There are **MANUAL** items to handle by hand |

## 3. Resolve the ASK questions

```bash
flareover resolve zone.snapshot.json --defaults > decisions.lock
```

`resolve` walks each ASK question into a `decisions.lock`. On a terminal it is interactive; `--defaults` accepts the safe default for each, and `--merge <file>` layers onto an existing lock. Anything you leave unanswered simply is **not** generated, never guessed.

## 4. Estimate the cost (optional)

```bash
flareover cost zone.snapshot.json --vps 12    # your EU VPS price, €/mo
```

Compares the managed-edge tier/add-on spend against a flat EU-sovereign stack.

## 5. Prepare: generate the target config

```bash
flareover prepare zone.snapshot.json \
  --decisions decisions.lock \
  --edge-ip 203.0.113.10 \
  --ca actalis \
  --out ./out --validate
```

This writes the deployable artifacts (Caddyfile, caddy-waf rules, PowerDNS zone, …) **plus a `MIGRATION.md`** report: a table of every element found and exactly what it became (1:1 AUTO / answered-ASK / MANUAL). `--validate` proves the generated Caddyfile and zone actually parse.

> Generation is a **pure function** of `snapshot + decisions.lock`: run it twice, get byte-identical config. Review `./out` in `git` before anything goes live.

## 6. Pre-flight: is the target ready?

```bash
export PDNS_API_KEY=… CERTMATE_TOKEN=…
flareover doctor \
  --pdns-url http://pdns:8081 \
  --certmate-url http://certmate:8000 \
  --check-caddy                 # GO / NO-GO: exit 0 only when every target is ready
```

## 7. Provision: stand the target up

```bash
flareover provision --snapshot zone.snapshot.json --decisions decisions.lock \
  --edge-ip 203.0.113.10 \
  --pdns-url http://pdns:8081 --nameservers ns1.example.eu,ns2.example.eu \
  --certmate-url http://certmate:8000 \
  --certmate-dns cloudflare      # pre-cutover: NS still at the source, so solve DNS-01 there
```

Swap `--pdns-url …` for `--dns <target>` to use a managed DNS backend instead of self-hosting (see **[DNS Targets](/docs/dns-targets/)**). Object storage is a separate step: `flareover storage buckets.json --out ./out` (see **[Object Storage](/docs/object-storage/)**).

## 8. Present: the parity gate

```bash
flareover present zone.snapshot.json --after-addr 203.0.113.10:443
```

Probes the live edge vs the staged edge and diffs status codes, redirects, headers, and body. **HARD** divergences block the cutover (exit `12`); **SOFT** ones are surfaced for review.

## 9. Cut over, then guard

The final NS move at your registrar stays an explicit human step; flareover never touches your registrar. Afterwards:

```bash
flareover guard --url https://example.com --interval 30s \
  --on-unhealthy "…rollback command…"
```

`guard` health-watches the new edge and can trigger rollback/failover.

---

**Next:** [The Contract](/docs/the-contract/) · [CLI Reference](/docs/cli-reference/) · [Coverage Matrix](/docs/coverage-matrix/)
