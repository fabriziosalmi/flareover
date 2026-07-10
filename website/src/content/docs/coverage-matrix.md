---
title: Coverage matrix
description: "Exactly what flareover carries over — AUTO, ASK, or MANUAL — generated from its own classifier, so the docs can never overstate coverage."
---

:::note[Generated from the code]
This matrix is produced by running flareover's **own classifier** over reference zones — the same code that enforces the [0% false-positive contract](/docs/the-contract/). It cannot claim coverage the engine does not deliver, and a test fails if it drifts from the code. For the exact verdicts on *your* zone, run `flareover assess your.snapshot.json`.
:::

Every element gets exactly one verdict. **AUTO** = a proven equivalent is generated. **ASK** = one bounded yes/no stands between it and AUTO. **MANUAL** = surfaced, never guessed.

## AUTO — a proven equivalent is generated

| Feature | Target | What flareover does |
|---|---|---|
| `cache` | `caddy` | PARTIAL — Cache rule → Caddy cache handler; behavior is approximate, review before relying on it. |
| `cache` | `caddy` | PARTIAL — Page Rule edge cache TTL → Caddy cache handler (souin); TTL parity is approximate. |
| `dns` | `powerdns` | Unproxied record copied verbatim into the authoritative PowerDNS zone. |
| `ip-access` | `caddy-waf` | ASN block → caddy-waf block_asns. |
| `ip-access` | `caddy-waf` | Country block → caddy-waf block_countries. |
| `ip-access` | `caddy-waf` | IP/CIDR allowlist → caddy-waf ip_whitelist_file entry. |
| `ip-access` | `caddy-waf` | IP/CIDR block → caddy-waf ip_blacklist_file entry. |
| `proto` | `caddy` | HTTP/3 → Caddy serves HTTP/3 (enabled by default). |
| `ratelimit` | `caddy-waf` | Per-IP rate limit (20 req / 10s) → caddy-waf rate_limit. |
| `ratelimit` | `caddy-waf` | Per-IP rate limit (20 req / 60s) → caddy-waf rate_limit. |
| `redirect` | `caddy` | Always Use HTTPS → Caddy global HTTP→HTTPS redirect (built in). |
| `redirect` | `caddy` | Dynamic redirect with a static target → Caddy redir to https://www.conformance.example. |
| `redirect` | `caddy` | Dynamic redirect with a static target → Caddy redir to https://www.example.com. |
| `redirect` | `caddy` | Page Rule Always Use HTTPS → Caddy HTTP→HTTPS redirect for the matched pattern. |
| `redirect` | `caddy` | Page Rule forwarding_url → Caddy redir with the configured status code. |
| `tls` | `caddy` | HSTS → Strict-Transport-Security header (max-age=31536000, includeSubDomains=true, preload=false). |
| `tls` | `caddy` | Minimum TLS 1.2 → Caddy tls protocols floor. |
| `tls` | `caddy` | SSL Full → Caddy terminates TLS and forwards over HTTPS without verifying the origin cert. |
| `tls` | `certmate` | Wildcard edge cert → CertMate issues via DNS-01 through PowerDNS (Caddy's native ACME is HTTP-01 only and cannot do wildcards). |
| `transform` | `caddy` | Global header transform → Caddy header directive (add/set/remove request or response headers). |
| `transform` | `caddy` | Static URL rewrite → Caddy rewrite directive (matcher-guarded when path-scoped). |
| `ua-block` | `caddy-waf` | User-Agent block → caddy-waf rule matching HEADERS:User-Agent. |
| `waf-custom` | `caddy-waf` | ASN block (ip.geoip.asnum) → caddy-waf block_asns. |
| `waf-custom` | `caddy-waf` | Country block (ip.geoip.country) → caddy-waf block_countries. |
| `waf-custom` | `caddy-waf` | Single-field match → caddy-waf JSON rule (pattern + targets + action). |
| `waf-managed` | `caddy-waf` | PARTIAL — Cloudflare managed ruleset → caddy-waf OWASP CRS import. OWASP CRS is not byte-identical to Cloudflare's proprietary set; coverage is comparable, not equal. |

## ASK — one bounded yes/no, then AUTO

| Feature | Target | The decision |
|---|---|---|
| `dns` | `powerdns` | Proxied (orange-cloud) record hides the true origin behind Cloudflare; the new edge needs the real backend address. |
| `dnssec` | `powerdns` | DNSSEC is active. PowerDNS can sign the zone, but the DS record at the registrar must be replaced during cutover or resolution breaks. |
| `ip-access` | `caddy-waf` | Challenge modes have no faithful caddy-waf equivalent (there is no interactive challenge). Treating as a hard block changes behavior for legitimate users. |
| `r2` | `minio` | R2 bucket → MinIO bucket on Contabo (S3-compatible). Bucket + data copy is deterministic; application code that binds to R2 must be repointed by hand. |
| `redirect` | `caddy` | Redirect target is expression-derived (built from request fields). Caddy can template many of these, but not all Cloudflare functions have equivalents. |
| `tls` | `caddy` | SSL Flexible means Cloudflare→origin is plaintext HTTP. That is insecure and often reflects an origin with no TLS. Confirm the intended origin scheme. |
| `tls` | `caddy` | SSL Full (strict) verifies the origin certificate, but a Cloudflare Origin CA cert is trusted only by Cloudflare — a self-hosted Caddy edge cannot verify it. Reproduce the verified edge→origin link with a replacement origin cert, or accept an encrypted-but-unverified link (a downgrade from strict). |
| `ua-block` | `caddy-waf` | User-Agent challenge has no faithful caddy-waf equivalent (no interactive challenge); a hard block would change behavior for real users. |

## MANUAL — surfaced, never guessed

| Feature | Why it can't be mapped faithfully |
|---|---|
| `config-rule` | Config Rule (Caddy-mappable once a Config-Rule generator exists: automatic_https_rewrites; provider-only edge features with no supported equivalent yet: email_obfuscation). |
| `email` | Cloudflare Email Routing (3 rules) requires standing up mail-forwarding infrastructure; not deterministically mappable. |
| `scrape-shield` | Provider-only edge feature — no supported equivalent yet; it is not carried over. Replicate it at the origin/app if you need it. |
| `snippet` | Snippet is arbitrary edge code (like a small Worker) — no deterministic config mapping; port by hand. |
| `transform` | Automatic HTTPS Rewrites rewrites http:// asset links in response bodies; Caddy's default build has no equivalent (it would need a response-body replace plugin) — reproduce it at the origin/app. |
| `waf-custom` | Cloudflare challenge on a compound/non-standard expression: caddy-waf cannot challenge, and the match can't be reproduced even as a hard block — handle by hand. |
| `waf-custom` | Custom firewall rule uses a compound or non-standard Cloudflare expression with no faithful caddy-waf translation — reproduce the intent by hand (compose caddy-waf conditions). |
| `worker` | Worker "api-router" is arbitrary edge code; it has no deterministic config mapping and must be ported by hand (e.g. to an app service or edge function). |

## Deliberately out of scope

Two things have **no faithful deterministic mapping** and are excluded on purpose — surfaced honestly, never faked:

- **Geographic traffic steering** — routing users to different origins by region (a paid load-balancing feature, distinct from country *blocking*, which **is** supported).
- **Cache-hit-ratio parity** — a self-hosted edge cache behaves differently from a global anycast one.

One honest caveat on rate limiting: a per-IP limit maps AUTO, but the source enforces the threshold across its whole anycast edge, so several independent self-hosted edge nodes each count locally unless they share a counter — a distributed-systems limit, noted rather than faked.
