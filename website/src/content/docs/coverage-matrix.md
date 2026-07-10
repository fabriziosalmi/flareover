---
title: "Coverage Matrix"
description: "What flareover carries over, honestly. This is the map behind the contract: AUTO means a proven equivalent is generated, ASK means one bounded yes/no"
---

What flareover carries over, honestly. This is the map behind the [contract](/docs/the-contract/): **AUTO** means a proven equivalent is generated, **ASK** means one bounded yes/no stands between it and AUTO, **MANUAL** means it is surfaced but never guessed.

> The authoritative answer for *your* zone is always `flareover assess your.snapshot.json`. This table is the general shape.

## AUTO — generated automatically

| Source feature | Becomes |
|----------------|---------|
| DNS records, **unproxied** (A/AAAA/CNAME/MX/TXT/SRV/NS/CAA) | Copied verbatim into the target zone |
| HSTS | `Strict-Transport-Security` header |
| Minimum TLS version | Caddy `tls` protocols floor |
| HTTP/3 | Caddy serves HTTP/3 (default) |
| Always Use HTTPS (zone + page rule) | Caddy HTTP→HTTPS redirect |
| Header transforms — global, **path-scoped**, or **host-scoped** (when the host is a proxied site) | Caddy `header` directive (matcher-guarded when scoped) |
| **Static** URL rewrites (literal path/query) | Caddy `rewrite` (matcher-guarded when path-scoped) |
| Firewall rule, single-field `http.<field> eq\|contains "…"` | caddy-waf rule |
| Country block (`ip.geoip.country`) | caddy-waf `block_countries` |
| ASN block (`ip.geoip.asnum`) | caddy-waf `block_asns` |
| Rate limit, **per-client-IP** | caddy-waf `rate_limit` |
| IP Access **block** (IP/CIDR, country, ASN) | caddy-waf blocklist / country / ASN block |
| IP Access **allowlist** — **IP/CIDR only** | caddy-waf `ip_whitelist` entry |
| **User-Agent Blocking** (block mode) | caddy-waf `HEADERS:User-Agent` rule |
| Origin Rules (host_header / origin / sni), host- or path-scoped | Caddy `reverse_proxy` override |
| Page Rule `forwarding_url` | Caddy `redir` with the configured status |
| Page Rule `edge_cache_ttl` | Caddy cache handler (souin) — *PARTIAL: TTL parity is approximate* |
| Managed OWASP ruleset | caddy-waf OWASP CRS — *PARTIAL: comparable, not byte-identical* |
| Object storage: bucket, versioning, **expiry** lifecycle (>0 days), CORS | `mc mb` / `mc version enable` / `mc ilm` / `mc cors` |

## ASK — one yes/no, then treated as AUTO

| Source feature | The question |
|----------------|--------------|
| **Proxied** (orange-cloud) DNS record | "What is the real origin?" — the true backend is hidden behind the edge |
| SSL mode = Flexible | "Confirm the origin scheme" — Flexible is ambiguous about origin TLS |
| SSL mode = Full (strict) | "Verify the origin cert, or skip?" — a Cloudflare Origin CA cert can't be verified by a self-hosted edge, so either verify a replacement cert (publicly-trusted via CertMate, or a private CA via `--origin-ca`) or accept an explicit skip-verify downgrade |
| DNSSEC active | "Can you update the DS record at the registrar during cutover?" |
| Firewall / IP-Access / User-Agent **challenge** (when the match is emittable) | "Convert this challenge to a hard block?" — there is no interactive challenge on a self-hosted edge |
| Object-storage bucket that is **publicly readable** | "Reproduce public read access?" — a security decision, never assumed |
| R2 bucket | "Migrate to MinIO / EU S3?" |

## MANUAL — surfaced, never guessed

| Source feature | Why |
|----------------|-----|
| Workers | It's code — no deterministic translation |
| Snippets | Edge code — same |
| Compound firewall expressions (`and` / `or` / `not`, functions) | No faithful single mapping; a wrong matcher is worse than none |
| Automatic HTTPS Rewrites | Rewrites `http://` links in **response bodies**; Caddy's default build has no equivalent |
| Custom cipher suite | Caddy's default set is safe but a custom list is not configurably mapped |
| IP Access **allowlist** on country / ASN | There is no allow-country / allow-ASN directive |
| Page Rule cache with only `cache_level` / `browser_cache_ttl` | Only `edge_cache_ttl` materializes |
| Lifecycle **transitions** (storage-class tiering) or **zero-expiry** rules | No MinIO equivalent |
| Load balancing / geographic traffic **steering** | Paid steering feature — no deterministic mapping |
| Email obfuscation / other Scrape Shield | Proprietary edge behavior |
| IAM / bucket policies | Policy semantics differ — never assumed equivalent |
| Config Rules with unmapped settings | The unmappable settings are named individually, not faked |
| ML bot-scoring, proprietary DDoS | Not reproducible deterministically |

## Deliberately out of scope

Two things have **no faithful deterministic mapping** and are excluded on purpose (surfaced honestly, never faked):

- **Geographic traffic steering** — sending users to different origins by region (a paid load-balancing feature, distinct from country *blocking*, which **is** supported).
- **Cache-hit-ratio parity** — a self-hosted edge cache behaves differently from a global anycast one.

## One honest caveat: global rate limiting

A per-IP rate limit maps AUTO. The nuance: the source enforces a threshold across its **whole anycast edge**, so several independent self-hosted edge nodes each count locally (the effective limit scales with the node count) unless they share a counter — a distributed-systems limit, noted rather than faked.
