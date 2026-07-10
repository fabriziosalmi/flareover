---
title: "FAQ / Q&A"
description: "Short answers to the questions people actually ask. For the 'how', see Quick Start; for the 'what maps', see the Coverage"
---

Short answers to the questions people actually ask. For the "how", see [Quick Start](/docs/quick-start/); for the "what maps", see the [Coverage Matrix](/docs/coverage-matrix/).

## The basics

### What is flareover, in one sentence?
A single-binary Go tool that reads a live managed-edge zone and rebuilds the equivalent configuration for an open-source, self-hosted stack on EU-sovereign infrastructure — without silently changing how your site behaves.

### What problem does it solve?
Leaving a big managed edge means re-creating, by hand, everything the dashboard did for you: DNS, TLS, redirects, WAF/firewall, caching. It's tedious and easy to get subtly wrong. flareover does that rebuild deterministically and tells you, honestly, exactly what it could and couldn't carry over.

### Is it free? What's the license?
Yes. It's [AGPL-3.0-only](https://github.com/fabriziosalmi/flareover/blob/main/LICENSE), open source, with no paid tier and no telemetry. Network use counts as distribution, so derivative *services* must offer their source under the same terms.

### Which source does it migrate *from*?
Today it reads a **Cloudflare** zone (the orange cloud) via the read-only API. The internal model is provider-agnostic, so other sources are a future possibility, but Cloudflare is what's implemented and tested now.

## Safety & trust

### Will it touch my current setup or break my site?
No. Everything up to the DNS flip is **read-only or writes only to your new target**. flareover never modifies your source zone and never touches your registrar. The final NS move is an explicit step you make yourself.

### What does "0% false-positive" actually guarantee?
That the tool never claims to have handled something it didn't. If a setting is reported **AUTO**, config for it is genuinely generated; if it can't be mapped faithfully, it's marked **MANUAL** and surfaced — never guessed. See [The Contract](/docs/the-contract/).

### Can I trust the generated config?
It's a **pure function** of your snapshot plus your answers — run it twice, get byte-identical output (golden-tested). So you review `./out` in `git` like any code change *before* anything goes live. Nothing is applied to production without your explicit action.

### How thoroughly is the "AUTO means emitted" promise checked?
The classifier and the generator share one source of truth, and *parity tests* assert that every AUTO finding materializes as real config. On top of that, the project periodically runs an adversarial audit specifically to hunt for any drift, and treats a verdict that claims coverage the generator doesn't deliver as a **critical** bug.

## Coverage

### What definitely migrates automatically?
DNS records, HSTS, minimum-TLS, HTTP/3, Always-Use-HTTPS redirects, header transforms and static URL rewrites, single-field firewall rules, country/ASN blocking, per-IP rate limits, IP and User-Agent blocking, origin rules, static page-rule redirects/caching, and object-storage buckets/versioning/lifecycle/CORS. Full list on the [Coverage Matrix](/docs/coverage-matrix/).

### What *doesn't* migrate?
Anything with no faithful deterministic mapping: **Workers** and **Snippets** (they're code), compound firewall expressions, **geographic traffic steering**, ML bot-scoring, proprietary DDoS, Automatic HTTPS Rewrites, custom cipher lists, IAM/bucket policies, and cache-hit-ratio parity. These are surfaced as **MANUAL** — you handle them by hand, informed, rather than being surprised in production.

### I rely on Cloudflare Workers. Can flareover convert them?
No — a Worker is code, and there's no deterministic translation of arbitrary code. It's flagged MANUAL. You re-implement the logic at your origin or edge yourself.

### Does country/ASN blocking really work self-hosted?
Yes — it maps AUTO to caddy-waf `block_countries` / `block_asns`. Country/ASN *blocking* is supported; geographic *steering* (routing users to different origins by region — a paid load-balancing feature) is not, and is surfaced honestly.

### What about the WAF — is it equivalent?
Single-field rules and the managed OWASP ruleset map to **caddy-waf**. OWASP CRS is comparable coverage, not byte-identical to the source's proprietary set — flareover marks it PARTIAL and says so. Compound expressions are MANUAL.

## Infrastructure

### Which DNS / storage / edge providers are supported?
- **DNS (10):** self-hosted PowerDNS, plus managed bunny.net, Scaleway, OVH, Gandi, Leaseweb, Hetzner (EU-owned) and Route 53, Cloud DNS, Azure (US-operated). → [DNS Targets](/docs/dns-targets/)
- **Object storage (5):** MinIO, Scaleway, OVH, Contabo, Aruba. → [Object Storage](/docs/object-storage/)
- **Edge (9):** six EU-owned + three US-operator EU regions. → [Sovereignty Tiers](/docs/sovereignty-tiers/)

### What's the difference between "EU-owned" and "EU region"?
Sovereignty follows the operator's nationality, not the datacenter's location. An EU-owned operator is under EU jurisdiction only; a US company's Frankfurt region gives you data *residency* but stays under US CLOUD Act reach. flareover labels the second tier honestly and never calls it sovereign. → [Sovereignty Tiers](/docs/sovereignty-tiers/)

### Do I have to self-host DNS?
No. PowerDNS is the default, but `--dns <provider>` points at a managed backend so you don't run nameservers yourself.

### Do I need Docker?
No — flareover is a single static binary. But if you don't already have a target stack, the `deploy/` `docker compose` landing zone is the quickest way to stand one up. → [Deploy](/docs/deploy/)

### Will my origin be exposed to the internet?
Not if you use the recommended shape: a **WireGuard** mesh between the edge and the origin keeps the origin inbound-free — it swaps its managed tunnel daemon for `wg-quick` and nothing else changes.

### Can I migrate a whole account, not just one zone?
Yes — `flareover zones` lists every zone a read-only account-scoped token can see; run the pipeline per zone.

## Operations

### How are secrets handled?
Every credential is read from an **environment variable**, never passed on the command line (so nothing leaks via `ps`, `/proc`, shell history, or CI logs). → [Security](/docs/security/)

### How does cutover work — is there downtime?
flareover stands up and validates the new edge first (the `present` parity gate diffs live vs staged and blocks on HARD divergences). You then move NS at your registrar; DNS propagation is the only "switch", and lowering TTLs beforehand keeps it tight. `guard` health-watches afterward and can trigger rollback/failover.

### What about DNSSEC?
On PowerDNS it's automated (the zone is signed and the DS is printed to publish at your registrar). On managed providers the DNSSEC request is surfaced with instructions — never silently assumed.

### How much does the target cost?
Run `flareover cost your.snapshot.json --vps <your-eur/mo>` for a comparison of the managed-edge tier/add-on spend vs a flat EU stack.

### What does "Tier A" vs "Tier B" mean in the docs?
**Tier A** = proven live against a real running service. **Tier B** = verified against the vendor's documented API and a test harness, but not yet exercised against the live service. The five core adapters are Tier A; the managed DNS/storage backends and the Terraform edge module are Tier B until a real run promotes them. Nothing claims a proof it hasn't earned.

## Meta

### Why the name "flareover"?
It's a "flare over"/"failover" wink — moving off the orange cloud toward your own edge. The brand nods at the orange flare rather than naming anyone.

### How can I report a bug or request a feature?
Open an issue on the [repository](https://github.com/fabriziosalmi/flareover/issues). If something in the coverage report looks wrong for your zone, attach the `assess --json` output (scrubbed of anything sensitive).

### Where do I go if the answer isn't here?
[Troubleshooting](/docs/troubleshooting/) for common errors, or the [CLI Reference](/docs/cli-reference/) for exact flags and exit codes.
