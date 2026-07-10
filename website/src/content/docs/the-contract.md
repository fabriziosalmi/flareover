---
title: "The Contract — no silent surprises"
description: "Every migration tool has to decide what to do with a setting it doesn't fully understand. Most guess. flareover doesn't. Its entire design is organized"
---

Every migration tool has to decide what to do with a setting it doesn't fully understand. Most guess. flareover doesn't. Its entire design is organized around one promise:

> **A 0% false-positive contract: flareover emits behavior-changing configuration only when it can prove the result is equivalent — or when you have answered a bounded yes/no. Everything else is surfaced, never applied.**

## Three verdicts

Every element of the source zone gets exactly one verdict.

| Verdict | Meaning | Emits config? |
|---------|---------|:---:|
| **AUTO** | There is a **proven exact equivalent** on the target. | ✅ generated automatically |
| **ASK** | A faithful mapping exists, but one detail is genuinely ambiguous. You answer one yes/no (saved in `decisions.lock`); then it is treated as AUTO. | ✅ only once answered |
| **MANUAL** | Nothing maps faithfully (Workers code, ML bot-scoring, proprietary DDoS, …). Documented and left for you. | ❌ never |

Behavior-changing configuration is emitted **only** for AUTO and answered-ASK items. A MANUAL item is written into the report and the `MIGRATION.md`, and nothing is generated for it — the tool would rather tell you "I can't carry this" than ship a plausible guess that silently changes how your site behaves.

## Determinism

Classification and artifact generation are a **pure function** of `snapshot + decisions.lock`:

```
verdicts, config = f(snapshot, decisions.lock)
```

Run it twice, get **byte-identical** output. This is enforced by golden tests. The practical consequence: the entire migration is reviewable in `git` — you diff `./out` like any code change before anything goes live. (Runtime state a *target* assigns later — e.g. a MinIO lifecycle-rule id — is outside this function and noted where it differs.)

## The invariant that makes it real: classify ⟺ generate

The report and the generated config are produced by two different parts of the engine — the **classifier** and the **generator**. The contract only holds if they can never disagree:

- A rule may be **AUTO** *only if* the generator actually emits config for it.
- A rule is **MANUAL** *only if* the generator emits nothing for it.

To guarantee this, the "is this faithfully translatable?" judgement lives in **one shared place** (the `cfexpr` predicates and shared helpers) that both the classifier and the generator call. There is no way for the report to claim coverage the generator doesn't deliver. This is verified by *parity tests*: for a conformance zone, every AUTO finding must materialize as real generated configuration.

> This invariant is taken seriously enough that a dedicated adversarial audit hunts for any drift — a verdict that claims emission without the generator backing it is treated as a **critical** bug, not a cosmetic one.

## Why "0% false-positive" and not "100% coverage"

A false *positive* here means: **the tool said it handled something, but it didn't.** That is the dangerous failure — you flip DNS believing your WAF rule migrated, and it silently didn't.

flareover optimizes to make that number **zero**, even at the cost of coverage. When it isn't sure, it degrades to ASK or MANUAL rather than risk a wrong AUTO. You may have to handle more by hand — but you will never be surprised in production by something the report told you was fine.

## What this looks like in practice

- A DNS `MX`/`TXT` record that isn't proxied → **AUTO**, copied verbatim.
- A proxied (orange-cloud) `A` record → the true origin is hidden behind the edge, so flareover **ASK**s you for the real backend, then repoints it.
- `Always Use HTTPS` → **AUTO** (a Caddy redirect).
- A single-field firewall rule like `http.user_agent eq "badbot"` → **AUTO** (a caddy-waf rule).
- A compound firewall expression with `and`/`or` → **MANUAL** (no faithful single mapping) — surfaced, not guessed.
- A Cloudflare Worker → **MANUAL** (it's code; there is no deterministic translation).

See the full breakdown on the **[Coverage Matrix](/docs/coverage-matrix/)**.
