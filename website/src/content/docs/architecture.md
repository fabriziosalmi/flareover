---
title: "Architecture & the Five Phases"
description: "flareover is a pipeline. A live zone goes in; a faithful, self-hosted EU stack comes out; a verdict is attached to every"
---

flareover is a pipeline. A live zone goes in; a faithful, self-hosted EU stack comes out; a verdict is attached to every step.

```
extract → CF-IR → classify → generate → parity-verify → gated cutover → guard
```

## The five phases

The product is a five-phase "diamond". Each phase has a CLI verb (or a small group of them).

| Phase | Verb(s) | What happens |
|-------|---------|--------------|
| **1. Assessment** | `extract`, `assess`, `cost` | Read-only capture of the source zone → a provider-agnostic intent model → classify every element AUTO/ASK/MANUAL. Output: an honest coverage report (+ cost comparison). |
| **2. Preparation** | `resolve`, `prepare` | Resolve the ASK items into `decisions.lock`; generate the target-stack artifacts; optionally auto-provision a **staged** target. |
| **3. Presentation** | `present` | The parity gate: probe the live edge vs the staged edge and diff status / redirects / headers / body. HARD divergences block; SOFT ones are surfaced. |
| **4. Execution** | `provision`, `execute` | Gated cutover, orchestrated live up to the DNS flip. The final NS move requires explicit human confirmation. |
| **5. Failguards** | `guard` | Health monitoring, automatic rollback / failover, fail-closed egress, idempotent re-runs. |

## The intent model (CF-IR)

The extractor produces a **snapshot** that is deliberately close to the source's own API shapes — extraction is a *dumb transcription*, so no interpretation leaks into it. Everything interpretive happens afterward, in the classifier, against a provider-agnostic **intermediate representation (IR)**: sites, origins, DNS zone/records, TLS, header ops, rewrites, redirects, a WAF policy, cache policy, and a mesh. This separation is why the same engine can, in principle, target more than one source or destination without the honesty logic changing.

## classify ⟺ generate

Two components turn the snapshot into results:

- **`classify`** decides the verdict of every element (AUTO / ASK / MANUAL).
- **`generate`** (the plan builder + the target adapters) emits the actual config.

They share a single source of truth for "is this faithfully translatable?" — the `cfexpr` predicates. That shared predicate is what keeps the report and the config in lock-step (see **[The Contract](/docs/the-contract/)**).

## Package map

| Package | Responsibility |
|---------|----------------|
| `internal/cloudflare` | The canonical read-only snapshot + the extractor |
| `internal/cfexpr` | Shared interpreters for the source rules language — the single "is this translatable?" authority |
| `internal/classify` | Assigns AUTO / ASK / MANUAL to every element |
| `internal/ir` | The provider-agnostic intent model |
| `internal/plan` | Builds the deployable plan from `snapshot + decisions.lock` — only the faithful surface |
| `internal/target/*` | Render/provision adapters: `caddy`, `caddywaf`, `certmate`, `mesh`, `spm`, and the DNS backends, all sharing the BIND renderer in `zonefile` |
| `internal/objstore` | R2/S3 → MinIO or managed EU S3; hand-rolled SigV4 extraction, `mc`/rclone generation |
| `internal/provider` | EU edge-provider catalogue + sovereignty tiering + edge cloud-init |
| `internal/parity` | The parity prober: live edge vs staged edge, HARD/SOFT divergence |
| `internal/doctor` · `internal/guard` · `internal/validate` | Pre-flight · failguards · artifact validation |
| `internal/report` · `internal/render` · `internal/cost` · `internal/runbook` | Verdict vocabulary · terminal rendering · cost model · the human-facing `MIGRATION.md` |
| `cmd/flareover` | The CLI: the thirteen phase verbs |

## Design principles

- **Env-only auth.** Every credential is read from an environment variable, never passed on `argv`. See [Security](/docs/security/).
- **Zero external Go dependencies.** Standard library only — a small, auditable supply chain.
- **Honest sovereignty tiering.** EU-owned operators are labelled sovereign; a US operator's EU region is offered but never called sovereign. See [Sovereignty Tiers](/docs/sovereignty-tiers/).
- **The engine never touches your source or your registrar.** The DS publish and the final NS move stay explicit human steps.
