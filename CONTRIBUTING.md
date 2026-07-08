# Contributing to flareover

Thanks for considering a contribution. flareover has one non-negotiable rule, and most of these notes
exist to protect it.

## The 0% false-positive contract

flareover must **never emit configuration that silently changes behaviour**. Every source element gets
exactly one verdict:

- **AUTO** — a provably-equivalent mapping exists → config is generated.
- **ASK** — a faithful mapping exists but one detail is ambiguous → a single bounded yes/no.
- **MANUAL** — no faithful deterministic mapping → surfaced, never guessed.

If you add a mapping, it may only be **AUTO** when the target genuinely reproduces the source
behaviour. When in doubt, it is ASK or MANUAL. A plausible-but-approximate mapping presented as AUTO is
the one kind of change that will always be rejected — "honest and incomplete" beats "complete and
wrong".

## Ground rules

- **Determinism.** Classification and generation are a pure function of `snapshot + decisions.lock`.
  No wall-clock, no randomness, no network in that path. Re-running must produce byte-identical output.
- **Standard library only.** The engine has zero external Go dependencies; please keep it that way
  unless there is a compelling, discussed reason.
- **Tests are the spec.** Add a test for every mapping (its verdict *and* its generated fragment).
  Golden snapshots live in `testdata/golden/`; update them deliberately, never blindly.

## Before you open a PR

```bash
gofmt -l cmd internal      # must print nothing
go vet ./...               # must be clean
go test -race ./...        # must pass
```

CI runs exactly these. Please keep commits focused and their messages explaining the *why*.

## Getting started

```bash
git clone https://github.com/fabriziosalmi/flareover
cd flareover
go build ./cmd/flareover
go test ./...
```

Test fixtures under `testdata/fixtures/` are sanitized captures — safe to read, never real data. Real
per-migration snapshots and any infrastructure notes stay out of the repo (see `.gitignore`).

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
