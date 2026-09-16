# Contributing to flareover

Thanks for considering a contribution. flareover has one non-negotiable rule, and most of these notes
exist to protect it.

## The 0% false-positive contract

flareover must **never emit configuration that silently changes behaviour**. Every source element gets
exactly one verdict:

- **AUTO**: a provably-equivalent mapping exists → config is generated.
- **ASK**: a faithful mapping exists but one detail is ambiguous → a single bounded yes/no.
- **MANUAL**: no faithful deterministic mapping → surfaced, never guessed.

If you add a mapping, it may only be **AUTO** when the target genuinely reproduces the source
behaviour. When in doubt, it is ASK or MANUAL. A plausible-but-approximate mapping presented as AUTO is
the one kind of change that will always be rejected: "honest and incomplete" beats "complete and
wrong".

## Ground rules

- **Determinism.** Classification and generation are a pure function of `snapshot + decisions.lock`.
  No wall-clock, no network in that path. Re-running must produce byte-identical output.
  The single exception is secret material, which cannot be a function of the inputs: the mesh
  keypairs are generated on the **first** run and reused from `<out>/mesh` on every run after
  it (`internal/target/mesh`), so a re-run is still byte-identical. If you ever need randomness
  elsewhere, it needs the same treatment — generate once, persist, reuse — not a new exception.
- **Standard library only.** The engine has zero external Go dependencies; please keep it that way
  unless there is a compelling, discussed reason.
- **Tests are the spec.** Add a test for every mapping (its verdict *and* its generated fragment).
  Golden snapshots live in `testdata/golden/`; update them deliberately, never blindly.

## Before you open a PR

```bash
make fmt        # gofmt ./cmd ./internal
make vet        # go vet ./...
make lint       # staticcheck, the version CI runs
make vuln       # govulncheck, the version CI runs
make race       # go test -race ./...
```

CI runs exactly these (build + vet + staticcheck + govulncheck + `go test -race`
+ gofmt check). `lint` and `vuln` are pinned to the versions in the Makefile;
bump them together with the `toolchain` line in `go.mod`, on purpose — a linter
release should not fail an unrelated PR. Please keep commits focused and their
messages explaining the *why*.

**Why govulncheck, with zero dependencies?** Because that is the reason it is
needed rather than the reason it is not: the only code that can carry an
advisory here is the standard library, and `osv-scanner` has no `go.sum` to
read. The first run reported eighteen reachable standard-library
vulnerabilities.

## Getting started

```bash
git clone https://github.com/fabriziosalmi/flareover
cd flareover
go build ./cmd/flareover
go test ./...
```

Test fixtures under `testdata/fixtures/` are sanitized captures, safe to read, never real data. Real
per-migration snapshots and any infrastructure notes stay out of the repo (see `.gitignore`).

## Changing what callers depend on

flareover is pre-1.0, and the surface callers actually depend on is the CLI: the
verb names, the flags, and the **exit codes**. A shell chain breaks as hard on a
changed exit code as on a renamed flag.

If a change alters any of those, add a `### Breaking` entry to `CHANGELOG.md`
under Unreleased saying what to do about it. The generated release notes list
commits; that file is where somebody upgrading looks.

## Documentation

The canonical docs are `website/src/content/docs/`. Three things are generated
from the code and defended by tests, so don't hand-edit them: the coverage
matrix, the sovereignty tiers, and the CLI reference's completeness (add a flag
to `usage` and `cmd/flareover/docs_test.go` fails until the reference documents
it).

The GitHub wiki is a mirror of those pages, not a second source. Regenerate it
rather than editing it by hand:

```bash
git clone https://github.com/fabriziosalmi/flareover.wiki.git /tmp/flareover-wiki
node website/scripts/sync-wiki.mjs /tmp/flareover-wiki
cd /tmp/flareover-wiki && git commit -am "docs: sync from canonical docs" && git push
```

`Home.md`, `_Sidebar.md` and `_Footer.md` are hand-maintained wiki furniture and
the script leaves them alone.

## Security

Please report vulnerabilities privately (see [SECURITY.md](SECURITY.md)).
