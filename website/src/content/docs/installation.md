---
title: "Installation"
description: "flareover ships as a single, statically-linked binary with zero external runtime dependencies. Pick whichever install path fits your"
---

flareover ships as a single, statically-linked binary with **zero external runtime dependencies**. Pick whichever install path fits your platform.

## Homebrew (macOS / Linux)

```bash
brew install fabriziosalmi/flareover/flareover
```

## Verified install script (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/flareover/main/install.sh | sh
```

The script downloads the release for your OS/arch and verifies it before installing:

- **If `cosign` is on your `PATH`**, it verifies the Sigstore signature over
  `checksums.txt` first — pinned to this repository's release workflow as the
  certificate identity and to GitHub as the OIDC issuer. A failed verification
  aborts the install. This is the check that proves the release is *ours*.
- **Then** it compares the archive's `sha256` against that (now trusted) file.

Without `cosign` the script still runs, using the checksum alone, and says so:
that detects corruption in transit, not a tampered release. If you want the full
guarantee, install cosign first — `brew install cosign`, or see
[sigstore/cosign](https://github.com/sigstore/cosign).

## From source

```bash
go install github.com/fabriziosalmi/flareover/cmd/flareover@latest
```

Building from source requires **Go 1.26+**. The engine is pure Go, standard library only: no `go.sum` full of third-party modules to vet.

## Release binaries

Every release ships prebuilt binaries for **linux / macOS / windows** on **amd64 / arm64**, each with:

- an **SBOM** (`*.sbom.json`), and
- a `checksums.txt` **signed keyless via Sigstore/cosign**.

## Verifying the signature by hand

The install script does this for you when cosign is available. To check a binary
you downloaded from the releases page yourself:

```bash
# from a release directory containing checksums.txt(.pem/.sig)
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/fabriziosalmi/flareover' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

## Credentials come from the environment

flareover **never** takes secrets on the command line: every token is read from an environment variable, so nothing leaks via `ps`, `/proc`, or shell history. You'll set these as you go (see [Security](/docs/security/) for the full list); the first one you need is the read-only zone token:

```bash
export CLOUDFLARE_API_TOKEN=…   # read-only, for `extract`
```

Next: **[Quick Start](/docs/quick-start/)**.
