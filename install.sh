#!/usr/bin/env sh
# flareover installer: downloads the latest release for your OS/arch, verifies
# its sha256 against the signed checksums file, and installs the binary.
#
#   curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/flareover/main/install.sh | sh
#
# Env overrides: VERSION=v0.1.0  BIN_DIR=/usr/local/bin
set -eu

REPO="fabriziosalmi/flareover"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

say() { printf 'flareover-install: %s\n' "$1" >&2; }
die() { say "error: $1"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

need uname
need tar
DL=""
if command -v curl >/dev/null 2>&1; then DL="curl"; elif command -v wget >/dev/null 2>&1; then DL="wget"; else
  die "need curl or wget"
fi
fetch() { # fetch <url> <out>
  if [ "$DL" = "curl" ]; then curl -fsSL "$1" -o "$2"; else wget -qO "$2" "$1"; fi
}

# Detect platform, mapping to goreleaser's naming.
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux) os=linux ;;
  darwin) os=darwin ;;
  *) die "unsupported OS: $os (Windows: download the .zip from the releases page)" ;;
esac
arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "unsupported arch: $arch" ;;
esac

# Resolve the version tag.
if [ "$VERSION" = "latest" ]; then
  tag="$(fetch "https://api.github.com/repos/$REPO/releases/latest" /dev/stdout 2>/dev/null \
    | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$tag" ] || die "could not resolve the latest version. Set VERSION=vX.Y.Z"
else
  tag="$VERSION"
fi
ver="${tag#v}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

archive="flareover_${ver}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"
say "downloading $archive ($tag)"
fetch "$base/$archive" "$tmp/$archive" || die "download failed. Check the version/platform exists"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "could not fetch checksums.txt"

# Verify the signature over checksums.txt when cosign is available.
#
# The checksum below proves the archive matches checksums.txt. It does NOT prove
# checksums.txt is ours: both come from the same place, so an attacker able to
# replace release assets would replace both. The cosign signature is what closes
# that, by tying checksums.txt to the workflow that built it. Verifying it first
# means the checksum check that follows rests on a trusted file.
#
# cosign is optional (it is a large dependency for a one-line installer), but
# when it IS present, using it is not optional: a failed verification aborts.
if command -v cosign >/dev/null 2>&1; then
  say "verifying signature (cosign)"
  fetch "$base/checksums.txt.sig" "$tmp/checksums.txt.sig" || die "could not fetch checksums.txt.sig"
  fetch "$base/checksums.txt.pem" "$tmp/checksums.txt.pem" || die "could not fetch checksums.txt.pem"
  cosign verify-blob "$tmp/checksums.txt" \
    --signature "$tmp/checksums.txt.sig" \
    --certificate "$tmp/checksums.txt.pem" \
    --certificate-identity-regexp "^https://github.com/$REPO/\.github/workflows/release\.yml@refs/tags/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    >/dev/null 2>&1 || die "SIGNATURE VERIFICATION FAILED for checksums.txt: refusing to install"
  say "signature OK (built by $REPO's release workflow)"
else
  say "cosign not found: falling back to checksum-only verification."
  say "  This detects corruption, not a tampered release. Install cosign for full provenance:"
  say "  https://github.com/sigstore/cosign"
fi

# Verify sha256 (fail closed if no checksum tool is available).
say "verifying checksum"
expected="$(grep " $archive\$" "$tmp/checksums.txt" | awk '{print $1}')"
[ -n "$expected" ] || die "no checksum entry for $archive"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$archive" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')"
else
  die "no sha256 tool (sha256sum/shasum): refusing to install unverified"
fi
[ "$expected" = "$actual" ] || die "checksum MISMATCH: expected $expected got $actual"

tar -xzf "$tmp/$archive" -C "$tmp"
[ -f "$tmp/flareover" ] || die "archive did not contain the flareover binary"
chmod +x "$tmp/flareover"

# Install (elevate only if the target dir isn't writable).
if [ -w "$BIN_DIR" ]; then
  mv "$tmp/flareover" "$BIN_DIR/flareover"
else
  say "elevating to write $BIN_DIR"
  sudo mv "$tmp/flareover" "$BIN_DIR/flareover"
fi

say "installed $("$BIN_DIR/flareover" version) → $BIN_DIR/flareover"
