// SPDX-License-Identifier: AGPL-3.0-only

// Package bunnydns renders the authoritative zone for bunny.net's managed EU
// DNS — the alternative to self-hosting PowerDNS. Where the powerdns target
// emits a full BIND zone (SOA/NS included) to load onto your own nameservers,
// bunny.net owns the SOA and NS itself, so this target emits two artifacts:
//
//	bunny-dns/<zone>.zone   records only (no SOA/NS), ready for `records import`
//	bunny-dns/apply.sh      a deterministic apply using the bunny.net CLI
//
// Proxied Cloudflare records have already been de-proxied by the plan builder;
// this package only serializes the resulting records and the CLI calls that
// stand them up. The apply script uses the verified bunny.net CLI v0.9 command
// surface (github.com/BunnyWay/cli): `dns zones add`, `dns records import`
// (imports a BIND zone file), `dns zones dnssec enable`, `dns zones
// nameservers`. Authentication is non-interactive via the BUNNYNET_API_KEY
// environment variable (or an existing `bunny login` profile).
package bunnydns

import (
	"fmt"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target"
	"github.com/fabriziosalmi/flareover/internal/target/zonefile"
)

// Generator renders the bunny.net zone import + apply script.
type Generator struct{}

// Name implements target.Generator.
func (Generator) Name() string { return "bunny-dns" }

// Generate implements target.Generator. It is a pure function of the plan.
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	z := p.DNS
	origin := zonefile.FQDN(z.Name)

	// 1) A records-only BIND zone. bunny.net is authoritative, so it manages the
	// SOA and NS — emitting placeholders here would import bogus apex NS and
	// break delegation. The importer adds these records into the zone created by
	// `dns zones add`.
	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s — import into bunny.net DNS.\n", z.Name)
	b.WriteString("; bunny.net owns SOA and NS for the zone; they are intentionally omitted.\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(zonefile.RenderRecord(origin, r))
	}
	zoneFile := z.Name + ".zone"
	zoneArt := target.Artifact{
		Path:    "bunny-dns/" + zoneFile,
		Content: []byte(b.String()),
		Mode:    0o644,
		Note:    "Records only — bunny.net owns SOA/NS. Applied by apply.sh via `bunny dns records import`.",
	}

	// 2) The apply script: deterministic, idempotent on the zone, honest about
	// the human registrar cutover it deliberately never performs.
	applyArt := target.Artifact{
		Path:    "bunny-dns/apply.sh",
		Content: []byte(renderApply(z, zoneFile)),
		Mode:    0o755,
		Note: "Auth: export BUNNYNET_API_KEY (or run `bunny login`). Re-running the import may " +
			"duplicate records — apply to a freshly created zone. The registrar NS cutover stays a human step.",
	}

	return []target.Artifact{zoneArt, applyArt}, nil
}

// renderApply builds the apply script from the verified bunny.net CLI surface.
func renderApply(z ir.DNSZone, zoneFile string) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env sh\n")
	b.WriteString("# flareover — apply the authoritative zone to bunny.net managed DNS.\n")
	b.WriteString("# Deterministically generated from the migration plan; review before running.\n")
	b.WriteString("# Verified against the bunny.net CLI v0.9 (https://github.com/BunnyWay/cli).\n")
	b.WriteString("set -eu\n\n")
	fmt.Fprintf(&b, "ZONE=%q\n", z.Name)
	b.WriteString(`DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)` + "\n")
	fmt.Fprintf(&b, "ZONEFILE=\"$DIR/%s\"\n\n", zoneFile)

	b.WriteString("# Auth is non-interactive via BUNNYNET_API_KEY; `bunny login` is the interactive\n")
	b.WriteString("# alternative. The key is read from the environment, never passed on argv.\n")
	b.WriteString("if [ -z \"${BUNNYNET_API_KEY:-}\" ]; then\n")
	b.WriteString("  echo \"note: BUNNYNET_API_KEY not set — relying on an existing 'bunny login' profile.\" >&2\n")
	b.WriteString("fi\n\n")

	b.WriteString("# Preflight: the CLI must be installed.\n")
	b.WriteString("if ! command -v bunny >/dev/null 2>&1; then\n")
	b.WriteString("  echo \"error: bunny CLI not found — install: curl -fsSL https://cli.bunny.net/install.sh | sh\" >&2\n")
	b.WriteString("  exit 127\n")
	b.WriteString("fi\n\n")

	b.WriteString("# 1) Create the zone. A pre-existing zone is not an error.\n")
	b.WriteString("bunny dns zones add \"$ZONE\" --output json || true\n\n")

	b.WriteString("# 2) Import the flareover-generated records from the BIND zone file.\n")
	b.WriteString("bunny dns records import \"$ZONE\" \"$ZONEFILE\"\n\n")

	if z.DNSSEC {
		b.WriteString("# 3) Enable DNSSEC and print the DS record to publish at your registrar.\n")
		b.WriteString("bunny dns zones dnssec enable \"$ZONE\"\n\n")
	}

	b.WriteString("# Final human step: point your registrar's nameservers at the ones below,\n")
	b.WriteString("# then let the old TTLs expire. flareover never touches the registrar.\n")
	b.WriteString("bunny dns zones nameservers \"$ZONE\"\n")
	return b.String()
}
