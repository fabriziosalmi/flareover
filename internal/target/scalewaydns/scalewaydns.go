// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package scalewaydns renders and provisions the authoritative zone on
// Scaleway's managed DNS (Domains and DNS, EU / France): an EU-owned
// alternative to self-hosting PowerDNS. Like every DNS target it splits into a
// pure Generator (an offline review artifact) and a live Provisioner:
//
//	scaleway-dns/<zone>.zone   records only (no SOA/NS: Scaleway owns them),
//	                           a human-readable preview of what will be applied
//
// The live apply (provision.go) uses the Domains API's idempotent record-set
// change (`PATCH …/records` with a per-(name,type) `set`), so re-running
// converges: no BIND round-trip, no duplicate records. Proxied Cloudflare
// records have already been de-proxied by the plan builder.
package scalewaydns

import (
	"fmt"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target"
	"github.com/fabriziosalmi/flareover/internal/target/zonefile"
)

// Generator renders the offline review zone.
type Generator struct{}

// Name implements target.Generator.
func (Generator) Name() string { return "scaleway-dns" }

// Generate implements target.Generator. It is a pure function of the plan: the
// live apply is provision.go, so here we only emit a records-only BIND preview
// (Scaleway is authoritative and manages SOA/NS itself).
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	z := p.DNS
	origin := zonefile.FQDN(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s: preview of the Scaleway DNS apply.\n", z.Name)
	b.WriteString("; Scaleway owns SOA and NS for the zone; they are intentionally omitted.\n")
	b.WriteString("; Apply live with: flareover provision --dns scaleway (SCW_SECRET_KEY + SCW_DEFAULT_PROJECT_ID).\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(zonefile.RenderRecord(origin, r))
	}

	note := "Preview only: the live apply sets records idempotently via the Scaleway Domains API " +
		"(provision --dns scaleway). Scaleway owns SOA/NS; the registrar NS cutover stays a human step."
	if z.DNSSEC {
		note += " DNSSEC requested: enable it for the zone in the Scaleway console (not yet automated)."
	}
	return []target.Artifact{{
		Path: "scaleway-dns/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}
