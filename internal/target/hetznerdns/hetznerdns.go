// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package hetznerdns renders and provisions the authoritative zone on Hetzner
// DNS (EU-owned, Germany: a sovereign option, unlike the US-operated
// Route 53 / Cloud DNS / Azure DNS bridges).
//
// Like every DNS target it splits into a pure Generator (an offline review
// artifact) and a live Provisioner. The Provisioner creates each record it does
// not already find via the Hetzner DNS API (create-if-absent, keyed on
// name/type/value), so re-running converges without duplicates. The zone must
// already exist. Hetzner owns SOA/NS; the registrar NS cutover stays a human
// step.
package hetznerdns

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
func (Generator) Name() string { return "hetzner-dns" }

// Generate implements target.Generator (a pure function of the plan).
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	z := p.DNS
	origin := zonefile.FQDN(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s: preview of the Hetzner DNS apply.\n", z.Name)
	b.WriteString("; Hetzner owns SOA and NS for the zone; they are intentionally omitted.\n")
	b.WriteString("; Apply live with: flareover provision --dns hetzner (HETZNER_DNS_TOKEN).\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(zonefile.RenderRecord(origin, r))
	}

	note := "Preview only: the live apply creates each record via the Hetzner DNS API (provision --dns hetzner). " +
		"The zone must already exist. TIER: Hetzner is EU-owned (Germany): a sovereign option. Hetzner owns SOA/NS; " +
		"the registrar NS cutover stays a human step."
	if z.DNSSEC {
		note += " DNSSEC requested: Hetzner has no record-API to automate it. Enable DNSSEC in the Hetzner DNS console and publish the DS at the registrar."
	}
	return []target.Artifact{{
		Path: "hetzner-dns/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}
