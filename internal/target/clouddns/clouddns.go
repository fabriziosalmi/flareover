// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package clouddns renders and provisions the authoritative zone on Google
// Cloud DNS.
//
// Honest tier: Cloud DNS is US-operated (Google) and globally anycast: the DNS
// control plane is not confinable to an EU region, and it stays under US CLOUD
// Act reach. flareover offers it as the pragmatic "keep your existing GCP
// project" bridge and states that trade-off; it is NOT a sovereign option. The
// EU-owned managed choices (bunny.net, Scaleway, OVH, Gandi, Leaseweb) are.
//
// Like every DNS target it splits into a pure Generator (an offline review
// artifact) and a live Provisioner. The Provisioner reconciles each rrset via
// the Cloud DNS API (create, then patch on conflict), so re-running converges.
package clouddns

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
func (Generator) Name() string { return "cloud-dns" }

// Generate implements target.Generator (a pure function of the plan).
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	z := p.DNS
	origin := zonefile.FQDN(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s: preview of the Cloud DNS apply.\n", z.Name)
	b.WriteString("; Cloud DNS owns SOA and NS for the managed zone; they are intentionally omitted.\n")
	b.WriteString("; Apply live with: flareover provision --dns clouddns (GOOGLE_APPLICATION_CREDENTIALS).\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(zonefile.RenderRecord(origin, r))
	}

	note := "Preview only: the live apply reconciles each rrset via the Cloud DNS API (provision --dns clouddns). " +
		"The managed zone must already exist. TIER: Cloud DNS is US-operated (Google), globally anycast, NOT a " +
		"sovereign option (US CLOUD Act reach); it is the pragmatic keep-your-GCP-project bridge. For EU " +
		"sovereignty use bunny.net / Scaleway / OVH / Gandi / Leaseweb. The registrar NS cutover stays a human step."
	if z.DNSSEC {
		note += " DNSSEC requested: enable it on the managed zone in the Cloud DNS console (not yet automated)."
	}
	return []target.Artifact{{
		Path: "cloud-dns/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}
