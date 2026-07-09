// SPDX-License-Identifier: AGPL-3.0-only

// Package route53 renders and provisions the authoritative zone on AWS Route 53.
//
// Honest tier: Route 53 is US-operated (AWS) and globally anycast — the DNS
// control plane is not confinable to an EU region, and it stays under US CLOUD
// Act reach. flareover offers it as the pragmatic "keep your existing AWS
// account" bridge and states that trade-off; it is NOT a sovereign option. The
// EU-owned managed choices (bunny.net, Scaleway, OVH, Gandi, Leaseweb) are.
//
// Like every DNS target it splits into a pure Generator (an offline review
// artifact) and a live Provisioner. The Provisioner UPSERTs each rrset via the
// Route 53 API (SigV4-signed), so re-running converges.
package route53

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
func (Generator) Name() string { return "route53" }

// Generate implements target.Generator (a pure function of the plan).
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	z := p.DNS
	origin := zonefile.FQDN(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s — preview of the Route 53 apply.\n", z.Name)
	b.WriteString("; Route 53 owns SOA and NS for the zone; they are intentionally omitted.\n")
	b.WriteString("; Apply live with: flareover provision --dns route53 (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY).\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(zonefile.RenderRecord(origin, r))
	}

	note := "Preview only — the live apply UPSERTs each rrset via the Route 53 API (provision --dns route53). " +
		"The hosted zone must already exist. TIER: Route 53 is US-operated (AWS), globally anycast — NOT a " +
		"sovereign option (US CLOUD Act reach); it is the pragmatic keep-your-AWS-account bridge. For EU " +
		"sovereignty use bunny.net / Scaleway / OVH / Gandi / Leaseweb. The registrar NS cutover stays a human step."
	if z.DNSSEC {
		note += " DNSSEC requested: enable it for the zone in the Route 53 console (not yet automated)."
	}
	return []target.Artifact{{
		Path: "route53/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}
