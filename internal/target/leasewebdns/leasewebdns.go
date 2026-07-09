// SPDX-License-Identifier: AGPL-3.0-only

// Package leasewebdns renders and provisions the authoritative zone on Leaseweb
// DNS (EU-owned, Netherlands). Like every DNS target it splits into a pure
// Generator (an offline review artifact) and a live Provisioner:
//
//	leaseweb-dns/<zone>.zone   records only (no SOA/NS — Leaseweb owns them), a
//	                           preview of what the apply will set
//
// The live apply (provision.go) uses the Leaseweb Domains API
// (/hosting/v2/domains/{domain}/resourceRecordSets): per (name,type) it deletes
// the existing set and recreates it (a REPLACE), so re-running converges. The
// Leaseweb DNS domain must already exist. Proxied Cloudflare records have
// already been de-proxied by the plan builder.
package leasewebdns

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
func (Generator) Name() string { return "leaseweb-dns" }

// Generate implements target.Generator (a pure function of the plan).
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	z := p.DNS
	origin := zonefile.FQDN(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s — preview of the Leaseweb DNS apply.\n", z.Name)
	b.WriteString("; Leaseweb owns SOA and NS for the zone; they are intentionally omitted.\n")
	b.WriteString("; Apply live with: flareover provision --dns leaseweb (LEASEWEB_API_KEY).\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(zonefile.RenderRecord(origin, r))
	}

	note := "Preview only — the live apply reconciles each rrset via the Leaseweb Domains API " +
		"(provision --dns leaseweb). The Leaseweb DNS domain must already exist. Leaseweb owns SOA/NS; " +
		"the registrar NS cutover stays a human step."
	if z.DNSSEC {
		note += " DNSSEC requested: manage it in the Leaseweb control panel (not yet automated)."
	}
	return []target.Artifact{{
		Path: "leaseweb-dns/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}
