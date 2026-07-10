// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package gandidns renders and provisions the authoritative zone on Gandi
// LiveDNS (EU-owned, France). Like every DNS target it splits into a pure
// Generator (an offline review artifact) and a live Provisioner:
//
//	gandi-dns/<zone>.zone   records only (no SOA/NS: Gandi owns them), a preview
//	                        of what the apply will set
//
// The live apply (provision.go) uses Gandi LiveDNS: it PUTs each (name,type)
// rrset (an idempotent REPLACE), so re-running converges. The domain must be
// attached to LiveDNS. Proxied Cloudflare records have already been de-proxied
// by the plan builder.
package gandidns

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
func (Generator) Name() string { return "gandi-dns" }

// Generate implements target.Generator (a pure function of the plan).
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	z := p.DNS
	origin := zonefile.FQDN(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s: preview of the Gandi LiveDNS apply.\n", z.Name)
	b.WriteString("; Gandi owns SOA and NS for the zone; they are intentionally omitted.\n")
	b.WriteString("; Apply live with: flareover provision --dns gandi (GANDI_PAT).\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(zonefile.RenderRecord(origin, r))
	}

	note := "Preview only: the live apply PUTs each rrset via Gandi LiveDNS (provision --dns gandi). " +
		"The domain must be attached to LiveDNS. Gandi owns SOA/NS; the registrar NS cutover stays a human step."
	if z.DNSSEC {
		note += " DNSSEC requested: manage it in the Gandi control panel (not yet automated)."
	}
	return []target.Artifact{{
		Path: "gandi-dns/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}
