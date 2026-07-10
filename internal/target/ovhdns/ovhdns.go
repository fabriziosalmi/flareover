// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package ovhdns renders and provisions the authoritative zone on OVHcloud's
// managed DNS (EU-owned, France). Like every DNS target it splits into a pure
// Generator (an offline review artifact) and a live Provisioner:
//
//	ovh-dns/<zone>.zone   records only (no SOA/NS: OVH owns them), a preview of
//	                      what the apply will set
//
// The live apply (provision.go) uses the OVH API (/domain/zone/{zone}/record):
// it REPLACEs each (subDomain,fieldType) rrset and then triggers a zone refresh,
// so re-running converges. Proxied Cloudflare records have already been
// de-proxied by the plan builder.
package ovhdns

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
func (Generator) Name() string { return "ovh-dns" }

// Generate implements target.Generator. The live apply is provision.go, so here
// we only emit a records-only BIND preview (OVH is authoritative and manages
// SOA/NS itself).
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	z := p.DNS
	origin := zonefile.FQDN(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s: preview of the OVHcloud DNS apply.\n", z.Name)
	b.WriteString("; OVH owns SOA and NS for the zone; they are intentionally omitted.\n")
	b.WriteString("; Apply live with: flareover provision --dns ovh (OVH_APPLICATION_KEY/SECRET + OVH_CONSUMER_KEY).\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(zonefile.RenderRecord(origin, r))
	}

	note := "Preview only: the live apply REPLACEs each rrset via the OVH API and refreshes the zone " +
		"(provision --dns ovh). The OVH DNS zone must already exist. OVH owns SOA/NS; the registrar NS " +
		"cutover stays a human step."
	if z.DNSSEC {
		note += " DNSSEC requested: enable it for the zone in the OVH control panel (not yet automated)."
	}
	return []target.Artifact{{
		Path: "ovh-dns/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}
