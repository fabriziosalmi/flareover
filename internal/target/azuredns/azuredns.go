// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package azuredns renders and provisions the authoritative zone on Azure DNS.
//
// Honest tier: Azure DNS is US-operated (Microsoft) and globally anycast: the
// DNS control plane is not confinable to an EU region, and it stays under US
// CLOUD Act reach. flareover offers it as the pragmatic "keep your existing
// Azure subscription" bridge and states that trade-off; it is NOT a sovereign
// option. The EU-owned managed choices (bunny.net, Scaleway, OVH, Gandi,
// Leaseweb) are.
//
// Like every DNS target it splits into a pure Generator (an offline review
// artifact) and a live Provisioner. The Provisioner PUTs each (name,type)
// recordset via the Azure Resource Manager DNS API (an idempotent
// create-or-replace), so re-running converges.
package azuredns

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
func (Generator) Name() string { return "azure-dns" }

// Generate implements target.Generator (a pure function of the plan).
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	z := p.DNS
	origin := zonefile.FQDN(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s: preview of the Azure DNS apply.\n", z.Name)
	b.WriteString("; Azure owns SOA and NS for the zone; they are intentionally omitted.\n")
	b.WriteString("; Apply live with: flareover provision --dns azure (AZURE_CLIENT_ID/SECRET/TENANT_ID + AZURE_SUBSCRIPTION_ID/RESOURCE_GROUP).\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(zonefile.RenderRecord(origin, r))
	}

	note := "Preview only: the live apply PUTs each recordset via the Azure DNS API (provision --dns azure). " +
		"The DNS zone must already exist in the resource group. TIER: Azure DNS is US-operated (Microsoft), " +
		"globally anycast: NOT a sovereign option (US CLOUD Act reach); it is the pragmatic keep-your-Azure-" +
		"subscription bridge. For EU sovereignty use bunny.net / Scaleway / OVH / Gandi / Leaseweb. The registrar " +
		"NS cutover stays a human step."
	if z.DNSSEC {
		note += " DNSSEC requested: enable it on the zone in the Azure portal (not yet automated)."
	}
	return []target.Artifact{{
		Path: "azure-dns/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}
