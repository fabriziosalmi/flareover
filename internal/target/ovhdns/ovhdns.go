// SPDX-License-Identifier: AGPL-3.0-only

// Package ovhdns renders and provisions the authoritative zone on OVHcloud's
// managed DNS (EU-owned, France). Like every DNS target it splits into a pure
// Generator (an offline review artifact) and a live Provisioner:
//
//	ovh-dns/<zone>.zone   records only (no SOA/NS — OVH owns them), a preview of
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
	origin := fqdn(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s — preview of the OVHcloud DNS apply.\n", z.Name)
	b.WriteString("; OVH owns SOA and NS for the zone; they are intentionally omitted.\n")
	b.WriteString("; Apply live with: flareover provision --dns ovh (OVH_APPLICATION_KEY/SECRET + OVH_CONSUMER_KEY).\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(renderRecord(origin, r))
	}

	note := "Preview only — the live apply REPLACEs each rrset via the OVH API and refreshes the zone " +
		"(provision --dns ovh). The OVH DNS zone must already exist. OVH owns SOA/NS; the registrar NS " +
		"cutover stays a human step."
	if z.DNSSEC {
		note += " DNSSEC requested: enable it for the zone in the OVH control panel (not yet automated)."
	}
	return []target.Artifact{{
		Path: "ovh-dns/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}

// renderRecord serializes one de-proxied record as a BIND preview line. OVH's
// record `target` is exactly this BIND rdata (priority embedded for MX/SRV), so
// the Provisioner reuses the same rendering.
func renderRecord(origin string, r ir.DNSRecord) string {
	name := recordName(origin, r.Name)
	ttl := ttlOrDefault(r.TTL)
	switch strings.ToUpper(r.Type) {
	case "MX":
		return fmt.Sprintf("%s\t%d\tIN\tMX\t%s\n", name, ttl, mxTarget(r))
	case "SRV":
		return fmt.Sprintf("%s\t%d\tIN\tSRV\t%s\n", name, ttl, srvTarget(r))
	case "TXT":
		return fmt.Sprintf("%s\t%d\tIN\tTXT\t%q\n", name, ttl, r.Content)
	case "CNAME":
		return fmt.Sprintf("%s\t%d\tIN\tCNAME\t%s\n", name, ttl, fqdn(r.Content))
	default: // A, AAAA, CAA, and other address-like records
		return fmt.Sprintf("%s\t%d\tIN\t%s\t%s\n", name, ttl, strings.ToUpper(r.Type), r.Content)
	}
}

// recordName renders a record name relative to the zone origin ("@" for apex).
func recordName(origin, name string) string {
	n := fqdn(name)
	if n == origin {
		return "@"
	}
	return strings.TrimSuffix(n, "."+origin)
}

func priority(r ir.DNSRecord) int {
	if r.Priority != nil {
		return *r.Priority
	}
	return 0
}

// mxTarget is the BIND MX rdata "priority target." — OVH stores exactly this.
func mxTarget(r ir.DNSRecord) string {
	return fmt.Sprintf("%d %s", priority(r), fqdn(r.Content))
}

// srvTarget is the BIND SRV rdata "priority weight port target." — the IR keeps
// priority separate and "weight port target" in Content.
func srvTarget(r ir.DNSRecord) string {
	fields := strings.Fields(r.Content)
	if len(fields) > 0 {
		fields[len(fields)-1] = fqdn(fields[len(fields)-1])
	}
	return fmt.Sprintf("%d %s", priority(r), strings.Join(fields, " "))
}

func fqdn(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

func ttlOrDefault(ttl int) int {
	if ttl <= 0 {
		return 300
	}
	return ttl
}
