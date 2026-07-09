// SPDX-License-Identifier: AGPL-3.0-only

// Package scalewaydns renders and provisions the authoritative zone on
// Scaleway's managed DNS (Domains and DNS, EU / France) — an EU-owned
// alternative to self-hosting PowerDNS. Like every DNS target it splits into a
// pure Generator (an offline review artifact) and a live Provisioner:
//
//	scaleway-dns/<zone>.zone   records only (no SOA/NS — Scaleway owns them),
//	                           a human-readable preview of what will be applied
//
// The live apply (provision.go) uses the Domains API's idempotent record-set
// change (`PATCH …/records` with a per-(name,type) `set`), so re-running
// converges — no BIND round-trip, no duplicate records. Proxied Cloudflare
// records have already been de-proxied by the plan builder.
package scalewaydns

import (
	"fmt"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target"
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
	origin := fqdn(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated records for %s — preview of the Scaleway DNS apply.\n", z.Name)
	b.WriteString("; Scaleway owns SOA and NS for the zone; they are intentionally omitted.\n")
	b.WriteString("; Apply live with: flareover provision --dns scaleway (SCW_SECRET_KEY + SCW_DEFAULT_PROJECT_ID).\n")
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")
	for _, r := range z.Records {
		b.WriteString(renderRecord(origin, r))
	}

	note := "Preview only — the live apply sets records idempotently via the Scaleway Domains API " +
		"(provision --dns scaleway). Scaleway owns SOA/NS; the registrar NS cutover stays a human step."
	if z.DNSSEC {
		note += " DNSSEC requested: enable it for the zone in the Scaleway console (not yet automated)."
	}
	return []target.Artifact{{
		Path: "scaleway-dns/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}

// renderRecord serializes one de-proxied record as a BIND preview line. It
// mirrors the powerdns/bunnydns rendering; the live Provisioner builds the
// structured Scaleway records separately (priority is a first-class field
// there, so it never has to live inside the rdata string).
func renderRecord(origin string, r ir.DNSRecord) string {
	name := recordName(origin, r.Name)
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 300
	}
	switch strings.ToUpper(r.Type) {
	case "MX":
		return fmt.Sprintf("%s\t%d\tIN\tMX\t%d %s\n", name, ttl, priority(r), fqdn(r.Content))
	case "SRV":
		return fmt.Sprintf("%s\t%d\tIN\tSRV\t%d %s\n", name, ttl, priority(r), srvTargetFQDN(r.Content))
	case "TXT":
		return fmt.Sprintf("%s\t%d\tIN\tTXT\t%q\n", name, ttl, r.Content)
	case "CNAME":
		return fmt.Sprintf("%s\t%d\tIN\tCNAME\t%s\n", name, ttl, fqdn(r.Content))
	default: // A, AAAA, CAA, and other address-like records
		return fmt.Sprintf("%s\t%d\tIN\t%s\t%s\n", name, ttl, strings.ToUpper(r.Type), r.Content)
	}
}

func priority(r ir.DNSRecord) int {
	if r.Priority != nil {
		return *r.Priority
	}
	return 0
}

// recordName renders a record name relative to the zone origin ("@" for apex).
func recordName(origin, name string) string {
	n := fqdn(name)
	if n == origin {
		return "@"
	}
	return strings.TrimSuffix(n, "."+origin)
}

func fqdn(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// srvTargetFQDN ensures the SRV target (last field of "weight port target")
// carries a trailing dot.
func srvTargetFQDN(content string) string {
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return content
	}
	fields[len(fields)-1] = fqdn(fields[len(fields)-1])
	return strings.Join(fields, " ")
}
