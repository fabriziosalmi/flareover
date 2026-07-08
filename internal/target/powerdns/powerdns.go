// Package powerdns renders the authoritative zone from the plan's DNS intent.
// It emits a BIND-style zone file (which PowerDNS loads directly, or which maps
// 1:1 onto the PowerDNS HTTP API) plus a short provisioning note. Proxied
// Cloudflare records have already been de-proxied by the plan builder — this
// package only serializes the resulting zone.
package powerdns

import (
	"fmt"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target"
)

// Generator renders the zone file.
type Generator struct{}

// Name implements target.Generator.
func (Generator) Name() string { return "powerdns" }

// Generate implements target.Generator.
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	z := p.DNS
	origin := fqdn(z.Name)

	var b strings.Builder
	fmt.Fprintf(&b, "; flareover-generated authoritative zone for %s\n", z.Name)
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	b.WriteString("$TTL 300\n\n")

	// SOA + NS are placeholders filled from target infrastructure at provision
	// time. Marked clearly so they are never mistaken for real values.
	fmt.Fprintf(&b, "@\tIN\tSOA\tns1.%s hostmaster.%s (\n", origin, origin)
	b.WriteString("\t\t1          ; serial (set at provision time)\n")
	b.WriteString("\t\t3600       ; refresh\n")
	b.WriteString("\t\t600        ; retry\n")
	b.WriteString("\t\t1209600    ; expire\n")
	b.WriteString("\t\t300 )      ; minimum\n\n")
	b.WriteString("@\tIN\tNS\tns1.NAMESERVER_PLACEHOLDER.\n")
	b.WriteString("@\tIN\tNS\tns2.NAMESERVER_PLACEHOLDER.\n\n")

	for _, r := range z.Records {
		b.WriteString(renderRecord(origin, r))
	}

	note := "SOA/NS are placeholders — set ns1/ns2 to the target PowerDNS servers before load."
	if z.DNSSEC {
		note += " DNSSEC requested: run `pdnsutil secure-zone " + z.Name +
			"` after load and publish the new DS at the registrar during cutover."
	}
	return []target.Artifact{{
		Path: "powerdns/" + z.Name + ".zone", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}

func renderRecord(origin string, r ir.DNSRecord) string {
	name := recordName(origin, r.Name)
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 300
	}
	switch strings.ToUpper(r.Type) {
	case "MX":
		prio := 0
		if r.Priority != nil {
			prio = *r.Priority
		}
		return fmt.Sprintf("%s\t%d\tIN\tMX\t%d %s\n", name, ttl, prio, fqdn(r.Content))
	case "SRV":
		prio := 0
		if r.Priority != nil {
			prio = *r.Priority
		}
		return fmt.Sprintf("%s\t%d\tIN\tSRV\t%d %s\n", name, ttl, prio, srvTargetFQDN(r.Content))
	case "TXT":
		return fmt.Sprintf("%s\t%d\tIN\tTXT\t%q\n", name, ttl, r.Content)
	case "CNAME":
		return fmt.Sprintf("%s\t%d\tIN\tCNAME\t%s\n", name, ttl, fqdn(r.Content))
	default: // A, AAAA, and other address-like records
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

func fqdn(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
