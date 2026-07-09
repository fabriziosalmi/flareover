// SPDX-License-Identifier: AGPL-3.0-only

// Package zonefile is the shared BIND rendering used by every DNS target. The
// per-record serialization is provider-independent — a de-proxied ir.DNSRecord
// becomes the same authoritative-DNS line whether it lands in a PowerDNS zone
// file or a bunny.net/Scaleway/OVH preview — so it lives here once. The pieces
// that genuinely differ per provider (structured API payloads, the empty-vs-"@"
// apex name, records-only-vs-full-zone headers) stay in each target package.
package zonefile

import (
	"fmt"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

// FQDN ensures a trailing dot.
func FQDN(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// RecordName renders a record name relative to the zone origin ("@" for apex).
func RecordName(origin, name string) string {
	n := FQDN(name)
	if n == origin {
		return "@"
	}
	return strings.TrimSuffix(n, "."+origin)
}

// TTLOrDefault clamps a non-positive TTL to the 300s default.
func TTLOrDefault(ttl int) int {
	if ttl <= 0 {
		return 300
	}
	return ttl
}

// Priority returns the record's priority (0 when unset).
func Priority(r ir.DNSRecord) int {
	if r.Priority != nil {
		return *r.Priority
	}
	return 0
}

// SRVTargetFQDN dots the SRV target (the last field of "weight port target").
func SRVTargetFQDN(content string) string {
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return content
	}
	fields[len(fields)-1] = FQDN(fields[len(fields)-1])
	return strings.Join(fields, " ")
}

// RData renders the BIND rdata for a record: the MX/SRV priority is embedded,
// FQDN targets are dotted, and TXT is quoted. This is exactly the value a
// PowerDNS rrset or an OVH record `target` carries (OVH aside for TXT, which it
// wants unquoted — that stays local).
func RData(r ir.DNSRecord) string {
	switch strings.ToUpper(r.Type) {
	case "MX":
		return fmt.Sprintf("%d %s", Priority(r), FQDN(r.Content))
	case "SRV":
		return fmt.Sprintf("%d %s", Priority(r), SRVTargetFQDN(r.Content))
	case "TXT":
		return fmt.Sprintf("%q", r.Content)
	case "CNAME":
		return FQDN(r.Content)
	default: // A, AAAA, CAA, NS, and other address-like records
		return r.Content
	}
}

// RenderRecord serializes one de-proxied record as a BIND zone line.
func RenderRecord(origin string, r ir.DNSRecord) string {
	return fmt.Sprintf("%s\t%d\tIN\t%s\t%s\n", RecordName(origin, r.Name), TTLOrDefault(r.TTL), strings.ToUpper(r.Type), RData(r))
}

// APIValue renders the rdata the way most managed-DNS REST APIs want it: like
// RData (MX/SRV priority embedded, CNAME/NS dotted), except TXT and address
// records are the raw value — these APIs quote TXT themselves. Use this for a
// provider whose record `value`/`content` field is not a BIND zone-file line
// (OVH, Leaseweb); use RData for BIND-quoting providers (PowerDNS, Gandi).
func APIValue(r ir.DNSRecord) string {
	switch strings.ToUpper(r.Type) {
	case "MX":
		return fmt.Sprintf("%d %s", Priority(r), FQDN(r.Content))
	case "SRV":
		return fmt.Sprintf("%d %s", Priority(r), SRVTargetFQDN(r.Content))
	case "CNAME", "NS":
		return FQDN(r.Content)
	default: // A, AAAA, TXT, CAA, ... — the raw value
		return r.Content
	}
}
