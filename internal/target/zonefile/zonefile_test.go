// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package zonefile

import (
	"testing"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

func p(i int) *int { return &i }

func TestRenderRecordAndValues(t *testing.T) {
	origin := "example.com."
	cases := []struct {
		r        ir.DNSRecord
		wantLine string // full BIND line
		wantAPI  string // APIValue (TXT raw)
	}{
		{ir.DNSRecord{Type: "A", Name: "example.com", Content: "1.2.3.4", TTL: 300},
			"@\t300\tIN\tA\t1.2.3.4\n", "1.2.3.4"},
		{ir.DNSRecord{Type: "A", Name: "www.example.com", Content: "1.2.3.4", TTL: 0}, // ttl clamp
			"www\t300\tIN\tA\t1.2.3.4\n", "1.2.3.4"},
		{ir.DNSRecord{Type: "CNAME", Name: "cdn.example.com", Content: "edge.example.net", TTL: 3600},
			"cdn\t3600\tIN\tCNAME\tedge.example.net.\n", "edge.example.net."},
		{ir.DNSRecord{Type: "MX", Name: "example.com", Content: "mail.example.com", TTL: 300, Priority: p(10)},
			"@\t300\tIN\tMX\t10 mail.example.com.\n", "10 mail.example.com."},
		{ir.DNSRecord{Type: "NS", Name: "sub.example.com", Content: "ns1.external.net", TTL: 300}, // delegation NS must be dotted
			"sub\t300\tIN\tNS\tns1.external.net.\n", "ns1.external.net."},
		{ir.DNSRecord{Type: "TXT", Name: "example.com", Content: "v=spf1 -all", TTL: 300},
			"@\t300\tIN\tTXT\t\"v=spf1 -all\"\n", "v=spf1 -all"}, // BIND quotes; APIValue raw
	}
	for _, c := range cases {
		if got := RenderRecord(origin, c.r); got != c.wantLine {
			t.Errorf("RenderRecord(%s) = %q, want %q", c.r.Type, got, c.wantLine)
		}
		if got := APIValue(c.r); got != c.wantAPI {
			t.Errorf("APIValue(%s) = %q, want %q", c.r.Type, got, c.wantAPI)
		}
	}
}

func TestRecordNameApex(t *testing.T) {
	if RecordName("example.com.", "example.com") != "@" {
		t.Error("apex should render as @")
	}
	if RecordName("example.com.", "www.example.com") != "www" {
		t.Error("subdomain should be relative to origin")
	}
}
