// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package gandidns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target"
)

func ptr(i int) *int { return &i }

func samplePlan() ir.Plan {
	return ir.Plan{
		Zone: "example.com",
		DNS: ir.DNSZone{
			Name: "example.com",
			Records: []ir.DNSRecord{
				{Type: "A", Name: "example.com", Content: "198.51.100.10", TTL: 120}, // sub-300 → clamped
				{Type: "MX", Name: "example.com", Content: "mail.example.com", TTL: 300, Priority: ptr(10)},
				{Type: "TXT", Name: "example.com", Content: "v=spf1 -all", TTL: 300},
			},
		},
	}
}

var _ target.Generator = Generator{}

func TestGeneratorOmitsSOAandNS(t *testing.T) {
	arts, err := Generator{}.Generate(samplePlan())
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 || arts[0].Path != "gandi-dns/example.com.zone" {
		t.Fatalf("artifacts = %+v", arts)
	}
	if b := string(arts[0].Content); strings.Contains(b, "\tSOA\t") || strings.Contains(b, "\tNS\t") {
		t.Error("preview leaked SOA/NS: Gandi owns them")
	}
}

type putBody struct {
	TTL    int      `json:"rrset_ttl"`
	Values []string `json:"rrset_values"`
}

func TestProvisionPutsRrsetsIdempotently(t *testing.T) {
	puts := map[string]putBody{} // "name/type" → body

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat" {
			w.WriteHeader(401)
			return
		}
		if r.Method != http.MethodPut || !strings.Contains(r.URL.Path, "/records/") {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		var b putBody
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &b)
		// key = the two path segments after /records/
		i := strings.Index(r.URL.Path, "/records/")
		puts[r.URL.Path[i+len("/records/"):]] = b
		w.WriteHeader(201)
	}))
	defer srv.Close()

	p := NewProvisioner("pat")
	p.BaseURL = srv.URL
	if err := p.Provision(context.Background(), samplePlan().DNS); err != nil {
		t.Fatal(err)
	}

	// Apex A rrset: PUT /records/@/A, ttl clamped to 300, value the raw IP.
	a, ok := puts["@/A"]
	if !ok {
		t.Fatalf("no PUT for @/A; got %v", keys(puts))
	}
	if a.TTL != 300 {
		t.Errorf("apex A ttl = %d, want 300 (clamped from 120)", a.TTL)
	}
	if len(a.Values) != 1 || a.Values[0] != "198.51.100.10" {
		t.Errorf("apex A values = %v", a.Values)
	}
	// MX rrset: priority embedded in the value, target dotted.
	mx, ok := puts["@/MX"]
	if !ok || len(mx.Values) != 1 || mx.Values[0] != "10 mail.example.com." {
		t.Errorf("MX PUT = %+v (want value %q)", mx, "10 mail.example.com.")
	}
	// TXT rrset: Gandi wants the BIND-quoted value.
	txt, ok := puts["@/TXT"]
	if !ok || txt.Values[0] != `"v=spf1 -all"` {
		t.Errorf("TXT PUT = %+v (want quoted value)", txt)
	}
}

func keys(m map[string]putBody) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
