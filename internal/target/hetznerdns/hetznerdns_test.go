// SPDX-License-Identifier: AGPL-3.0-only

package hetznerdns

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
	return ir.Plan{Zone: "example.com", DNS: ir.DNSZone{Name: "example.com", Records: []ir.DNSRecord{
		{Type: "A", Name: "example.com", Content: "198.51.100.10", TTL: 300},
		{Type: "MX", Name: "example.com", Content: "mail.example.com", TTL: 300, Priority: ptr(10)},
		{Type: "TXT", Name: "example.com", Content: "v=spf1 -all", TTL: 300},
	}}}
}

var _ target.Generator = Generator{}

// TestGeneratorTierIsSovereign: Hetzner is EU-owned, so — unlike the US-operated
// bridges — its note must claim the sovereign tier, never "US-operated".
func TestGeneratorTierIsSovereign(t *testing.T) {
	arts, err := Generator{}.Generate(samplePlan())
	if err != nil {
		t.Fatal(err)
	}
	if arts[0].Path != "hetzner-dns/example.com.zone" {
		t.Errorf("path = %q", arts[0].Path)
	}
	n := arts[0].Note
	if !strings.Contains(n, "EU-owned") || !strings.Contains(n, "sovereign") {
		t.Errorf("Hetzner note must claim the sovereign tier: %q", n)
	}
	if strings.Contains(n, "US-operated") {
		t.Errorf("Hetzner is not US-operated: %q", n)
	}
}

func TestProvisionCreatesOnlyMissing(t *testing.T) {
	var gotToken string
	var created []hetznerRecord
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones"):
			if r.URL.Query().Get("name") != "example.com" {
				t.Errorf("zone name = %q", r.URL.Query().Get("name"))
			}
			io.WriteString(w, `{"zones":[{"id":"z1","name":"example.com","ns":["hydrogen.ns.hetzner.com","oxygen.ns.hetzner.de"]}]}`)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/records"):
			// The A record already exists → must be skipped (idempotency).
			io.WriteString(w, `{"records":[{"id":"r1","zone_id":"z1","type":"A","name":"@","value":"198.51.100.10","ttl":300}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/records":
			gotToken = r.Header.Get("Auth-API-Token")
			var rec hetznerRecord
			json.NewDecoder(r.Body).Decode(&rec)
			created = append(created, rec)
			io.WriteString(w, `{"record":{"id":"new"}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	p := NewProvisioner("tok-123")
	p.BaseURL = srv.URL
	if err := p.Provision(context.Background(), samplePlan().DNS); err != nil {
		t.Fatal(err)
	}

	if gotToken != "tok-123" {
		t.Errorf("Auth-API-Token = %q", gotToken)
	}
	// A already existed → not re-created; MX + TXT are new.
	byType := map[string]hetznerRecord{}
	for _, r := range created {
		byType[r.Type] = r
	}
	if _, ok := byType["A"]; ok {
		t.Error("A record already existed and must NOT be re-created")
	}
	if mx := byType["MX"]; mx.Value != "10 mail.example.com." {
		t.Errorf("MX value = %q (want priority embedded, FQDN dotted)", mx.Value)
	}
	if txt := byType["TXT"]; txt.Value != `"v=spf1 -all"` {
		t.Errorf("TXT value = %q (want BIND-quoted)", txt.Value)
	}
	if len(created) != 2 {
		t.Errorf("created %d records, want 2 (MX, TXT)", len(created))
	}
	// Apex name is "@".
	if byType["MX"].Name != "@" {
		t.Errorf("apex name = %q, want @", byType["MX"].Name)
	}

	ns, err := p.Nameservers(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 || ns[0] != "hydrogen.ns.hetzner.com" {
		t.Errorf("nameservers = %v", ns)
	}
}
