// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package scalewaydns

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

func samplePlan(dnssec bool) ir.Plan {
	return ir.Plan{
		Zone: "example.com",
		DNS: ir.DNSZone{
			Name:   "example.com",
			DNSSEC: dnssec,
			Records: []ir.DNSRecord{
				{Type: "A", Name: "example.com", Content: "198.51.100.10", TTL: 300},
				{Type: "A", Name: "www.example.com", Content: "198.51.100.10", TTL: 300},
				{Type: "CNAME", Name: "cdn.example.com", Content: "edge.example.net", TTL: 3600},
				{Type: "MX", Name: "example.com", Content: "mail.example.com", TTL: 300, Priority: ptr(10)},
				{Type: "TXT", Name: "example.com", Content: "v=spf1 -all", TTL: 300},
			},
		},
	}
}

// --- Generator ------------------------------------------------------------

// TestGeneratorOmitsSOAandNS is the correctness guard: Scaleway owns SOA/NS, so
// the preview must carry neither.
func TestGeneratorOmitsSOAandNS(t *testing.T) {
	arts, err := Generator{}.Generate(samplePlan(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 {
		t.Fatalf("artifacts = %d, want 1", len(arts))
	}
	a := arts[0]
	if a.Path != "scaleway-dns/example.com.zone" {
		t.Errorf("path = %q", a.Path)
	}
	body := string(a.Content)
	if strings.Contains(body, "\tSOA\t") || strings.Contains(body, "\tNS\t") {
		t.Error("preview leaked SOA/NS: Scaleway owns them")
	}
	for _, w := range []string{"$ORIGIN example.com.", "@\t300\tIN\tMX\t10 mail.example.com.", "www\t300\tIN\tA\t198.51.100.10"} {
		if !strings.Contains(body, w) {
			t.Errorf("preview missing %q", w)
		}
	}
}

// --- Provisioner ----------------------------------------------------------

type patchBody struct {
	Changes []struct {
		Set struct {
			IDFields struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"id_fields"`
			Records []struct {
				Data     string `json:"data"`
				Name     string `json:"name"`
				Priority uint32 `json:"priority"`
				TTL      uint32 `json:"ttl"`
				Type     string `json:"type"`
			} `json:"records"`
		} `json:"set"`
	} `json:"changes"`
	DisallowNewZoneCreation bool `json:"disallow_new_zone_creation"`
}

func TestProvisionCreatesZoneAndSetsRecords(t *testing.T) {
	var sawCreate, sawPatch bool
	var patch patchBody

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") != "sk" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/domain/v2beta1/dns-zones":
			sawCreate = true
			var b map[string]any
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &b)
			if b["domain"] != "example.com" || b["subdomain"] != "" || b["project_id"] != "proj" {
				t.Errorf("create body = %v", b)
			}
			w.WriteHeader(200)
		case r.Method == http.MethodPatch && r.URL.Path == "/domain/v2beta1/dns-zones/example.com/records":
			sawPatch = true
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &patch); err != nil {
				t.Fatalf("patch body: %v", err)
			}
			w.WriteHeader(200)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	p := NewProvisioner("sk", "proj")
	p.BaseURL = srv.URL
	if err := p.Provision(context.Background(), samplePlan(false).DNS); err != nil {
		t.Fatal(err)
	}
	if !sawCreate || !sawPatch {
		t.Fatalf("missing calls: create=%v patch=%v", sawCreate, sawPatch)
	}
	if !patch.DisallowNewZoneCreation {
		t.Error("disallow_new_zone_creation should be true after explicit create")
	}

	// Find the MX and the apex A among the set changes and check the shape.
	var foundMX, foundApexA bool
	for _, c := range patch.Changes {
		if c.Set.IDFields.Type == "MX" {
			foundMX = true
			if len(c.Set.Records) != 1 || c.Set.Records[0].Priority != 10 || c.Set.Records[0].Data != "mail.example.com." {
				t.Errorf("MX set = %+v (want priority 10, data mail.example.com., dotted)", c.Set.Records)
			}
		}
		if c.Set.IDFields.Type == "A" && c.Set.IDFields.Name == "" {
			foundApexA = true // Scaleway apex name is the empty string, not "@"
			if c.Set.Records[0].Name != "" {
				t.Errorf("apex A record name = %q, want empty", c.Set.Records[0].Name)
			}
		}
	}
	if !foundMX || !foundApexA {
		t.Errorf("missing changes: MX=%v apexA=%v", foundMX, foundApexA)
	}
}

// TestProvisionIdempotentOnExistingZone: a 409 on create must not abort; the
// record set still runs, so re-applying an already-migrated zone converges.
func TestProvisionIdempotentOnExistingZone(t *testing.T) {
	var sawPatch bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusConflict) // zone already exists
			io.WriteString(w, `{"message":"dns zone already exists"}`)
		case r.Method == http.MethodPatch:
			sawPatch = true
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	p := NewProvisioner("sk", "proj")
	p.BaseURL = srv.URL
	if err := p.Provision(context.Background(), samplePlan(false).DNS); err != nil {
		t.Fatalf("409-on-create should be tolerated, got: %v", err)
	}
	if !sawPatch {
		t.Error("record set was not attempted after an existing-zone conflict")
	}
}

func TestNameservers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/nameservers") {
			io.WriteString(w, `{"ns":[{"name":"ns0.dom.scw.cloud"},{"name":"ns1.dom.scw.cloud"}]}`)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	p := NewProvisioner("sk", "proj")
	p.BaseURL = srv.URL
	ns, err := p.Nameservers(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 || ns[0] != "ns0.dom.scw.cloud" {
		t.Errorf("nameservers = %v", ns)
	}
}

var _ target.Generator = Generator{} // compile-time: Generator satisfies the contract
