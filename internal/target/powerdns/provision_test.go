package powerdns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

func sampleZone() ir.DNSZone {
	prio := 10
	return ir.DNSZone{
		Name:   "example.com",
		DNSSEC: true,
		Records: []ir.DNSRecord{
			{Type: "A", Name: "example.com", Content: "5.9.1.1", TTL: 300},
			{Type: "A", Name: "www.example.com", Content: "5.9.1.1", TTL: 300},
			{Type: "MX", Name: "example.com", Content: "mail.example.com", TTL: 3600, Priority: &prio},
			{Type: "TXT", Name: "example.com", Content: "v=spf1 ~all", TTL: 3600},
		},
	}
}

func TestBuildRRSetsGroupsAndFormats(t *testing.T) {
	rr := buildRRSets(sampleZone(), []string{"ns1.eu-dns.net", "ns2.eu-dns.net"})
	byKey := map[string]rrset{}
	for _, r := range rr {
		byKey[r.Type+" "+r.Name] = r
	}
	// A example.com. is one rrset with one record; www is separate.
	if a := byKey["A example.com."]; len(a.Records) != 1 || a.Records[0].Content != "5.9.1.1" {
		t.Errorf("apex A = %+v", a)
	}
	if _, ok := byKey["A www.example.com."]; !ok {
		t.Error("missing www A rrset")
	}
	// MX carries the priority in content.
	if mx := byKey["MX example.com."]; mx.Records[0].Content != "10 mail.example.com." {
		t.Errorf("MX content = %q", mx.Records[0].Content)
	}
	// TXT is quoted; names and CNAME/MX targets are FQDN.
	if txt := byKey["TXT example.com."]; !strings.HasPrefix(txt.Records[0].Content, `"`) {
		t.Errorf("TXT not quoted: %q", txt.Records[0].Content)
	}
	// SOA + 2 NS at apex.
	if _, ok := byKey["SOA example.com."]; !ok {
		t.Error("missing SOA")
	}
	if ns := byKey["NS example.com."]; len(ns.Records) != 2 {
		t.Errorf("NS records = %d, want 2", len(ns.Records))
	}
}

func TestProvisionCreatesWhenAbsent(t *testing.T) {
	var gotCreate bool
	var createBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/zones/example.com."):
			w.WriteHeader(404) // absent → triggers create
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/zones"):
			gotCreate = true
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &createBody)
			w.WriteHeader(201)
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	p := NewProvisioner(srv.URL, "secret")
	if err := p.Provision(context.Background(), sampleZone(), []string{"ns1.eu-dns.net", "ns2.eu-dns.net"}); err != nil {
		t.Fatal(err)
	}
	if !gotCreate {
		t.Fatal("expected a zone create POST")
	}
	if createBody["kind"] != "Native" || createBody["name"] != "example.com." {
		t.Errorf("create body = %+v", createBody)
	}
}

func TestProvisionPatchesWhenPresent(t *testing.T) {
	var gotPatch bool
	var patchBody struct {
		RRSets []rrset `json:"rrsets"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(200) // present
		case r.Method == http.MethodPatch:
			gotPatch = true
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			w.WriteHeader(204)
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()

	p := NewProvisioner(srv.URL, "k")
	if err := p.Provision(context.Background(), sampleZone(), []string{"ns1.eu-dns.net"}); err != nil {
		t.Fatal(err)
	}
	if !gotPatch {
		t.Fatal("expected a PATCH when the zone exists")
	}
	for _, rr := range patchBody.RRSets {
		if rr.ChangeType != "REPLACE" {
			t.Errorf("rrset %s changetype = %q, want REPLACE", rr.Name, rr.ChangeType)
		}
	}
}

func TestEnableDNSSECReturnsDS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/cryptokeys") {
			_, _ = w.Write([]byte(`[{"active":true,"ds":["12345 13 2 abcdef"]}]`))
			return
		}
		w.WriteHeader(201)
	}))
	defer srv.Close()

	ds, err := NewProvisioner(srv.URL, "k").EnableDNSSEC(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 || !strings.Contains(ds[0], "12345") {
		t.Errorf("DS = %v", ds)
	}
}
