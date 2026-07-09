// SPDX-License-Identifier: AGPL-3.0-only

package azuredns

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
		{Type: "SRV", Name: "_sip._tcp.example.com", Content: "5 5060 sipserver.example.com", TTL: 300, Priority: ptr(10)},
		{Type: "CAA", Name: "example.com", Content: `0 issue "letsencrypt.org"`, TTL: 300},
	}}}
}

var _ target.Generator = Generator{}

func TestGeneratorTierIsHonest(t *testing.T) {
	arts, err := Generator{}.Generate(samplePlan())
	if err != nil {
		t.Fatal(err)
	}
	if arts[0].Path != "azure-dns/example.com.zone" {
		t.Errorf("path = %q", arts[0].Path)
	}
	if n := arts[0].Note; !strings.Contains(n, "US-operated") || !strings.Contains(n, "NOT a") {
		t.Errorf("Azure DNS note must state the sovereignty trade-off: %q", n)
	}
}

func TestProvisionAuthenticatesAndPutsPerType(t *testing.T) {
	var gotAuth string
	puts := map[string]map[string]any{} // "TYPE/name" -> properties
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			io.WriteString(w, `{"access_token":"aad.test","expires_in":3600,"token_type":"Bearer"}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/dnsZones/example.com"):
			io.WriteString(w, `{"properties":{"nameServers":["ns1-01.azure-dns.com.","ns2-01.azure-dns.net."]}}`)
		case r.Method == http.MethodPut:
			gotAuth = r.Header.Get("Authorization")
			if r.URL.Query().Get("api-version") == "" {
				t.Error("PUT missing api-version query param")
			}
			// .../dnsZones/example.com/<TYPE>/<name>
			parts := strings.Split(r.URL.Path, "/dnsZones/example.com/")
			var body struct {
				Properties map[string]any `json:"properties"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			puts[parts[1]] = body.Properties
			io.WriteString(w, `{}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	p := NewProvisioner("tid", "cid", "csecret", "sub-1", "rg-1")
	p.BaseURL, p.AuthHost = srv.URL, srv.URL
	if err := p.Provision(context.Background(), samplePlan().DNS); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer aad.test" {
		t.Errorf("Authorization = %q", gotAuth)
	}

	// A (apex "@"): ARecords[].ipv4Address, TTL preserved.
	if a := puts["A/@"]; a == nil {
		t.Error("missing A/@ PUT")
	} else {
		if a["TTL"].(float64) != 300 {
			t.Errorf("A TTL = %v", a["TTL"])
		}
		recs := a["ARecords"].([]any)
		if recs[0].(map[string]any)["ipv4Address"] != "198.51.100.10" {
			t.Errorf("A record = %v", recs)
		}
	}
	// MX: preference from Priority, exchange undotted.
	if mx := puts["MX/@"]; mx == nil {
		t.Error("missing MX/@ PUT")
	} else {
		rec := mx["MXRecords"].([]any)[0].(map[string]any)
		if rec["preference"].(float64) != 10 || rec["exchange"] != "mail.example.com" {
			t.Errorf("MX record = %v", rec)
		}
	}
	// TXT: value is an array of raw (unquoted) strings.
	if txt := puts["TXT/@"]; txt == nil {
		t.Error("missing TXT/@ PUT")
	} else {
		val := txt["TXTRecords"].([]any)[0].(map[string]any)["value"].([]any)
		if val[0] != "v=spf1 -all" {
			t.Errorf("TXT value = %v (want raw, unquoted)", val)
		}
	}
	// SRV: priority/weight/port/target parsed out of "weight port target".
	if srv := puts["SRV/_sip._tcp"]; srv == nil {
		t.Error("missing SRV/_sip._tcp PUT")
	} else {
		rec := srv["SRVRecords"].([]any)[0].(map[string]any)
		if rec["priority"].(float64) != 10 || rec["weight"].(float64) != 5 ||
			rec["port"].(float64) != 5060 || rec["target"] != "sipserver.example.com" {
			t.Errorf("SRV record = %v", rec)
		}
	}
	// CAA: flags/tag/value, value unquoted; Azure's lowercase caaRecords key.
	if caa := puts["CAA/@"]; caa == nil {
		t.Error("missing CAA/@ PUT")
	} else {
		rec := caa["caaRecords"].([]any)[0].(map[string]any)
		if rec["flags"].(float64) != 0 || rec["tag"] != "issue" || rec["value"] != "letsencrypt.org" {
			t.Errorf("CAA record = %v", rec)
		}
	}

	ns, err := p.Nameservers(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 || ns[0] != "ns1-01.azure-dns.com." {
		t.Errorf("nameservers = %v", ns)
	}
}

func TestUnsupportedTypeSurfaces(t *testing.T) {
	// A type we cannot map faithfully must error, never silently vanish.
	_, err := recordProps("NAPTR", 300, []ir.DNSRecord{{Type: "NAPTR", Content: "x"}})
	if err == nil {
		t.Error("expected an error for an unsupported record type")
	}
}
