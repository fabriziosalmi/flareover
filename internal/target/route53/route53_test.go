// SPDX-License-Identifier: AGPL-3.0-only

package route53

import (
	"context"
	"encoding/xml"
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

func TestGeneratorTierIsHonest(t *testing.T) {
	arts, err := Generator{}.Generate(samplePlan())
	if err != nil {
		t.Fatal(err)
	}
	if arts[0].Path != "route53/example.com.zone" {
		t.Errorf("path = %q", arts[0].Path)
	}
	// The note must state the US-operated / not-sovereign trade-off, never hide it.
	if n := arts[0].Note; !strings.Contains(n, "US-operated") || !strings.Contains(n, "NOT a") {
		t.Errorf("Route 53 note must state the sovereignty trade-off: %q", n)
	}
}

func TestProvisionSignsAndUpserts(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/hostedzonesbyname"):
			io.WriteString(w, `<ListHostedZonesByNameResponse><HostedZones><HostedZone><Id>/hostedzone/Z123</Id><Name>example.com.</Name></HostedZone></HostedZones></ListHostedZonesByNameResponse>`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rrset"):
			gotAuth = r.Header.Get("Authorization")
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			io.WriteString(w, `<ChangeResourceRecordSetsResponse/>`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	p := NewProvisioner("AKID", "secret", "")
	p.Endpoint = srv.URL
	if err := p.Provision(context.Background(), samplePlan().DNS); err != nil {
		t.Fatal(err)
	}

	// SigV4 auth header present + well-formed.
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 Credential=AKID/") || !strings.Contains(gotAuth, "/us-east-1/route53/aws4_request") {
		t.Errorf("bad SigV4 Authorization: %q", gotAuth)
	}
	// The change batch UPSERTs, with TXT quoted and MX priority embedded.
	var req struct {
		Changes []struct {
			Action string   `xml:"Action"`
			Name   string   `xml:"ResourceRecordSet>Name"`
			Type   string   `xml:"ResourceRecordSet>Type"`
			Values []string `xml:"ResourceRecordSet>ResourceRecords>ResourceRecord>Value"`
		} `xml:"ChangeBatch>Changes>Change"`
	}
	if err := xml.Unmarshal([]byte(gotBody), &req); err != nil {
		t.Fatalf("parse change batch: %v\n%s", err, gotBody)
	}
	var mx, txt bool
	for _, c := range req.Changes {
		if c.Action != "UPSERT" {
			t.Errorf("action = %q, want UPSERT", c.Action)
		}
		if c.Type == "MX" && (len(c.Values) != 1 || c.Values[0] != "10 mail.example.com.") {
			t.Errorf("MX value = %v", c.Values)
		} else if c.Type == "MX" {
			mx = true
		}
		if c.Type == "TXT" && (len(c.Values) != 1 || c.Values[0] != `"v=spf1 -all"`) {
			t.Errorf("TXT value = %v (want quoted)", c.Values)
		} else if c.Type == "TXT" {
			txt = true
		}
	}
	if !mx || !txt {
		t.Errorf("missing MX/TXT changes: mx=%v txt=%v", mx, txt)
	}
	if !strings.Contains(gotBody, `xmlns="`+xmlns+`"`) {
		t.Error("change batch missing the Route 53 XML namespace")
	}
}
