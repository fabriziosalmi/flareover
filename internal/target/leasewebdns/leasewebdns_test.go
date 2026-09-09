// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package leasewebdns

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
				{Type: "A", Name: "www.example.com", Content: "198.51.100.10", TTL: 300},
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
	if len(arts) != 1 || arts[0].Path != "leaseweb-dns/example.com.zone" {
		t.Fatalf("artifacts = %+v", arts)
	}
	if b := string(arts[0].Content); strings.Contains(b, "\tSOA\t") || strings.Contains(b, "\tNS\t") {
		t.Error("preview leaked SOA/NS: Leaseweb owns them")
	}
}

func TestProvisionDeletesThenCreates(t *testing.T) {
	var seq []string
	var posted []lswRecordSet

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Lsw-Auth") != "key" {
			w.WriteHeader(401)
			return
		}
		seq = append(seq, r.Method+" "+r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			// The pre-read that makes the replacement window recoverable.
			w.WriteHeader(404)
		case http.MethodDelete:
			// Pretend the MX set doesn't exist yet → 404 must be tolerated.
			if strings.HasSuffix(r.URL.Path, "/example.com/MX") {
				w.WriteHeader(404)
				return
			}
			w.WriteHeader(204)
		case http.MethodPost:
			var rs lswRecordSet
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &rs)
			posted = append(posted, rs)
			w.WriteHeader(201)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	p := NewProvisioner("key")
	p.BaseURL = srv.URL
	if err := p.Provision(context.Background(), samplePlan().DNS); err != nil {
		t.Fatal(err)
	}

	// Every rrset is read, then deleted, then created (REPLACE). The GET is what
	// lets a failed create put back what the delete removed: without it the
	// replacement window is destructive rather than merely incomplete.
	for i := 0; i+2 < len(seq); i += 3 {
		if !strings.HasPrefix(seq[i], "GET ") {
			t.Errorf("step %d = %q, want a GET first (so the old rrset can be restored)", i, seq[i])
		}
		if !strings.HasPrefix(seq[i+1], "DELETE ") {
			t.Errorf("step %d = %q, want a DELETE after the GET", i+1, seq[i+1])
		}
		if !strings.HasPrefix(seq[i+2], "POST ") {
			t.Errorf("step %d = %q, want a POST after the DELETE", i+2, seq[i+2])
		}
	}

	// The POST body uses the dotted FQDN name, content via APIValue (MX priority
	// embedded, TXT raw, not BIND-quoted).
	var www, mx, txt *lswRecordSet
	for i := range posted {
		switch posted[i].Type {
		case "A":
			www = &posted[i]
		case "MX":
			mx = &posted[i]
		case "TXT":
			txt = &posted[i]
		}
	}
	if www == nil || www.Name != "www.example.com." || www.Content[0] != "198.51.100.10" {
		t.Errorf("A set = %+v (want dotted name)", www)
	}
	if mx == nil || mx.Content[0] != "10 mail.example.com." {
		t.Errorf("MX set = %+v (want priority embedded)", mx)
	}
	if txt == nil || txt.Content[0] != "v=spf1 -all" {
		t.Errorf("TXT set = %+v (want raw, unquoted value)", txt)
	}
}
