// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package ovhdns

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
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
				{Type: "A", Name: "example.com", Content: "198.51.100.10", TTL: 300},
				{Type: "A", Name: "www.example.com", Content: "198.51.100.10", TTL: 300},
				{Type: "MX", Name: "example.com", Content: "mail.example.com", TTL: 300, Priority: ptr(10)},
				{Type: "TXT", Name: "example.com", Content: "v=spf1 -all", TTL: 300},
			},
		},
	}
}

var _ target.Generator = Generator{}

// --- Generator ------------------------------------------------------------

func TestGeneratorOmitsSOAandNS(t *testing.T) {
	arts, err := Generator{}.Generate(samplePlan())
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 || arts[0].Path != "ovh-dns/example.com.zone" {
		t.Fatalf("artifacts = %+v", arts)
	}
	body := string(arts[0].Content)
	if strings.Contains(body, "\tSOA\t") || strings.Contains(body, "\tNS\t") {
		t.Error("preview leaked SOA/NS: OVH owns them")
	}
	if !strings.Contains(body, "@\t300\tIN\tMX\t10 mail.example.com.") {
		t.Error("MX preview must embed the priority (BIND rdata)")
	}
}

// --- Signature (pinned against an independent recomputation) --------------

func TestSignMatchesFormula(t *testing.T) {
	got := sign("sec", "ck", "POST", "https://eu.api.ovh.com/1.0/domain/zone/x/record", `{"a":1}`, 1700000000)

	h := sha1.New()
	io.WriteString(h, `sec+ck+POST+https://eu.api.ovh.com/1.0/domain/zone/x/record+{"a":1}+1700000000`)
	want := fmt.Sprintf("$1$%x", h.Sum(nil))

	if got != want {
		t.Errorf("sign = %s, want %s", got, want)
	}
	if !strings.HasPrefix(got, "$1$") || len(got) != 3+40 {
		t.Errorf("signature format wrong: %q", got)
	}
	// Sensitivity: a different body must change the signature.
	if sign("sec", "ck", "POST", "https://x", "a", 1) == sign("sec", "ck", "POST", "https://x", "b", 1) {
		t.Error("signature must depend on the body")
	}
}

// --- Provisioner ----------------------------------------------------------

func TestProvisionReplacesRrsetsAndRefreshes(t *testing.T) {
	var seq []string
	var posted []ovhRecordBody
	var sawDelete, sawRefresh bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seq = append(seq, r.Method+" "+r.URL.Path)
		// /auth/time is unauthenticated; everything else must be signed.
		if r.URL.Path != "/auth/time" {
			for _, hdr := range []string{"X-Ovh-Application", "X-Ovh-Consumer", "X-Ovh-Timestamp", "X-Ovh-Signature"} {
				if r.Header.Get(hdr) == "" {
					t.Errorf("%s %s missing %s", r.Method, r.URL.Path, hdr)
				}
			}
			if sig := r.Header.Get("X-Ovh-Signature"); sig != "" && !strings.HasPrefix(sig, "$1$") {
				t.Errorf("bad signature %q", sig)
			}
		}
		switch {
		case r.URL.Path == "/auth/time":
			io.WriteString(w, "1700000000")
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/record"):
			// One existing record for the apex A set, none otherwise.
			if r.URL.Query().Get("fieldType") == "A" && r.URL.Query().Get("subDomain") == "" {
				io.WriteString(w, "[111]")
			} else {
				io.WriteString(w, "[]")
			}
		case r.Method == http.MethodDelete:
			sawDelete = true
			w.WriteHeader(200)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/record"):
			var b ovhRecordBody
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &b)
			posted = append(posted, b)
			w.WriteHeader(200)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/refresh"):
			sawRefresh = true
			w.WriteHeader(200)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	p := NewProvisioner("app", "sec", "ck")
	p.BaseURL = srv.URL
	if err := p.Provision(context.Background(), samplePlan().DNS); err != nil {
		t.Fatal(err)
	}

	if !sawDelete {
		t.Error("existing apex A record was not deleted before recreate (no REPLACE)")
	}
	if !sawRefresh {
		t.Error("zone refresh was never triggered")
	}
	if last := seq[len(seq)-1]; !strings.HasSuffix(last, "/refresh") {
		t.Errorf("refresh must be last, got %q", last)
	}

	// The MX POST carries the priority embedded in target; apex records use "".
	var mx *ovhRecordBody
	for i := range posted {
		if posted[i].FieldType == "MX" {
			mx = &posted[i]
		}
	}
	if mx == nil || mx.Target != "10 mail.example.com." || mx.SubDomain != "" {
		t.Errorf("MX body = %+v (want target %q, empty subDomain)", mx, "10 mail.example.com.")
	}
}
