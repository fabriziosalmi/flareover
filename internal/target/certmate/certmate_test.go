// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package certmate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

func TestIssueSendsDNS01AndCA(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates/create") {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			w.WriteHeader(202)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	err := NewClient(srv.URL, "tok").Issue(context.Background(), IssueRequest{
		Domain: "*.example.com", SANs: []string{"example.com"}, CA: "actalis",
	})
	if err != nil {
		t.Fatal(err)
	}
	if body["dns_provider"] != "powerdns" {
		t.Errorf("dns_provider = %v, want powerdns (wildcard needs DNS-01)", body["dns_provider"])
	}
	if body["ca_provider"] != "actalis" {
		t.Errorf("ca_provider = %v, want actalis (EU CA)", body["ca_provider"])
	}
	if body["domain"] != "*.example.com" {
		t.Errorf("domain = %v", body["domain"])
	}
}

func TestIssueIdempotentOnAlreadyExists(t *testing.T) {
	// CertMate rejects a duplicate create with 409 CERTIFICATE_ALREADY_EXISTS.
	// A re-run must be a success (the cert already exists = goal met), not a fail.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"Certificate for *.example.com already exists.","code":"CERTIFICATE_ALREADY_EXISTS"}`))
	}))
	defer srv.Close()

	err := NewClient(srv.URL, "t").Issue(context.Background(), IssueRequest{Domain: "*.example.com"})
	if err != nil {
		t.Fatalf("409 already-exists must be idempotent success, got: %v", err)
	}
}

func TestIssueOtherConflictStillErrors(t *testing.T) {
	// A 409 that is NOT the already-exists signal must still surface as an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"account is locked","code":"ACCOUNT_LOCKED"}`))
	}))
	defer srv.Close()

	err := NewClient(srv.URL, "t").Issue(context.Background(), IssueRequest{Domain: "*.example.com"})
	if err == nil {
		t.Fatal("a non-already-exists 409 must not be swallowed")
	}
}

func TestDownloadReturnsMaterial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"fullchain_pem":"FULL","private_key_pem":"KEY","chain_pem":"CH","cert_pem":"CRT"}`))
	}))
	defer srv.Close()

	m, err := NewClient(srv.URL, "t").Download(context.Background(), "*.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if m.FullchainPEM != "FULL" || m.PrivateKeyPEM != "KEY" {
		t.Errorf("material = %+v", m)
	}
}

func TestEnsureReadyPolls(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n < 2 {
			w.WriteHeader(404) // not ready yet
			return
		}
		_, _ = w.Write([]byte(`{"fullchain_pem":"F","private_key_pem":"K"}`))
	}))
	defer srv.Close()

	m, err := NewClient(srv.URL, "t").EnsureReady(context.Background(), "d", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m.FullchainPEM != "F" {
		t.Error("expected material after polling")
	}
}

func TestPlanCertsWildcardConsolidation(t *testing.T) {
	// A plan with a wildcard site → ONE *.apex cert (with apex SAN), via DNS-01.
	p := ir.Plan{Zone: "example.com", Sites: []ir.Site{
		{Host: "*.example.com", TLS: ir.TLS{Wildcard: true}},
		{Host: "www.example.com"},
		{Host: "api.example.com"},
	}}
	certs := PlanCerts(p, "actalis", "prod", "")
	if len(certs) != 1 {
		t.Fatalf("wildcard plan should yield 1 cert, got %d", len(certs))
	}
	c := certs[0]
	if c.Domain != "*.example.com" || len(c.SANs) != 1 || c.SANs[0] != "example.com" {
		t.Errorf("wildcard cert = %+v", c)
	}
	if c.DNSProvider != "powerdns" || c.CA != "actalis" {
		t.Errorf("wildcard cert must default to DNS-01/powerdns + actalis: %+v", c)
	}
}

func TestPlanCertsDNSProviderOverride(t *testing.T) {
	// Pre-cutover bootstrap: NS still at the source, so the DNS-01 challenge must
	// be written to the SOURCE provider (cloudflare), not the target powerdns.
	p := ir.Plan{Zone: "example.com", Sites: []ir.Site{
		{Host: "*.example.com", TLS: ir.TLS{Wildcard: true}},
	}}
	certs := PlanCerts(p, "letsencrypt", "", "cloudflare")
	if len(certs) != 1 || certs[0].DNSProvider != "cloudflare" {
		t.Errorf("override must thread through to the request: %+v", certs)
	}
}

func TestPlanCertsPerHostWithoutWildcard(t *testing.T) {
	p := ir.Plan{Zone: "example.com", Sites: []ir.Site{
		{Host: "www.example.com"}, {Host: "api.example.com"},
	}}
	certs := PlanCerts(p, "letsencrypt", "", "")
	if len(certs) != 2 {
		t.Fatalf("no wildcard → per-host certs, got %d", len(certs))
	}
}
