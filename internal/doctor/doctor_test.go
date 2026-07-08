// SPDX-License-Identifier: AGPL-3.0-only

package doctor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenStrength(t *testing.T) {
	cases := []struct {
		token string
		want  Status
	}{
		{"short", Fail}, // < 32
		{"flareover-certmate-demo-token-1234567890abcdef", Fail}, // contains "demo"
		{"aVeryLongButPerfectlyStrongBearerToken0001", OK},
	}
	for _, c := range cases {
		got := checkTokenStrength("tok", c.token).Status
		if got != c.want {
			t.Errorf("token %q: got %v want %v", c.token, got, c.want)
		}
	}
}

func TestGoNoGo(t *testing.T) {
	if !GoNoGo([]Check{{Status: OK}, {Status: Warn}}) {
		t.Error("OK + WARN must be GO")
	}
	if GoNoGo([]Check{{Status: OK}, {Status: Fail}}) {
		t.Error("any FAIL must be NO-GO")
	}
}

func TestPowerDNSAndSPMLive(t *testing.T) {
	pdns := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`[{"id":"localhost"}]`))
	}))
	defer pdns.Close()
	spm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	}))
	defer spm.Close()

	checks := Run(context.Background(), Options{PDNSURL: pdns.URL, PDNSKey: "k", SPMURL: spm.URL})
	if len(checks) != 2 || !GoNoGo(checks) {
		t.Fatalf("expected 2 passing checks, got %+v", checks)
	}

	// Wrong key → FAIL.
	bad := Run(context.Background(), Options{PDNSURL: pdns.URL, PDNSKey: "nope"})
	if GoNoGo(bad) {
		t.Error("a rejected PowerDNS key must be NO-GO")
	}
}

func TestCertMateDNSProviderWarning(t *testing.T) {
	// Healthy, token accepted, but no DNS provider configured → WARN (DNS-01 would fail).
	cm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
		case "/api/settings":
			_, _ = w.Write([]byte(`{"cloudflare_token":"","dns_providers":{"cloudflare":{"api_token":null}}}`))
		}
	}))
	defer cm.Close()

	checks := Run(context.Background(), Options{CertMateURL: cm.URL, CertMateToken: "aStrongEnoughBearerTokenValue00001"})
	var cmCheck *Check
	for i := range checks {
		if checks[i].Name == "CertMate API" {
			cmCheck = &checks[i]
		}
	}
	if cmCheck == nil || cmCheck.Status != Warn {
		t.Fatalf("expected CertMate WARN for missing DNS provider, got %+v", checks)
	}
}
