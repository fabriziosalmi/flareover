// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package clouddns

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	if arts[0].Path != "cloud-dns/example.com.zone" {
		t.Errorf("path = %q", arts[0].Path)
	}
	// The note must state the US-operated / not-sovereign trade-off, never hide it.
	if n := arts[0].Note; !strings.Contains(n, "US-operated") || !strings.Contains(n, "NOT a") {
		t.Errorf("Cloud DNS note must state the sovereignty trade-off: %q", n)
	}
}

// testSA builds a minimal, valid service-account key JSON with a fresh RSA key,
// so the provisioner can sign a real JWT in the token exchange.
func testSA(t *testing.T, tokenURI string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	sa := map[string]string{
		"type":         "service_account",
		"project_id":   "proj-123",
		"private_key":  string(keyPEM),
		"client_email": "sa@proj-123.iam.gserviceaccount.com",
		"token_uri":    tokenURI,
	}
	b, _ := json.Marshal(sa)
	return b
}

func TestProvisionAuthenticatesAndReconciles(t *testing.T) {
	var gotAuth string
	var creates, patches []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			io.WriteString(w, `{"access_token":"ya29.test","expires_in":3600,"token_type":"Bearer"}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/managedZones"):
			if r.URL.Query().Get("dnsName") != "example.com." {
				t.Errorf("dnsName = %q", r.URL.Query().Get("dnsName"))
			}
			io.WriteString(w, `{"managedZones":[{"name":"zone-abc","dnsName":"example.com.","nameServers":["ns-cloud-a1.googledomains.com.","ns-cloud-a2.googledomains.com."]}]}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rrsets"):
			gotAuth = r.Header.Get("Authorization")
			var rs map[string]any
			json.NewDecoder(r.Body).Decode(&rs)
			if rs["type"] == "TXT" { // force the conflict→patch branch for TXT
				w.WriteHeader(http.StatusConflict)
				io.WriteString(w, `{"error":{"code":409,"message":"already exists"}}`)
				return
			}
			creates = append(creates, rs)
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/rrsets/"):
			var rs map[string]any
			json.NewDecoder(r.Body).Decode(&rs)
			patches = append(patches, rs)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	p, err := NewProvisioner(testSA(t, srv.URL+"/token"), "")
	if err != nil {
		t.Fatal(err)
	}
	p.BaseURL = srv.URL
	if p.Project != "proj-123" {
		t.Errorf("project = %q, want proj-123 (from the key)", p.Project)
	}
	if err := p.Provision(context.Background(), samplePlan().DNS); err != nil {
		t.Fatal(err)
	}

	if gotAuth != "Bearer ya29.test" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	// A + MX created; MX priority embedded in the rrdata (Cloud DNS/BIND style).
	var sawA, sawMX bool
	for _, c := range creates {
		switch c["type"] {
		case "A":
			sawA = true
			if got := c["name"]; got != "example.com." {
				t.Errorf("A name = %v (want FQDN)", got)
			}
		case "MX":
			sawMX = true
			if rd, _ := c["rrdatas"].([]any); len(rd) != 1 || rd[0] != "10 mail.example.com." {
				t.Errorf("MX rrdatas = %v", c["rrdatas"])
			}
		}
	}
	if !sawA || !sawMX {
		t.Errorf("missing create: A=%v MX=%v", sawA, sawMX)
	}
	// TXT conflicted → patched, with the value BIND-quoted.
	if len(patches) != 1 || patches[0]["type"] != "TXT" {
		t.Fatalf("expected one TXT patch, got %v", patches)
	}
	if rd, _ := patches[0]["rrdatas"].([]any); len(rd) != 1 || rd[0] != `"v=spf1 -all"` {
		t.Errorf("TXT rrdatas = %v (want quoted)", patches[0]["rrdatas"])
	}

	ns, err := p.Nameservers(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 || ns[0] != "ns-cloud-a1.googledomains.com." {
		t.Errorf("nameservers = %v", ns)
	}
}

func TestNewProvisionerRejectsBadKey(t *testing.T) {
	if _, err := NewProvisioner([]byte(`{"client_email":"x","private_key":"not-a-pem"}`), "p"); err == nil {
		t.Error("expected error for a non-PEM private_key")
	}
}
