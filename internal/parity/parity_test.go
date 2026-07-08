// SPDX-License-Identifier: AGPL-3.0-only

package parity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

// edge builds a fake edge whose behavior is controlled per (host,path).
func edge(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}

// ep turns an httptest server URL into an Endpoint that dials it directly
// (probe Host is used for routing, the server address for the connection).
func ep(server *httptest.Server) Endpoint {
	return Endpoint{Scheme: "http", DialOverride: strings.TrimPrefix(server.URL, "http://")}
}

// A faithful "Caddy" edge and a noisy "Cloudflare" edge with identical behavior
// must produce a PASS gate — provider noise (Date/Server/CF-Ray) is ignored.
func TestParityPassIgnoresNoise(t *testing.T) {
	cf := edge(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "abc123")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/old/probe" {
			w.Header().Set("Location", "https://www.example.com/new/probe")
			w.WriteHeader(301)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("hello"))
	})
	defer cf.Close()
	caddy := edge(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Caddy")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/old/probe" {
			w.Header().Set("Location", "https://www.example.com/new/probe")
			w.WriteHeader(301)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("hello"))
	})
	defer caddy.Close()

	probes := []Probe{
		{Name: "root", Host: "example.com", Path: "/"},
		{Name: "redirect", Host: "example.com", Path: "/old/probe"},
	}
	rep, err := NewComparer().Compare(context.Background(), ep(cf), ep(caddy), probes)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Gate() {
		t.Fatalf("expected PASS gate, got:\n%s", rep.Text())
	}
}

// A status mismatch is a HARD divergence and must FAIL the gate.
func TestParityHardFailOnStatus(t *testing.T) {
	cf := edge(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("ok")) })
	defer cf.Close()
	caddy := edge(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) })
	defer caddy.Close()

	rep, _ := NewComparer().Compare(context.Background(), ep(cf), ep(caddy),
		[]Probe{{Name: "root", Host: "example.com", Path: "/"}})
	if rep.Gate() {
		t.Fatal("status 200 vs 502 must fail the gate")
	}
	if !rep.Results[0].HardFail() {
		t.Fatal("expected a hard divergence")
	}
}

// A redirect-target mismatch is HARD (behavior changed).
func TestParityHardFailOnRedirect(t *testing.T) {
	cf := edge(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://www.example.com/")
		w.WriteHeader(301)
	})
	defer cf.Close()
	caddy := edge(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.org/wrong")
		w.WriteHeader(301)
	})
	defer caddy.Close()

	rep, _ := NewComparer().Compare(context.Background(), ep(cf), ep(caddy),
		[]Probe{{Name: "apex", Host: "example.com", Path: "/"}})
	if rep.Gate() {
		t.Fatal("different redirect target must fail the gate")
	}
}

// A body difference on a 200 is SOFT: surfaced, but does not block cutover.
func TestParitySoftOnBody(t *testing.T) {
	cf := edge(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("A")) })
	defer cf.Close()
	caddy := edge(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("B")) })
	defer caddy.Close()

	rep, _ := NewComparer().Compare(context.Background(), ep(cf), ep(caddy),
		[]Probe{{Name: "root", Host: "example.com", Path: "/"}})
	if !rep.Gate() {
		t.Fatal("body-only difference should be SOFT and still PASS the gate")
	}
	if rep.Results[0].Match() {
		t.Fatal("body difference should still be reported as a divergence")
	}
}

func TestProbesFromPlan(t *testing.T) {
	p := ir.Plan{Sites: []ir.Site{{
		Host:      "example.com",
		Redirects: []ir.Redirect{{Match: "/old/*", To: "https://x/", Status: 301}},
	}}}
	probes := ProbesFromPlan(p)
	if len(probes) != 2 {
		t.Fatalf("expected root + redirect probe, got %d", len(probes))
	}
	var haveRedirect bool
	for _, pr := range probes {
		if pr.Path == "/old/probe" {
			haveRedirect = true
		}
	}
	if !haveRedirect {
		t.Errorf("redirect glob not turned into a concrete probe path: %+v", probes)
	}
}
