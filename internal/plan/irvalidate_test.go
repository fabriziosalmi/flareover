// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package plan

import (
	"strings"
	"testing"

	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
)

// Build validates the plan before returning it, which is the only check that
// covers values arriving from decisions.lock — a hand-editable JSON map with no
// schema whose values reach the Caddyfile through a bare %s.
func TestBuildRejectsAnInjectedOriginFromDecisions(t *testing.T) {
	s := cf.Snapshot{
		SchemaVersion: cf.CurrentSchemaVersion,
		Zone:          cf.Zone{Name: "example.com"},
		Settings:      cf.ZoneSettings{SSL: "strict"},
		DNSRecords: []cf.DNSRecord{
			{Type: "A", Name: "www.example.com", Content: "192.0.2.1", Proxied: true, TTL: 300},
		},
	}
	// The payload closes the reverse_proxy line and opens a file_server rooted
	// at / inside the generated site block.
	opts := Options{
		EdgeIP: "5.9.1.1",
		Decisions: map[string]string{
			"origin:www.example.com": "10.0.0.9:443\n\tfile_server browse root /",
		},
	}
	_, err := Build(s, opts)
	if err == nil {
		t.Fatal("a decisions value carrying a newline was accepted into the plan")
	}
	if !strings.Contains(err.Error(), "control character") {
		t.Errorf("error should name the problem, got: %v", err)
	}
}

// The origin scheme is returned verbatim from the answer and decides both the
// upstream URL and, via a case-sensitive comparison, whether
// tls_insecure_skip_verify is emitted. Anything outside {http, https} silently
// changes both.
func TestBuildRejectsAnOriginSchemeOutsideHTTPAndHTTPS(t *testing.T) {
	s := cf.Snapshot{
		SchemaVersion: cf.CurrentSchemaVersion,
		Zone:          cf.Zone{Name: "example.com"},
		Settings:      cf.ZoneSettings{SSL: "flexible"},
		DNSRecords: []cf.DNSRecord{
			{Type: "A", Name: "www.example.com", Content: "192.0.2.1", Proxied: true, TTL: 300},
		},
	}
	opts := Options{
		EdgeIP: "5.9.1.1",
		Decisions: map[string]string{
			"origin:www.example.com": "10.0.0.9:80",
			"flexible-origin-scheme": "HTTPS", // the question's options are http/https, lower-case
		},
	}
	_, err := Build(s, opts)
	if err == nil {
		t.Fatal("an out-of-vocabulary origin scheme was accepted; tls_insecure_skip_verify would be silently dropped")
	}
	if !strings.Contains(err.Error(), "Scheme") {
		t.Errorf("error should name the field, got: %v", err)
	}
}

func TestBuildAcceptsTheAnsweredVocabulary(t *testing.T) {
	s := cf.Snapshot{
		SchemaVersion: cf.CurrentSchemaVersion,
		Zone:          cf.Zone{Name: "example.com"},
		Settings:      cf.ZoneSettings{SSL: "flexible"},
		DNSRecords: []cf.DNSRecord{
			{Type: "A", Name: "www.example.com", Content: "192.0.2.1", Proxied: true, TTL: 300},
		},
	}
	for _, scheme := range []string{"http", "https"} {
		opts := Options{
			EdgeIP: "5.9.1.1",
			Decisions: map[string]string{
				"origin:www.example.com": "10.0.0.9:80",
				"flexible-origin-scheme": scheme,
			},
		}
		p, err := Build(s, opts)
		if err != nil {
			t.Fatalf("scheme %q was rejected: %v", scheme, err)
		}
		if len(p.Sites) != 1 || p.Sites[0].Origin.Scheme != scheme {
			t.Errorf("scheme %q did not survive into the plan", scheme)
		}
	}
}

// IPv6 origins and bare hostnames are legitimate answers and must keep working.
func TestBuildAcceptsOrdinaryOriginShapes(t *testing.T) {
	for _, origin := range []string{
		"10.0.0.9:443",
		"origin.internal.example.com:8443",
		"[2001:db8::1]:443",
		"192.0.2.7",
	} {
		s := cf.Snapshot{
			SchemaVersion: cf.CurrentSchemaVersion,
			Zone:          cf.Zone{Name: "example.com"},
			Settings:      cf.ZoneSettings{SSL: "strict"},
			DNSRecords: []cf.DNSRecord{
				{Type: "A", Name: "www.example.com", Content: "192.0.2.1", Proxied: true, TTL: 300},
			},
		}
		opts := Options{EdgeIP: "5.9.1.1", Decisions: map[string]string{"origin:www.example.com": origin}}
		if _, err := Build(s, opts); err != nil {
			t.Errorf("origin %q was rejected: %v", origin, err)
		}
	}
}
