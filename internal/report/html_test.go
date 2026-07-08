// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"strings"
	"testing"
)

func TestHTMLStructureAndCounts(t *testing.T) {
	r := Report{Zone: "example.com", Findings: []Finding{
		{Kind: "dns", Name: "www.example.com", Verdict: Auto, Target: "powerdns", Rationale: "A record → PowerDNS"},
		{Kind: "worker", Name: "edge-fn", Verdict: Manual, Rationale: "Workers logic has no faithful mapping"},
		{Kind: "tls", Name: "flexible", Verdict: Ask, Target: "caddy", Rationale: "insecure origin scheme",
			Question: &Question{ID: "tls.flexible", Prompt: "confirm plaintext origin?", Options: []string{"yes", "no"}, Default: "no"}},
	}}
	out := r.HTML()

	if !strings.HasPrefix(out, "<!doctype html>") {
		t.Error("must be a full self-contained document")
	}
	for _, must := range []string{"AUTO", "ASK", "MANUAL", "example.com", "PowerDNS", "confirm plaintext origin?"} {
		if !strings.Contains(out, must) {
			t.Errorf("HTML missing %q", must)
		}
	}
	// Self-contained / CSP-safe: no external asset references.
	for _, banned := range []string{"http://", "https://", "src=", "<link", "cdn"} {
		if strings.Contains(out, banned) {
			t.Errorf("HTML must be self-contained, found %q", banned)
		}
	}
}

func TestHTMLEscapesUserData(t *testing.T) {
	// A rule name carrying HTML must be escaped, never injected raw.
	r := Report{Zone: "x.io", Findings: []Finding{
		{Kind: "waf-custom", Name: `<script>alert(1)</script>`, Verdict: Auto, Target: "caddy-waf", Rationale: `a & b < c`},
	}}
	out := r.HTML()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("finding name was not HTML-escaped — injection risk")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected escaped finding name")
	}
	if !strings.Contains(out, "a &amp; b &lt; c") {
		t.Error("rationale not escaped")
	}
}

func TestHTMLDeterministicBanner(t *testing.T) {
	allAuto := Report{Zone: "z", Findings: []Finding{{Kind: "dns", Name: "a", Verdict: Auto, Target: "powerdns", Rationale: "ok"}}}
	if !strings.Contains(allAuto.HTML(), "Fully deterministic") {
		t.Error("all-AUTO report should show the deterministic banner")
	}
}
