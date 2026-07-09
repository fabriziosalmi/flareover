// SPDX-License-Identifier: AGPL-3.0-only

package plan

import (
	"encoding/json"
	"os"
	"testing"

	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
)

// TestChallengeConvertedToBlockOnYes pins the waf-challenge round-trip: the
// answer key classify mints (via cf.Rule.Name) must route back here so that
// opting in actually emits a hard block — and opting out emits nothing.
func TestChallengeConvertedToBlockOnYes(t *testing.T) {
	snap := cf.Snapshot{Rulesets: []cf.Ruleset{{
		Phase: "http_request_firewall_custom",
		Rules: []cf.Rule{{Description: "challenge scanner", Expression: `http.user_agent eq "scanner"`, Action: "managed_challenge", Enabled: true}},
	}}}

	// No opt-in → nothing emitted (never a silent conversion).
	if p, _ := Build(snap, Options{}); len(p.WAF.CustomRules) != 0 {
		t.Fatalf("challenge without opt-in must not emit, got %d rules", len(p.WAF.CustomRules))
	}

	// Opt-in "yes" → emitted as a hard block.
	p, err := Build(snap, Options{Decisions: map[string]string{"waf-challenge:challenge scanner": "yes"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.WAF.CustomRules) != 1 || p.WAF.CustomRules[0].Action != "block" {
		t.Fatalf("answered challenge should emit one hard-block rule, got %+v", p.WAF.CustomRules)
	}
}

func fixture(t *testing.T) (cf.Snapshot, Options) {
	t.Helper()
	sb, err := os.ReadFile("../../testdata/fixtures/example.snapshot.json")
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	var s cf.Snapshot
	if err := json.Unmarshal(sb, &s); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	db, err := os.ReadFile("../../testdata/fixtures/example.decisions.json")
	if err != nil {
		t.Fatalf("read decisions: %v", err)
	}
	d := map[string]string{}
	if err := json.Unmarshal(db, &d); err != nil {
		t.Fatalf("unmarshal decisions: %v", err)
	}
	return s, Options{EdgeIP: "5.9.100.200", CA: "actalis", Decisions: d}
}

func TestBuildShape(t *testing.T) {
	s, opts := fixture(t)
	p, err := Build(s, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 2 {
		t.Fatalf("sites = %d, want 2", len(p.Sites))
	}
	if len(p.DNS.Records) != 4 { // apex A, www A, MX, TXT
		t.Fatalf("records = %d, want 4", len(p.DNS.Records))
	}
	if !p.DNS.DNSSEC {
		t.Error("DNSSEC should be enabled (answered yes)")
	}
	// The compound WAF rule was left ASK (unanswered) → must NOT be generated.
	if len(p.WAF.CustomRules) != 1 {
		t.Fatalf("custom WAF rules = %d, want 1 (only the simple one)", len(p.WAF.CustomRules))
	}
	if p.WAF.CustomRules[0].Description != "block bad UA" {
		t.Errorf("unexpected WAF rule: %q", p.WAF.CustomRules[0].Description)
	}
	if !p.WAF.ManagedOWASP {
		t.Error("managed OWASP should be on")
	}
}

func TestBuildOriginRepoint(t *testing.T) {
	s, opts := fixture(t)
	p, _ := Build(s, opts)
	for _, r := range p.DNS.Records {
		if r.Name == "example.com" && r.Type == "A" && r.Content != "5.9.100.200" {
			t.Errorf("apex A should repoint to edge, got %s", r.Content)
		}
	}
	for _, site := range p.Sites {
		if site.Origin.Scheme != "https" { // flexible answered "https"
			t.Errorf("site %s scheme = %s, want https", site.Host, site.Origin.Scheme)
		}
		if len(site.Origin.Upstreams) != 1 || site.Origin.Upstreams[0] != "10.44.44.20:8080" {
			t.Errorf("site %s origin = %v", site.Host, site.Origin.Upstreams)
		}
	}
}

// TestBuildWithoutOriginDecision proves the 0% FP behavior: with no origin
// answer, no site and no de-proxied record are emitted (nothing guessed).
func TestBuildWithoutOriginDecision(t *testing.T) {
	s, _ := fixture(t)
	p, _ := Build(s, Options{EdgeIP: "5.9.100.200"})
	if len(p.Sites) != 0 {
		t.Errorf("no origin decisions → expected 0 sites, got %d", len(p.Sites))
	}
	// Only the two unproxied records (MX, TXT) should survive.
	if len(p.DNS.Records) != 2 {
		t.Errorf("expected 2 unproxied records, got %d", len(p.DNS.Records))
	}
}

func TestOriginRuleAppliedToSite(t *testing.T) {
	snap := cf.Snapshot{
		Zone:       cf.Zone{Name: "example.com"},
		DNSRecords: []cf.DNSRecord{{Type: "A", Name: "app.example.com", Content: "192.0.2.1", Proxied: true}},
		Rulesets: []cf.Ruleset{{Phase: "http_request_origin", Rules: []cf.Rule{
			{Expression: `http.host eq "app.example.com"`, Enabled: true, ActionParams: map[string]any{
				"host_header": "app.origin",
				"sni":         map[string]any{"value": "app.tls"},
			}},
		}}},
	}
	p, err := Build(snap, Options{EdgeIP: "5.9.1.1", Decisions: map[string]string{"origin:app.example.com": "10.0.0.9:8080"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(p.Sites))
	}
	if o := p.Sites[0].Origin; o.HostHeader != "app.origin" || o.SNI != "app.tls" {
		t.Errorf("origin-rule override not applied to the site: %+v", o)
	}
}

// TestHostScopedHeaderLandsOnlyInItsSite pins #6: a host-scoped header transform
// is emitted unmatched inside its own host's block (the block is already that
// host) and does not leak into any other site; a global one is on every site.
func TestHostScopedHeaderLandsOnlyInItsSite(t *testing.T) {
	snap := cf.Snapshot{
		Zone: cf.Zone{Name: "example.com"},
		DNSRecords: []cf.DNSRecord{
			{Type: "A", Name: "app.example.com", Content: "192.0.2.1", Proxied: true},
			{Type: "A", Name: "blog.example.com", Content: "192.0.2.2", Proxied: true},
		},
		Rulesets: []cf.Ruleset{{Phase: "http_response_headers_transform", Rules: []cf.Rule{
			{Description: "global", Expression: "true", Enabled: true, ActionParams: map[string]any{
				"headers": map[string]any{"X-Global": map[string]any{"operation": "set", "value": "1"}}}},
			{Description: "app only", Expression: `http.host eq "app.example.com"`, Enabled: true, ActionParams: map[string]any{
				"headers": map[string]any{"X-App": map[string]any{"operation": "set", "value": "yes"}}}},
		}}},
	}
	p, err := Build(snap, Options{EdgeIP: "5.9.1.1", Decisions: map[string]string{
		"origin:app.example.com":  "10.0.0.1:80",
		"origin:blog.example.com": "10.0.0.2:80",
	}})
	if err != nil {
		t.Fatal(err)
	}
	// get returns the op's (match, host, found) for a header name on a given site.
	get := func(host, name string) (match, hostf string, found bool) {
		for _, s := range p.Sites {
			if s.Host != host {
				continue
			}
			for _, op := range s.Headers {
				if op.Name == name {
					return op.Match, op.Host, true
				}
			}
		}
		return "", "", false
	}

	// Global header on both sites.
	if _, _, ok := get("app.example.com", "X-Global"); !ok {
		t.Error("global header missing from app site")
	}
	if _, _, ok := get("blog.example.com", "X-Global"); !ok {
		t.Error("global header missing from blog site")
	}
	// Host-scoped header only on its own site, emitted unmatched (no Match, no Host).
	m, h, ok := get("app.example.com", "X-App")
	if !ok {
		t.Fatal("host-scoped header missing from its own site")
	}
	if m != "" || h != "" {
		t.Errorf("host-scoped header must be emitted unmatched in its block, got Match=%q Host=%q", m, h)
	}
	if _, _, ok := get("blog.example.com", "X-App"); ok {
		t.Error("host-scoped header leaked into another host's site")
	}
}
