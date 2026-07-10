// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package plan_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/classify"
	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
	"github.com/fabriziosalmi/flareover/internal/plan"
	"github.com/fabriziosalmi/flareover/internal/report"
	"github.com/fabriziosalmi/flareover/internal/target/caddy"
	"github.com/fabriziosalmi/flareover/internal/target/caddywaf"
)

func load(t *testing.T) cf.Snapshot {
	t.Helper()
	b, err := os.ReadFile("../../testdata/fixtures/example.snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	var s cf.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func buildPlan(t *testing.T, s cf.Snapshot) plan.Options {
	return plan.Options{EdgeIP: "5.9.100.200", CA: "letsencrypt", Decisions: map[string]string{
		"origin:example.com":     "10.0.0.10:8080",
		"origin:www.example.com": "10.0.0.10:8080",
	}}
}

// TestIPAccessParity is the diamond invariant: every IP Access Rule the
// classifier marks AUTO must materialize as generated config. A rule classified
// AUTO but not emitted would be a silently-dropped security control.
func TestIPAccessParity(t *testing.T) {
	s := load(t)

	// Count AUTO ip-access findings from the classifier.
	rep := classify.Classify(s)
	autoIP := 0
	for _, f := range rep.Findings {
		if f.Kind == "ip-access" && f.Verdict == report.Auto {
			autoIP++
		}
	}

	// Count the same rules as materialized in the generated WAF policy.
	p, err := plan.Build(s, buildPlan(t, s))
	if err != nil {
		t.Fatal(err)
	}
	got := len(p.WAF.BlockCountries) + len(p.WAF.BlockASNs) + len(p.WAF.BlockIPs) + len(p.WAF.AllowIPs)

	if got != autoIP {
		t.Fatalf("parity broken: %d AUTO ip-access findings but %d generated entries", autoIP, got)
	}
	if autoIP == 0 {
		t.Fatal("fixture should exercise IP access rules")
	}
}

// TestUABlockMaterializes extends the diamond invariant to legacy User-Agent
// Blocking rules: every block-mode UA rule (which the classifier marks AUTO) must
// materialize as a caddy-waf HEADERS:User-Agent rule carrying its UA as the
// sample. It was a silently-dropped security control before the audit fix, and
// matching per-UA (not by count) means a regression can't be masked by an
// unrelated firewall-custom UA rule.
func TestUABlockMaterializes(t *testing.T) {
	s := load(t)
	p, err := plan.Build(s, buildPlan(t, s))
	if err != nil {
		t.Fatal(err)
	}
	uaSamples := map[string]bool{}
	for _, r := range p.WAF.CustomRules {
		if len(r.Targets) == 1 && r.Targets[0] == "HEADERS:User-Agent" {
			uaSamples[r.Sample] = true
		}
	}
	found := false
	for _, ua := range s.UARules {
		if ua.Mode != "block" {
			continue
		}
		found = true
		if !uaSamples[ua.UserAgent] {
			t.Errorf("UA block rule %q is classified AUTO but was not emitted as a caddy-waf rule", ua.UserAgent)
		}
	}
	if !found {
		t.Skip("fixture exercises no User-Agent Blocking rule")
	}
}

func TestBlocklistsWiring(t *testing.T) {
	s := load(t)
	p, err := plan.Build(s, plan.Options{Blocklists: []string{"domain", "ip"}, Decisions: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.WAF.Blocklists) != 2 {
		t.Fatalf("expected 2 blocklist feeds, got %d", len(p.WAF.Blocklists))
	}
	arts, _ := caddywaf.Generator{}.Generate(p)
	var script string
	for _, a := range arts {
		if a.Path == "caddy-waf/update-blocklists.sh" {
			script = string(a.Content)
		}
	}
	if !strings.Contains(script, "fabriziosalmi/blacklists") || !strings.Contains(script, "caddy reload") {
		t.Errorf("update script missing feed URL or reload:\n%s", script)
	}
}

func TestWAFPolicyValues(t *testing.T) {
	p, err := plan.Build(load(t), buildPlan(t, load(t)))
	if err != nil {
		t.Fatal(err)
	}
	w := p.WAF
	if len(w.BlockCountries) != 1 || w.BlockCountries[0] != "CN" {
		t.Errorf("BlockCountries = %v", w.BlockCountries)
	}
	if len(w.BlockASNs) != 1 || w.BlockASNs[0] != 64512 {
		t.Errorf("BlockASNs = %v", w.BlockASNs)
	}
	if len(w.BlockIPs) != 1 || w.BlockIPs[0] != "192.0.2.10" {
		t.Errorf("BlockIPs = %v", w.BlockIPs)
	}
	if len(w.AllowIPs) != 1 || w.AllowIPs[0] != "203.0.113.5" {
		t.Errorf("AllowIPs = %v", w.AllowIPs)
	}
}

// TestGeneratedArtifactsForIPLists proves the generators emit the list files and
// the Caddy snippet references them: the config is real, not just intent.
func TestGeneratedArtifactsForIPLists(t *testing.T) {
	p, err := plan.Build(load(t), buildPlan(t, load(t)))
	if err != nil {
		t.Fatal(err)
	}

	arts, err := caddywaf.Generator{}.Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	var haveBlack, haveWhite bool
	for _, a := range arts {
		switch a.Path {
		case "caddy-waf/ip_blacklist.txt":
			haveBlack = true
			if !strings.Contains(string(a.Content), "192.0.2.10") {
				t.Error("ip_blacklist.txt missing the blocked IP")
			}
		case "caddy-waf/ip_whitelist.txt":
			haveWhite = true
		}
	}
	if !haveBlack || !haveWhite {
		t.Errorf("missing IP list artifacts (black=%v white=%v)", haveBlack, haveWhite)
	}

	cad, err := caddy.Generator{}.Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	body := string(cad[0].Content)
	for _, want := range []string{"ip_blacklist_file", "ip_whitelist_file", "block_countries", "block_asns"} {
		if !strings.Contains(body, want) {
			t.Errorf("Caddyfile WAF snippet missing %q", want)
		}
	}
}
