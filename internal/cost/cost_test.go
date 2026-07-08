// SPDX-License-Identifier: AGPL-3.0-only

package cost

import (
	"strings"
	"testing"

	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
)

func TestFreeZoneHonest(t *testing.T) {
	// A zone using only free-tier features implies the Free plan; the report must
	// say so honestly rather than inventing savings.
	s := cf.Snapshot{Zone: cf.Zone{Name: "free.example"}}
	r := Estimate(s, Options{})
	if r.CloudflarePlan != "free" || r.CloudflareMonthlyMin != 0 {
		t.Fatalf("expected free/0, got %s/%.2f", r.CloudflarePlan, r.CloudflareMonthlyMin)
	}
	if r.SavingsMonthly > 0 {
		t.Errorf("free zone should not report positive savings, got %.2f", r.SavingsMonthly)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "sovereignty") {
		t.Error("free-zone note should pivot to sovereignty, not a fake saving")
	}
}

func TestPaidDriversInferPlanAndAddons(t *testing.T) {
	s := cf.Snapshot{
		Zone:          cf.Zone{Name: "busy.example"},
		ManagedRules:  []cf.ManagedRuleset{{Name: "Cloudflare OWASP Core Ruleset", Enabled: true}},
		LoadBalancers: []cf.LoadBalancer{{Name: "lb1"}, {Name: "lb2"}},
		Workers:       []cf.WorkerRoute{{Pattern: "busy.example/*", Script: "x"}},
	}
	r := Estimate(s, Options{EUStackVPSMonthly: 10})
	if r.CloudflarePlan != "pro" {
		t.Errorf("OWASP → at least pro, got %s", r.CloudflarePlan)
	}
	// pro (20) + 2 LBs (2*5) + workers (5) = 35 floor.
	if r.CloudflareMonthlyMin != 35 {
		t.Errorf("floor = %.2f, want 35", r.CloudflareMonthlyMin)
	}
	if r.SavingsMonthly != 25 { // 35 - 10
		t.Errorf("savings = %.2f, want 25", r.SavingsMonthly)
	}
}

func TestManyCustomRulesRequirePaid(t *testing.T) {
	rules := make([]cf.Rule, 6)
	for i := range rules {
		rules[i] = cf.Rule{Enabled: true, Action: "block", Expression: "x"}
	}
	s := cf.Snapshot{
		Zone:     cf.Zone{Name: "rules.example"},
		Rulesets: []cf.Ruleset{{Phase: "http_request_firewall_custom", Rules: rules}},
	}
	r := Estimate(s, Options{})
	if r.CloudflarePlan == "free" {
		t.Error("6 custom rules exceed the free allowance → should require paid")
	}
}
