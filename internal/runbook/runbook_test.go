// SPDX-License-Identifier: AGPL-3.0-only

package runbook

import (
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/report"
)

func TestGenerate(t *testing.T) {
	rep := report.Report{Zone: "example.com", Findings: []report.Finding{
		{Kind: "worker", Name: "api/*", Verdict: report.Manual, Rationale: "edge code"},
		{Kind: "dns", Name: "A example.com", Verdict: report.Ask, Rationale: "origin?",
			Question: &report.Question{Prompt: "Origin?", Default: ""}},
		{Kind: "tls", Name: "hsts", Verdict: report.Auto, Rationale: "ok"},
	}}
	p := ir.Plan{Zone: "example.com", DNS: ir.DNSZone{DNSSEC: true, Records: make([]ir.DNSRecord, 3)},
		Sites: make([]ir.Site, 2)}
	md := string(Generate(rep, p, []string{"caddy/Caddyfile", "powerdns/example.com.zone"}))

	// Report header + the found→became table + MANUAL/ASK sections + gated cutover.
	for _, want := range []string{
		"Migration report", "Cloudflare elements found", "migrated 1:1", "mapped automatically",
		"What we found on Cloudflare", "✅ AUTO", "✋ MANUAL", "⚠️ ASK",
		"Handle by hand (MANUAL)", "worker", "edge code",
		"Decisions required (ASK)", "Origin?",
		"flareover present", "GATE: PASS", "Rollback",
		"DNSSEC", "caddy/Caddyfile",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("MIGRATION.md missing %q", want)
		}
	}
}
