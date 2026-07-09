// SPDX-License-Identifier: AGPL-3.0-only

package classify

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/cfexpr"
	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
	"github.com/fabriziosalmi/flareover/internal/report"
)

func loadFixture(t *testing.T) cf.Snapshot {
	t.Helper()
	b, err := os.ReadFile("../../testdata/fixtures/example.snapshot.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var s cf.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return s
}

// find returns the first finding matching kind+name, or nil.
func find(r report.Report, kind, name string) *report.Finding {
	for i := range r.Findings {
		if r.Findings[i].Kind == kind && r.Findings[i].Name == name {
			return &r.Findings[i]
		}
	}
	return nil
}

// TestScopedHeaderTransformIsManual is the classify ⟺ generate guard for #6:
// the generator only emits globally-matched header transforms, so a host/path-
// scoped one must be MANUAL — never a silent AUTO that is then dropped.
func TestScopedHeaderTransformIsManual(t *testing.T) {
	hdr := map[string]any{"headers": map[string]any{
		"X-Frame-Options": map[string]any{"operation": "set", "value": "DENY"},
	}}
	snap := cf.Snapshot{Rulesets: []cf.Ruleset{{
		Phase: "http_response_headers_transform",
		Rules: []cf.Rule{
			{Description: "global header", Expression: "true", ActionParams: hdr, Enabled: true},
			{Description: "scoped header", Expression: `http.host eq "app.example.com"`, ActionParams: hdr, Enabled: true},
		},
	}}}
	r := Classify(snap)
	if g := find(r, "transform", "global header"); g == nil || g.Verdict != report.Auto {
		t.Errorf("global header transform should be AUTO, got %v", g)
	}
	if s := find(r, "transform", "scoped header"); s == nil || s.Verdict != report.Manual {
		t.Errorf("scoped header transform must be MANUAL (not a silent AUTO), got %v", s)
	}
}

// TestChallengeAskOnlyWhenEmittable: a challenge rule is an honorable ASK
// ("convert to a hard block?") only when the match is one the plan can emit; a
// compound match is MANUAL — never an ASK the generator would then ignore.
func TestChallengeAskOnlyWhenEmittable(t *testing.T) {
	snap := cf.Snapshot{Rulesets: []cf.Ruleset{{
		Phase: "http_request_firewall_custom",
		Rules: []cf.Rule{
			{Description: "challenge simple", Expression: `http.user_agent eq "scanner"`, Action: "managed_challenge", Enabled: true},
			{Description: "challenge compound", Expression: `http.user_agent eq "scanner" and ip.src eq 203.0.113.5`, Action: "js_challenge", Enabled: true},
		},
	}}}
	r := Classify(snap)
	if s := find(r, "waf-custom", "challenge simple"); s == nil || s.Verdict != report.Ask || s.Question == nil || s.Question.ID != "waf-challenge:challenge simple" {
		t.Errorf("simple-match challenge should be an honorable ASK, got %+v", s)
	}
	if c := find(r, "waf-custom", "challenge compound"); c == nil || c.Verdict != report.Manual {
		t.Errorf("compound-match challenge should be MANUAL, got %v", c)
	}
}

func TestClassifyFixtureVerdicts(t *testing.T) {
	r := Classify(loadFixture(t))

	cases := []struct {
		kind, name string
		want       report.Verdict
	}{
		{"dns", "A example.com", report.Ask},   // proxied → origin unknown
		{"dns", "MX example.com", report.Auto}, // unproxied → verbatim
		{"dnssec", "example.com", report.Ask},  // registrar DS update
		{"tls", "ssl-mode", report.Ask},        // flexible → confirm scheme
		{"tls", "hsts", report.Auto},
		{"redirect", "always-use-https", report.Auto},
		{"waf-custom", "block bad UA", report.Auto},               // single-field match
		{"waf-custom", "block admin from outside", report.Manual}, // compound expr → no faithful mapping, handled by hand
		{"ratelimit", "login throttle", report.Auto},
		{"transform", "add security header", report.Auto},
		{"redirect", "apex to www", report.Auto},                      // static target
		{"waf-managed", "Cloudflare OWASP Core Ruleset", report.Auto}, // PARTIAL == emitted
		{"worker", "example.com/api/*", report.Manual},
		{"r2", "example-assets", report.Ask},
		{"email", "example.com", report.Manual},
		{"ua-block", "block curl", report.Auto},               // UA block → caddy-waf
		{"ua-block", "challenge scanner", report.Ask},         // UA challenge → ASK
		{"snippet", "geo-router", report.Manual},              // edge code → MANUAL
		{"scrape-shield", "email obfuscation", report.Manual}, // CF-only → surfaced, not dropped
	}
	for _, c := range cases {
		f := find(r, c.kind, c.name)
		if f == nil {
			t.Errorf("missing finding %s/%s", c.kind, c.name)
			continue
		}
		if f.Verdict != c.want {
			t.Errorf("%s/%s: verdict = %s, want %s", c.kind, c.name, f.Verdict, c.want)
		}
	}
}

// TestNoFalseAuto is the 0% FP guard: every ASK finding must carry a question,
// and no MANUAL finding may claim a target (which would imply it emits config).
func TestNoFalseAuto(t *testing.T) {
	r := Classify(loadFixture(t))
	for _, f := range r.Findings {
		if f.Verdict == report.Ask && f.Question == nil {
			t.Errorf("ASK finding %s/%s has no question", f.Kind, f.Name)
		}
		if f.Verdict == report.Manual && f.Target != "" {
			t.Errorf("MANUAL finding %s/%s claims target %q", f.Kind, f.Name, f.Target)
		}
		if f.Rationale == "" {
			t.Errorf("finding %s/%s has empty rationale", f.Kind, f.Name)
		}
	}
}

func TestConfigAndOriginRuleSpecificRationale(t *testing.T) {
	b, err := os.ReadFile("../../testdata/fixtures/conformance.snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	var s cf.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	r := Classify(s)
	f := find(r, "config-rule", "tweak features on /api")
	if f == nil {
		t.Fatal("missing config-rule finding")
	}
	if f.Verdict != report.Manual {
		t.Errorf("config-rule verdict = %s, want MANUAL", f.Verdict)
	}
	// The rationale must name the concrete settings, split by mappability. The
	// unmappable side is framed target-agnostic and future-open ("no supported
	// equivalent yet"), not tied to one target or stated as permanent.
	for _, want := range []string{"automatic_https_rewrites", "email_obfuscation", "no supported equivalent yet"} {
		if !strings.Contains(f.Rationale, want) {
			t.Errorf("config-rule rationale missing %q: %s", want, f.Rationale)
		}
	}
}

func TestSimpleExpression(t *testing.T) {
	simple := []string{
		`http.user_agent eq "badbot"`,
		`ip.src eq 203.0.113.7`,
	}
	compound := []string{
		`http.request.uri.path contains "/admin" and ip.src ne 203.0.113.7`,
		`not http.request.uri.path eq "/x"`,
		`http.host matches "^a"`,
		``,
	}
	for _, e := range simple {
		if !cfexpr.IsSimple(e) {
			t.Errorf("expected simple: %q", e)
		}
	}
	for _, e := range compound {
		if cfexpr.IsSimple(e) {
			t.Errorf("expected NOT simple: %q", e)
		}
	}
}

func TestDeterministic(t *testing.T) {
	s := loadFixture(t)
	a, _ := json.Marshal(Classify(s))
	b, _ := json.Marshal(Classify(s))
	if string(a) != string(b) {
		t.Fatal("classification is not deterministic across runs")
	}
}
