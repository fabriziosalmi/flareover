// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package caddy

import (
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

func samplePlan() ir.Plan {
	return ir.Plan{
		Zone: "example.com",
		Sites: []ir.Site{{
			Host:    "example.com",
			Origin:  ir.Origin{Upstreams: []string{"10.44.44.20:8080"}, Scheme: "https", VerifyTLS: false},
			TLS:     ir.TLS{Provider: "certmate", MinVersion: "1.2", HSTS: &ir.HSTS{MaxAge: 31536000, IncludeSubDomains: true}},
			Headers: []ir.HeaderOp{{Phase: "response", Op: "set", Name: "X-Frame-Options", Value: "DENY"}},
			Redirects: []ir.Redirect{
				{Match: "*", To: "https://www.example.com", Status: 301},
				{Match: "/old/*", To: "https://example.com/new/$1", Status: 301},
			},
			Cache: &ir.CachePolicy{Enabled: true, TTL: 7200},
		}},
		WAF: ir.WAFPolicy{
			ManagedOWASP: true,
			CustomRules:  []ir.WAFRule{{Description: "block bad UA", Pattern: "(?i)badbot", Targets: []string{"HEADERS:User-Agent"}, Action: "block", Score: 10}},
			RateLimits:   []ir.RateLimit{{Requests: 20, Window: 60, Path: "/login"}},
		},
	}
}

func generate(t *testing.T) string {
	t.Helper()
	arts, err := Generator{}.Generate(samplePlan())
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 {
		t.Fatalf("artifacts = %d, want 1", len(arts))
	}
	return string(arts[0].Content)
}

// TestNoCloudflareCaptureSyntax is the 0% FP guard: Cloudflare's `$1` capture
// must never survive into a Caddyfile (it would silently break the redirect).
func TestNoCloudflareCaptureSyntax(t *testing.T) {
	out := generate(t)
	if strings.Contains(out, "/new/$1") {
		t.Error("Caddyfile leaked Cloudflare capture syntax $1")
	}
	if !strings.Contains(out, "path_regexp") || !strings.Contains(out, "{re.rd") {
		t.Error("capture redirect was not translated to a path_regexp matcher")
	}
}

func TestCaddyfileEssentials(t *testing.T) {
	out := generate(t)
	wants := []string{
		"order waf first",
		"example.com {",
		"reverse_proxy https://10.44.44.20:8080",
		"tls_insecure_skip_verify",               // https origin, no verify
		"Strict-Transport-Security",              // HSTS
		"protocols tls1.2",                       // min TLS floor
		`header X-Frame-Options "DENY"`,          // header transform
		"import waf",                             // WAF snippet
		"redir https://www.example.com{uri} 301", // catch-all preserves path
		"rate_limit {",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("Caddyfile missing %q\n---\n%s", w, out)
		}
	}
}

func TestRedirectOrdering(t *testing.T) {
	out := generate(t)
	specific := strings.Index(out, "path_regexp")
	catchall := strings.Index(out, "redir https://www.example.com{uri}")
	if specific == -1 || catchall == -1 || specific > catchall {
		t.Errorf("specific redirect must precede catch-all (specific=%d catchall=%d)", specific, catchall)
	}
}

func TestDeterministic(t *testing.T) {
	a := generate(t)
	b := generate(t)
	if a != b {
		t.Error("Caddyfile generation is not deterministic")
	}
}

func TestReverseProxyOriginOverride(t *testing.T) {
	plan := ir.Plan{
		Zone: "example.com",
		Sites: []ir.Site{{
			Host:   "app.example.com",
			Origin: ir.Origin{Upstreams: []string{"backend.internal:8443"}, Scheme: "https", VerifyTLS: true, HostHeader: "app.origin", SNI: "backend.tls"},
			TLS:    ir.TLS{Provider: "certmate"},
		}},
	}
	arts, err := Generator{}.Generate(plan)
	if err != nil {
		t.Fatal(err)
	}
	out := string(arts[0].Content)
	for _, w := range []string{"reverse_proxy https://backend.internal:8443", "header_up Host app.origin", "tls_server_name backend.tls"} {
		if !strings.Contains(out, w) {
			t.Errorf("Caddyfile missing %q\n---\n%s", w, out)
		}
	}
}

func TestMatcherGuardedHeader(t *testing.T) {
	plan := ir.Plan{
		Zone: "example.com",
		Sites: []ir.Site{{
			Host:   "example.com",
			Origin: ir.Origin{Upstreams: []string{"10.0.0.1:80"}, Scheme: "http"},
			TLS:    ir.TLS{Provider: "certmate"},
			Headers: []ir.HeaderOp{
				{Phase: "response", Op: "set", Name: "X-Global", Value: "g"},                   // unscoped → flat
				{Phase: "response", Op: "set", Name: "X-Api", Value: "a", Match: "path /api*"}, // path-scoped → matcher
			},
		}},
	}
	arts, err := Generator{}.Generate(plan)
	if err != nil {
		t.Fatal(err)
	}
	out := string(arts[0].Content)
	for _, w := range []string{`header X-Global "g"`, "@h0 path /api*", `header @h0 X-Api "a"`} {
		if !strings.Contains(out, w) {
			t.Errorf("Caddyfile missing %q\n---\n%s", w, out)
		}
	}
}

// TestOriginTrustedCARendered pins #12's render side: a verified origin with a
// private replacement-cert CA emits tls_trusted_ca_certs and never skips
// verification.
func TestOriginTrustedCARendered(t *testing.T) {
	plan := ir.Plan{Zone: "example.com", Sites: []ir.Site{{
		Host:   "example.com",
		Origin: ir.Origin{Upstreams: []string{"10.0.0.9:443"}, Scheme: "https", VerifyTLS: true, TrustedCA: "/etc/caddy/origin-ca.pem"},
		TLS:    ir.TLS{Provider: "certmate"},
	}}}
	arts, err := Generator{}.Generate(plan)
	if err != nil {
		t.Fatal(err)
	}
	out := string(arts[0].Content)
	if !strings.Contains(out, "tls_trusted_ca_certs /etc/caddy/origin-ca.pem") {
		t.Errorf("verified origin with a trusted CA must emit tls_trusted_ca_certs:\n%s", out)
	}
	if strings.Contains(out, "tls_insecure_skip_verify") {
		t.Error("a verified origin must NOT skip verification")
	}
}

func TestScopedProxyEmission(t *testing.T) {
	plan := ir.Plan{Zone: "example.com", Sites: []ir.Site{{
		Host:   "example.com",
		Origin: ir.Origin{Upstreams: []string{"10.0.0.1:80"}, Scheme: "http"},
		TLS:    ir.TLS{Provider: "certmate"},
		ScopedProxies: []ir.ScopedProxy{{
			Match:  "path /api*",
			Origin: ir.Origin{Upstreams: []string{"api.internal:8443"}, Scheme: "https", VerifyTLS: true},
		}},
	}}}
	arts, err := Generator{}.Generate(plan)
	if err != nil {
		t.Fatal(err)
	}
	out := string(arts[0].Content)
	scoped := strings.Index(out, "reverse_proxy @p0 https://api.internal:8443")
	deflt := strings.Index(out, "reverse_proxy http://10.0.0.1:80")
	if scoped < 0 || deflt < 0 || scoped > deflt {
		t.Errorf("scoped proxy must precede the catch-all default:\n%s", out)
	}
	if !strings.Contains(out, "@p0 path /api*") {
		t.Error("named path matcher missing")
	}
}
