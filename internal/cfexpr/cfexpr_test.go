// SPDX-License-Identifier: AGPL-3.0-only

package cfexpr

import "testing"

// TestSimpleWAFMatchAllowlist is the 0% FP guard for custom firewall rules: only
// the exact shapes the plan can emit may be reported AUTO. The regression it
// locks in — classify once marked ip.src/ip.geoip/`ne` rules AUTO while the plan
// emitted nothing.
func TestSimpleWAFMatchAllowlist(t *testing.T) {
	cases := []struct {
		expr string
		ok   bool
		kind string
		val  string
	}{
		// Emittable → AUTO.
		{`http.user_agent eq "badbot"`, true, "field", "badbot"},
		{`http.request.uri.path contains "/admin"`, true, "field", "/admin"},
		{`ip.geoip.country eq "CN"`, true, "country", "CN"},
		{`ip.geoip.asnum eq 64512`, true, "asn", "64512"},
		// NOT emittable → must be ok=false (the drift cases).
		{`ip.src eq "203.0.113.7"`, false, "", ""},                                  // not an http.* field
		{`http.host ne "x"`, false, "", ""},                                         // ne is not eq/contains
		{`http.host in {"a" "b"}`, false, "", ""},                                   // membership
		{`starts_with(http.request.uri.path, "/x") and ip.src ne y`, false, "", ""}, // compound
		{``, false, "", ""},
	}
	for _, c := range cases {
		m, ok := SimpleWAFMatch(c.expr)
		if ok != c.ok {
			t.Errorf("SimpleWAFMatch(%q) ok=%v, want %v", c.expr, ok, c.ok)
			continue
		}
		if ok && (m.Kind != c.kind || m.Value != c.val) {
			t.Errorf("SimpleWAFMatch(%q) = {%s %q}, want {%s %q}", c.expr, m.Kind, m.Value, c.kind, c.val)
		}
	}
}

func TestIsSimple(t *testing.T) {
	// IsSimple catches boolean composition / functions (used for transform
	// AUTO-vs-PARTIAL). WAF-emittability is a stricter, separate check —
	// SimpleWAFMatch — which is what rejects `ne`, non-http fields, etc.
	simple := []string{`http.host eq "x"`, `http.request.uri.path contains "/a"`}
	compound := []string{`a and b`, `a or b`, `not a`, `x matches "y"`, `len(http.host) != 0`}
	for _, e := range simple {
		if !IsSimple(e) {
			t.Errorf("IsSimple(%q) = false, want true", e)
		}
	}
	for _, e := range compound {
		if IsSimple(e) {
			t.Errorf("IsSimple(%q) = true, want false", e)
		}
	}
}

func TestHostEq(t *testing.T) {
	if h, ok := HostEq(`http.host eq "example.com"`); !ok || h != "example.com" {
		t.Errorf("HostEq = %q,%v", h, ok)
	}
	if _, ok := HostEq(`http.host contains "example"`); ok {
		t.Error("HostEq must reject non-eq")
	}
}

func TestIsPerIPRateLimit(t *testing.T) {
	if !IsPerIPRateLimit([]string{"ip.src"}) {
		t.Error("ip.src alone is per-IP")
	}
	if !IsPerIPRateLimit([]string{"ip.src", "cf.colo.id"}) {
		t.Error("the mandated colo counter must be ignored, still per-IP")
	}
	if IsPerIPRateLimit([]string{"ip.src", "http.request.headers"}) {
		t.Error("a header key means it is not faithfully per-IP")
	}
	if IsPerIPRateLimit(nil) {
		t.Error("no ip.src key means not per-IP")
	}
}

func TestRedirectStatusAndTarget(t *testing.T) {
	params := map[string]any{"from_value": map[string]any{
		"status_code": float64(301),
		"target_url":  map[string]any{"value": "https://example.com/new"},
	}}
	if s := RedirectStatus(params); s != 301 {
		t.Errorf("RedirectStatus = %d, want 301", s)
	}
	if tgt, ok := StaticRedirectTarget(params); !ok || tgt != "https://example.com/new" {
		t.Errorf("StaticRedirectTarget = %q,%v", tgt, ok)
	}
	// Defaults + dynamic target.
	if s := RedirectStatus(map[string]any{}); s != 302 {
		t.Errorf("default status = %d, want 302", s)
	}
	dyn := map[string]any{"from_value": map[string]any{"target_url": map[string]any{"expression": "concat(...)"}}}
	if _, ok := StaticRedirectTarget(dyn); ok {
		t.Error("an expression-derived target must not be treated as static")
	}
}

func TestOriginOverride(t *testing.T) {
	params := map[string]any{
		"host_header": "app.origin",
		"origin":      map[string]any{"host": "backend.internal", "port": float64(8443)},
		"sni":         map[string]any{"value": "backend.tls"},
	}
	ov, ok := OriginOverride(`http.host eq "app.example.com"`, params)
	if !ok {
		t.Fatal("host-scoped, fully-mappable origin rule should be ok")
	}
	if ov.Host != "app.example.com" || ov.HostHeader != "app.origin" || ov.Upstream != "backend.internal:8443" || ov.SNI != "backend.tls" {
		t.Errorf("override = %+v", ov)
	}
	// path-scoped → not mappable (stays MANUAL)
	if _, ok := OriginOverride(`starts_with(http.request.uri.path,"/api")`, map[string]any{"host_header": "x"}); ok {
		t.Error("a path-scoped origin rule must not be mappable")
	}
	// an unrecognized parameter → not mappable
	if _, ok := OriginOverride(`http.host eq "x"`, map[string]any{"host_header": "h", "cache": true}); ok {
		t.Error("an unrecognized parameter must make the rule not mappable")
	}
	// no parameters → not mappable
	if _, ok := OriginOverride(`http.host eq "x"`, map[string]any{}); ok {
		t.Error("an empty rule → not mappable")
	}
}

func TestCaddyMatcher(t *testing.T) {
	cases := []struct {
		expr, want string
		ok         bool
	}{
		{`starts_with(http.request.uri.path, "/api")`, "path /api*", true},
		{`http.request.uri.path eq "/health"`, "path /health", true},
		{`http.host eq "app.example.com"`, "", false},                               // host scope is HostEq's job
		{`starts_with(http.request.uri.path,"/x") and http.host eq "h"`, "", false}, // compound
		{`http.request.uri.path contains "/admin"`, "", false},                      // contains: too loose, stays MANUAL
	}
	for _, c := range cases {
		got, ok := CaddyMatcher(c.expr)
		if ok != c.ok || got != c.want {
			t.Errorf("CaddyMatcher(%q) = (%q,%v), want (%q,%v)", c.expr, got, ok, c.want, c.ok)
		}
	}
}
