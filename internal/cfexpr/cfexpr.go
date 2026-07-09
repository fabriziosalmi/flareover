// SPDX-License-Identifier: AGPL-3.0-only

// Package cfexpr holds the small, shared interpreters for Cloudflare's rules
// language and action parameters. Both the classifier (which decides AUTO/ASK/
// MANUAL) and the plan builder (which emits config) depend on it, so the
// "is this faithfully translatable?" judgement is made in exactly one place —
// there is no way for classification and generation to drift, which is what the
// 0% false-positive contract requires.
package cfexpr

import (
	"regexp"
	"strconv"
	"strings"
)

// compound matches expression operators that indicate more than a single-field
// equality/membership test. Presence of any means "not simple".
var compound = regexp.MustCompile(`\b(and|or|not)\b|[!<>]=|\bmatches\b|\bconcat\b|\blower\b|\blen\b`)

// IsSimple reports whether an expression is a single-field match that can be
// translated with confidence. Deliberately strict: anything with boolean
// composition or functions is "not simple" so it routes to ASK/MANUAL rather
// than a risky AUTO.
func IsSimple(expr string) bool {
	e := strings.TrimSpace(strings.ToLower(expr))
	if e == "" {
		return false
	}
	return !compound.MatchString(e)
}

// WAFMatch describes a Cloudflare firewall expression that flareover can
// faithfully translate, and how.
type WAFMatch struct {
	Kind  string // "field" | "country" | "asn"
	Field string // the http.* field, for Kind == "field"
	Op    string // "eq" | "contains", for Kind == "field"
	Value string // matched value: field value, ISO country code, or ASN digits
}

var (
	wafField   = regexp.MustCompile(`(?i)^\s*(http\.[a-z0-9_.]+)\s+(eq|contains)\s+"([^"]+)"\s*$`)
	wafCountry = regexp.MustCompile(`(?i)^\s*ip\.geoip\.country\s+eq\s+"([A-Za-z]{2})"\s*$`)
	wafASN     = regexp.MustCompile(`(?i)^\s*ip\.geoip\.asnum\s+eq\s+([0-9]+)\s*$`)
)

// SimpleWAFMatch is the SINGLE predicate both the classifier (AUTO decision) and
// the plan builder (emission) use for custom firewall rules, so a rule is only
// marked AUTO when config is actually generated for it — the 0% false-positive
// invariant. It is a deliberate allowlist of shapes flareover emits faithfully:
// a single-field `http.<field> eq|contains "…"` (→ caddy-waf JSON rule), a
// `ip.geoip.country eq "XX"` (→ block_countries), or a `ip.geoip.asnum eq N`
// (→ block_asns). Anything else (compound expressions, other fields/operators)
// returns ok=false and must route to ASK/MANUAL, never AUTO.
func SimpleWAFMatch(expr string) (WAFMatch, bool) {
	if m := wafCountry.FindStringSubmatch(expr); m != nil {
		return WAFMatch{Kind: "country", Value: strings.ToUpper(m[1])}, true
	}
	if m := wafASN.FindStringSubmatch(expr); m != nil {
		return WAFMatch{Kind: "asn", Value: m[1]}, true
	}
	if m := wafField.FindStringSubmatch(expr); m != nil {
		return WAFMatch{Kind: "field", Field: strings.ToLower(m[1]), Op: strings.ToLower(m[2]), Value: m[3]}, true
	}
	return WAFMatch{}, false
}

var hostEq = regexp.MustCompile(`(?i)^\s*http\.host\s+eq\s+"([^"]+)"\s*$`)

// HostEq extracts the host from a `http.host eq "example.com"` expression.
// ok is false for anything more complex.
func HostEq(expr string) (string, bool) {
	m := hostEq.FindStringSubmatch(expr)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Override is a host-scoped Origin Rule mapping flareover can faithfully emit as
// Caddy reverse_proxy directives.
type Override struct {
	Host       string // the http.host the rule is scoped to
	Upstream   string // "host[:port]" if the origin param overrides the backend, else ""
	HostHeader string // Host header override (→ header_up Host), else ""
	SNI        string // SNI override (→ tls_server_name), else ""
}

// OriginOverride is the SINGLE predicate the classifier (AUTO decision) and the
// plan builder (emission) use for Origin Rules, so a rule is AUTO only when Caddy
// config is actually produced for it. It maps a host-scoped rule
// (`http.host eq "…"`) whose action parameters are all faithfully reproducible —
// host_header (→ header_up Host), origin {host,port} (→ the upstream), sni
// (→ tls_server_name) — into an Override. A path-scoped rule, an empty rule, or
// any unrecognized parameter returns ok=false and must stay MANUAL.
func OriginOverride(expr string, params map[string]any) (Override, bool) {
	host, ok := HostEq(expr)
	if !ok || len(params) == 0 {
		return Override{}, false
	}
	ov := Override{Host: host}
	for k, v := range params {
		switch k {
		case "host_header":
			s, ok := v.(string)
			if !ok || s == "" {
				return Override{}, false
			}
			ov.HostHeader = s
		case "origin":
			m, ok := v.(map[string]any)
			if !ok {
				return Override{}, false
			}
			h, _ := m["host"].(string)
			if h == "" {
				return Override{}, false
			}
			if p, ok := m["port"].(float64); ok && p > 0 {
				ov.Upstream = h + ":" + strconv.Itoa(int(p))
			} else {
				ov.Upstream = h
			}
		case "sni":
			m, ok := v.(map[string]any)
			if !ok {
				return Override{}, false
			}
			s, ok := m["value"].(string)
			if !ok || s == "" {
				return Override{}, false
			}
			ov.SNI = s
		default:
			return Override{}, false // an unmappable parameter → not AUTO
		}
	}
	return ov, true
}

// IsPerIPRateLimit reports whether a rate-limit's characteristics reduce to a
// per-client-IP counter. Cloudflare's free tier forces "cf.colo.id" into the
// characteristics (counting happens per-colo), which is a Cloudflare accounting
// detail with no bearing on the intent — so it is ignored. Any other key
// (headers, cookies, query) means the limit is not faithfully per-IP.
func IsPerIPRateLimit(chars []string) bool {
	hasIP := false
	for _, c := range chars {
		switch c {
		case "ip.src":
			hasIP = true
		case "cf.colo.id":
			// Cloudflare-mandated colo counter; ignore.
		default:
			return false
		}
	}
	return hasIP
}

// StaticRedirectTarget extracts a constant redirect target URL from dynamic-
// redirect action parameters, returning ok=false when the target is
// expression-derived (built from request fields at runtime).
func StaticRedirectTarget(params map[string]any) (string, bool) {
	fromValue, ok := params["from_value"].(map[string]any)
	if !ok {
		return "", false
	}
	tv, ok := fromValue["target_url"].(map[string]any)
	if !ok {
		return "", false
	}
	if v, ok := tv["value"].(string); ok && v != "" {
		return v, true
	}
	return "", false
}

// RedirectStatus reads the status code (default 302) from dynamic-redirect
// action parameters.
func RedirectStatus(params map[string]any) int {
	fromValue, ok := params["from_value"].(map[string]any)
	if !ok {
		return 302
	}
	switch v := fromValue["status_code"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 302
}
