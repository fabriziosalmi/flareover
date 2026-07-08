// Package cfexpr holds the small, shared interpreters for Cloudflare's rules
// language and action parameters. Both the classifier (which decides AUTO/ASK/
// MANUAL) and the plan builder (which emits config) depend on it, so the
// "is this faithfully translatable?" judgement is made in exactly one place —
// there is no way for classification and generation to drift, which is what the
// 0% false-positive contract requires.
package cfexpr

import (
	"regexp"
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
