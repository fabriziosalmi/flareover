// SPDX-License-Identifier: AGPL-3.0-only

// Package caddy renders an ir.Plan into a Caddyfile for the default flareover
// stack profile (Caddy + caddy-waf + souin cache). The output assumes a custom
// Caddy build (xcaddy with the caddy-waf and souin modules) and certificates
// delivered by CertMate to /etc/caddy/certs/<host>/. Generation is a pure
// function of the plan.
package caddy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target"
)

const (
	certDir     = "/etc/caddy/certs"
	wafRuleFile = "/etc/caddy/waf/rules.json"
)

// Generator renders the Caddyfile.
type Generator struct{}

// Name implements target.Generator.
func (Generator) Name() string { return "caddy" }

// Generate implements target.Generator.
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	var b strings.Builder

	// Global options: caddy-waf must run before reverse_proxy; enable a shared
	// cache when any site caches.
	b.WriteString("{\n")
	b.WriteString("\torder waf first\n")
	if anyCache(p) {
		b.WriteString("\torder cache before rewrite\n")
		b.WriteString("\tcache\n")
	}
	b.WriteString("}\n\n")

	// A single WAF snippet imported by every site keeps the zone policy in one
	// place (Cloudflare's WAF is zone-global).
	if wafActive(p.WAF) {
		b.WriteString(renderWAFSnippet(p.WAF))
		b.WriteString("\n")
	}

	for _, site := range p.Sites {
		b.WriteString(renderSite(site, p.WAF))
		b.WriteString("\n")
	}

	note := "Assumes a custom Caddy build: xcaddy build --with github.com/fabriziosalmi/caddy-waf" +
		" --with github.com/darkweak/souin/plugins/caddy. Certs expected under " + certDir + "/<host>/."
	return []target.Artifact{{
		Path: "caddy/Caddyfile", Content: []byte(b.String()), Mode: 0o644, Note: note,
	}}, nil
}

func renderSite(s ir.Site, waf ir.WAFPolicy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s {\n", s.Host)

	// TLS: CertMate-delivered material, with an optional protocol floor.
	fmt.Fprintf(&b, "\ttls %s/%s/fullchain.pem %s/%s/privkey.pem\n", certDir, s.Host, certDir, s.Host)
	if v := caddyTLSProtocol(s.TLS.MinVersion); v != "" {
		fmt.Fprintf(&b, "\ttls {\n\t\tprotocols %s\n\t}\n", v)
	}

	// HSTS.
	if h := s.TLS.HSTS; h != nil {
		fmt.Fprintf(&b, "\theader Strict-Transport-Security \"%s\"\n", hstsValue(h))
	}

	// Header transforms — unscoped ops first (sorted so Match "" leads), then each
	// path-scoped group under its own named matcher.
	mi, lastMatch, mname := 0, "", ""
	for i, op := range s.Headers {
		if i == 0 || op.Match != lastMatch {
			lastMatch, mname = op.Match, ""
			if op.Match != "" {
				mname = fmt.Sprintf("@h%d", mi)
				mi++
				fmt.Fprintf(&b, "\t%s %s\n", mname, op.Match)
			}
		}
		if line := headerDirective(op, mname); line != "" {
			b.WriteString("\t" + line + "\n")
		}
	}

	// WAF (zone-global snippet).
	if wafActive(waf) {
		b.WriteString("\timport waf\n")
	}

	// Cache.
	if s.Cache != nil && s.Cache.Enabled {
		if s.Cache.TTL > 0 {
			fmt.Fprintf(&b, "\tcache {\n\t\tttl %ds\n\t}\n", s.Cache.TTL)
		} else {
			b.WriteString("\tcache\n")
		}
	}

	// Redirects (before the proxy). Specific path matchers must precede the
	// catch-all, or the catch-all would shadow them.
	for i, r := range orderRedirects(s.Redirects) {
		b.WriteString(renderRedirect(i, r))
	}

	// Reverse proxy to the de-proxied origin.
	b.WriteString(renderReverseProxy(s.Origin))

	b.WriteString("}\n")
	return b.String()
}

func renderReverseProxy(o ir.Origin) string {
	var b strings.Builder
	ups := make([]string, len(o.Upstreams))
	for i, u := range o.Upstreams {
		ups[i] = fmt.Sprintf("%s://%s", schemeOr(o.Scheme, "https"), u)
	}
	fmt.Fprintf(&b, "\treverse_proxy %s", strings.Join(ups, " "))

	// Optional block: Origin-Rule Host-header override + a TLS transport carrying
	// the SNI override and/or the skip-verify already implied by the scheme.
	var body strings.Builder
	if o.HostHeader != "" {
		fmt.Fprintf(&body, "\t\theader_up Host %s\n", o.HostHeader)
	}
	insecure := o.Scheme == "https" && !o.VerifyTLS
	if insecure || o.SNI != "" {
		body.WriteString("\t\ttransport http {\n")
		if o.SNI != "" {
			fmt.Fprintf(&body, "\t\t\ttls_server_name %s\n", o.SNI)
		}
		if insecure {
			body.WriteString("\t\t\ttls_insecure_skip_verify\n")
		}
		body.WriteString("\t\t}\n")
	}
	if body.Len() > 0 {
		b.WriteString(" {\n")
		b.WriteString(body.String())
		b.WriteString("\t}\n")
	} else {
		b.WriteString("\n")
	}
	return b.String()
}

// renderWAFSnippet emits a reusable (waf) snippet with the zone security policy.
func renderWAFSnippet(w ir.WAFPolicy) string {
	var b strings.Builder
	b.WriteString("(waf) {\n")
	b.WriteString("\twaf {\n")
	fmt.Fprintf(&b, "\t\trule_file %s\n", wafRuleFile)
	if w.ManagedOWASP {
		b.WriteString("\t\tanomaly_threshold 5\n")
	}
	for _, rl := range w.RateLimits {
		b.WriteString("\t\trate_limit {\n")
		fmt.Fprintf(&b, "\t\t\trequests %d\n", rl.Requests)
		fmt.Fprintf(&b, "\t\t\twindow %ds\n", rl.Window)
		if rl.Path != "" {
			fmt.Fprintf(&b, "\t\t\tpaths %s\n", rl.Path)
		}
		b.WriteString("\t\t}\n")
	}
	if len(w.BlockASNs) > 0 {
		fmt.Fprintf(&b, "\t\tblock_asns %s\n", joinInts(w.BlockASNs))
	}
	if len(w.BlockCountries) > 0 {
		fmt.Fprintf(&b, "\t\tblock_countries GeoLite2-Country.mmdb %s\n", strings.Join(w.BlockCountries, " "))
	}
	// Consolidate IP/domain lists into one file each: local deny entries (from
	// IP Access Rules) and external feeds merge into the same path, so caddy-waf
	// gets a single ip_blacklist_file / dns_blacklist_file directive.
	hasIPList, hasDomainList := len(w.BlockIPs) > 0, false
	for _, bl := range w.Blocklists {
		switch bl.Kind {
		case "ip":
			hasIPList = true
		case "domain":
			hasDomainList = true
		}
	}
	if hasIPList {
		b.WriteString("\t\tip_blacklist_file /etc/caddy/waf/ip_blacklist.txt\n")
	}
	if hasDomainList {
		b.WriteString("\t\tdns_blacklist_file /etc/caddy/waf/domains.txt\n")
	}
	if len(w.AllowIPs) > 0 {
		b.WriteString("\t\tip_whitelist_file /etc/caddy/waf/ip_whitelist.txt\n")
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// --- helpers -----------------------------------------------------------------

func wafActive(w ir.WAFPolicy) bool {
	return len(w.CustomRules) > 0 || len(w.RateLimits) > 0 || w.ManagedOWASP ||
		len(w.BlockASNs) > 0 || len(w.BlockCountries) > 0 || len(w.Blocklists) > 0 ||
		len(w.BlockIPs) > 0 || len(w.AllowIPs) > 0
}

func anyCache(p ir.Plan) bool {
	for _, s := range p.Sites {
		if s.Cache != nil && s.Cache.Enabled {
			return true
		}
	}
	return false
}

func headerDirective(op ir.HeaderOp, matcher string) string {
	// Caddy header directive prefixes: no prefix = set (response), + = add,
	// - = remove; request_header handles the request phase. A non-empty matcher
	// (e.g. "@h0") scopes the op and slots in right after the directive name.
	m := ""
	if matcher != "" {
		m = matcher + " "
	}
	name, val := op.Name, op.Value
	switch op.Phase {
	case "request":
		switch op.Op {
		case "remove":
			return fmt.Sprintf("request_header %s-%s", m, name)
		default:
			return strings.TrimSpace(fmt.Sprintf("request_header %s%s %q", m, name, val))
		}
	default: // response
		switch op.Op {
		case "add":
			return fmt.Sprintf("header %s+%s %q", m, name, val)
		case "remove":
			return fmt.Sprintf("header %s-%s", m, name)
		default:
			return fmt.Sprintf("header %s%s %q", m, name, val)
		}
	}
}

func hstsValue(h *ir.HSTS) string {
	v := fmt.Sprintf("max-age=%d", h.MaxAge)
	if h.IncludeSubDomains {
		v += "; includeSubDomains"
	}
	if h.Preload {
		v += "; preload"
	}
	return v
}

func caddyTLSProtocol(min string) string {
	switch min {
	case "1.3":
		return "tls1.3"
	case "1.2":
		return "tls1.2"
	case "1.1":
		return "tls1.1"
	case "1.0":
		return "tls1.0"
	default:
		return ""
	}
}

// isCatchAll reports whether a redirect matches every path.
func isCatchAll(m string) bool { return m == "" || m == "*" || m == "/*" }

// orderRedirects puts specific path matchers before catch-alls so the latter
// cannot shadow the former in Caddy's route evaluation.
func orderRedirects(rs []ir.Redirect) []ir.Redirect {
	out := make([]ir.Redirect, 0, len(rs))
	for _, r := range rs {
		if !isCatchAll(r.Match) {
			out = append(out, r)
		}
	}
	for _, r := range rs {
		if isCatchAll(r.Match) {
			out = append(out, r)
		}
	}
	return out
}

var captureRef = regexp.MustCompile(`\$([1-9])`)

// renderRedirect renders one redirect, faithfully translating three shapes:
//   - catch-all: `redir <to>{uri} <code>` (path preserved),
//   - path glob with a capture ($1..$9): a path_regexp matcher + {re.NAME.n},
//   - plain path glob: `redir <path> <to> <code>` using Caddy's path matcher.
//
// The capture case matters for 0% FP: Cloudflare's `$1` is not Caddy syntax, so
// emitting it verbatim would silently break the redirect.
func renderRedirect(i int, r ir.Redirect) string {
	status := r.Status
	if status == 0 {
		status = 302
	}
	if isCatchAll(r.Match) {
		return fmt.Sprintf("\tredir %s{uri} %d\n", r.To, status)
	}
	if captureRef.MatchString(r.To) {
		name := fmt.Sprintf("rd%d", i)
		rx := globToRegex(r.Match)
		to := captureRef.ReplaceAllString(r.To, "{re."+name+".$1}")
		return fmt.Sprintf("\t@%s path_regexp %s %s\n\tredir @%s %s %d\n", name, name, rx, name, to, status)
	}
	return fmt.Sprintf("\tredir %s %s %d\n", r.Match, r.To, status)
}

// globToRegex converts a `/old/*` style path glob into an anchored regex with a
// single capture group for the wildcard tail.
func globToRegex(glob string) string {
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString("(.*)")
		case '.', '+', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('$')
	return b.String()
}

func schemeOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func joinInts(xs []int) string {
	ss := make([]string, len(xs))
	for i, x := range xs {
		ss[i] = fmt.Sprintf("%d", x)
	}
	sort.Strings(ss)
	return strings.Join(ss, " ")
}
