// Package plan builds the provider-agnostic ir.Plan from a Cloudflare snapshot
// plus the answers to any ASK questions. It emits IR only for what can be
// faithfully translated — the same judgement the classifier makes, via the
// shared cfexpr package — so the generated stack is exactly the AUTO plus
// answered-ASK surface, never more. Anything needing an unanswered decision is
// left out (and shows up in the assessment report as ASK), never guessed.
package plan

import (
	"regexp"
	"sort"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/cfexpr"
	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
	"github.com/fabriziosalmi/flareover/internal/ir"
)

// Options carries deployment parameters and the resolved ASK answers.
type Options struct {
	// EdgeIP is the public address of the new Caddy edge; proxied records are
	// repointed here. Empty yields a clearly-marked placeholder in the zone.
	EdgeIP string
	// CA is the default certificate authority ("letsencrypt" | "actalis").
	CA string
	// Decisions maps report.Question.ID → chosen answer.
	Decisions map[string]string
	// Blocklists names external threat feeds to layer onto the WAF: "domain"
	// and/or "ip" (from the fabriziosalmi/blacklists project).
	Blocklists []string
	// Egress* configure the optional outbound shield (secure-proxy-manager).
	EgressDeny    bool
	EgressAllow   []string
	EgressSSLBump bool
}

// Blocklist feed URLs (fabriziosalmi/blacklists, published on the `latest` tag).
const (
	blocklistDomainURL = "https://github.com/fabriziosalmi/blacklists/releases/download/latest/blacklist.txt"
	blocklistIPURL     = "https://github.com/fabriziosalmi/blacklists/releases/download/latest/ip_blacklist.txt"
)

func (o Options) answer(id string) (string, bool) {
	v, ok := o.Decisions[id]
	return v, ok && strings.TrimSpace(v) != ""
}

func (o Options) edge() string {
	if strings.TrimSpace(o.EdgeIP) == "" {
		return "EDGE_IP_PLACEHOLDER"
	}
	return o.EdgeIP
}

// Build turns a snapshot and its decisions into a deployable plan.
func Build(s cf.Snapshot, opts Options) (ir.Plan, error) {
	if opts.CA == "" {
		opts.CA = "letsencrypt"
	}
	p := ir.Plan{Zone: s.Zone.Name}
	p.DNS = buildDNS(s, opts)
	p.Sites = buildSites(s, opts)
	p.WAF = buildWAF(s)
	for _, kind := range opts.Blocklists {
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case "domain":
			p.WAF.Blocklists = append(p.WAF.Blocklists, ir.Blocklist{Kind: "domain", URL: blocklistDomainURL})
		case "ip":
			p.WAF.Blocklists = append(p.WAF.Blocklists, ir.Blocklist{Kind: "ip", URL: blocklistIPURL})
		}
	}
	if opts.EgressDeny || len(opts.EgressAllow) > 0 {
		p.Egress = &ir.EgressPolicy{
			DefaultDeny: opts.EgressDeny, Allow: opts.EgressAllow, SSLBump: opts.EgressSSLBump,
			Blocklists: p.WAF.Blocklists,
		}
	}
	return p, nil
}

// --- DNS ---------------------------------------------------------------------

func buildDNS(s cf.Snapshot, opts Options) ir.DNSZone {
	z := ir.DNSZone{Name: s.Zone.Name}
	if s.Settings.DNSSEC == "active" {
		if a, ok := opts.answer("dnssec-ds-update"); ok && a == "yes" {
			z.DNSSEC = true
		}
	}
	deproxied := map[string]bool{}
	for _, rec := range s.DNSRecords {
		if rec.Proxied && isHTTPFrontable(rec.Type) {
			// De-proxy: only if we know the origin (answered ASK). The record now
			// points at the new edge; the origin lives on the Site. A host with
			// several proxied records (A + AAAA) yields ONE A → edge, not a
			// duplicate.
			if _, ok := opts.answer("origin:" + rec.Name); !ok {
				continue
			}
			if deproxied[rec.Name] {
				continue
			}
			deproxied[rec.Name] = true
			z.Records = append(z.Records, ir.DNSRecord{
				Type: "A", Name: rec.Name, Content: opts.edge(), TTL: normalizeTTL(rec.TTL),
			})
			continue
		}
		// Everything else copies verbatim.
		z.Records = append(z.Records, ir.DNSRecord{
			Type: rec.Type, Name: rec.Name, Content: rec.Content,
			TTL: normalizeTTL(rec.TTL), Priority: rec.Priority,
		})
	}
	sort.SliceStable(z.Records, func(i, j int) bool {
		if z.Records[i].Name != z.Records[j].Name {
			return z.Records[i].Name < z.Records[j].Name
		}
		return z.Records[i].Type < z.Records[j].Type
	})
	return z
}

// --- Sites -------------------------------------------------------------------

func buildSites(s cf.Snapshot, opts Options) []ir.Site {
	scheme, verify := originScheme(s, opts)
	globalHeaders := buildGlobalHeaders(s)
	wildcard := hasWildcardCert(s)

	var sites []ir.Site
	seen := map[string]bool{}
	for _, rec := range s.DNSRecords {
		if !rec.Proxied || !isHTTPFrontable(rec.Type) {
			continue
		}
		// One host may have several proxied records (A + AAAA, etc.) — it is a
		// single virtual host, not several. Emit it once.
		if seen[rec.Name] {
			continue
		}
		origin, ok := opts.answer("origin:" + rec.Name)
		if !ok {
			continue
		}
		seen[rec.Name] = true
		// An origin answer may carry an explicit scheme ("http://host:port"),
		// which overrides the SSL-mode-derived scheme — the operator knows what
		// the backend actually speaks. Without a scheme, the SSL mode decides.
		upstream, oScheme, oVerify := resolveOrigin(origin, scheme, verify)
		site := ir.Site{
			Host: rec.Name,
			Origin: ir.Origin{
				Upstreams: []string{upstream},
				Scheme:    oScheme,
				VerifyTLS: oVerify,
			},
			TLS: ir.TLS{
				Provider:   "certmate",
				CA:         opts.CA,
				MinVersion: s.Settings.MinTLSVersion,
				Wildcard:   wildcard,
				HSTS:       buildHSTS(s),
			},
			Headers:   append([]ir.HeaderOp(nil), globalHeaders...),
			Redirects: redirectsForHost(s, rec.Name),
			Cache:     cacheForZone(s),
		}
		sites = append(sites, site)
	}
	sort.SliceStable(sites, func(i, j int) bool { return sites[i].Host < sites[j].Host })
	return sites
}

// resolveOrigin splits an origin answer into (host:port, scheme, verifyTLS).
// An explicit "http://" / "https://" prefix wins over the SSL-mode default and
// avoids scheme/port conflicts Caddy would reject (e.g. https:// with :80).
func resolveOrigin(answer, defScheme string, defVerify bool) (string, string, bool) {
	switch {
	case strings.HasPrefix(answer, "http://"):
		return strings.TrimPrefix(answer, "http://"), "http", false
	case strings.HasPrefix(answer, "https://"):
		return strings.TrimPrefix(answer, "https://"), "https", defVerify
	default:
		return answer, defScheme, defVerify
	}
}

// originScheme maps the zone SSL mode (and the Flexible ASK answer) to how the
// edge should talk to the origin.
func originScheme(s cf.Snapshot, opts Options) (scheme string, verify bool) {
	switch strings.ToLower(s.Settings.SSL) {
	case "strict":
		return "https", true
	case "full":
		return "https", false
	case "flexible":
		if a, ok := opts.answer("flexible-origin-scheme"); ok {
			return a, false
		}
		return "http", false
	default:
		if a, ok := opts.answer("enable-https"); ok && a == "no" {
			return "http", false
		}
		return "https", false
	}
}

func buildHSTS(s cf.Snapshot) *ir.HSTS {
	h := s.Settings.HSTS
	if h == nil || !h.Enabled {
		return nil
	}
	return &ir.HSTS{MaxAge: h.MaxAge, IncludeSubDomains: h.IncludeSubDomains, Preload: h.Preload}
}

// buildGlobalHeaders translates header-transform rules whose match is global
// (expression == "true") into header ops that apply to every site. Host- or
// path-scoped header rules are intentionally not emitted here — they need a
// matcher translation and surface as ASK in the assessment.
func buildGlobalHeaders(s cf.Snapshot) []ir.HeaderOp {
	var ops []ir.HeaderOp
	for _, rs := range s.Rulesets {
		phase := ""
		switch rs.Phase {
		case "http_request_transform", "http_request_late_transform":
			phase = "request"
		case "http_response_headers_transform":
			phase = "response"
		default:
			continue
		}
		for _, rule := range rs.Rules {
			if !rule.Enabled || strings.TrimSpace(strings.ToLower(rule.Expression)) != "true" {
				continue
			}
			headers, ok := rule.ActionParams["headers"].(map[string]any)
			if !ok {
				continue
			}
			for name, raw := range headers {
				spec, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				op, _ := spec["operation"].(string)
				val, _ := spec["value"].(string)
				if op == "" {
					op = "set"
				}
				ops = append(ops, ir.HeaderOp{Phase: phase, Op: op, Name: name, Value: val})
			}
		}
	}
	sort.SliceStable(ops, func(i, j int) bool { return ops[i].Name < ops[j].Name })
	return ops
}

// redirectsForHost collects redirects that faithfully bind to a given host:
// dynamic redirects with a static target guarded by `http.host eq "<host>"`,
// and Page Rule forwarding_url rules whose pattern is on that host.
func redirectsForHost(s cf.Snapshot, host string) []ir.Redirect {
	var reds []ir.Redirect
	for _, rs := range s.Rulesets {
		if rs.Phase != "http_request_dynamic_redirect" {
			continue
		}
		for _, rule := range rs.Rules {
			if !rule.Enabled {
				continue
			}
			h, ok := cfexpr.HostEq(rule.Expression)
			if !ok || h != host {
				continue
			}
			tgt, static := cfexpr.StaticRedirectTarget(rule.ActionParams)
			if !static {
				continue
			}
			reds = append(reds, ir.Redirect{Match: "*", To: tgt, Status: cfexpr.RedirectStatus(rule.ActionParams)})
		}
	}
	for _, pr := range s.PageRules {
		if pr.Status != "active" {
			continue
		}
		fwd, ok := pr.Actions["forwarding_url"].(map[string]any)
		if !ok || pageRuleHost(pr.Target) != host {
			continue
		}
		to, _ := fwd["url"].(string)
		status := 302
		if sc, ok := fwd["status_code"].(float64); ok {
			status = int(sc)
		}
		reds = append(reds, ir.Redirect{Match: pageRulePath(pr.Target), To: to, Status: status})
	}
	sort.SliceStable(reds, func(i, j int) bool { return reds[i].Match < reds[j].Match })
	return reds
}

func cacheForZone(s cf.Snapshot) *ir.CachePolicy {
	// Any cache signal (aggressive cache level, a cache Page Rule, or a cache
	// ruleset) enables an approximate cache. Parity is not exact — the generator
	// annotates this.
	if s.Settings.CacheLevel == "aggressive" {
		return &ir.CachePolicy{Enabled: true, TTL: s.Settings.BrowserCacheTTL}
	}
	for _, pr := range s.PageRules {
		if pr.Status != "active" {
			continue
		}
		if ttl, ok := pr.Actions["edge_cache_ttl"]; ok {
			if f, ok := ttl.(float64); ok {
				return &ir.CachePolicy{Enabled: true, TTL: int(f)}
			}
			return &ir.CachePolicy{Enabled: true}
		}
	}
	// Modern Cache Rules (rules engine) also enable caching.
	for _, rs := range s.Rulesets {
		if rs.Phase != "http_request_cache_settings" {
			continue
		}
		for _, rule := range rs.Rules {
			if rule.Enabled {
				return &ir.CachePolicy{Enabled: true}
			}
		}
	}
	return nil
}

// --- WAF ---------------------------------------------------------------------

func buildWAF(s cf.Snapshot) ir.WAFPolicy {
	var w ir.WAFPolicy
	for _, rs := range s.Rulesets {
		switch rs.Phase {
		case "http_request_firewall_custom":
			for _, rule := range rs.Rules {
				if !rule.Enabled || !cfexpr.IsSimple(rule.Expression) {
					continue
				}
				if rule.Action != "block" && rule.Action != "log" {
					continue
				}
				if wr, ok := wafRuleFromExpr(rule); ok {
					w.CustomRules = append(w.CustomRules, wr)
				}
			}
		case "http_ratelimit":
			for _, rule := range rs.Rules {
				rl := rule.RateLimit
				if !rule.Enabled || rl == nil {
					continue
				}
				if cfexpr.IsPerIPRateLimit(rl.Characteristics) {
					w.RateLimits = append(w.RateLimits, ir.RateLimit{
						Requests: rl.RequestsPerPeriod, Window: rl.Period, Path: ratelimitPath(rule.Expression),
					})
				}
			}
		}
	}
	for _, m := range s.ManagedRules {
		if m.Enabled && strings.Contains(strings.ToLower(m.Name), "owasp") {
			w.ManagedOWASP = true
		}
	}
	// Zone IP Access Rules become deny/allow lists and country/ASN blocks. Only
	// the faithfully-mappable modes are folded in here; challenge modes are left
	// to the classifier's ASK and never silently downgraded to a block.
	for _, r := range s.IPAccessRules {
		switch r.Mode {
		case "block":
			switch r.Target {
			case "country":
				w.BlockCountries = append(w.BlockCountries, r.Value)
			case "asn":
				if n, ok := parseASN(r.Value); ok {
					w.BlockASNs = append(w.BlockASNs, n)
				}
			case "ip", "ip_range", "ip6":
				w.BlockIPs = append(w.BlockIPs, r.Value)
			}
		case "whitelist":
			if r.Target == "ip" || r.Target == "ip_range" || r.Target == "ip6" {
				w.AllowIPs = append(w.AllowIPs, r.Value)
			}
		}
	}
	return w
}

// parseASN turns "AS64512" or "64512" into 64512.
func parseASN(s string) (int, bool) {
	s = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "AS")
	n := 0
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// wafRuleFromExpr parses a single-field `<field> eq|contains "<value>"`
// expression into a caddy-waf rule.
func wafRuleFromExpr(rule cf.Rule) (ir.WAFRule, bool) {
	field, value, ok := parseFieldMatch(rule.Expression)
	if !ok {
		return ir.WAFRule{}, false
	}
	action := "block"
	if rule.Action == "log" {
		action = "log"
	}
	return ir.WAFRule{
		Description: rule.Description,
		Pattern:     regexpQuote(value),
		Targets:     []string{wafTargetForField(field)},
		Action:      action,
		Score:       10,
		Sample:      value,
	}, true
}

// --- small helpers -----------------------------------------------------------

func isHTTPFrontable(recType string) bool {
	switch strings.ToUpper(recType) {
	case "A", "AAAA", "CNAME":
		return true
	}
	return false
}

func normalizeTTL(ttl int) int {
	if ttl <= 1 { // Cloudflare "automatic"
		return 300
	}
	return ttl
}

func hasWildcardCert(s cf.Snapshot) bool {
	for _, c := range s.Certificates {
		for _, h := range c.Hosts {
			if strings.HasPrefix(h, "*.") {
				return true
			}
		}
	}
	return false
}

func pageRuleHost(target string) string {
	t := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	if i := strings.IndexByte(t, '/'); i >= 0 {
		return t[:i]
	}
	return t
}

func pageRulePath(target string) string {
	t := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	if i := strings.IndexByte(t, '/'); i >= 0 {
		return t[i:]
	}
	return "/*"
}

// fieldMatch parses `http.<field> eq|contains "<value>"`.
var fieldMatch = regexp.MustCompile(`(?i)^(http\.[a-z_.]+)\s+(eq|contains)\s+"([^"]+)"$`)

func parseFieldMatch(expr string) (field, value string, ok bool) {
	m := fieldMatch.FindStringSubmatch(strings.TrimSpace(expr))
	if m == nil {
		return "", "", false
	}
	return m[1], m[3], true
}

func wafTargetForField(field string) string {
	switch strings.ToLower(field) {
	case "http.user_agent":
		return "HEADERS:User-Agent"
	case "http.request.uri.path":
		return "URL"
	case "http.request.uri":
		return "URL"
	case "http.referer":
		return "HEADERS:Referer"
	default:
		return "HEADERS"
	}
}

func ratelimitPath(expr string) string {
	if _, value, ok := parseFieldMatch(expr); ok {
		return value
	}
	return ""
}

func regexpQuote(s string) string {
	// caddy-waf patterns are regexes; treat the Cloudflare literal as exact.
	return "(?i)" + escapeRegex(s)
}

func escapeRegex(s string) string {
	const special = `\.+*?()|[]{}^$`
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(special, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
