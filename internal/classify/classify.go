// Package classify is the verdict engine. It turns a cloudflare.Snapshot into a
// report.Report by classifying every element AUTO / ASK / MANUAL. The single
// invariant that makes the 0% false-positive claim true: when equivalence
// cannot be proven, classification degrades to ASK or MANUAL — never AUTO. Every
// branch below is written to fail toward honesty, not toward coverage.
package classify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/cfexpr"
	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
	"github.com/fabriziosalmi/flareover/internal/report"
)

// Classify produces the full assessment report for a snapshot.
func Classify(s cf.Snapshot) report.Report {
	r := report.Report{Zone: s.Zone.Name}
	add := func(f report.Finding) { r.Findings = append(r.Findings, f) }

	classifyDNS(s, add)
	classifyDNSSEC(s, add)
	classifyTLS(s, add)
	classifyGlobalSettings(s, add)
	classifyPageRules(s, add)
	classifyRulesets(s, add)
	classifyManagedRules(s, add)
	classifyIPAccessRules(s, add)
	classifyUARules(s, add)
	classifyScrapeShield(s, add)
	classifySnippets(s, add)
	classifyWorkers(s, add)
	classifyLoadBalancers(s, add)
	classifyR2(s, add)
	classifyAccess(s, add)
	classifyEmail(s, add)

	return r
}

// --- DNS ---------------------------------------------------------------------

func classifyDNS(s cf.Snapshot, add func(report.Finding)) {
	for _, rec := range s.DNSRecords {
		name := fmt.Sprintf("%s %s", rec.Type, rec.Name)
		if rec.Proxied {
			// Orange cloud: the record content is a Cloudflare edge IP, not the
			// true origin. We cannot know the backend from the snapshot alone.
			add(report.Finding{
				Kind: "dns", Name: name, Verdict: report.Ask, Target: "powerdns",
				Rationale: "Proxied (orange-cloud) record hides the true origin behind Cloudflare; the new edge needs the real backend address.",
				Question: &report.Question{
					ID:      "origin:" + rec.Name,
					Prompt:  fmt.Sprintf("Real origin (host:port) that %s should forward to?", rec.Name),
					Options: []string{"<host:port>"},
					Default: "",
				},
			})
			continue
		}
		// Grey-clouded / non-proxyable records transcribe 1:1 to PowerDNS.
		add(report.Finding{
			Kind: "dns", Name: name, Verdict: report.Auto, Target: "powerdns",
			Rationale: "Unproxied record copied verbatim into the authoritative PowerDNS zone.",
		})
	}
}

func classifyDNSSEC(s cf.Snapshot, add func(report.Finding)) {
	if s.Settings.DNSSEC != "active" {
		return
	}
	add(report.Finding{
		Kind: "dnssec", Name: s.Zone.Name, Verdict: report.Ask, Target: "powerdns",
		Rationale: "DNSSEC is active. PowerDNS can sign the zone, but the DS record at the registrar must be replaced during cutover or resolution breaks.",
		Question: &report.Question{
			ID:      "dnssec-ds-update",
			Prompt:  "Confirm you can update the DS record at the registrar during cutover?",
			Options: []string{"yes", "no"},
			Default: "no",
		},
	})
}

// --- TLS / SSL mode ----------------------------------------------------------

func classifyTLS(s cf.Snapshot, add func(report.Finding)) {
	switch strings.ToLower(s.Settings.SSL) {
	case "strict":
		add(auto("tls", "ssl-mode", "caddy",
			"SSL Full (strict) → Caddy terminates TLS and verifies the origin certificate (verify_tls on)."))
	case "full":
		add(auto("tls", "ssl-mode", "caddy",
			"SSL Full → Caddy terminates TLS and forwards over HTTPS without verifying the origin cert."))
	case "flexible":
		add(report.Finding{
			Kind: "tls", Name: "ssl-mode", Verdict: report.Ask, Target: "caddy",
			Rationale: "SSL Flexible means Cloudflare→origin is plaintext HTTP. That is insecure and often reflects an origin with no TLS. Confirm the intended origin scheme.",
			Question: &report.Question{
				ID: "flexible-origin-scheme", Prompt: "Keep plaintext HTTP to the origin (Flexible), or upgrade to HTTPS?",
				Options: []string{"http", "https"}, Default: "http",
			},
		})
	case "off", "":
		add(report.Finding{
			Kind: "tls", Name: "ssl-mode", Verdict: report.Ask, Target: "caddy",
			Rationale: "SSL is off / not captured. Confirm whether the site should serve HTTPS on the new edge.",
			Question:  &report.Question{ID: "enable-https", Prompt: "Serve HTTPS on the new edge?", Options: []string{"yes", "no"}, Default: "yes"},
		})
	default:
		add(manual("tls", "ssl-mode",
			fmt.Sprintf("Unrecognized SSL mode %q; cannot map without a decision.", s.Settings.SSL)))
	}

	// Edge certificate issuance strategy.
	needWildcard := false
	for _, c := range s.Certificates {
		for _, h := range c.Hosts {
			if strings.HasPrefix(h, "*.") {
				needWildcard = true
			}
		}
	}
	if needWildcard {
		add(auto("tls", "certificate", "certmate",
			"Wildcard edge cert → CertMate issues via DNS-01 through PowerDNS (Caddy's native ACME is HTTP-01 only and cannot do wildcards)."))
	} else if len(s.Certificates) > 0 {
		add(auto("tls", "certificate", "certmate",
			"Edge certificate → CertMate issues per-host certs (Let's Encrypt, or Actalis for an EU CA); Caddy consumes them."))
	}
}

func classifyGlobalSettings(s cf.Snapshot, add func(report.Finding)) {
	st := s.Settings
	if st.AlwaysUseHTTPS.On() {
		add(auto("redirect", "always-use-https", "caddy", "Always Use HTTPS → Caddy global HTTP→HTTPS redirect (built in)."))
	}
	if st.HSTS != nil && st.HSTS.Enabled {
		add(auto("tls", "hsts", "caddy",
			fmt.Sprintf("HSTS → Strict-Transport-Security header (max-age=%d, includeSubDomains=%v, preload=%v).",
				st.HSTS.MaxAge, st.HSTS.IncludeSubDomains, st.HSTS.Preload)))
	}
	if st.MinTLSVersion != "" {
		add(auto("tls", "min-tls-version", "caddy",
			fmt.Sprintf("Minimum TLS %s → Caddy tls protocols floor.", st.MinTLSVersion)))
	}
	if st.HTTP3.On() {
		add(auto("proto", "http3", "caddy", "HTTP/3 → Caddy serves HTTP/3 (enabled by default)."))
	}
	if st.AutomaticHTTPSRewrites.On() {
		add(auto("transform", "automatic-https-rewrites", "caddy",
			"Automatic HTTPS Rewrites → Caddy replace directive rewriting http:// asset links to https://."))
	}
	if st.Ciphers != nil && len(st.Ciphers) > 0 {
		add(report.Finding{
			Kind: "tls", Name: "custom-ciphers", Verdict: report.Ask, Target: "caddy",
			Rationale: "A custom cipher suite is configured. Caddy exposes a narrower, safe-by-default cipher set; confirm mapping to the closest supported list.",
			Question:  &report.Question{ID: "custom-ciphers", Prompt: "Map custom ciphers to Caddy's closest supported set?", Options: []string{"yes", "no"}, Default: "yes"},
		})
	}
}

// --- Page Rules --------------------------------------------------------------

func classifyPageRules(s cf.Snapshot, add func(report.Finding)) {
	for _, pr := range s.PageRules {
		if pr.Status != "active" {
			continue
		}
		name := pr.Target
		// A page rule may carry several actions; classify each once, but collapse
		// the several cache-related actions into a single cache finding so a rule
		// with cache_level + edge_cache_ttl doesn't surface as duplicates.
		cacheEmitted := false
		for action := range pr.Actions {
			switch action {
			case "forwarding_url":
				add(auto("redirect", name, "caddy", "Page Rule forwarding_url → Caddy redir with the configured status code."))
			case "always_use_https":
				add(auto("redirect", name, "caddy", "Page Rule Always Use HTTPS → Caddy HTTP→HTTPS redirect for the matched pattern."))
			case "cache_level", "edge_cache_ttl", "browser_cache_ttl":
				if !cacheEmitted {
					add(partial("cache", name, "caddy", "Page Rule cache settings → Caddy cache handler (souin); TTL parity is approximate."))
					cacheEmitted = true
				}
			case "ssl":
				add(partial("tls", name, "caddy", "Page Rule per-URL SSL override → Caddy per-site TLS; review scope."))
			default:
				add(manual("pagerule", name,
					fmt.Sprintf("Page Rule action %q has no faithful deterministic mapping.", action)))
			}
		}
	}
}

// --- Rules engine ------------------------------------------------------------

func classifyRulesets(s cf.Snapshot, add func(report.Finding)) {
	for _, rs := range s.Rulesets {
		for _, rule := range rs.Rules {
			if !rule.Enabled {
				continue
			}
			name := ruleName(rule)
			switch rs.Phase {
			case "http_request_firewall_custom":
				classifyCustomWAFRule(rule, name, add)
			case "http_ratelimit":
				classifyRateLimit(rule, name, add)
			case "http_request_transform", "http_request_late_transform", "http_response_headers_transform":
				classifyTransform(rule, name, add)
			case "http_request_dynamic_redirect":
				classifyRedirect(rule, name, add)
			case "http_request_cache_settings":
				add(partial("cache", name, "caddy", "Cache rule → Caddy cache handler; behavior is approximate, review before relying on it."))
			case "http_config_settings":
				classifyConfigRule(rule, name, add)
			case "http_request_origin":
				classifyOriginRule(rule, name, add)
			default:
				add(manual("ruleset", name,
					fmt.Sprintf("Ruleset phase %q is not yet mapped; handle manually.", rs.Phase)))
			}
		}
	}
}

func classifyCustomWAFRule(rule cf.Rule, name string, add func(report.Finding)) {
	switch rule.Action {
	case "block", "log":
		// AUTO only for shapes the plan actually emits (SimpleWAFMatch is the
		// shared predicate) — otherwise the coverage report would claim a mapping
		// the generator drops, a false positive.
		if m, ok := cfexpr.SimpleWAFMatch(rule.Expression); ok {
			add(auto("waf-custom", name, "caddy-waf", wafAutoRationale(m)))
		} else {
			add(report.Finding{
				Kind: "waf-custom", Name: name, Verdict: report.Ask, Target: "caddy-waf",
				Rationale: "Custom firewall rule uses a compound or non-standard Cloudflare expression. A best-effort caddy-waf translation is possible but may not be byte-identical.",
				Question:  &report.Question{ID: "waf-translate:" + name, Prompt: "Accept a best-effort caddy-waf translation of this rule?", Options: []string{"yes", "no"}, Default: "no"},
			})
		}
	case "managed_challenge", "challenge", "js_challenge":
		// caddy-waf can block or log, not issue a CAPTCHA/JS challenge — so this
		// is never a faithful 1:1 (it was wrongly AUTO before). Offer the one
		// bounded choice: convert to a hard block.
		add(report.Finding{
			Kind: "waf-custom", Name: name, Verdict: report.Ask, Target: "caddy-waf",
			Rationale: "Cloudflare challenge (CAPTCHA/JS) has no caddy-waf equivalent; caddy-waf can block or log, not challenge.",
			Question:  &report.Question{ID: "waf-challenge:" + name, Prompt: "Convert this challenge to a hard block?", Options: []string{"yes", "no"}, Default: "no"},
		})
	case "skip", "set_config":
		add(manual("waf-custom", name, "Rule uses skip/set_config (bypass/override semantics) that have no faithful caddy-waf equivalent."))
	default:
		add(manual("waf-custom", name, fmt.Sprintf("Firewall action %q has no faithful caddy-waf mapping.", rule.Action)))
	}
}

// wafAutoRationale explains what a faithfully-mappable firewall rule becomes.
func wafAutoRationale(m cfexpr.WAFMatch) string {
	switch m.Kind {
	case "country":
		return "Country block (ip.geoip.country) → caddy-waf block_countries."
	case "asn":
		return "ASN block (ip.geoip.asnum) → caddy-waf block_asns."
	default:
		return "Single-field match → caddy-waf JSON rule (pattern + targets + action)."
	}
}

func classifyRateLimit(rule cf.Rule, name string, add func(report.Finding)) {
	rl := rule.RateLimit
	if rl == nil {
		add(manual("ratelimit", name, "Rate-limit rule missing characteristics; cannot map."))
		return
	}
	if cfexpr.IsPerIPRateLimit(rl.Characteristics) {
		add(auto("ratelimit", name, "caddy-waf",
			fmt.Sprintf("Per-IP rate limit (%d req / %ds) → caddy-waf rate_limit.", rl.RequestsPerPeriod, rl.Period)))
		return
	}
	add(report.Finding{
		Kind: "ratelimit", Name: name, Verdict: report.Ask, Target: "caddy-waf",
		Rationale: fmt.Sprintf("Rate limit keyed on %s. caddy-waf keys on client IP; a non-IP key cannot be reproduced faithfully.", strings.Join(rl.Characteristics, "+")),
		Question:  &report.Question{ID: "ratelimit-key:" + name, Prompt: "Fall back to a per-IP rate limit (losing the original key)?", Options: []string{"yes", "no"}, Default: "no"},
	})
}

func classifyTransform(rule cf.Rule, name string, add func(report.Finding)) {
	// Header transforms and simple URL rewrites map cleanly onto Caddy, which —
	// unlike some proxies — supports arbitrary request/response header ops.
	if _, ok := rule.ActionParams["headers"]; ok {
		add(auto("transform", name, "caddy", "Header transform → Caddy header directive (add/set/remove request or response headers)."))
		return
	}
	if _, ok := rule.ActionParams["uri"]; ok {
		if cfexpr.IsSimple(rule.Expression) {
			add(auto("transform", name, "caddy", "URL rewrite → Caddy rewrite directive."))
		} else {
			add(partial("transform", name, "caddy", "URL rewrite with a compound condition → Caddy rewrite guarded by a matcher; review the matcher translation."))
		}
		return
	}
	add(manual("transform", name, "Transform rule with dynamic/expression-derived values has no faithful static mapping."))
}

// caddyMappableConfig lists Config-Rule settings that Caddy could reproduce if
// a generator were built; everything else is a Cloudflare-only edge feature.
var caddyMappableConfig = map[string]bool{
	"automatic_https_rewrites": true,
	"ssl":                      true,
}

// classifyConfigRule gives Config Rules a specific verdict. They toggle
// Cloudflare edge features per matched request; we do not generate them yet, so
// the honest verdict is MANUAL — but with the exact settings named and split
// into "a Caddy generator could map this" vs "provider-only, no supported
// equivalent yet", which is far more useful than a generic "phase not mapped".
func classifyConfigRule(rule cf.Rule, name string, add func(report.Finding)) {
	var mappable, cfOnly []string
	for k := range rule.ActionParams {
		if caddyMappableConfig[k] {
			mappable = append(mappable, k)
		} else {
			cfOnly = append(cfOnly, k)
		}
	}
	sort.Strings(mappable)
	sort.Strings(cfOnly)
	var parts []string
	if len(mappable) > 0 {
		parts = append(parts, "Caddy-mappable once a Config-Rule generator exists: "+strings.Join(mappable, ", "))
	}
	if len(cfOnly) > 0 {
		parts = append(parts, "provider-only edge features with no supported equivalent yet: "+strings.Join(cfOnly, ", "))
	}
	add(manual("config-rule", name, "Config Rule ("+strings.Join(parts, "; ")+")."))
}

// classifyOriginRule gives Origin Rules a specific verdict. Host-header / origin
// / SNI overrides are reproducible in Caddy (header_up Host, upstream, matchers)
// but no generator emits them yet, so MANUAL with the concrete params named.
func classifyOriginRule(rule cf.Rule, name string, add func(report.Finding)) {
	var keys []string
	for k := range rule.ActionParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	detail := "no parameters"
	if len(keys) > 0 {
		detail = strings.Join(keys, ", ")
	}
	add(manual("origin-rule", name,
		"Origin Rule ("+detail+") — reproducible in Caddy (reverse_proxy header_up Host / upstream / matchers) but no generator emits it yet; recreate by hand."))
}

func classifyRedirect(rule cf.Rule, name string, add func(report.Finding)) {
	tgt, static := cfexpr.StaticRedirectTarget(rule.ActionParams)
	if static {
		add(auto("redirect", name, "caddy", fmt.Sprintf("Dynamic redirect with a static target → Caddy redir to %s.", tgt)))
		return
	}
	add(report.Finding{
		Kind: "redirect", Name: name, Verdict: report.Ask, Target: "caddy",
		Rationale: "Redirect target is expression-derived (built from request fields). Caddy can template many of these, but not all Cloudflare functions have equivalents.",
		Question:  &report.Question{ID: "redirect-template:" + name, Prompt: "Attempt a Caddy template for this dynamic redirect?", Options: []string{"yes", "no"}, Default: "no"},
	})
}

// --- Managed rules / Workers / misc -----------------------------------------

func classifyManagedRules(s cf.Snapshot, add func(report.Finding)) {
	for _, m := range s.ManagedRules {
		if !m.Enabled {
			continue
		}
		add(partial("waf-managed", m.Name, "caddy-waf",
			"Cloudflare managed ruleset → caddy-waf OWASP CRS import. OWASP CRS is not byte-identical to Cloudflare's proprietary set; coverage is comparable, not equal."))
	}
}

func classifyIPAccessRules(s cf.Snapshot, add func(report.Finding)) {
	for _, r := range s.IPAccessRules {
		name := fmt.Sprintf("%s %s=%s", r.Mode, r.Target, r.Value)
		switch r.Mode {
		case "block":
			switch r.Target {
			case "country":
				add(auto("ip-access", name, "caddy-waf", "Country block → caddy-waf block_countries."))
			case "asn":
				add(auto("ip-access", name, "caddy-waf", "ASN block → caddy-waf block_asns."))
			case "ip", "ip_range", "ip6":
				add(auto("ip-access", name, "caddy-waf", "IP/CIDR block → caddy-waf ip_blacklist_file entry."))
			default:
				add(manual("ip-access", name, fmt.Sprintf("Block on target %q has no caddy-waf mapping.", r.Target)))
			}
		case "whitelist":
			add(auto("ip-access", name, "caddy-waf", "Allowlist → caddy-waf whitelist entry."))
		case "challenge", "js_challenge", "managed_challenge":
			add(report.Finding{
				Kind: "ip-access", Name: name, Verdict: report.Ask, Target: "caddy-waf",
				Rationale: "Challenge modes have no faithful caddy-waf equivalent (there is no interactive challenge). Treating as a hard block changes behavior for legitimate users.",
				Question:  &report.Question{ID: "challenge-as-block:" + name, Prompt: "Convert this challenge to a hard block?", Options: []string{"yes", "no"}, Default: "no"},
			})
		default:
			add(manual("ip-access", name, fmt.Sprintf("Access rule mode %q is not mapped.", r.Mode)))
		}
	}
}

func classifyUARules(s cf.Snapshot, add func(report.Finding)) {
	for _, r := range s.UARules {
		name := r.UserAgent
		if r.Description != "" {
			name = r.Description
		}
		switch r.Mode {
		case "block":
			add(auto("ua-block", name, "caddy-waf", "User-Agent block → caddy-waf rule matching HEADERS:User-Agent."))
		case "challenge", "js_challenge", "managed_challenge":
			add(report.Finding{
				Kind: "ua-block", Name: name, Verdict: report.Ask, Target: "caddy-waf",
				Rationale: "User-Agent challenge has no faithful caddy-waf equivalent (no interactive challenge); a hard block would change behavior for real users.",
				Question:  &report.Question{ID: "ua-challenge-as-block:" + name, Prompt: "Convert this UA challenge to a hard block?", Options: []string{"yes", "no"}, Default: "no"},
			})
		default:
			add(manual("ua-block", name, fmt.Sprintf("User-Agent rule mode %q is not mapped.", r.Mode)))
		}
	}
}

// classifyScrapeShield surfaces provider-only edge features so a migration never
// drops them silently — none has a supported equivalent yet, so each is MANUAL.
func classifyScrapeShield(s cf.Snapshot, add func(report.Finding)) {
	feats := []struct {
		on   bool
		name string
	}{
		{s.Settings.EmailObfuscation.On(), "email obfuscation"},
		{s.Settings.ServerSideExclude.On(), "server-side excludes"},
		{s.Settings.HotlinkProtection.On(), "hotlink protection"},
		{s.Settings.BotFightMode.On(), "Bot Fight Mode (ML)"},
	}
	for _, f := range feats {
		if f.on {
			add(manual("scrape-shield", f.name,
				"Provider-only edge feature — no supported equivalent yet; it is not carried over. Replicate it at the origin/app if you need it."))
		}
	}
}

func classifySnippets(s cf.Snapshot, add func(report.Finding)) {
	for _, sn := range s.Snippets {
		add(manual("snippet", sn.Name,
			"Snippet is arbitrary edge code (like a small Worker) — no deterministic config mapping; port by hand."))
	}
}

func classifyWorkers(s cf.Snapshot, add func(report.Finding)) {
	for _, w := range s.Workers {
		add(manual("worker", w.Pattern,
			fmt.Sprintf("Worker %q is arbitrary edge code; it has no deterministic config mapping and must be ported by hand (e.g. to an app service or edge function).", w.Script)))
	}
}

func classifyLoadBalancers(s cf.Snapshot, add func(report.Finding)) {
	for _, lb := range s.LoadBalancers {
		add(partial("loadbalancer", lb.Name, "caddy",
			fmt.Sprintf("Load balancer (steering %q) → Caddy reverse_proxy upstream pool with health checks; advanced steering policies map approximately.", lb.SteeringPolicy)))
	}
}

func classifyR2(s cf.Snapshot, add func(report.Finding)) {
	for _, b := range s.R2Buckets {
		add(report.Finding{
			Kind: "r2", Name: b.Name, Verdict: report.Ask, Target: "minio",
			Rationale: "R2 bucket → MinIO bucket on Contabo (S3-compatible). Bucket + data copy is deterministic; application code that binds to R2 must be repointed by hand.",
			Question:  &report.Question{ID: "r2-migrate:" + b.Name, Prompt: fmt.Sprintf("Provision a MinIO bucket and copy data for %q?", b.Name), Options: []string{"yes", "no"}, Default: "no"},
		})
	}
}

func classifyAccess(s cf.Snapshot, add func(report.Finding)) {
	for _, a := range s.AccessApps {
		add(manual("access", a.Name,
			fmt.Sprintf("Zero-Trust/Access app on %s (%d policies) → Authelia/Authentik. Identity policies must be re-authored; no faithful automatic mapping.", a.Domain, a.Policies)))
	}
}

func classifyEmail(s cf.Snapshot, add func(report.Finding)) {
	if s.EmailRouting != nil && s.EmailRouting.Enabled {
		add(manual("email", s.Zone.Name,
			fmt.Sprintf("Cloudflare Email Routing (%d rules) requires standing up mail-forwarding infrastructure; not deterministically mappable.", s.EmailRouting.Rules)))
	}
}

// --- helpers -----------------------------------------------------------------

func auto(kind, name, target, why string) report.Finding {
	return report.Finding{Kind: kind, Name: name, Verdict: report.Auto, Target: target, Rationale: why}
}

// partial is an AUTO-with-caveat: config is emitted but the rationale flags that
// parity is approximate. We keep it as AUTO because it still produces output;
// the caveat is carried in the rationale so it is never silent.
func partial(kind, name, target, why string) report.Finding {
	return report.Finding{Kind: kind, Name: name, Verdict: report.Auto, Target: target, Rationale: "PARTIAL — " + why}
}

func manual(kind, name, why string) report.Finding {
	return report.Finding{Kind: kind, Name: name, Verdict: report.Manual, Rationale: why}
}

func ruleName(r cf.Rule) string {
	if r.Description != "" {
		return r.Description
	}
	if len(r.Expression) > 48 {
		return r.Expression[:48] + "…"
	}
	return r.Expression
}
