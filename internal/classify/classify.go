// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package classify is the verdict engine. It turns a cloudflare.Snapshot into a
// report.Report by classifying every element AUTO / ASK / MANUAL. The single
// invariant that makes the 0% false-positive claim true: when equivalence
// cannot be proven, classification degrades to ASK or MANUAL, never AUTO. Every
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
		// Full (strict) verifies the origin cert, but on Cloudflare that cert is
		// typically a Cloudflare Origin CA cert, trusted ONLY by Cloudflare. A
		// self-hosted Caddy edge would fail to verify it, so emitting verify_tls
		// unconditionally would ship a Caddyfile whose edge→origin handshake
		// breaks. Not a silent AUTO: ask how the new edge should trust the origin.
		add(report.Finding{
			Kind: "tls", Name: "ssl-mode", Verdict: report.Ask, Target: "caddy",
			Rationale: "SSL Full (strict) verifies the origin certificate, but a Cloudflare Origin CA cert is trusted only by Cloudflare: a self-hosted Caddy edge cannot verify it. Reproduce the verified edge→origin link with a replacement origin cert, or accept an encrypted-but-unverified link (a downgrade from strict).",
			Question: &report.Question{
				ID:      "origin-verify",
				Prompt:  "Verify the origin certificate on the new edge? 'verify' needs a replacement trusted origin cert (issue one via CertMate and install it on the origin, or pass --origin-ca <ca.pem>); 'skip' encrypts but does not verify (a downgrade from strict).",
				Options: []string{"verify", "skip"}, Default: "verify",
			},
		})
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
		// Cloudflare rewrites http:// asset links inside response BODIES. Caddy's
		// default build has no response-body replace directive (the xcaddy build
		// carries only caddy-waf + souin), and nothing in the plan/IR emits one,
		// so this cannot be AUTO without silently claiming coverage it never emits.
		add(manual("transform", "automatic-https-rewrites",
			"Automatic HTTPS Rewrites rewrites http:// asset links in response bodies; Caddy's default build has no equivalent (it would need a response-body replace plugin): reproduce it at the origin/app."))
	}
	if len(st.Ciphers) > 0 {
		// A custom cipher list is not mapped: ir.TLS carries no cipher field and the
		// caddy generator emits only `protocols`, never `ciphers`. Surfacing this as
		// an answerable ASK would be a false-ASK (the answer changes nothing), so it
		// is MANUAL: Caddy's default suite is safe but not a faithful reproduction.
		add(manual("tls", "custom-ciphers",
			"A custom cipher suite is configured. Caddy's default cipher set is safe but flareover does not map a custom list: apply cipher customization by hand if it is required."))
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
		// with cache_level + edge_cache_ttl doesn't surface as duplicates. Only
		// edge_cache_ttl actually materializes (plan.cacheForZone reads that key and
		// nothing else), so a rule whose sole cache action is cache_level or
		// browser_cache_ttl emits nothing: it must be MANUAL, not PARTIAL, to keep
		// classify ⟺ generate honest.
		_, hasEdgeCacheTTL := pr.Actions["edge_cache_ttl"]
		cacheEmitted := false
		for action := range pr.Actions {
			switch action {
			case "forwarding_url":
				add(auto("redirect", name, "caddy", "Page Rule forwarding_url → Caddy redir with the configured status code."))
			case "always_use_https":
				add(auto("redirect", name, "caddy", "Page Rule Always Use HTTPS → Caddy HTTP→HTTPS redirect for the matched pattern."))
			case "cache_level", "edge_cache_ttl", "browser_cache_ttl":
				if !cacheEmitted {
					cacheEmitted = true
					if hasEdgeCacheTTL {
						add(partial("cache", name, "caddy", "Page Rule edge cache TTL → Caddy cache handler (souin); TTL parity is approximate."))
					} else {
						add(manual("cache", name, "Page Rule cache_level/browser_cache_ttl has no faithful Caddy cache mapping (only edge_cache_ttl is emitted): set caching by hand."))
					}
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
	proxied := s.ProxiedHTTPHosts() // hosts that become a Caddy site (for host-scoped rules)
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
				classifyTransform(rule, name, proxied, add)
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
		// shared predicate), otherwise the coverage report would claim a mapping
		// the generator drops, a false positive.
		if m, ok := cfexpr.SimpleWAFMatch(rule.Expression); ok {
			add(auto("waf-custom", name, "caddy-waf", wafAutoRationale(m)))
		} else {
			// The plan emits only SimpleWAFMatch shapes, so a compound/non-standard
			// expression has no faithful mapping, and no answer could change that.
			// MANUAL, never an ASK the generator would silently ignore (0%FP).
			add(manual("waf-custom", name,
				"Custom firewall rule uses a compound or non-standard Cloudflare expression with no faithful caddy-waf translation: reproduce the intent by hand (compose caddy-waf conditions)."))
		}
	case "managed_challenge", "challenge", "js_challenge":
		// caddy-waf can block or log, not issue a CAPTCHA/JS challenge. Converting
		// to a hard block is a faithful-to-intent hardening the operator can opt
		// into, but only when the match is one the plan can actually emit. Offer
		// the ASK only for a SimpleWAFMatch expression (the plan honors it); a
		// compound match can't be reproduced even as a block, so it is MANUAL,
		// never an ASK the generator would then ignore.
		if _, ok := cfexpr.SimpleWAFMatch(rule.Expression); ok {
			add(report.Finding{
				Kind: "waf-custom", Name: name, Verdict: report.Ask, Target: "caddy-waf",
				Rationale: "Cloudflare challenge (CAPTCHA/JS) has no caddy-waf equivalent; caddy-waf can block or log, not challenge.",
				Question:  &report.Question{ID: "waf-challenge:" + name, Prompt: "Convert this challenge to a hard block?", Options: []string{"yes", "no"}, Default: "no"},
			})
		} else {
			add(manual("waf-custom", name,
				"Cloudflare challenge on a compound/non-standard expression: caddy-waf cannot challenge, and the match can't be reproduced even as a hard block: handle by hand."))
		}
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

func classifyTransform(rule cf.Rule, name string, proxied map[string]bool, add func(report.Finding)) {
	// Header transforms and simple URL rewrites map cleanly onto Caddy, which,
	// unlike some proxies, supports arbitrary request/response header ops.
	if _, ok := rule.ActionParams["headers"]; ok {
		// Same cfexpr.TransformScope predicate the plan builder emits from, so a
		// header transform is AUTO only when config is actually generated for it
		// (classify ⟺ generate). Global → every site; path-scoped → a matcher-
		// guarded directive on every site; host-scoped → an unmatched directive in
		// that host's block, but only if the host is a proxied record (else there
		// is no site to attach it to). Compound/host+path → MANUAL, never silent.
		host, match, ok := cfexpr.TransformScope(rule.Expression)
		switch {
		case !ok:
			add(manual("transform", name, "Compound or host+path header transform: no faithful Caddy matcher; reproduce it by hand (e.g. `@m <matcher>` then `header @m …`)."))
		case host != "" && !proxied[host]:
			add(manual("transform", name, "Header transform scoped to a host with no proxied record: there is no migrated site to attach it to; reproduce it by hand."))
		case host != "":
			add(auto("transform", name, "caddy", "Host-scoped header transform → Caddy header directive in that host's site block."))
		case match != "":
			add(auto("transform", name, "caddy", "Path-scoped header transform → Caddy header directive guarded by a path matcher."))
		default:
			add(auto("transform", name, "caddy", "Global header transform → Caddy header directive (add/set/remove request or response headers)."))
		}
		return
	}
	if uri, ok := rule.ActionParams["uri"].(map[string]any); ok {
		// Same predicates the plan emits from: the scope must be a faithful Caddy
		// matcher (global/host/path) AND the target must be static (a literal path/
		// query, not expression-derived). A host-scoped rewrite also needs its host
		// to be a proxied site. Anything else → MANUAL, never a silent AUTO.
		host, _, scopeOK := cfexpr.TransformScope(rule.Expression)
		_, targetOK := cfexpr.RewriteTarget(uri)
		switch {
		case !scopeOK || !targetOK:
			add(manual("transform", name, "URL rewrite with a dynamic (expression-derived) target or a compound/unmappable match: no faithful static Caddy rewrite; reproduce it by hand."))
		case host != "" && !proxied[host]:
			add(manual("transform", name, "URL rewrite scoped to a host with no proxied record: there is no migrated site to attach it to; reproduce it by hand."))
		default:
			add(auto("transform", name, "caddy", "Static URL rewrite → Caddy rewrite directive (matcher-guarded when path-scoped)."))
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
// the honest verdict is MANUAL, but with the exact settings named and split
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
	// A host-scoped rule whose parameters all map (host_header / origin / sni) is
	// emitted as a Caddy reverse_proxy override: the same predicate the plan uses.
	if _, ok := cfexpr.OriginOverride(rule.Expression, rule.ActionParams); ok {
		add(auto("origin-rule", name, "caddy",
			"Host-scoped Origin Rule → Caddy reverse_proxy override (header_up Host / upstream / tls_server_name)."))
		return
	}
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
		"Origin Rule ("+detail+"): path-scoped, or a parameter with no faithful Caddy mapping; recreate by hand (reverse_proxy header_up Host / upstream / matchers)."))
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
			// buildWAF only materializes an allow entry for IP/CIDR targets
			// (AllowIPs); there is no allow-country / allow-ASN directive in
			// ir.WAFPolicy or caddy-waf, so a country/ASN allowlist must not be AUTO.
			switch r.Target {
			case "ip", "ip_range", "ip6":
				add(auto("ip-access", name, "caddy-waf", "IP/CIDR allowlist → caddy-waf ip_whitelist_file entry."))
			default:
				add(manual("ip-access", name, fmt.Sprintf("Allowlist on target %q has no caddy-waf allow directive (only IP/CIDR allowlists map).", r.Target)))
			}
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
// drops them silently: none has a supported equivalent yet, so each is MANUAL.
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
				"Provider-only edge feature: no supported equivalent yet; it is not carried over. Replicate it at the origin/app if you need it."))
		}
	}
}

func classifySnippets(s cf.Snapshot, add func(report.Finding)) {
	for _, sn := range s.Snippets {
		add(manual("snippet", sn.Name,
			"Snippet is arbitrary edge code (like a small Worker): no deterministic config mapping; port by hand."))
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
	return report.Finding{Kind: kind, Name: name, Verdict: report.Auto, Target: target, Rationale: "PARTIAL: " + why}
}

func manual(kind, name, why string) report.Finding {
	return report.Finding{Kind: kind, Name: name, Verdict: report.Manual, Rationale: why}
}

// ruleName delegates to cf.Rule.Name so classify and plan derive identical
// decision-lock keys (an answered ASK must route back to the same rule).
func ruleName(r cf.Rule) string { return r.Name() }
