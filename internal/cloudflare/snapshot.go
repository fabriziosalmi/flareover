// SPDX-License-Identifier: AGPL-3.0-only

// Package cloudflare defines the canonical, read-only snapshot of a Cloudflare
// zone. A Snapshot is produced by the extractor (or hand-authored as a test
// fixture) and is the single input to classification and generation. It is a
// faithful transcription of Cloudflare's configuration surface — no
// interpretation happens here; that is the classifier's job.
package cloudflare

import (
	"fmt"
	"strings"
)

// Snapshot is a point-in-time, provider-native capture of one Cloudflare zone.
// It is deliberately close to Cloudflare's own API shapes so extraction stays a
// dumb transcription and every interpretation lives in the classifier.
type Snapshot struct {
	SchemaVersion int          `json:"schema_version"`
	Zone          Zone         `json:"zone"`
	Settings      ZoneSettings `json:"settings"`

	DNSRecords    []DNSRecord      `json:"dns_records,omitempty"`
	PageRules     []PageRule       `json:"page_rules,omitempty"`
	Rulesets      []Ruleset        `json:"rulesets,omitempty"`
	ManagedRules  []ManagedRuleset `json:"managed_rulesets,omitempty"`
	Certificates  []Certificate    `json:"certificates,omitempty"`
	Workers       []WorkerRoute    `json:"workers,omitempty"`
	LoadBalancers []LoadBalancer   `json:"load_balancers,omitempty"`
	R2Buckets     []R2Bucket       `json:"r2_buckets,omitempty"`
	AccessApps    []AccessApp      `json:"access_apps,omitempty"`
	IPAccessRules []IPAccessRule   `json:"ip_access_rules,omitempty"`
	UARules       []UARule         `json:"ua_rules,omitempty"`
	Snippets      []Snippet        `json:"snippets,omitempty"`
	EmailRouting  *EmailRouting    `json:"email_routing,omitempty"`
}

// UARule is a User-Agent Blocking rule (block/challenge by user-agent). Like IP
// access rules, dropping these silently would remove a real security control.
type UARule struct {
	Mode        string `json:"mode"` // block | challenge | js_challenge | managed_challenge
	UserAgent   string `json:"user_agent"`
	Description string `json:"description,omitempty"`
}

// Snippet is a Cloudflare Snippet (lightweight edge code, like a small Worker).
type Snippet struct {
	Name string `json:"name"`
}

// IPAccessRule is a legacy zone firewall access rule (allow/block/challenge by
// IP, CIDR, country, or ASN). These are separate from the Rules engine and, if
// not extracted, would silently drop security controls during migration.
type IPAccessRule struct {
	Mode   string `json:"mode"`   // block | challenge | js_challenge | managed_challenge | whitelist
	Target string `json:"target"` // ip | ip_range | country | asn
	Value  string `json:"value"`
	Notes  string `json:"notes,omitempty"`
}

// Zone is the top-level identity of the zone under migration.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"` // apex domain, e.g. example.com
	Status string `json:"status,omitempty"`
	Paused bool   `json:"paused,omitempty"`
	// NameServers currently assigned by Cloudflare (what we migrate away from).
	NameServers []string `json:"name_servers,omitempty"`
}

// ZoneSettings mirrors the flat key/value settings surface of a Cloudflare zone.
// Zero values mean "not captured"; use pointers where the off/default state is
// itself meaningful.
type ZoneSettings struct {
	// SSL mode: "off" | "flexible" | "full" | "strict" (full-strict) | "origin_pull".
	SSL                     string   `json:"ssl,omitempty"`
	AlwaysUseHTTPS          *OnOff   `json:"always_use_https,omitempty"`
	AutomaticHTTPSRewrites  *OnOff   `json:"automatic_https_rewrites,omitempty"`
	MinTLSVersion           string   `json:"min_tls_version,omitempty"` // "1.0".."1.3"
	TLS13                   *OnOff   `json:"tls_1_3,omitempty"`
	Ciphers                 []string `json:"ciphers,omitempty"`
	HTTP2                   *OnOff   `json:"http2,omitempty"`
	HTTP3                   *OnOff   `json:"http3,omitempty"`
	OpportunisticEncryption *OnOff   `json:"opportunistic_encryption,omitempty"`
	HSTS                    *HSTS    `json:"hsts,omitempty"`
	BrotliCompression       *OnOff   `json:"brotli,omitempty"`
	// Cache level: "aggressive" | "basic" | "simplified".
	CacheLevel      string `json:"cache_level,omitempty"`
	BrowserCacheTTL int    `json:"browser_cache_ttl,omitempty"`
	DevelopmentMode *OnOff `json:"development_mode,omitempty"`
	IPGeolocation   *OnOff `json:"ip_geolocation,omitempty"`
	WebSockets      *OnOff `json:"websockets,omitempty"`
	DNSSEC          string `json:"dnssec,omitempty"` // "active" | "disabled" | "pending"
	// Scrape Shield / bot — provider-only edge features (no supported equivalent yet).
	EmailObfuscation  *OnOff `json:"email_obfuscation,omitempty"`
	ServerSideExclude *OnOff `json:"server_side_exclude,omitempty"`
	HotlinkProtection *OnOff `json:"hotlink_protection,omitempty"`
	BotFightMode      *OnOff `json:"bot_fight_mode,omitempty"`
}

// HSTS captures Strict-Transport-Security intent.
type HSTS struct {
	Enabled           bool `json:"enabled"`
	MaxAge            int  `json:"max_age"`
	IncludeSubDomains bool `json:"include_subdomains"`
	Preload           bool `json:"preload"`
	NoSniff           bool `json:"nosniff"`
}

// DNSRecord is a single record. Proxied=true is the "orange cloud" — the record
// resolves to Cloudflare, hiding the true origin.
type DNSRecord struct {
	Type     string `json:"type"` // A, AAAA, CNAME, MX, TXT, ...
	Name     string `json:"name"` // FQDN
	Content  string `json:"content"`
	TTL      int    `json:"ttl"` // 1 == "automatic" in Cloudflare
	Proxied  bool   `json:"proxied"`
	Priority *int   `json:"priority,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// ProxiedHTTPHosts returns the set of hostnames served by a proxied,
// HTTP-frontable record (A/AAAA/CNAME). These are exactly the hosts that become
// a Caddy site, so both the classifier and the plan builder use it to decide
// whether a host-scoped rule has a site to attach to — the classify ⟺ generate
// symmetry the 0% false-positive contract requires.
func (s Snapshot) ProxiedHTTPHosts() map[string]bool {
	hosts := map[string]bool{}
	for _, r := range s.DNSRecords {
		if !r.Proxied {
			continue
		}
		switch strings.ToUpper(r.Type) {
		case "A", "AAAA", "CNAME":
			hosts[r.Name] = true
		}
	}
	return hosts
}

// PageRule is a legacy Page Rule (ordered, first-match).
type PageRule struct {
	Target   string         `json:"target"`  // URL pattern with wildcards
	Actions  map[string]any `json:"actions"` // action id -> value
	Priority int            `json:"priority"`
	Status   string         `json:"status"` // "active" | "disabled"
}

// Ruleset is an entry from the Rules engine (custom firewall, rate limiting,
// transform, redirect, origin, cache, config rules).
type Ruleset struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Phase, e.g. http_request_firewall_custom, http_ratelimit,
	// http_request_transform, http_request_dynamic_redirect,
	// http_response_headers_transform, http_request_cache_settings.
	Phase string `json:"phase"`
	Rules []Rule `json:"rules"`
}

// Rule is a single rule inside a Ruleset.
type Rule struct {
	Description  string         `json:"description,omitempty"`
	Expression   string         `json:"expression"` // Cloudflare rules language
	Action       string         `json:"action"`     // block, challenge, skip, rewrite, redirect, set_config, ...
	ActionParams map[string]any `json:"action_parameters,omitempty"`
	Enabled      bool           `json:"enabled"`
	// RateLimit carries the characteristics of http_ratelimit rules.
	RateLimit *RateLimit `json:"ratelimit,omitempty"`
}

// Name is the rule's stable identifier for report findings and decision-lock
// keys: its description, or a truncated expression when unnamed. classify (which
// mints the ASK) and plan (which honors the answer) both use this, so an
// answered ASK always routes back to the right rule.
func (r Rule) Name() string {
	if r.Description != "" {
		return r.Description
	}
	if len(r.Expression) > 48 {
		return r.Expression[:48] + "…"
	}
	return r.Expression
}

// RateLimit describes a rate-limiting rule's shape.
type RateLimit struct {
	Characteristics   []string `json:"characteristics,omitempty"` // e.g. ["ip.src"]
	Period            int      `json:"period"`                    // seconds
	RequestsPerPeriod int      `json:"requests_per_period"`
	MitigationTimeout int      `json:"mitigation_timeout,omitempty"`
}

// ManagedRuleset references a Cloudflare-managed ruleset (Managed, OWASP CRS).
type ManagedRuleset struct {
	ID      string `json:"id"`
	Name    string `json:"name"` // "Cloudflare Managed Ruleset", "Cloudflare OWASP Core Ruleset"
	Enabled bool   `json:"enabled"`
	// Sensitivity/paranoia where applicable (OWASP): "low"|"medium"|"high".
	Sensitivity string `json:"sensitivity,omitempty"`
}

// Certificate describes an edge certificate.
type Certificate struct {
	Type   string   `json:"type"` // "universal" | "advanced" | "custom"
	Hosts  []string `json:"hosts"`
	Issuer string   `json:"issuer,omitempty"`
}

// WorkerRoute binds a Worker script to a route pattern.
type WorkerRoute struct {
	Pattern string `json:"pattern"`
	Script  string `json:"script"`
}

// LoadBalancer captures an LB with its pools (summarized).
type LoadBalancer struct {
	Name           string   `json:"name"`
	DefaultPools   []string `json:"default_pools,omitempty"`
	SteeringPolicy string   `json:"steering_policy,omitempty"`
	Proxied        bool     `json:"proxied,omitempty"`
}

// R2Bucket is an object-storage bucket.
type R2Bucket struct {
	Name     string `json:"name"`
	Location string `json:"location,omitempty"`
}

// AccessApp is a Zero-Trust / Access application (summarized).
type AccessApp struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Policies int    `json:"policies"`
}

// EmailRouting captures whether Cloudflare Email Routing is in use.
type EmailRouting struct {
	Enabled bool `json:"enabled"`
	Rules   int  `json:"rules"`
}

// OnOff is a tri-state (on/off) setting where "absent" (nil pointer) is distinct
// from "off" (false). Cloudflare represents these as the strings "on"/"off".
type OnOff bool

// On reports whether the setting is present and enabled.
func (o *OnOff) On() bool { return o != nil && bool(*o) }

// UnmarshalJSON accepts Cloudflare's "on"/"off" strings as well as raw booleans.
func (o *OnOff) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	switch s {
	case `"on"`, "true":
		*o = true
	case `"off"`, "false", `""`, "null":
		*o = false
	default:
		return fmt.Errorf("cloudflare: invalid on/off value %s", s)
	}
	return nil
}

// MarshalJSON emits Cloudflare's "on"/"off" spelling for round-trip stability.
func (o OnOff) MarshalJSON() ([]byte, error) {
	if o {
		return []byte(`"on"`), nil
	}
	return []byte(`"off"`), nil
}
