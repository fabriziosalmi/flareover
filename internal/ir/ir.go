// SPDX-License-Identifier: AGPL-3.0-only

// Package ir defines the provider-agnostic Intermediate Representation of a
// migration. Extraction produces a cloudflare.Snapshot; classification turns
// the AUTO (and answered-ASK) parts of that snapshot into this IR, which
// describes *intent* — "this host proxies to this origin with these headers,
// this path 301s there, this rule blocks these requests" — independent of any
// target. Target adapters (Caddy, PowerDNS, CertMate, ...) consume the IR and
// emit concrete configuration. Adding a new backend is adding a new generator,
// never touching extraction or classification.
package ir

// Plan is the complete target-independent intent for one migration.
type Plan struct {
	Zone  string    `json:"zone"` // apex domain
	DNS   DNSZone   `json:"dns"`
	Sites []Site    `json:"sites,omitempty"`
	WAF   WAFPolicy `json:"waf"`
	// Egress is populated only when the optional egress-shield module is enabled.
	Egress *EgressPolicy `json:"egress,omitempty"`
}

// DNSZone is the authoritative zone to stand up on the target DNS (PowerDNS).
type DNSZone struct {
	Name    string      `json:"name"`
	Records []DNSRecord `json:"records,omitempty"`
	DNSSEC  bool        `json:"dnssec"`
	// SOA/NS are filled by the DNS adapter from target infrastructure.
}

// DNSRecord is a de-proxied record: proxied Cloudflare records are rewritten to
// point at the new edge (Caddy) IP, with the true origin recorded on the Site.
type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority,omitempty"`
}

// Site is one virtual host served by the edge proxy.
type Site struct {
	Host      string       `json:"host"`
	Origin    Origin       `json:"origin"`
	TLS       TLS          `json:"tls"`
	Headers   []HeaderOp   `json:"headers,omitempty"`
	Rewrites  []Rewrite    `json:"rewrites,omitempty"`
	Redirects []Redirect   `json:"redirects,omitempty"`
	Cache     *CachePolicy `json:"cache,omitempty"`
	// ScopedProxies are path-scoped origin overrides (from path-scoped Origin
	// Rules): each routes its matched path to a different origin, emitted as a
	// matcher-guarded reverse_proxy ahead of the site default.
	ScopedProxies []ScopedProxy `json:"scoped_proxies,omitempty"`
	// HSTS, HTTP/3 etc. inherited from global unless overridden here.
}

// ScopedProxy is a matcher-guarded reverse_proxy: requests matching Match go to
// Origin instead of the site default.
type ScopedProxy struct {
	Match  string `json:"match"` // a Caddy matcher directive, e.g. "path /api*"
	Origin Origin `json:"origin"`
}

// Origin is where the edge forwards to (the true, de-proxied backend).
type Origin struct {
	Upstreams []string `json:"upstreams"` // host:port list
	Scheme    string   `json:"scheme"`    // http | https
	VerifyTLS bool     `json:"verify_tls"`
	// HostHeader and SNI are Origin-Rule overrides (empty when unset): the Host
	// header sent upstream (→ Caddy header_up Host) and the TLS SNI
	// (→ tls_server_name).
	HostHeader string `json:"host_header,omitempty"`
	SNI        string `json:"sni,omitempty"`
}

// TLS is the certificate intent for a Site.
type TLS struct {
	// Provider: "certmate" (issued via DNS-01) or "caddy-acme" (native HTTP-01).
	Provider   string `json:"provider"`
	CA         string `json:"ca,omitempty"` // "letsencrypt" | "actalis" | ...
	MinVersion string `json:"min_version,omitempty"`
	HSTS       *HSTS  `json:"hsts,omitempty"`
	Wildcard   bool   `json:"wildcard"`
}

// HSTS mirrors the Strict-Transport-Security intent.
type HSTS struct {
	MaxAge            int  `json:"max_age"`
	IncludeSubDomains bool `json:"include_subdomains"`
	Preload           bool `json:"preload"`
}

// HeaderOp adds, sets, or removes a request or response header.
type HeaderOp struct {
	Phase string `json:"phase"` // "request" | "response"
	Op    string `json:"op"`    // "add" | "set" | "remove"
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	// Match is a Caddy request-matcher directive (e.g. `path /api*`) that scopes
	// this op; empty means it applies to the whole site.
	Match string `json:"match,omitempty"`
	// Host scopes this op to a single host's site (from `http.host eq "…"`). It is
	// a plan-internal routing hint: buildSites keeps the op only for that host and
	// clears Host, so the op is emitted unmatched inside that host's block (the
	// whole block is already that host). Never set on a serialized site.
	Host string `json:"host,omitempty"`
}

// Rewrite is an internal URL rewrite (path/query), not a client-visible redirect.
type Rewrite struct {
	// Match is a Caddy request-matcher directive (e.g. `path /legacy*`) that scopes
	// the rewrite; empty means it applies to the whole site.
	Match string `json:"match"`
	// To is the Caddy rewrite target, e.g. `/modern` or `/modern?a=b`.
	To string `json:"to"`
	// Host scopes the rewrite to a single host's site (plan-internal, like
	// HeaderOp.Host): buildSites keeps it only for that host and clears Host, so it
	// emits unmatched in that block. Never set on a serialized site.
	Host string `json:"host,omitempty"`
}

// Redirect is a client-visible redirect.
type Redirect struct {
	Match  string `json:"match"`
	To     string `json:"to"`
	Status int    `json:"status"` // 301, 302, 307, 308
}

// CachePolicy is a coarse cache intent (full parity requires a cache handler).
type CachePolicy struct {
	Enabled bool `json:"enabled"`
	TTL     int  `json:"ttl,omitempty"`
}

// WAFPolicy is the ingress security intent for the whole zone.
type WAFPolicy struct {
	CustomRules    []WAFRule   `json:"custom_rules,omitempty"`
	ManagedOWASP   bool        `json:"managed_owasp"`
	RateLimits     []RateLimit `json:"rate_limits,omitempty"`
	BlockASNs      []int       `json:"block_asns,omitempty"`
	BlockCountries []string    `json:"block_countries,omitempty"`
	// BlockIPs / AllowIPs come from zone IP Access Rules (deny/allow lists).
	BlockIPs   []string    `json:"block_ips,omitempty"`
	AllowIPs   []string    `json:"allow_ips,omitempty"`
	Blocklists []Blocklist `json:"blocklists,omitempty"`
}

// WAFRule is one translated custom firewall rule.
type WAFRule struct {
	Description string   `json:"description,omitempty"`
	Pattern     string   `json:"pattern"`
	Targets     []string `json:"targets"`
	Action      string   `json:"action"` // "block" | "log"
	Score       int      `json:"score,omitempty"`
	// Sample is the raw literal that triggers the rule (the value from the
	// Cloudflare expression). It lets the parity prober build a request that
	// exercises the rule on both edges. Empty when not derivable.
	Sample string `json:"sample,omitempty"`
}

// RateLimit is a translated rate-limit rule.
type RateLimit struct {
	Requests int    `json:"requests"`
	Window   int    `json:"window"` // seconds
	Path     string `json:"path,omitempty"`
}

// Blocklist wires an external feed (e.g. the blacklists repo) into the WAF.
type Blocklist struct {
	Kind string `json:"kind"` // "domain" | "ip"
	URL  string `json:"url"`
}

// EgressPolicy is the outbound-shield intent (secure-proxy-manager).
type EgressPolicy struct {
	DefaultDeny bool        `json:"default_deny"`
	Allow       []string    `json:"allow,omitempty"` // domains/CIDRs the app legitimately calls
	SSLBump     bool        `json:"ssl_bump"`
	Blocklists  []Blocklist `json:"blocklists,omitempty"`
}
