// SPDX-License-Identifier: AGPL-3.0-only

// Package cloudflare's extractor turns a live zone into a Snapshot by calling
// the Cloudflare REST API v4 read-only. It depends on nothing but an API token
// (scoped Zone:Read, DNS:Read, and — for firewall/rules — Zone WAF:Read), so
// flareover is a standalone tool: no dashboard, no MCP, no write access. Every
// call here is a GET. Failures on optional surfaces (workers, LBs, email) are
// tolerated and noted, never fatal — extraction should degrade, not abort.
package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"

// Client is a read-only Cloudflare API client.
type Client struct {
	Token string
	// AccountID enables account-scoped reads (R2 buckets, account rulesets).
	// Optional; when empty those surfaces are skipped with a warning.
	AccountID string
	HTTP      *http.Client
	// BaseURL overrides the API root (default apiBase). Set by tests to point at
	// a mock; otherwise leave empty.
	BaseURL string
	// Warnings accumulates non-fatal extraction gaps (optional surfaces that
	// could not be read). Surfaced to the user so nothing is silently missing.
	Warnings []string
}

// NewClient builds a client with a sane default HTTP timeout.
func NewClient(token string) *Client {
	return &Client{Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// base is the API root — the mock override, or the real Cloudflare endpoint.
func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return apiBase
}

// envelope is the standard Cloudflare API response wrapper.
type envelope struct {
	Success    bool              `json:"success"`
	Errors     []json.RawMessage `json:"errors"`
	Result     json.RawMessage   `json:"result"`
	ResultInfo *struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base()+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%s: HTTP %d (token missing scope?)", path, resp.StatusCode)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("%s: decoding response: %w", path, err)
	}
	if !env.Success {
		return fmt.Errorf("%s: API error: %s", path, string(body))
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("%s: decoding result: %w", path, err)
		}
	}
	return nil
}

// warn records a non-fatal extraction gap.
func (c *Client) warn(format string, args ...any) {
	c.Warnings = append(c.Warnings, fmt.Sprintf(format, args...))
}

// ZoneRef is a lightweight zone listing entry (for account-scoped tokens).
type ZoneRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Account struct {
		Name string `json:"name"`
	} `json:"account"`
}

// ListZones returns every zone the token can see. An account-scoped read-only
// token ("Read all resources") lists the whole account, which is what flareover
// wants: one credential migrates any or all of a user's zones.
func (c *Client) ListZones(ctx context.Context) ([]ZoneRef, error) {
	var out []ZoneRef
	for page := 1; ; page++ {
		var zs []ZoneRef
		info, err := c.getPaged(ctx, fmt.Sprintf("/zones?per_page=50&page=%d", page), &zs)
		if err != nil {
			return nil, err
		}
		out = append(out, zs...)
		if info == nil || info.TotalPages == 0 || page >= info.TotalPages {
			break
		}
	}
	return out, nil
}

// Extract reads a whole zone (looked up by apex name or zone id) into a Snapshot.
func (c *Client) Extract(ctx context.Context, zoneRef string) (Snapshot, error) {
	var s Snapshot
	s.SchemaVersion = 1

	zone, err := c.lookupZone(ctx, zoneRef)
	if err != nil {
		return s, err
	}
	s.Zone = zone
	id := zone.ID

	// Settings drive much of classification (SSL mode, HSTS, DNSSEC), but a token
	// without Zone-Settings:Read should still yield a usable DNS+rules snapshot,
	// so this degrades to a warning rather than aborting.
	if err := c.extractSettings(ctx, id, &s.Settings); err != nil {
		c.warn("settings (add Zone Settings:Read for SSL/HSTS/DNSSEC fidelity): %v", err)
	}
	if recs, err := c.extractDNS(ctx, id); err != nil {
		return s, fmt.Errorf("dns_records: %w", err)
	} else {
		s.DNSRecords = recs
	}
	if pr, err := c.extractPageRules(ctx, id); err != nil {
		c.warn("page rules: %v", err)
	} else {
		s.PageRules = pr
	}
	if rs, managed, err := c.extractRulesets(ctx, id); err != nil {
		c.warn("rulesets: %v", err)
	} else {
		s.Rulesets = rs
		s.ManagedRules = managed
	}
	if certs, err := c.extractCertificates(ctx, id); err != nil {
		c.warn("certificates: %v", err)
	} else {
		s.Certificates = certs
	}
	if w, err := c.extractWorkers(ctx, id); err != nil {
		c.warn("workers: %v", err)
	} else {
		s.Workers = w
	}
	if rules, err := c.extractIPAccessRules(ctx, id); err != nil {
		c.warn("ip access rules: %v", err)
	} else {
		s.IPAccessRules = rules
	}
	if ua, err := c.extractUARules(ctx, id); err != nil {
		c.warn("ua blocking rules: %v", err)
	} else {
		s.UARules = ua
	}
	if sn, err := c.extractSnippets(ctx, id); err != nil {
		c.warn("snippets: %v", err)
	} else {
		s.Snippets = sn
	}
	if er, err := c.extractEmailRouting(ctx, id); err != nil {
		c.warn("email routing: %v", err)
	} else {
		s.EmailRouting = er
	}
	if c.AccountID == "" {
		c.warn("R2 buckets + Access apps: skipped (set CLOUDFLARE_ACCOUNT_ID)")
	} else {
		if buckets, err := c.extractR2(ctx); err != nil {
			c.warn("R2 buckets: %v", err)
		} else {
			s.R2Buckets = buckets
		}
		if apps, err := c.extractAccess(ctx, zone.Name); err != nil {
			c.warn("access apps: %v", err)
		} else {
			s.AccessApps = apps
		}
	}
	return s, nil
}

// extractAccess lists Cloudflare Access (Zero Trust) apps whose domain belongs
// to the zone. Account-scoped; requires Access: Apps and Policies:Read.
func (c *Client) extractAccess(ctx context.Context, zoneName string) ([]AccessApp, error) {
	var apps []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Domain string `json:"domain"`
	}
	if err := c.get(ctx, "/accounts/"+c.AccountID+"/access/apps", &apps); err != nil {
		return nil, err
	}
	var out []AccessApp
	for _, a := range apps {
		if a.Domain != zoneName && !strings.HasSuffix(a.Domain, "."+zoneName) {
			continue
		}
		policies := 0
		var pols []json.RawMessage
		if err := c.get(ctx, "/accounts/"+c.AccountID+"/access/apps/"+a.ID+"/policies", &pols); err == nil {
			policies = len(pols)
		}
		out = append(out, AccessApp{Name: a.Name, Domain: a.Domain, Policies: policies})
	}
	return out, nil
}

// extractR2 lists R2 buckets (account-scoped). Requires CLOUDFLARE_ACCOUNT_ID
// and the Workers R2 Storage:Read permission on the token.
func (c *Client) extractR2(ctx context.Context) ([]R2Bucket, error) {
	var res struct {
		Buckets []struct {
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"buckets"`
	}
	if err := c.get(ctx, "/accounts/"+c.AccountID+"/r2/buckets", &res); err != nil {
		return nil, err
	}
	out := make([]R2Bucket, 0, len(res.Buckets))
	for _, b := range res.Buckets {
		out = append(out, R2Bucket{Name: b.Name, Location: b.Location})
	}
	return out, nil
}

// --- zone --------------------------------------------------------------------

func (c *Client) lookupZone(ctx context.Context, ref string) (Zone, error) {
	// A 32-hex string is treated as a zone id; anything else as a name.
	if isZoneID(ref) {
		var z struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			Status      string   `json:"status"`
			Paused      bool     `json:"paused"`
			NameServers []string `json:"name_servers"`
		}
		if err := c.get(ctx, "/zones/"+ref, &z); err != nil {
			return Zone{}, err
		}
		return Zone(z), nil
	}
	var zones []struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Status      string   `json:"status"`
		Paused      bool     `json:"paused"`
		NameServers []string `json:"name_servers"`
	}
	if err := c.get(ctx, "/zones?name="+url.QueryEscape(ref), &zones); err != nil {
		return Zone{}, err
	}
	if len(zones) == 0 {
		return Zone{}, fmt.Errorf("no zone found named %q (token may lack access)", ref)
	}
	z := zones[0]
	return Zone{ID: z.ID, Name: z.Name, Status: z.Status, Paused: z.Paused, NameServers: z.NameServers}, nil
}

func isZoneID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// --- settings ----------------------------------------------------------------

func (c *Client) extractSettings(ctx context.Context, id string, out *ZoneSettings) error {
	var items []struct {
		ID    string          `json:"id"`
		Value json.RawMessage `json:"value"`
	}
	if err := c.get(ctx, "/zones/"+id+"/settings", &items); err != nil {
		return err
	}
	get := map[string]json.RawMessage{}
	for _, it := range items {
		get[it.ID] = it.Value
	}
	str := func(k string) string {
		var v string
		if raw := get[k]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &v); err != nil {
				c.warn("setting %q: unreadable value (%v)", k, err)
			}
		}
		return v
	}
	onoff := func(k string) *OnOff {
		raw, ok := get[k]
		if !ok {
			return nil
		}
		var v OnOff
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil
		}
		return &v
	}

	out.SSL = str("ssl")
	out.AlwaysUseHTTPS = onoff("always_use_https")
	out.AutomaticHTTPSRewrites = onoff("automatic_https_rewrites")
	out.MinTLSVersion = str("min_tls_version")
	out.TLS13 = onoff("tls_1_3")
	out.HTTP2 = onoff("http2")
	out.HTTP3 = onoff("http3")
	out.OpportunisticEncryption = onoff("opportunistic_encryption")
	out.BrotliCompression = onoff("brotli")
	out.CacheLevel = str("cache_level")
	out.WebSockets = onoff("websockets")
	out.IPGeolocation = onoff("ip_geolocation")
	out.EmailObfuscation = onoff("email_obfuscation")
	out.ServerSideExclude = onoff("server_side_exclude")
	out.HotlinkProtection = onoff("hotlink_protection")

	// HSTS lives under the composite "security_header" setting.
	if raw, ok := get["security_header"]; ok {
		var sh struct {
			STS struct {
				Enabled           bool `json:"enabled"`
				MaxAge            int  `json:"max_age"`
				IncludeSubdomains bool `json:"include_subdomains"`
				Preload           bool `json:"preload"`
				Nosniff           bool `json:"nosniff"`
			} `json:"strict_transport_security"`
		}
		if json.Unmarshal(raw, &sh) == nil && sh.STS.Enabled {
			out.HSTS = &HSTS{
				Enabled: true, MaxAge: sh.STS.MaxAge, IncludeSubDomains: sh.STS.IncludeSubdomains,
				Preload: sh.STS.Preload, NoSniff: sh.STS.Nosniff,
			}
		}
	}

	// DNSSEC is a separate endpoint.
	var ds struct {
		Status string `json:"status"`
	}
	if err := c.get(ctx, "/zones/"+id+"/dnssec", &ds); err == nil {
		out.DNSSEC = ds.Status
	} else {
		c.warn("dnssec: %v", err)
	}
	return nil
}

// --- DNS ---------------------------------------------------------------------

func (c *Client) extractDNS(ctx context.Context, id string) ([]DNSRecord, error) {
	var out []DNSRecord
	for page := 1; ; page++ {
		var recs []struct {
			Type     string `json:"type"`
			Name     string `json:"name"`
			Content  string `json:"content"`
			TTL      int    `json:"ttl"`
			Proxied  bool   `json:"proxied"`
			Priority *int   `json:"priority"`
			Comment  string `json:"comment"`
		}
		info, err := c.getPaged(ctx, fmt.Sprintf("/zones/%s/dns_records?per_page=100&page=%d", id, page), &recs)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			out = append(out, DNSRecord(r))
		}
		if info == nil || page >= info.TotalPages || info.TotalPages == 0 {
			break
		}
	}
	return out, nil
}

// getPaged is like get but also returns pagination info.
func (c *Client) getPaged(ctx context.Context, path string, out any) (*struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if !env.Success {
		return nil, fmt.Errorf("%s: %s", path, string(body))
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return env.ResultInfo, nil
}

// --- page rules --------------------------------------------------------------

func (c *Client) extractPageRules(ctx context.Context, id string) ([]PageRule, error) {
	var prs []struct {
		Targets []struct {
			Target     string `json:"target"`
			Constraint struct {
				Value string `json:"value"`
			} `json:"constraint"`
		} `json:"targets"`
		Actions []struct {
			ID    string          `json:"id"`
			Value json.RawMessage `json:"value"`
		} `json:"actions"`
		Priority int    `json:"priority"`
		Status   string `json:"status"`
	}
	if err := c.get(ctx, "/zones/"+id+"/pagerules", &prs); err != nil {
		return nil, err
	}
	out := make([]PageRule, 0, len(prs))
	for _, pr := range prs {
		target := ""
		if len(pr.Targets) > 0 {
			target = pr.Targets[0].Constraint.Value
		}
		actions := map[string]any{}
		for _, a := range pr.Actions {
			var v any
			if err := json.Unmarshal(a.Value, &v); err != nil {
				c.warn("page rule %q action %q: unreadable (%v)", target, a.ID, err)
			}
			actions[a.ID] = v
		}
		out = append(out, PageRule{Target: target, Actions: actions, Priority: pr.Priority, Status: pr.Status})
	}
	return out, nil
}

// --- rulesets ----------------------------------------------------------------

// phasesOfInterest are the zone-owned rule phases flareover classifies.
var phasesOfInterest = map[string]bool{
	"http_request_firewall_custom":    true,
	"http_ratelimit":                  true,
	"http_request_transform":          true,
	"http_request_late_transform":     true, // request header modification
	"http_response_headers_transform": true,
	"http_request_dynamic_redirect":   true,
	"http_request_cache_settings":     true,
	"http_request_origin":             true, // origin rules
	"http_config_settings":            true, // config rules
}

func (c *Client) extractRulesets(ctx context.Context, id string) ([]Ruleset, []ManagedRuleset, error) {
	var list []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Phase string `json:"phase"`
		Kind  string `json:"kind"`
	}
	if err := c.get(ctx, "/zones/"+id+"/rulesets", &list); err != nil {
		return nil, nil, err
	}

	var rulesets []Ruleset
	var managed []ManagedRuleset
	for _, meta := range list {
		// Kind "managed" entries are Cloudflare's rule *templates* (the catalog),
		// not what this zone deploys. Only the zone's own entrypoint rulesets
		// (kind zone/root) describe the actual configuration.
		if meta.Kind == "managed" {
			continue
		}
		if meta.Phase == "http_request_firewall_managed" {
			if m, err := c.extractManaged(ctx, id, meta.ID); err == nil {
				managed = append(managed, m...)
			} else {
				c.warn("managed ruleset %s: %v", meta.ID, err)
			}
			continue
		}
		if !phasesOfInterest[meta.Phase] {
			continue
		}
		rs, err := c.getRulesetRules(ctx, id, meta.ID, meta.Name, meta.Phase)
		if err != nil {
			c.warn("ruleset %s (%s): %v", meta.ID, meta.Phase, err)
			continue
		}
		if len(rs.Rules) > 0 {
			rulesets = append(rulesets, rs)
		}
	}
	return rulesets, managed, nil
}

func (c *Client) getRulesetRules(ctx context.Context, zoneID, rulesetID, name, phase string) (Ruleset, error) {
	var detail struct {
		Rules []struct {
			Description      string          `json:"description"`
			Expression       string          `json:"expression"`
			Action           string          `json:"action"`
			ActionParameters json.RawMessage `json:"action_parameters"`
			Enabled          bool            `json:"enabled"`
			RateLimit        *struct {
				Characteristics   []string `json:"characteristics"`
				Period            int      `json:"period"`
				RequestsPerPeriod int      `json:"requests_per_period"`
				MitigationTimeout int      `json:"mitigation_timeout"`
			} `json:"ratelimit"`
		} `json:"rules"`
	}
	if err := c.get(ctx, fmt.Sprintf("/zones/%s/rulesets/%s", zoneID, rulesetID), &detail); err != nil {
		return Ruleset{}, err
	}
	rs := Ruleset{ID: rulesetID, Name: name, Phase: phase}
	for _, r := range detail.Rules {
		rule := Rule{
			Description: r.Description, Expression: r.Expression, Action: r.Action, Enabled: r.Enabled,
		}
		if len(r.ActionParameters) > 0 {
			if err := json.Unmarshal(r.ActionParameters, &rule.ActionParams); err != nil {
				c.warn("ruleset %q rule %q: unreadable action params (%v)", name, r.Description, err)
			}
		}
		if r.RateLimit != nil {
			rule.RateLimit = &RateLimit{
				Characteristics: r.RateLimit.Characteristics, Period: r.RateLimit.Period,
				RequestsPerPeriod: r.RateLimit.RequestsPerPeriod, MitigationTimeout: r.RateLimit.MitigationTimeout,
			}
		}
		rs.Rules = append(rs.Rules, rule)
	}
	return rs, nil
}

// extractManaged reads the firewall_managed entrypoint and records which managed
// rulesets are deployed (execute actions), mapped to friendly names.
func (c *Client) extractManaged(ctx context.Context, zoneID, rulesetID string) ([]ManagedRuleset, error) {
	var detail struct {
		Rules []struct {
			Action           string `json:"action"`
			Enabled          bool   `json:"enabled"`
			ActionParameters struct {
				ID string `json:"id"`
			} `json:"action_parameters"`
		} `json:"rules"`
	}
	if err := c.get(ctx, fmt.Sprintf("/zones/%s/rulesets/%s", zoneID, rulesetID), &detail); err != nil {
		return nil, err
	}
	var out []ManagedRuleset
	for _, r := range detail.Rules {
		// A managed ruleset is deployed via an "execute" action referencing its
		// id. Anything else in this entrypoint is not a managed-ruleset deployment.
		if r.Action != "execute" || r.ActionParameters.ID == "" {
			continue
		}
		out = append(out, ManagedRuleset{
			ID: r.ActionParameters.ID, Name: managedName(r.ActionParameters.ID), Enabled: r.Enabled,
		})
	}
	return out, nil
}

// managedName maps well-known Cloudflare managed ruleset ids to readable names.
func managedName(id string) string {
	switch id {
	case "efb7b8c949ac4650a09736fc376e9aee":
		return "Cloudflare Managed Ruleset"
	case "4814384a9e5d4991b9815dcfc25d2f1f":
		return "Cloudflare OWASP Core Ruleset"
	default:
		return "Managed Ruleset " + id
	}
}

// --- certificates / workers / email -----------------------------------------

func (c *Client) extractCertificates(ctx context.Context, id string) ([]Certificate, error) {
	var packs []struct {
		Type         string   `json:"type"`
		Hosts        []string `json:"hosts"`
		Certificates []struct {
			Issuer string `json:"issuer"`
		} `json:"certificates"`
	}
	if err := c.get(ctx, "/zones/"+id+"/ssl/certificate_packs?status=all", &packs); err != nil {
		return nil, err
	}
	out := make([]Certificate, 0, len(packs))
	for _, p := range packs {
		issuer := ""
		if len(p.Certificates) > 0 {
			issuer = p.Certificates[0].Issuer
		}
		out = append(out, Certificate{Type: p.Type, Hosts: p.Hosts, Issuer: issuer})
	}
	return out, nil
}

func (c *Client) extractWorkers(ctx context.Context, id string) ([]WorkerRoute, error) {
	var routes []struct {
		Pattern string `json:"pattern"`
		Script  string `json:"script"`
	}
	if err := c.get(ctx, "/zones/"+id+"/workers/routes", &routes); err != nil {
		return nil, err
	}
	out := make([]WorkerRoute, 0, len(routes))
	for _, r := range routes {
		out = append(out, WorkerRoute(r))
	}
	return out, nil
}

// extractIPAccessRules reads the legacy zone firewall access rules (IP/CIDR/
// country/ASN allow/block/challenge). Requires Firewall Services:Read.
func (c *Client) extractIPAccessRules(ctx context.Context, id string) ([]IPAccessRule, error) {
	var out []IPAccessRule
	for page := 1; ; page++ {
		var rules []struct {
			Mode          string `json:"mode"`
			Notes         string `json:"notes"`
			Configuration struct {
				Target string `json:"target"`
				Value  string `json:"value"`
			} `json:"configuration"`
		}
		info, err := c.getPaged(ctx, fmt.Sprintf("/zones/%s/firewall/access_rules/rules?per_page=100&page=%d", id, page), &rules)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			out = append(out, IPAccessRule{
				Mode: r.Mode, Target: r.Configuration.Target, Value: r.Configuration.Value, Notes: r.Notes,
			})
		}
		if info == nil || info.TotalPages == 0 || page >= info.TotalPages {
			break
		}
	}
	return out, nil
}

// extractUARules reads User-Agent Blocking rules. Requires Firewall Services:Read.
func (c *Client) extractUARules(ctx context.Context, id string) ([]UARule, error) {
	var out []UARule
	for page := 1; ; page++ {
		var rules []struct {
			Mode          string `json:"mode"`
			Description   string `json:"description"`
			Configuration struct {
				Target string `json:"target"`
				Value  string `json:"value"`
			} `json:"configuration"`
		}
		info, err := c.getPaged(ctx, fmt.Sprintf("/zones/%s/firewall/ua_rules?per_page=100&page=%d", id, page), &rules)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			out = append(out, UARule{Mode: r.Mode, UserAgent: r.Configuration.Value, Description: r.Description})
		}
		if info == nil || info.TotalPages == 0 || page >= info.TotalPages {
			break
		}
	}
	return out, nil
}

// extractSnippets lists Cloudflare Snippets (lightweight edge code).
func (c *Client) extractSnippets(ctx context.Context, id string) ([]Snippet, error) {
	var snips []struct {
		SnippetName string `json:"snippet_name"`
	}
	if err := c.get(ctx, "/zones/"+id+"/snippets", &snips); err != nil {
		return nil, err
	}
	out := make([]Snippet, 0, len(snips))
	for _, s := range snips {
		out = append(out, Snippet{Name: s.SnippetName})
	}
	return out, nil
}

func (c *Client) extractEmailRouting(ctx context.Context, id string) (*EmailRouting, error) {
	var er struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.get(ctx, "/zones/"+id+"/email/routing", &er); err != nil {
		return nil, err
	}
	if !er.Enabled {
		return nil, nil
	}
	var rules []json.RawMessage
	if _, err := c.getPaged(ctx, "/zones/"+id+"/email/routing/rules?per_page=50", &rules); err != nil {
		c.warn("email routing rules: %v", err)
	}
	return &EmailRouting{Enabled: true, Rules: len(rules)}, nil
}
