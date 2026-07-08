// SPDX-License-Identifier: AGPL-3.0-only

// Package caddywaf renders the caddy-waf rule corpus (rules.json) from the
// plan's WAF policy. The Caddyfile (see the caddy package) references this file
// via `rule_file` and carries the directive-level policy (rate limits, ASN/
// country blocks, blocklists); this package owns only the JSON rule set so the
// two concerns stay separate and diffable.
package caddywaf

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target"
)

// rule is one caddy-waf JSON rule. Field names match caddy-waf's schema; note
// that caddy-waf spells the action field "mode".
type rule struct {
	ID          string   `json:"id"`
	Phase       int      `json:"phase"`
	Pattern     string   `json:"pattern"`
	Targets     []string `json:"targets"`
	Severity    string   `json:"severity"`
	Mode        string   `json:"mode"`
	Score       int      `json:"score"`
	Description string   `json:"description,omitempty"`
}

// Generator renders caddy-waf/rules.json.
type Generator struct{}

// Name implements target.Generator.
func (Generator) Name() string { return "caddy-waf" }

// Generate implements target.Generator.
func (Generator) Generate(p ir.Plan) ([]target.Artifact, error) {
	rules := make([]rule, 0, len(p.WAF.CustomRules))
	for i, cr := range p.WAF.CustomRules {
		mode := "block"
		if cr.Action == "log" {
			mode = "log"
		}
		rules = append(rules, rule{
			ID:          ruleID(i, cr),
			Phase:       1, // request headers
			Pattern:     cr.Pattern,
			Targets:     cr.Targets,
			Severity:    "HIGH",
			Mode:        mode,
			Score:       orDefault(cr.Score, 10),
			Description: cr.Description,
		})
	}

	// Stable, human-diffable JSON.
	body, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')

	note := ""
	if p.WAF.ManagedOWASP {
		note = "OWASP CRS not included here — generate it into the same rules.json with caddy-waf's" +
			" get_owasp_rules.py, then merge. CRS is comparable to, not identical to, Cloudflare's managed set."
	}
	arts := []target.Artifact{{
		Path: "caddy-waf/rules.json", Content: body, Mode: 0o644, Note: note,
	}}
	// IP deny/allow lists from zone IP Access Rules (one entry per line, the
	// format caddy-waf's ip_blacklist_file / ip_whitelist_file expect).
	if len(p.WAF.BlockIPs) > 0 {
		arts = append(arts, target.Artifact{
			Path: "caddy-waf/ip_blacklist.txt", Content: ipList(p.WAF.BlockIPs), Mode: 0o644,
		})
	}
	if len(p.WAF.AllowIPs) > 0 {
		arts = append(arts, target.Artifact{
			Path: "caddy-waf/ip_whitelist.txt", Content: ipList(p.WAF.AllowIPs), Mode: 0o644,
		})
	}
	// External threat feeds → an update script (run on a timer) that refreshes the
	// list files caddy-waf reads. Domain feed replaces the domain list; IP feed
	// appends to the local deny list so both sources coexist.
	if len(p.WAF.Blocklists) > 0 {
		var s strings.Builder
		s.WriteString("#!/usr/bin/env bash\n# flareover-generated blocklist refresh (run on a systemd timer / cron).\nset -euo pipefail\n\n")
		for _, bl := range p.WAF.Blocklists {
			switch bl.Kind {
			case "domain":
				fmt.Fprintf(&s, "curl -fsSL %q -o /etc/caddy/waf/domains.txt\n", bl.URL)
			case "ip":
				fmt.Fprintf(&s, "curl -fsSL %q >> /etc/caddy/waf/ip_blacklist.txt\n", bl.URL)
			}
		}
		s.WriteString("\n# reload so caddy-waf picks up the refreshed lists\ncaddy reload --config /etc/caddy/Caddyfile 2>/dev/null || systemctl reload caddy\n")
		arts = append(arts, target.Artifact{
			Path: "caddy-waf/update-blocklists.sh", Content: []byte(s.String()), Mode: 0o755,
			Note: "run on a timer to keep the threat feeds fresh",
		})
	}
	return arts, nil
}

// ipList renders one IP/CIDR per line.
func ipList(ips []string) []byte {
	var b []byte
	for _, ip := range ips {
		b = append(b, ip...)
		b = append(b, '\n')
	}
	return b
}

func ruleID(i int, r ir.WAFRule) string {
	if r.Description != "" {
		return slug(r.Description)
	}
	return "rule-" + itoa(i+1)
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func slug(s string) string {
	out := make([]rune, 0, len(s))
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
			prevDash = false
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
			prevDash = false
		default:
			if !prevDash && len(out) > 0 {
				out = append(out, '-')
				prevDash = true
			}
		}
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return "rule"
	}
	return string(out)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
