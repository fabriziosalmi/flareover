// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package cost estimates the monetary picture of a migration: which Cloudflare
// paid tiers/add-ons the captured configuration implies, versus a flat EU-stack
// cost. It is deliberately honest (it reports a *floor* with ranges and notes,
// never a fake-precise number) because the strongest argument for leaving is
// usually not "you pay X today" but "you're one price/policy change away from
// lock-in, and the sovereign stack is a flat low cost with no traffic/egress
// fees." Estimates are surfaced, assumptions are named.
package cost

import (
	"fmt"
	"sort"
	"strings"

	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
)

// Options carries the pricing assumptions (all overridable, all named in output).
type Options struct {
	// EUStackVPSMonthly is the flat cost of the sovereign edge+origin host
	// (e.g. a Contabo VPS). Defaults to a small VPS.
	EUStackVPSMonthly float64
	// Currency label for display.
	Currency string
}

func (o Options) withDefaults() Options {
	if o.EUStackVPSMonthly == 0 {
		o.EUStackVPSMonthly = 8.49 // Contabo VPS S, approx
	}
	if o.Currency == "" {
		o.Currency = "EUR"
	}
	return o
}

// Driver is one configuration fact that pushes Cloudflare toward a paid tier or
// add-on. MinTier is the lowest Cloudflare plan/add-on that unlocks it.
type Driver struct {
	Feature string  `json:"feature"`
	Detail  string  `json:"detail"`
	MinTier string  `json:"min_tier"` // "free" | "pro" | "business" | "enterprise" | "addon"
	Monthly float64 `json:"monthly"`  // estimated monthly contribution
}

// Report is the cost comparison.
type Report struct {
	Zone                 string   `json:"zone"`
	Currency             string   `json:"currency"`
	Drivers              []Driver `json:"drivers,omitempty"`
	CloudflarePlan       string   `json:"cloudflare_plan"`
	CloudflareMonthlyMin float64  `json:"cloudflare_monthly_min"`
	EUStackMonthly       float64  `json:"eu_stack_monthly"`
	EUStackItems         []string `json:"eu_stack_items"`
	SavingsMonthly       float64  `json:"savings_monthly"`
	Notes                []string `json:"notes"`
}

// Cloudflare plan monthly floors (per zone, approximate, 2026).
const (
	planFreeMonthly     = 0.0
	planProMonthly      = 20.0
	planBusinessMonthly = 200.0
	addonLoadBalancer   = 5.0
	addonWorkersPaid    = 5.0
	addonArgo           = 5.0
)

// Estimate builds the cost report from a snapshot.
func Estimate(s cf.Snapshot, opts Options) Report {
	opts = opts.withDefaults()
	r := Report{Zone: s.Zone.Name, Currency: opts.Currency}

	add := func(feature, detail, tier string, monthly float64) {
		r.Drivers = append(r.Drivers, Driver{Feature: feature, Detail: detail, MinTier: tier, Monthly: monthly})
	}

	// --- detect paid-tier cost drivers -------------------------------------

	// Cloudflare Free allows up to 5 custom firewall rules; beyond that is Pro+.
	if n := countCustomWAF(s); n > 5 {
		add("waf-custom-rules", fmt.Sprintf("%d custom firewall rules (Free allows 5)", n), "pro", planProMonthly)
	}
	// Managed WAF rulesets beyond the free managed ruleset (e.g. OWASP CRS) are Pro+.
	for _, m := range s.ManagedRules {
		if m.Enabled && strings.Contains(strings.ToLower(m.Name), "owasp") {
			add("waf-managed-owasp", "OWASP Core Ruleset (paid WAF)", "pro", planProMonthly)
			break
		}
	}
	// Load balancing is a paid add-on, priced per origin.
	if len(s.LoadBalancers) > 0 {
		add("load-balancing", fmt.Sprintf("%d load balancer(s)", len(s.LoadBalancers)), "addon", addonLoadBalancer*float64(len(s.LoadBalancers)))
	}
	// Workers on routes imply the paid Workers plan for production traffic.
	if len(s.Workers) > 0 {
		add("workers", fmt.Sprintf("%d Worker route(s)", len(s.Workers)), "addon", addonWorkersPaid)
	}
	// Argo smart routing / tiered cache (only if captured; placeholder detector).
	if s.Settings.CacheLevel == "aggressive" && len(s.LoadBalancers) > 0 {
		add("argo", "smart routing / tiered cache likely", "addon", addonArgo)
	}
	// R2 object storage: variable by volume; noted rather than priced.
	if len(s.R2Buckets) > 0 {
		add("r2-storage", fmt.Sprintf("%d R2 bucket(s): volume-priced; migrates to MinIO (no egress fee)", len(s.R2Buckets)), "usage", 0)
	}
	// Access / Zero Trust beyond the free seat tier.
	if len(s.AccessApps) > 0 {
		add("zero-trust", fmt.Sprintf("%d Access app(s): free up to 50 users, then per-seat", len(s.AccessApps)), "usage", 0)
	}

	// --- infer the Cloudflare plan floor -----------------------------------

	r.CloudflarePlan, r.CloudflareMonthlyMin = inferPlan(r.Drivers)

	// --- EU sovereign stack cost -------------------------------------------

	r.EUStackMonthly = opts.EUStackVPSMonthly
	r.EUStackItems = []string{
		fmt.Sprintf("VPS (edge + origin): %.2f %s/mo", opts.EUStackVPSMonthly, opts.Currency),
		"PowerDNS (authoritative DNS): free",
		"Caddy + caddy-waf (proxy + WAF): free",
		"Let's Encrypt / Actalis (certs): free",
	}
	if len(s.R2Buckets) > 0 {
		r.EUStackItems = append(r.EUStackItems, "MinIO (S3-compatible, on the same VPS): free software, no egress fee")
	}

	r.SavingsMonthly = r.CloudflareMonthlyMin - r.EUStackMonthly

	// --- honest notes ------------------------------------------------------

	if r.CloudflareMonthlyMin == 0 {
		r.Notes = append(r.Notes,
			"On paper this zone fits Cloudflare's Free plan today. The case for leaving is sovereignty and resilience, not this month's bill.",
			"The real long-term win is no traffic/egress fees and no exposure to a future price or policy change: a flat, self-owned cost.")
	} else {
		r.Notes = append(r.Notes,
			fmt.Sprintf("Cloudflare floor is a minimum: your usage requires at least the %s plan; real bills often add usage and add-ons on top.", r.CloudflarePlan))
	}
	r.Notes = append(r.Notes, "Estimates are approximate and name their assumptions; verify against your actual Cloudflare invoice.")

	sort.SliceStable(r.Drivers, func(i, j int) bool { return r.Drivers[i].Feature < r.Drivers[j].Feature })
	return r
}

func countCustomWAF(s cf.Snapshot) int {
	n := 0
	for _, rs := range s.Rulesets {
		if rs.Phase == "http_request_firewall_custom" {
			for _, rule := range rs.Rules {
				if rule.Enabled {
					n++
				}
			}
		}
	}
	return n
}

// inferPlan returns the highest tier any driver requires and its monthly floor
// (the base plan floor plus any add-ons stacked on top).
func inferPlan(drivers []Driver) (string, float64) {
	base := "free"
	baseMonthly := planFreeMonthly
	addons := 0.0
	rank := map[string]int{"free": 0, "pro": 1, "business": 2, "enterprise": 3}
	for _, d := range drivers {
		switch d.MinTier {
		case "pro", "business", "enterprise":
			if rank[d.MinTier] > rank[base] {
				base = d.MinTier
				baseMonthly = planMonthly(d.MinTier)
			}
		case "addon":
			addons += d.Monthly
		}
	}
	return base, baseMonthly + addons
}

func planMonthly(tier string) float64 {
	switch tier {
	case "pro":
		return planProMonthly
	case "business":
		return planBusinessMonthly
	default:
		return planFreeMonthly
	}
}

// Text renders the cost report for the terminal.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "flareover cost: %s\n\n", r.Zone)
	if len(r.Drivers) > 0 {
		b.WriteString("Cost drivers detected:\n")
		for _, d := range r.Drivers {
			amt := "usage-priced"
			if d.Monthly > 0 {
				amt = fmt.Sprintf("~%.2f %s/mo", d.Monthly, r.Currency)
			}
			fmt.Fprintf(&b, "  • %-20s %s  [%s, %s]\n", d.Feature, d.Detail, d.MinTier, amt)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Cloudflare floor:  %s plan ≈ %.2f %s/mo (minimum)\n", r.CloudflarePlan, r.CloudflareMonthlyMin, r.Currency)
	fmt.Fprintf(&b, "EU sovereign stack: %.2f %s/mo\n", r.EUStackMonthly, r.Currency)
	for _, it := range r.EUStackItems {
		fmt.Fprintf(&b, "    - %s\n", it)
	}
	if r.SavingsMonthly > 0 {
		fmt.Fprintf(&b, "\n→ Estimated saving: %.2f %s/mo (%.0f %s/yr)\n", r.SavingsMonthly, r.Currency, r.SavingsMonthly*12, r.Currency)
	} else {
		fmt.Fprintf(&b, "\n→ Flat sovereign cost: %.2f %s/mo, no traffic/egress fees, no lock-in.\n", r.EUStackMonthly, r.Currency)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "  note: %s\n", n)
	}
	return b.String()
}
