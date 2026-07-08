// SPDX-License-Identifier: AGPL-3.0-only

// Package target defines the adapter contracts that turn a provider-agnostic
// ir.Plan into concrete configuration for a specific EU-stack tool. The IR is
// the seam: extraction and classification never know which target is in play,
// so adding a backend (nginx, traefik, ...) is adding a Generator, never
// touching the phases before it.
//
// Targets are grouped into a StackProfile because caching and WAF are bound to
// the reverse proxy: caddy-waf only runs inside Caddy, nginx needs Coraza, and
// so on. A profile bundles the proxy + WAF + DNS + cert generators that belong
// together. Today only the "caddy" profile is implemented; the interface is
// deliberately ready for more.
package target

import "github.com/fabriziosalmi/flareover/internal/ir"

// Artifact is a single generated file destined for the target host.
type Artifact struct {
	// Path is the intended on-disk location relative to the deploy root,
	// e.g. "caddy/Caddyfile", "caddy-waf/rules.json", "powerdns/example.com.zone".
	Path string
	// Content is the rendered file body.
	Content []byte
	// Mode is the intended file permission (0 → 0o644).
	Mode uint32
	// Note is an optional human-facing caveat carried alongside the artifact
	// (e.g. "cache TTL is approximate"). Never silent.
	Note string
}

// Generator renders one slice of the plan into artifacts. All concrete targets
// (proxy, WAF, DNS, cert) implement it.
type Generator interface {
	// Name identifies the target tool, e.g. "caddy", "caddy-waf", "powerdns".
	Name() string
	// Generate is a pure function of the plan: same plan → same artifacts.
	Generate(ir.Plan) ([]Artifact, error)
}

// StackProfile is a coherent bundle of generators that deploy together. The
// proxy, its WAF, and its cache must come from the same family.
type StackProfile struct {
	// ID is the profile selector, e.g. "caddy".
	ID string
	// ReverseProxy renders the proxy + caching + TLS wiring.
	ReverseProxy Generator
	// WAF renders the ingress security policy for this proxy family.
	WAF Generator
	// DNS renders the authoritative zone (profile-independent in practice, but
	// kept here so a profile is a complete deployable set).
	DNS Generator
}

// Generate runs every generator in the profile and concatenates their
// artifacts. A nil sub-generator is skipped, so partial profiles are valid.
func (p StackProfile) Generate(plan ir.Plan) ([]Artifact, error) {
	var out []Artifact
	for _, g := range []Generator{p.ReverseProxy, p.WAF, p.DNS} {
		if g == nil {
			continue
		}
		arts, err := g.Generate(plan)
		if err != nil {
			return nil, err
		}
		out = append(out, arts...)
	}
	return out, nil
}
