// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package ir

import (
	"fmt"
	"net"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/textguard"
)

// Validate checks that a plan is safe to render before any generator touches it.
//
// This is the second of the two checks, and the one that catches what the first
// cannot. cloudflare.Snapshot.Validate covers everything arriving from the
// snapshot; a plan also carries values from decisions.lock — an origin's
// host:port, an answered origin scheme — which are read from a hand-editable
// JSON map with no schema. Both reach the Caddyfile through a bare %s.
//
// plan.Build calls this before returning, so every generator downstream
// consumes a validated plan and no generator has to remember to check.
func (p Plan) Validate() error {
	var problems []string
	note := func(format string, args ...any) {
		if len(problems) < 20 {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}

	for _, bad := range textguard.FindControlStrings(p, "plan") {
		note("%s", bad)
	}

	if p.Zone != "" && !textguard.IsHostname(p.Zone) {
		note("plan.Zone %q is not a valid hostname", p.Zone)
	}
	for i, s := range p.Sites {
		if !textguard.IsHostname(s.Host) {
			note("plan.Sites[%d].Host %q is not a valid hostname", i, s.Host)
		}
		checkOrigin(fmt.Sprintf("plan.Sites[%d].Origin", i), s.Origin, note)
		for j, sp := range s.ScopedProxies {
			checkOrigin(fmt.Sprintf("plan.Sites[%d].ScopedProxies[%d].Origin", i, j), sp.Origin, note)
		}
	}
	for i, r := range p.DNS.Records {
		if r.Name != "" && !textguard.IsHostname(r.Name) {
			note("plan.DNS.Records[%d].Name %q is not a valid hostname", i, r.Name)
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("generated plan failed validation (this is a bug, or a hand-edited decisions file):\n  - %s",
		strings.Join(problems, "\n  - "))
}

// checkOrigin validates the fields of an Origin that are interpolated into the
// Caddyfile's reverse_proxy block.
func checkOrigin(path string, o Origin, note func(string, ...any)) {
	// Scheme reaches the upstream URL as "%s://%s" and also decides whether
	// tls_insecure_skip_verify is emitted, via a case-sensitive comparison to
	// "https". Anything outside the two known values silently changes both.
	if o.Scheme != "" && o.Scheme != "http" && o.Scheme != "https" {
		note("%s.Scheme %q is not http or https", path, o.Scheme)
	}
	for i, up := range o.Upstreams {
		if !isHostPort(up) {
			note("%s.Upstreams[%d] %q is not a host:port", path, i, up)
		}
	}
	if o.HostHeader != "" && !textguard.IsHostname(o.HostHeader) {
		note("%s.HostHeader %q is not a valid hostname", path, o.HostHeader)
	}
	if o.SNI != "" && !textguard.IsHostname(o.SNI) {
		note("%s.SNI %q is not a valid hostname", path, o.SNI)
	}
}

// isHostPort accepts "host:port", "host", and a bracketed IPv6 literal — the
// shapes an operator legitimately writes as an origin answer.
func isHostPort(s string) bool {
	if s == "" {
		return false
	}
	host := s
	if h, port, err := net.SplitHostPort(s); err == nil {
		host = h
		if port == "" {
			return false
		}
		for _, r := range port {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	return textguard.IsHostname(host)
}
