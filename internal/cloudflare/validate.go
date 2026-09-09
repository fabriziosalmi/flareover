// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package cloudflare

import (
	"fmt"
	"net"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/textguard"
)

// maxValidationProblems bounds how many issues one error reports: enough to be
// useful, few enough that the message stays readable.
const maxValidationProblems = 20

// Validate checks a decoded snapshot before anything downstream trusts it.
//
// Until this existed, the strict JSON decoder established that the *shape* was
// right and nothing checked a single value, so every string flowed untouched
// into the Caddyfile and zone-file generators — which interpolate with a bare
// %s. Two consequences followed: a value carrying a newline injected directives
// into the generated configuration, and Zone.Name, which is concatenated into
// artifact paths, could carry "../" out of the output directory.
//
// The checks are deliberately narrow. They reject what cannot be legitimate
// Cloudflare configuration (a control character anywhere, a zone or record name
// that is not a hostname, an address record whose content is not an address)
// and say nothing about anything else, so a snapshot of a real zone always
// passes. ir.Plan.Validate is the matching check on the far side, covering the
// values that arrive from decisions.lock rather than from here.
func (s Snapshot) Validate() error {
	var problems []string
	note := func(format string, args ...any) {
		if len(problems) < maxValidationProblems {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}

	for _, bad := range textguard.FindControlStrings(s, "snapshot") {
		note("%s", bad)
	}

	// Zone.Name is the value concatenated into every artifact path
	// ("powerdns/" + name + ".zone"), so it is the traversal source as well as
	// a correctness concern.
	if s.Zone.Name != "" && !textguard.IsHostname(s.Zone.Name) {
		note("zone.name %q is not a valid hostname", s.Zone.Name)
	}

	for i, r := range s.DNSRecords {
		if r.Name != "" && !textguard.IsHostname(r.Name) {
			note("dns_records[%d].name %q is not a valid hostname", i, r.Name)
		}
		switch strings.ToUpper(r.Type) {
		case "A":
			if ip := net.ParseIP(r.Content); ip == nil || ip.To4() == nil {
				note("dns_records[%d] (A %s) content %q is not an IPv4 address", i, r.Name, r.Content)
			}
		case "AAAA":
			if ip := net.ParseIP(r.Content); ip == nil || ip.To4() != nil {
				note("dns_records[%d] (AAAA %s) content %q is not an IPv6 address", i, r.Name, r.Content)
			}
		case "CNAME", "NS":
			if r.Content != "" && !textguard.IsHostname(r.Content) {
				note("dns_records[%d] (%s %s) target %q is not a valid hostname", i, strings.ToUpper(r.Type), r.Name, r.Content)
			}
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("snapshot failed validation:\n  - %s", strings.Join(problems, "\n  - "))
}
