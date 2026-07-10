// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package spm

import (
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

func gen(e ir.EgressPolicy) string { return string(Generate(e)[0].Content) }

func TestDefaultDenyAndAllowlist(t *testing.T) {
	out := gen(ir.EgressPolicy{
		DefaultDeny: true,
		Allow:       []string{"api.stripe.com", "10.0.0.0/8", "192.0.2.1"},
	})
	// /api/settings is a flat bulk map, NOT {"name":...,"value":...}, which SPM
	// silently drops (leaving egress open). This asserts the real API shape.
	if !strings.Contains(out, `{"egress_default_deny":"true"}`) {
		t.Error("default-deny must be a flat {key:value} settings update")
	}
	// The allowlist item is {"entry":...}; SPM auto-classifies CIDR vs domain.
	for _, d := range []string{"api.stripe.com", "10.0.0.0/8", "192.0.2.1"} {
		if !strings.Contains(out, `{"entry":"`+d+`"}`) {
			t.Errorf("allow entry %q must be sent as {\"entry\":...}", d)
		}
	}
	// The old buggy target/value shape must never reappear.
	if strings.Contains(out, `"target":`) || strings.Contains(out, `"value":`) {
		t.Error("stale target/value payload shape leaked back in")
	}
}

// TestSSLBumpOptIn is the 0% FP guard for egress: TLS interception (a MITM CA on
// clients) must never be enabled unless explicitly confirmed.
func TestSSLBumpOptIn(t *testing.T) {
	off := gen(ir.EgressPolicy{DefaultDeny: true})
	if strings.Contains(off, "ssl_bump_enabled") {
		t.Error("SSL-bump enabled without explicit consent")
	}
	if !strings.Contains(off, "NOT enabled") {
		t.Error("declined SSL-bump should be noted, not silent")
	}
	on := gen(ir.EgressPolicy{DefaultDeny: true, SSLBump: true})
	if !strings.Contains(on, `{"ssl_bump_enabled":"true"}`) {
		t.Error("confirmed SSL-bump should be enabled via a flat settings update")
	}
}

func TestBlocklistImport(t *testing.T) {
	out := gen(ir.EgressPolicy{DefaultDeny: true, Blocklists: []ir.Blocklist{{Kind: "domain", URL: "https://x/list.txt"}}})
	if !strings.Contains(out, `/api/blacklists/import`) || !strings.Contains(out, "https://x/list.txt") {
		t.Error("blocklist feed not imported into egress")
	}
}
