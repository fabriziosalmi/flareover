// SPDX-License-Identifier: AGPL-3.0-only

// Package spm generates the egress-shield configuration for secure-proxy-manager
// — the outbound counterpart almost no migration touches. It turns the egress
// intent (default-deny, an allowlist of legitimate destinations, threat feeds,
// optional TLS inspection) into an API setup script. The 0% FP discipline holds
// on the way out too: SSL-bump installs a MITM CA on clients, so it is only
// emitted when explicitly confirmed, never by default.
package spm

import (
	"fmt"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target"
)

// Generate renders the egress setup script from the policy. It reads SPM_URL and
// SPM_TOKEN from the environment at run time; it never embeds credentials.
func Generate(e ir.EgressPolicy) []target.Artifact {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# flareover-generated egress shield for secure-proxy-manager.\n")
	b.WriteString("# Requires SPM_URL and SPM_TOKEN in the environment.\n")
	b.WriteString("set -euo pipefail\n")
	b.WriteString(`api(){ curl -fsSL -H "Authorization: Bearer $SPM_TOKEN" -H "Content-Type: application/json" "$SPM_URL$1" "${@:2}"; }` + "\n\n")

	if e.DefaultDeny {
		b.WriteString("# Default-deny egress: outbound is blocked unless explicitly allowed (fail-closed).\n")
		// /api/settings is a BULK update: a flat {key:value} map, and only known
		// writable keys are honored. {"name":...,"value":...} would be silently
		// dropped (keys "name"/"value" aren't settings), leaving egress WIDE OPEN.
		b.WriteString(`api /api/settings -X POST --data '{"egress_default_deny":"true"}'` + "\n\n")
	}

	if len(e.Allow) > 0 {
		b.WriteString("# Allowlist — the destinations the app legitimately calls out to.\n")
		// SPM's allowlist item is {entry[, description]}; it auto-classifies the
		// entry as CIDR vs domain server-side. An "entry" that is empty (or the
		// wrong field name) is rejected 400, so send exactly {"entry":...}.
		for _, d := range e.Allow {
			fmt.Fprintf(&b, "api /api/egress-allowlist -X POST --data '{\"entry\":%q}'\n", d)
		}
		b.WriteString("\n")
	}

	for _, bl := range e.Blocklists {
		fmt.Fprintf(&b, "api /api/blacklists/import -X POST --data '{\"type\":%q,\"url\":%q}'\n", bl.Kind, bl.URL)
	}
	if len(e.Blocklists) > 0 {
		b.WriteString("\n")
	}

	note := "run with SPM_URL + SPM_TOKEN set; enables fail-closed egress + allowlist"
	if e.SSLBump {
		b.WriteString("# TLS inspection (SSL-Bump) — CONFIRMED. Installs a MITM CA on clients; a legal/privacy decision.\n")
		b.WriteString(`api /api/settings -X POST --data '{"ssl_bump_enabled":"true"}'` + "\n")
		note += "; SSL-bump ENABLED (MITM CA)"
	} else {
		b.WriteString("# SSL-Bump NOT enabled (it MITMs client TLS — enable only with explicit consent).\n")
	}

	return []target.Artifact{{
		Path: "spm/setup-egress.sh", Content: []byte(b.String()), Mode: 0o755, Note: note,
	}}
}
