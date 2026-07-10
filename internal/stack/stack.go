// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package stack assembles concrete StackProfiles from the target generators.
// It is the one place that knows which proxy/WAF/DNS implementations belong
// together, so selecting a profile ("caddy" today; "nginx"/"traefik" later) is
// a single switch and everything upstream stays profile-agnostic.
package stack

import (
	"fmt"

	"github.com/fabriziosalmi/flareover/internal/target"
	"github.com/fabriziosalmi/flareover/internal/target/caddy"
	"github.com/fabriziosalmi/flareover/internal/target/caddywaf"
	"github.com/fabriziosalmi/flareover/internal/target/powerdns"
)

// Profile returns the stack profile for the given id. The empty id defaults to
// the flagship "caddy" profile.
func Profile(id string) (target.StackProfile, error) {
	switch id {
	case "", "caddy":
		return target.StackProfile{
			ID:           "caddy",
			ReverseProxy: caddy.Generator{},
			WAF:          caddywaf.Generator{},
			DNS:          powerdns.Generator{},
		}, nil
	case "nginx", "traefik", "apache":
		return target.StackProfile{}, fmt.Errorf("stack profile %q is on the roadmap; only %q is implemented", id, "caddy")
	default:
		return target.StackProfile{}, fmt.Errorf("unknown stack profile %q", id)
	}
}
