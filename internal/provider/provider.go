// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package provider is the honest catalogue of places to put an edge node. Its
// whole reason to exist is a single distinction the sovereignty pitch must never
// blur: an EU *region* is not EU *sovereignty*. A US-operated cloud in Milan
// gives European data residency but remains reachable under the US CLOUD Act /
// FISA, so this package tags every provider with its Operator and Exposure and
// refuses to call a hyperscaler "sovereign". flareover offers the pragmatic
// option and states the trade-off; it never markets it away.
//
// This is corporate-jurisdiction information to inform a choice, not legal
// advice; confirm the exact region and terms with the provider at deploy time.
package provider

import "strings"

// Operator is who ultimately controls the infrastructure: the fact that decides
// which jurisdiction can compel access.
type Operator string

const (
	// EUOwned: an EU-headquartered operator, no non-EU parent compelling access.
	EUOwned Operator = "EU-owned"
	// USHyperscaler: a US operator; even an EU region is under US CLOUD Act reach.
	USHyperscaler Operator = "US hyperscaler"
)

// Provider is one edge-node home, with the sovereignty facts stated plainly.
type Provider struct {
	Key       string   // stable id, e.g. "hetzner", "aws-milano"
	Name      string   // display name
	Residency string   // where the data physically sits
	Operator  Operator // who controls it
	Exposure  string   // the honest jurisdiction consequence
}

// Sovereign reports whether the operator is EU-owned (no foreign-jurisdiction
// compulsion path): the only providers flareover will call "sovereign".
func (p Provider) Sovereign() bool { return p.Operator == EUOwned }

// Registry is the built-in catalogue. Order: EU-sovereign first, then the
// residency-only hyperscaler regions.
var Registry = []Provider{
	{"hetzner", "Hetzner", "DE (Nuremberg/Falkenstein) · FI (Helsinki)", EUOwned, "EU jurisdiction only"},
	{"ovh", "OVHcloud", "FR (Gravelines/Roubaix) + EU", EUOwned, "EU jurisdiction only"},
	{"contabo", "Contabo", "DE (Munich) + EU", EUOwned, "EU jurisdiction only"},
	{"aruba", "Aruba", "IT (Arezzo/Milan)", EUOwned, "EU jurisdiction only · Italian operator"},
	{"scaleway", "Scaleway", "FR (Paris) · NL · PL", EUOwned, "EU jurisdiction only"},
	{"leaseweb", "Leaseweb", "NL (Amsterdam) + EU", EUOwned, "EU jurisdiction only · Dutch operator"},
	{"aws-milano", "AWS (eu-south-1, Milan)", "IT (Milan)", USHyperscaler, "EU residency, but US CLOUD Act / FISA reach"},
	{"gcp-milano", "Google Cloud (europe-west8, Milan)", "IT (Milan)", USHyperscaler, "EU residency, but US CLOUD Act / FISA reach"},
	{"azure-milano", "Azure (Italy North, Milan)", "IT (Milan)", USHyperscaler, "EU residency, but US CLOUD Act / FISA reach"},
}

// Lookup finds a provider by key (case-insensitive).
func Lookup(key string) (Provider, bool) {
	k := strings.ToLower(strings.TrimSpace(key))
	for _, p := range Registry {
		if p.Key == k {
			return p, true
		}
	}
	return Provider{}, false
}

// Sovereign returns the EU-owned providers.
func Sovereign() []Provider { return filter(true) }

// ResidencyOnly returns the US-operated (EU-region) providers.
func ResidencyOnly() []Provider { return filter(false) }

func filter(sovereign bool) []Provider {
	var out []Provider
	for _, p := range Registry {
		if p.Sovereign() == sovereign {
			out = append(out, p)
		}
	}
	return out
}
