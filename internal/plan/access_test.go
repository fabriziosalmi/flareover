// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package plan

import (
	"testing"

	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
)

// accessSnapshot: two proxied hosts, one of them behind a Cloudflare Access
// identity policy.
func accessSnapshot() cf.Snapshot {
	return cf.Snapshot{
		SchemaVersion: cf.CurrentSchemaVersion,
		Zone:          cf.Zone{Name: "example.com"},
		Settings:      cf.ZoneSettings{SSL: "strict"},
		DNSRecords: []cf.DNSRecord{
			{Type: "A", Name: "app.example.com", Content: "192.0.2.1", Proxied: true, TTL: 300},
			{Type: "A", Name: "www.example.com", Content: "192.0.2.2", Proxied: true, TTL: 300},
		},
		AccessApps: []cf.AccessApp{
			{Name: "Internal admin", Domain: "app.example.com", Policies: 3},
		},
	}
}

func accessOptions() Options {
	return Options{
		EdgeIP: "5.9.1.1",
		Decisions: map[string]string{
			"origin:app.example.com": "10.0.0.9:443",
			"origin:www.example.com": "10.0.0.8:443",
		},
	}
}

// The defect this pins: classify marked the Access app MANUAL, but the plan
// builder never looked at Snapshot.AccessApps, so the generated Caddyfile
// served an identity-gated application to the entire internet.
func TestAccessGatedHostGetsNoSite(t *testing.T) {
	p, err := Build(accessSnapshot(), accessOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Sites {
		if s.Host == "app.example.com" {
			t.Fatalf("an Access-protected host was emitted as a public site: %+v", s.Origin)
		}
	}
	// The unprotected host must still be migrated: the gate is targeted, not a
	// blanket refusal.
	var sawWWW bool
	for _, s := range p.Sites {
		if s.Host == "www.example.com" {
			sawWWW = true
		}
	}
	if !sawWWW {
		t.Error("the unprotected host was dropped too; the gate is too broad")
	}
}

// A site that is not served must not have DNS pointed at the edge either, or
// the migration turns a working authenticated app into an outage.
func TestAccessGatedHostGetsNoEdgeDNSRecord(t *testing.T) {
	p, err := Build(accessSnapshot(), accessOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.DNS.Records {
		if r.Name == "app.example.com" && r.Content == "5.9.1.1" {
			t.Fatalf("DNS for an Access-gated host was repointed at the edge: %+v", r)
		}
	}
	var sawWWWEdge bool
	for _, r := range p.DNS.Records {
		if r.Name == "www.example.com" && r.Content == "5.9.1.1" {
			sawWWWEdge = true
		}
	}
	if !sawWWWEdge {
		t.Error("the unprotected host was not de-proxied; the gate is too broad")
	}
}

func TestAccessAppDomainMatchingIsCaseAndPathInsensitive(t *testing.T) {
	s := accessSnapshot()
	// Cloudflare reports an app domain with a path and inconsistent case; the
	// gate applies to the host either way, and omitting a little too much is
	// the safe direction.
	s.AccessApps = []cf.AccessApp{{Name: "admin", Domain: "APP.example.com/admin", Policies: 1}}

	p, err := Build(s, accessOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range p.Sites {
		if site.Host == "app.example.com" {
			t.Fatal("a mixed-case, path-carrying Access domain did not gate its host")
		}
	}
}

func TestNoAccessAppsChangesNothing(t *testing.T) {
	s := accessSnapshot()
	s.AccessApps = nil

	p, err := Build(s, accessOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 2 {
		t.Fatalf("sites = %d, want both hosts when no Access app is present", len(p.Sites))
	}
}

// An Access app can be registered on a wildcard domain. Stored verbatim,
// "*.internal.example.com" is a map key nothing matches, so every host it
// actually protects gets an A record and a plain reverse_proxy — the gate
// present, covering nothing.
func TestWildcardAccessAppGatesTheHostsItProtects(t *testing.T) {
	snap := cf.Snapshot{
		SchemaVersion: cf.CurrentSchemaVersion,
		Zone:          cf.Zone{Name: "example.com"},
		AccessApps: []cf.AccessApp{
			{Name: "internal tools", Domain: "*.internal.example.com", Policies: 2},
		},
		DNSRecords: []cf.DNSRecord{
			{Type: "A", Name: "grafana.internal.example.com", Content: "198.51.100.7", Proxied: true, TTL: 300},
			{Type: "A", Name: "shop.example.com", Content: "198.51.100.8", Proxied: true, TTL: 300},
		},
	}
	p, err := Build(snap, Options{
		EdgeIP: "203.0.113.10",
		Decisions: map[string]string{
			"origin:grafana.internal.example.com": "198.51.100.7:443",
			"origin:shop.example.com":             "198.51.100.8:443",
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, s := range p.Sites {
		if s.Host == "grafana.internal.example.com" {
			t.Error("a host behind a wildcard Access app was given a site block: it would be published without its login")
		}
	}
	for _, r := range p.DNS.Records {
		if r.Name == "grafana.internal.example.com" && r.Type == "A" {
			t.Error("a host behind a wildcard Access app was given an A record pointing at the new edge")
		}
	}
	// The gate must not swallow the rest of the zone.
	var sawShop bool
	for _, s := range p.Sites {
		if s.Host == "shop.example.com" {
			sawShop = true
		}
	}
	if !sawShop {
		t.Error("an unrelated host was gated: the wildcard suffix matched too much")
	}
}

// Cloudflare's "*.internal.example.com" does not cover the bare parent, and
// neither should the gate: over-matching would silently drop a host nobody
// protected.
func TestWildcardAccessAppDoesNotGateTheBareParent(t *testing.T) {
	g := accessGatedHosts(cf.Snapshot{
		AccessApps: []cf.AccessApp{{Domain: "*.internal.example.com"}},
	})
	if g.has("internal.example.com") {
		t.Error("the bare parent of a wildcard app was gated")
	}
	if !g.has("app.internal.example.com") {
		t.Error("a host under the wildcard was not gated")
	}
	if g.has("notinternal.example.com") {
		t.Error("a host merely ending in the same letters was gated")
	}
}
