// SPDX-License-Identifier: AGPL-3.0-only

package bunnydns

import (
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target"
)

func ptr(i int) *int { return &i }

func samplePlan(dnssec bool) ir.Plan {
	return ir.Plan{
		Zone: "example.com",
		DNS: ir.DNSZone{
			Name:   "example.com",
			DNSSEC: dnssec,
			Records: []ir.DNSRecord{
				{Type: "A", Name: "example.com", Content: "198.51.100.10", TTL: 300},
				{Type: "A", Name: "www.example.com", Content: "198.51.100.10", TTL: 300},
				{Type: "CNAME", Name: "cdn.example.com", Content: "edge.example.net", TTL: 3600},
				{Type: "MX", Name: "example.com", Content: "mail.example.com", TTL: 300, Priority: ptr(10)},
				{Type: "TXT", Name: "example.com", Content: "v=spf1 -all", TTL: 300},
			},
		},
	}
}

func gen(t *testing.T, dnssec bool) (zone, apply target.Artifact) {
	t.Helper()
	arts, err := Generator{}.Generate(samplePlan(dnssec))
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 2 {
		t.Fatalf("artifacts = %d, want 2", len(arts))
	}
	for _, a := range arts {
		switch {
		case strings.HasSuffix(a.Path, ".zone"):
			zone = a
		case strings.HasSuffix(a.Path, "apply.sh"):
			apply = a
		}
	}
	if zone.Path == "" || apply.Path == "" {
		t.Fatalf("missing artifact: zone=%q apply=%q", zone.Path, apply.Path)
	}
	return zone, apply
}

// TestZoneOmitsSOAandNS is the correctness guard: bunny.net owns the zone's SOA
// and NS. If either leaks into the import file, the apply would either be
// rejected or import bogus apex nameservers and break delegation.
func TestZoneOmitsSOAandNS(t *testing.T) {
	zone, _ := gen(t, false)
	body := string(zone.Content)
	if zone.Path != "bunny-dns/example.com.zone" {
		t.Errorf("zone path = %q", zone.Path)
	}
	// Anchor on the tab-delimited rdata type so the header comment (which names
	// SOA/NS to explain their absence) is not mistaken for a record.
	if strings.Contains(body, "\tSOA\t") {
		t.Error("import zone leaked an SOA record — bunny.net owns the SOA")
	}
	if strings.Contains(body, "\tNS\t") || strings.Contains(body, "NAMESERVER_PLACEHOLDER") {
		t.Error("import zone leaked apex NS records — bunny.net owns delegation")
	}
	if !strings.Contains(body, "$ORIGIN example.com.") {
		t.Error("zone missing $ORIGIN")
	}
}

// TestRecordRenderingIsCanonicalBIND checks the rdata order that makes the
// import path safe (canonical BIND, not the CLI's records-add order).
func TestRecordRenderingIsCanonicalBIND(t *testing.T) {
	zone, _ := gen(t, false)
	body := string(zone.Content)
	want := []string{
		"@\t300\tIN\tA\t198.51.100.10",
		"www\t300\tIN\tA\t198.51.100.10",
		"cdn\t3600\tIN\tCNAME\tedge.example.net.",
		"@\t300\tIN\tMX\t10 mail.example.com.", // priority THEN target (BIND order)
		"@\t300\tIN\tTXT\t\"v=spf1 -all\"",
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("zone missing line %q\n---\n%s", w, body)
		}
	}
}

// TestApplyUsesVerifiedCLISurface pins the apply script to the real CLI syntax
// and the env-var (never-on-argv) auth model.
func TestApplyUsesVerifiedCLISurface(t *testing.T) {
	_, apply := gen(t, false)
	body := string(apply.Content)
	if apply.Mode != 0o755 {
		t.Errorf("apply.sh mode = %#o, want 0755", apply.Mode)
	}
	for _, w := range []string{
		"#!/usr/bin/env sh",
		"set -eu",
		"BUNNYNET_API_KEY",
		`bunny dns zones add "$ZONE"`,
		`bunny dns records import "$ZONE" "$ZONEFILE"`,
		`bunny dns zones nameservers "$ZONE"`,
	} {
		if !strings.Contains(body, w) {
			t.Errorf("apply.sh missing %q", w)
		}
	}
	// The key must be read from the environment, not spilled onto the command
	// line where `ps` would expose it.
	if strings.Contains(body, "--api-key") {
		t.Error("apply.sh passes --api-key on argv; use the BUNNYNET_API_KEY env instead")
	}
}

// TestDNSSECIsConditional: the DNSSEC enable line appears only when requested.
func TestDNSSECIsConditional(t *testing.T) {
	_, off := gen(t, false)
	if strings.Contains(string(off.Content), "dnssec enable") {
		t.Error("apply.sh enabled DNSSEC without it being requested")
	}
	_, on := gen(t, true)
	if !strings.Contains(string(on.Content), `bunny dns zones dnssec enable "$ZONE"`) {
		t.Error("apply.sh omitted DNSSEC enable when the zone requested it")
	}
}
