// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package dnstarget

import (
	"strings"
	"testing"
)

// The defect this registry exists to make impossible: `prepare` and `provision`
// each carried their own hand-maintained alias list, and they drifted — bunny
// was accepted by one and rejected by the other, mid-migration, with artifacts
// already written. There is now one list, so a target either exists for the
// whole pipeline or not at all.
func TestEveryTargetResolvesByKeyAndByEveryAlias(t *testing.T) {
	for _, want := range All() {
		got, ok := Lookup(want.Key)
		if !ok || got.Key != want.Key {
			t.Errorf("Lookup(%q) did not resolve to itself", want.Key)
		}
		for _, a := range want.Aliases {
			got, ok := Lookup(a)
			if !ok {
				t.Errorf("alias %q of %q does not resolve", a, want.Key)
				continue
			}
			if got.Key != want.Key {
				t.Errorf("alias %q resolved to %q, want %q", a, got.Key, want.Key)
			}
		}
	}
}

func TestLookupIsCaseAndSpaceInsensitive(t *testing.T) {
	for _, s := range []string{"Scaleway", "  scaleway  ", "SCALEWAY", "Aws-Route53"} {
		if _, ok := Lookup(s); !ok {
			t.Errorf("Lookup(%q) failed; an operator's spelling should not matter", s)
		}
	}
}

func TestEmptyMeansPowerDNS(t *testing.T) {
	got, ok := Lookup("")
	if !ok || got.Key != "powerdns" {
		t.Fatalf("Lookup(\"\") = %q,%v; the default must be self-hosted PowerDNS", got.Key, ok)
	}
}

func TestUnknownTargetIsRefused(t *testing.T) {
	if _, ok := Lookup("nonsense"); ok {
		t.Fatal("an unknown --dns value resolved")
	}
	err := UnknownError("provision", "nonsense")
	// The error must list the whole vocabulary: both verbs use this one
	// function, so neither can advertise a stale list.
	for _, k := range Keys() {
		if !strings.Contains(err.Error(), k) {
			t.Errorf("error message omits %q: %v", k, err)
		}
	}
}

// Every target must be usable by `prepare`. A target with no generator would be
// selectable and then produce nothing.
func TestEveryTargetHasAGenerator(t *testing.T) {
	for _, tg := range All() {
		if tg.Generator == nil {
			t.Errorf("%q has no generator", tg.Key)
			continue
		}
		if tg.Generator.Name() == "" {
			t.Errorf("%q generator reports no name", tg.Key)
		}
	}
}

// Keys are unique, and no alias collides with another target's key or alias.
// A collision would resolve silently to whichever came first.
func TestNoDuplicateKeysOrAliases(t *testing.T) {
	seen := map[string]string{}
	for _, tg := range All() {
		for _, s := range append([]string{tg.Key}, tg.Aliases...) {
			if prev, dup := seen[s]; dup {
				t.Errorf("%q is claimed by both %q and %q", s, prev, tg.Key)
			}
			seen[s] = tg.Key
		}
	}
}

// Sovereignty is a claim the tool makes to users; it must not be accidental.
func TestSovereigntyTiersAreDeliberate(t *testing.T) {
	usOperated := map[string]bool{"route53": true, "clouddns": true, "azure": true}
	for _, tg := range All() {
		if usOperated[tg.Key] && tg.Sovereign {
			t.Errorf("%q is US-operated but marked sovereign", tg.Key)
		}
		if !usOperated[tg.Key] && !tg.Sovereign {
			t.Errorf("%q is EU-owned but marked non-sovereign", tg.Key)
		}
		if !tg.Sovereign && !strings.Contains(tg.Label, "not sovereign") {
			t.Errorf("%q label %q does not say it is not sovereign", tg.Key, tg.Label)
		}
	}
}

// A missing credential must name the variable, not fail vaguely at request time.
func TestMissingCredentialsAreNamed(t *testing.T) {
	cases := map[string][]string{
		"scaleway": {"SCW_SECRET_KEY", "SCW_DEFAULT_PROJECT_ID"},
		"ovh":      {"OVH_APPLICATION_KEY", "OVH_APPLICATION_SECRET", "OVH_CONSUMER_KEY"},
		"gandi":    {"GANDI_PAT"},
		"leaseweb": {"LEASEWEB_API_KEY"},
		"hetzner":  {"HETZNER_DNS_TOKEN"},
		"route53":  {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
		"azure":    {"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP"},
		"clouddns": {"GOOGLE_APPLICATION_CREDENTIALS"},
	}
	for key, vars := range cases {
		tg, ok := Lookup(key)
		if !ok {
			t.Fatalf("%q is not registered", key)
		}
		for _, v := range vars {
			t.Setenv(v, "")
		}
		_, err := tg.NewProvisioner(Opts{})
		if err == nil {
			t.Errorf("%q built a provisioner with no credentials", key)
			continue
		}
		for _, v := range vars {
			if !strings.Contains(err.Error(), v) {
				t.Errorf("%q: error %q does not name the missing %s", key, err, v)
			}
		}
	}
}

func TestPowerDNSNeedsBothURLAndKey(t *testing.T) {
	tg, _ := Lookup("powerdns")

	t.Setenv("PDNS_API_KEY", "k")
	if _, err := tg.NewProvisioner(Opts{}); err == nil {
		t.Error("built a PowerDNS provisioner with no --pdns-url")
	} else if !strings.Contains(err.Error(), "--pdns-url") {
		t.Errorf("error should name the flag, got: %v", err)
	}

	t.Setenv("PDNS_API_KEY", "")
	if _, err := tg.NewProvisioner(Opts{PDNSURL: "http://localhost:8081"}); err == nil {
		t.Error("built a PowerDNS provisioner with no API key")
	} else if !strings.Contains(err.Error(), "PDNS_API_KEY") {
		t.Errorf("error should name the variable, got: %v", err)
	}

	t.Setenv("PDNS_API_KEY", "k")
	p, err := tg.NewProvisioner(Opts{PDNSURL: "http://localhost:8081", Nameservers: []string{"ns1.example.com"}})
	if err != nil {
		t.Fatalf("a fully configured PowerDNS target failed to build: %v", err)
	}
	// PowerDNS is the only backend that can sign a zone itself; the others say
	// so in DNSSECNote instead.
	if _, ok := p.(DNSSECEnabler); !ok {
		t.Error("the PowerDNS provisioner no longer offers EnableDNSSEC")
	}
}

// bunny is registered deliberately with no provisioner, so `provision --dns
// bunny` can say "generate-only" instead of "unknown".
func TestBunnyIsRegisteredButGenerateOnly(t *testing.T) {
	tg, ok := Lookup("bunny")
	if !ok {
		t.Fatal("bunny is not registered; provision would call it unknown again")
	}
	if !tg.GenerateOnly() {
		t.Error("bunny now claims a live applier")
	}
	if tg.Generator == nil {
		t.Error("bunny has no generator, so prepare cannot emit its zone")
	}
}

// Every managed backend that cannot sign a zone must tell the operator where to
// click, or DNSSEC is silently dropped.
func TestManagedTargetsExplainDNSSEC(t *testing.T) {
	for _, tg := range All() {
		if tg.Key == "powerdns" || tg.GenerateOnly() {
			continue // powerdns signs; bunny emits a script
		}
		if strings.TrimSpace(tg.DNSSECNote) == "" {
			t.Errorf("%q has no DNSSEC note: a signed source zone would go quiet", tg.Key)
		}
	}
}
