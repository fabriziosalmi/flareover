package provider

import (
	"strings"
	"testing"
)

func TestSovereigntyTiering(t *testing.T) {
	// The core promise: no US hyperscaler is ever labelled sovereign.
	for _, p := range ResidencyOnly() {
		if p.Sovereign() {
			t.Errorf("%s must not be sovereign", p.Key)
		}
		if !strings.Contains(p.Exposure, "US") {
			t.Errorf("%s exposure must name the US-jurisdiction reach: %q", p.Key, p.Exposure)
		}
	}
	for _, p := range Sovereign() {
		if p.Operator != EUOwned {
			t.Errorf("%s in the sovereign set is not EU-owned", p.Key)
		}
	}
	// Both known hyperscaler regions are present and correctly tiered.
	for _, key := range []string{"aws-milano", "gcp-milano"} {
		p, ok := Lookup(key)
		if !ok || p.Sovereign() {
			t.Errorf("%s should be a known, non-sovereign provider", key)
		}
	}
	// And the EU-owned ones are sovereign.
	for _, key := range []string{"hetzner", "ovh", "contabo", "aruba"} {
		p, ok := Lookup(key)
		if !ok || !p.Sovereign() {
			t.Errorf("%s should be a known, sovereign provider", key)
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	if _, ok := Lookup("digitalocean"); ok {
		t.Error("unknown provider must not resolve")
	}
	if _, ok := Lookup("HETZNER"); !ok {
		t.Error("lookup should be case-insensitive")
	}
}

func TestEdgeCloudInitEmbedsArtifactsAndFlagsSovereignty(t *testing.T) {
	caddy := []byte("example.com {\n\treverse_proxy 10.99.0.254:80\n}\n")
	wg := []byte("[Interface]\nPrivateKey = SECRET\nListenPort = 51820\n")

	aws, _ := Lookup("aws-milano")
	out := string(EdgeCloudInit(aws, caddy, wg))
	if !strings.HasPrefix(out, "#cloud-config") {
		t.Error("must be a valid cloud-config document")
	}
	// Artifacts are embedded, indented under their block scalars.
	if !strings.Contains(out, "      example.com {") || !strings.Contains(out, "      PrivateKey = SECRET") {
		t.Error("cloud-init must embed the Caddyfile and wg config, indented")
	}
	// A hyperscaler edge is explicitly flagged non-sovereign.
	if !strings.Contains(out, "NOT sovereign") {
		t.Error("a US-operator edge must be flagged NOT sovereign in the cloud-init")
	}
	// Fail-closed firewall + mesh + caddy present.
	for _, want := range []string{"ufw default deny incoming", "51820/udp", "wg-quick@wg0", "caddy"} {
		if !strings.Contains(out, want) {
			t.Errorf("cloud-init missing %q", want)
		}
	}

	// A sovereign edge does NOT carry the non-sovereign warning.
	hetz, _ := Lookup("hetzner")
	if strings.Contains(string(EdgeCloudInit(hetz, caddy, wg)), "NOT sovereign") {
		t.Error("a sovereign edge must not be flagged non-sovereign")
	}
}
