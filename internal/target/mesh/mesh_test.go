// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package mesh

import (
	"crypto/ecdh"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

func TestGenerateWireGuardStructure(t *testing.T) {
	arts, err := GenerateWireGuard(Config{EdgeEndpoint: "5.9.1.1:51820"})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, a := range arts {
		files[a.Path] = string(a.Content)
	}
	edge, origin := files["mesh/edge.wg0.conf"], files["mesh/origin.wg0.conf"]
	if edge == "" || origin == "" {
		t.Fatal("missing edge/origin configs")
	}

	// Edge listens; origin is outbound-only (Endpoint + keepalive, no ListenPort).
	if !strings.Contains(edge, "ListenPort = 51820") {
		t.Error("edge should listen")
	}
	if strings.Contains(origin, "ListenPort") {
		t.Error("origin must NOT listen (zero inbound)")
	}
	if !strings.Contains(origin, "Endpoint = 5.9.1.1:51820") || !strings.Contains(origin, "PersistentKeepalive = 25") {
		t.Error("origin must dial the edge and keep the link alive")
	}
	// edge = 10.99.0.1, origin = 10.99.0.254; peers reference each other's mesh IP.
	if !strings.Contains(origin, "AllowedIPs = 10.99.0.1/32") || !strings.Contains(edge, "AllowedIPs = 10.99.0.254/32") {
		t.Error("mesh IPs not wired correctly")
	}

	// Keys are valid 32-byte Curve25519, and the peers reference each other.
	edgePriv := field(t, edge, "PrivateKey")
	edgePeerPub := field(t, edge, "PublicKey")
	originPriv := field(t, origin, "PrivateKey")
	originPeerPub := field(t, origin, "PublicKey")
	for _, k := range []string{edgePriv, edgePeerPub, originPriv, originPeerPub} {
		if b, err := base64.StdEncoding.DecodeString(k); err != nil || len(b) != 32 {
			t.Errorf("invalid WireGuard key %q (len err %v)", k, err)
		}
	}
	if edgePriv == originPriv {
		t.Error("edge and origin share a private key")
	}
	// The edge's peer key is the origin's key, and vice versa: derive pub from priv.
	if pub := pubOf(t, edgePriv); pub == originPeerPub {
		// origin's [Peer] PublicKey should equal the edge's public key
	} else {
		t.Errorf("origin peer key %q is not the edge public key %q", originPeerPub, pub)
	}
	if pub := pubOf(t, originPriv); pub != edgePeerPub {
		t.Errorf("edge peer key %q is not the origin public key %q", edgePeerPub, pub)
	}
}

func TestMultiEdgeHA(t *testing.T) {
	arts, err := GenerateWireGuard(Config{Edges: []Edge{
		{Name: "hetzner", Endpoint: "5.9.1.1:51820"},
		{Name: "aws-milano", Endpoint: "18.2.3.4:51820"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, a := range arts {
		files[a.Path] = string(a.Content)
	}
	// One config per named edge (names honored as given), plus origin + README.
	for _, want := range []string{"mesh/hetzner.wg0.conf", "mesh/aws-milano.wg0.conf", "mesh/origin.wg0.conf", "mesh/README.md"} {
		if _, ok := files[want]; !ok {
			t.Errorf("missing artifact %s", want)
		}
	}
	origin := files["mesh/origin.wg0.conf"]

	// The origin peers with BOTH edges (two [Peer] blocks, both endpoints).
	if strings.Count(origin, "[Peer]") != 2 {
		t.Errorf("origin must have one peer per edge, got %d", strings.Count(origin, "[Peer]"))
	}
	for _, ep := range []string{"Endpoint = 5.9.1.1:51820", "Endpoint = 18.2.3.4:51820"} {
		if !strings.Contains(origin, ep) {
			t.Errorf("origin missing edge endpoint %q", ep)
		}
	}
	// Edges get distinct mesh IPs (.1 and .2); origin still has zero inbound.
	if !strings.Contains(origin, "AllowedIPs = 10.99.0.1/32") || !strings.Contains(origin, "AllowedIPs = 10.99.0.2/32") {
		t.Error("edges must get distinct mesh IPs")
	}
	if strings.Contains(origin, "ListenPort") {
		t.Error("origin must never listen, even with multiple edges")
	}
	// Each edge's single peer is the origin at 10.99.0.254.
	e1, e2 := files["mesh/hetzner.wg0.conf"], files["mesh/aws-milano.wg0.conf"]
	if !strings.Contains(e1, "AllowedIPs = 10.99.0.254/32") || !strings.Contains(e2, "AllowedIPs = 10.99.0.254/32") {
		t.Error("each edge must route to the origin mesh IP")
	}
	if field(t, e1, "PrivateKey") == field(t, e2, "PrivateKey") {
		t.Error("edges must have distinct keys")
	}
}

func TestNoEdgeIsAnError(t *testing.T) {
	if _, err := GenerateWireGuard(Config{}); err == nil {
		t.Error("a mesh with no edge must be rejected, not silently empty")
	}
}

func field(t *testing.T, conf, key string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + key + ` = (.+)$`)
	m := re.FindStringSubmatch(conf)
	if m == nil {
		t.Fatalf("field %s not found", key)
	}
	return strings.TrimSpace(m[1])
}

func pubOf(t *testing.T, privB64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}
