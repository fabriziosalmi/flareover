// Package mesh generates a sovereign WireGuard link between one or more public
// edge nodes and the isolated origin — the substitute for a Cloudflare Tunnel,
// which would route a leave-Cloudflare migration back through Cloudflare. It
// keeps the same property the tunnel gave (the origin is outbound-only, zero
// inbound) but with no third party in the path: the origin dials every edge and
// each edge reaches the origin over the encrypted mesh.
//
// This is the headline "keep your origin, re-tunnel it elsewhere" topology: the
// on-prem (or existing) origin does not move — only its tunnel agent changes
// (cloudflared → WireGuard). With more than one edge you get an HA front:
// several public entry points, all meshed to the same untouched origin,
// distributed by round-robin DNS and health-gated by `flareover guard`.
//
// Keys are freshly generated (they are secrets); the config structure is
// deterministic.
package mesh

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/target"
)

// Config parameterizes the mesh. Sensible defaults are applied for empty fields.
type Config struct {
	// Edges is one entry per public edge node; the origin peers with all of them.
	Edges []Edge
	// EdgeEndpoint is a convenience for the single-edge case; it is used only
	// when Edges is empty.
	EdgeEndpoint string
	// OriginWGIP is the origin's mesh address every edge dials into (default
	// 10.99.0.254). Point each edge's origin upstream at this address.
	OriginWGIP string
	// ListenPort is the WireGuard listen port on each edge (default 51820).
	ListenPort int
}

// Edge describes one public edge node the origin will dial out to.
type Edge struct {
	// Name labels the artifact (mesh/<name>.wg0.conf). Defaults to "edge" for a
	// single edge, else "edge-<i>".
	Name string
	// Endpoint is the public <ip|host>:port the origin dials for this edge.
	Endpoint string
	// WGIP is this edge's mesh address (default 10.99.0.<i>).
	WGIP string
}

func (c Config) normalized() (Config, error) {
	if len(c.Edges) == 0 && c.EdgeEndpoint != "" {
		c.Edges = []Edge{{Endpoint: c.EdgeEndpoint}}
	}
	if len(c.Edges) == 0 {
		return c, fmt.Errorf("mesh: at least one edge endpoint is required")
	}
	if c.OriginWGIP == "" {
		c.OriginWGIP = "10.99.0.254"
	}
	if c.ListenPort == 0 {
		c.ListenPort = 51820
	}
	single := len(c.Edges) == 1
	for i := range c.Edges {
		if strings.TrimSpace(c.Edges[i].Endpoint) == "" {
			return c, fmt.Errorf("mesh: edge %d has no endpoint (host:port the origin dials)", i+1)
		}
		if c.Edges[i].WGIP == "" {
			c.Edges[i].WGIP = fmt.Sprintf("10.99.0.%d", i+1)
		}
		if c.Edges[i].Name == "" {
			if single {
				c.Edges[i].Name = "edge"
			} else {
				c.Edges[i].Name = fmt.Sprintf("edge-%d", i+1)
			}
		}
	}
	return c, nil
}

// keypair holds a base64-encoded WireGuard keypair (Curve25519 / X25519).
type keypair struct{ priv, pub string }

func genKey() (keypair, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return keypair{}, err
	}
	return keypair{
		priv: base64.StdEncoding.EncodeToString(k.Bytes()),
		pub:  base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()),
	}, nil
}

// GenerateWireGuard emits wg configs for every edge (WireGuard server, public)
// and the origin (client, outbound-only, one peer per edge). Each edge then
// reaches the origin at the origin's mesh IP; point every origin upstream there
// (e.g. http://10.99.0.254:80).
func GenerateWireGuard(cfg Config) ([]target.Artifact, error) {
	cfg, err := cfg.normalized()
	if err != nil {
		return nil, err
	}

	origin, err := genKey()
	if err != nil {
		return nil, err
	}
	edgeKeys := make([]keypair, len(cfg.Edges))
	for i := range cfg.Edges {
		if edgeKeys[i], err = genKey(); err != nil {
			return nil, err
		}
	}

	arts := make([]target.Artifact, 0, len(cfg.Edges)+2)

	// One config per edge: it listens and peers only with the origin.
	for i, e := range cfg.Edges {
		var b strings.Builder
		fmt.Fprintf(&b, "# flareover mesh — EDGE %q (WireGuard server, public). Keep PrivateKey secret.\n", e.Name)
		b.WriteString("[Interface]\n")
		fmt.Fprintf(&b, "Address = %s/24\n", e.WGIP)
		fmt.Fprintf(&b, "ListenPort = %d\n", cfg.ListenPort)
		fmt.Fprintf(&b, "PrivateKey = %s\n\n", edgeKeys[i].priv)
		b.WriteString("[Peer]  # origin (dials in — no Endpoint here)\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", origin.pub)
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", cfg.OriginWGIP)

		note := fmt.Sprintf("edge %q reaches the origin at http://%s:80 over the mesh; open udp/%d inbound on this node.",
			e.Name, cfg.OriginWGIP, cfg.ListenPort)
		arts = append(arts, target.Artifact{
			Path: "mesh/" + e.Name + ".wg0.conf", Content: []byte(b.String()), Mode: 0o600, Note: note,
		})
	}

	// One origin config: outbound-only, one [Peer] per edge, keepalive on each.
	var o strings.Builder
	o.WriteString("# flareover mesh — ORIGIN (WireGuard client, outbound-only, zero inbound). Keep PrivateKey secret.\n")
	o.WriteString("[Interface]\n")
	fmt.Fprintf(&o, "Address = %s/24\n", cfg.OriginWGIP)
	fmt.Fprintf(&o, "PrivateKey = %s\n", origin.priv)
	for i, e := range cfg.Edges {
		fmt.Fprintf(&o, "\n[Peer]  # %s\n", e.Name)
		fmt.Fprintf(&o, "PublicKey = %s\n", edgeKeys[i].pub)
		fmt.Fprintf(&o, "Endpoint = %s\n", e.Endpoint)
		fmt.Fprintf(&o, "AllowedIPs = %s/32\n", e.WGIP)
		o.WriteString("PersistentKeepalive = 25\n")
	}
	originNote := fmt.Sprintf("outbound-only origin: it dials %d edge(s) and holds each link with keepalive. "+
		"Swap cloudflared for this: `wg-quick up wg0`. The app stays exactly as it is.", len(cfg.Edges))
	arts = append(arts, target.Artifact{
		Path: "mesh/origin.wg0.conf", Content: []byte(o.String()), Mode: 0o600, Note: originNote,
	})

	arts = append(arts, target.Artifact{Path: "mesh/README.md", Content: []byte(readme(cfg))})
	return arts, nil
}

func readme(cfg Config) string {
	var b strings.Builder
	b.WriteString("# Sovereign mesh — keep your origin, re-tunnel it elsewhere\n\n")
	b.WriteString("WireGuard replaces the Cloudflare Tunnel: the origin stays outbound-only (zero inbound),\n")
	b.WriteString("but nothing routes through a third party. Your origin app does **not** change — only its\n")
	b.WriteString("tunnel agent does (cloudflared → WireGuard).\n\n")

	fmt.Fprintf(&b, "Topology: %d public edge node(s) → one origin at `%s`.\n\n", len(cfg.Edges), cfg.OriginWGIP)

	b.WriteString("## Bring it up\n\n")
	b.WriteString("On each edge node (public):\n")
	for _, e := range cfg.Edges {
		fmt.Fprintf(&b, "  - put `%s.wg0.conf` at `/etc/wireguard/wg0.conf`; open `udp/%d` inbound; `wg-quick up wg0`.\n",
			e.Name, cfg.ListenPort)
	}
	b.WriteString("\nOn the origin (on-prem or wherever it already runs — no inbound ports):\n")
	b.WriteString("  1. put `origin.wg0.conf` at `/etc/wireguard/wg0.conf`.\n")
	b.WriteString("  2. stop the old tunnel agent (`systemctl disable --now cloudflared`).\n")
	b.WriteString("  3. `wg-quick up wg0` — the origin dials every edge and holds each link with keepalive.\n")
	fmt.Fprintf(&b, "  4. point each edge's origin upstream at `http://%s:80` (over the mesh).\n\n", cfg.OriginWGIP)

	if len(cfg.Edges) > 1 {
		b.WriteString("## High availability\n\n")
		b.WriteString("With more than one edge, publish an A/AAAA record per edge IP (round-robin), and let\n")
		b.WriteString("`flareover guard` health-check each edge and pull a failed one from DNS. The origin keeps\n")
		b.WriteString("all tunnels up simultaneously, so any surviving edge serves traffic. Note: this makes the\n")
		b.WriteString("**edge** highly available — the origin's own redundancy is yours to provide, not faked here.\n\n")
	}

	b.WriteString("Prefer a managed mesh at scale: NetBird (self-hosted) or Tailscale with a self-hosted\n")
	b.WriteString("headscale control plane — both WireGuard under the hood, both EU-sovereign when self-hosted.\n")
	return b.String()
}
