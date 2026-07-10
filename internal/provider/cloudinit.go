// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"fmt"
	"strings"
)

// EdgeCloudInit renders a provider-agnostic cloud-init that brings up a flareover
// edge node from already-generated artifacts: it writes the Caddyfile and the
// edge's WireGuard config, builds the custom Caddy (caddy-waf + souin) the config
// assumes, opens the firewall, and starts the services. cloud-init is understood
// identically by Hetzner, OVH, Contabo, Aruba, AWS, GCP and Azure, so one file
// works everywhere: the provider only decides *where* (and the sovereignty tier
// stamped in the header).
//
// The WireGuard config carries a private key; cloud-init user_data is the
// standard channel for instance secrets, but treat it as sensitive.
func EdgeCloudInit(p Provider, caddyfile, wgConf []byte) []byte {
	var b strings.Builder
	b.WriteString("#cloud-config\n")
	fmt.Fprintf(&b, "# flareover edge node: %s\n", p.Name)
	fmt.Fprintf(&b, "# residency: %s | operator: %s | exposure: %s\n", p.Residency, p.Operator, p.Exposure)
	if !p.Sovereign() {
		b.WriteString("# NOTE: EU data residency, but a US operator: NOT sovereign (US CLOUD Act reach).\n")
	}
	b.WriteString("# Contains a WireGuard private key: treat this user-data as a secret.\n\n")

	b.WriteString("package_update: true\n")
	b.WriteString("packages:\n")
	for _, pkg := range []string{"wireguard-tools", "ufw", "curl", "git", "ca-certificates"} {
		fmt.Fprintf(&b, "  - %s\n", pkg)
	}

	b.WriteString("\nwrite_files:\n")
	b.WriteString("  - path: /etc/caddy/Caddyfile\n")
	b.WriteString("    permissions: '0644'\n")
	b.WriteString("    content: |\n")
	b.WriteString(indent(caddyfile, 6))
	b.WriteString("  - path: /etc/wireguard/wg0.conf\n")
	b.WriteString("    permissions: '0600'\n")
	b.WriteString("    content: |\n")
	b.WriteString(indent(wgConf, 6))

	b.WriteString("\nruncmd:\n")
	b.WriteString("  # Fail-closed firewall: only HTTP/HTTPS in, plus the WireGuard port for the mesh.\n")
	b.WriteString("  - ufw --force reset\n")
	b.WriteString("  - ufw default deny incoming\n")
	b.WriteString("  - ufw default allow outgoing\n")
	b.WriteString("  - ufw allow 22/tcp\n")
	b.WriteString("  - ufw allow 80/tcp\n")
	b.WriteString("  - ufw allow 443/tcp\n")
	b.WriteString("  - ufw allow 51820/udp\n")
	b.WriteString("  - ufw --force enable\n")
	b.WriteString("  # Bring the mesh up (the origin dials in and holds it with keepalive).\n")
	b.WriteString("  - systemctl enable --now wg-quick@wg0\n")
	b.WriteString("  # Build the custom Caddy the generated Caddyfile assumes (caddy-waf + souin).\n")
	b.WriteString("  # First boot takes a few minutes; swap in a prebuilt binary to skip this.\n")
	b.WriteString("  - curl -fsSL https://go.dev/dl/go1.23.4.linux-amd64.tar.gz | tar -C /usr/local -xz\n")
	b.WriteString("  - /usr/local/go/bin/go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest\n")
	b.WriteString("  - /root/go/bin/xcaddy build --with github.com/fabriziosalmi/caddy-waf --with github.com/darkweak/souin/caddy --output /usr/local/bin/caddy\n")
	b.WriteString("  - useradd --system --home /var/lib/caddy --create-home --shell /usr/sbin/nologin caddy || true\n")
	b.WriteString("  - /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile\n")
	b.WriteString("  - /usr/local/bin/caddy start --config /etc/caddy/Caddyfile --adapter caddyfile\n")
	return []byte(b.String())
}

// indent prefixes every line of b with n spaces (for a YAML block scalar) and
// guarantees a trailing newline.
func indent(b []byte, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i, l := range lines {
		if l == "" {
			lines[i] = ""
		} else {
			lines[i] = pad + l
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
