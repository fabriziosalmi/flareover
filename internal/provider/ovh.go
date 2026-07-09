// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"fmt"
	"strings"
)

// OVHInstanceScript renders an `openstack` script that creates and boots a
// flareover edge on OVHcloud Public Cloud (OpenStack, EU-owned), feeding it the
// generated cloud-init as user-data. As with the Scaleway edge, flareover
// generates the mechanics; running it — which provisions a *paid* server —
// stays an explicit, reviewed operator step.
//
// Verified against the OpenStack CLI + OVH Public Cloud: `openstack server
// create --user-data <file> --network Ext-Net` (Ext-Net is OVH's public network,
// which assigns a public IP). Auth comes from the OVH openrc.sh (OS_* env), not
// argv.
func OVHInstanceScript(edgeName, cloudInitFile string) []byte {
	name := "flareover-edge-" + edgeName
	var b strings.Builder
	b.WriteString("#!/usr/bin/env sh\n")
	b.WriteString("# flareover — create the edge instance on OVHcloud Public Cloud (OpenStack, EU-owned).\n")
	b.WriteString("# Deterministically generated; review before running — it provisions a PAID server.\n")
	b.WriteString("# Verified against the OpenStack CLI + OVH Public Cloud (Ext-Net public network).\n")
	b.WriteString("set -eu\n\n")

	b.WriteString("# Sizing/placement — override via env. Pick a current flavor (openstack flavor list;\n")
	b.WriteString("# the first boot compiles Caddy with xcaddy, so give it >=2GB RAM):\n")
	b.WriteString("FLAVOR=\"${OVH_EDGE_FLAVOR:-d2-4}\"\n")
	b.WriteString("IMAGE=\"${OVH_EDGE_IMAGE:-Ubuntu 22.04}\"\n")
	b.WriteString("NETWORK=\"${OVH_EDGE_NETWORK:-Ext-Net}\"   # OVH public network → public IP\n")
	b.WriteString("KEY=\"${OVH_EDGE_SSH_KEY:-}\"              # optional SSH key name in the project\n")
	fmt.Fprintf(&b, "NAME=%q\n", name)
	fmt.Fprintf(&b, "CLOUD_INIT=\"$(dirname \"$0\")/%s\"\n\n", cloudInitFile)

	b.WriteString("# Auth: source your OVH OpenStack openrc.sh (from the OVH control panel) first —\n")
	b.WriteString("# it sets OS_AUTH_URL / OS_USERNAME / OS_PASSWORD / OS_PROJECT_* in the environment.\n")
	b.WriteString(": \"${OS_AUTH_URL:?source your OVH openrc.sh first (sets the OS_* OpenStack credentials)}\"\n")
	b.WriteString("if ! command -v openstack >/dev/null 2>&1; then\n")
	b.WriteString("  echo \"error: openstack CLI not found — install python-openstackclient\" >&2\n")
	b.WriteString("  exit 127\n")
	b.WriteString("fi\n")
	b.WriteString("if [ ! -f \"$CLOUD_INIT\" ]; then\n")
	b.WriteString("  echo \"error: cloud-init not found at $CLOUD_INIT\" >&2\n")
	b.WriteString("  exit 1\n")
	b.WriteString("fi\n\n")

	b.WriteString("# Create + boot the edge with the generated cloud-init as user-data.\n")
	b.WriteString("set -- --flavor \"$FLAVOR\" --image \"$IMAGE\" --network \"$NETWORK\" --user-data \"$CLOUD_INIT\"\n")
	b.WriteString("[ -n \"$KEY\" ] && set -- \"$@\" --key-name \"$KEY\"\n")
	b.WriteString("openstack server create \"$@\" \"$NAME\"\n\n")

	b.WriteString("# The server boots and runs cloud-init (builds Caddy + brings up WireGuard, starts\n")
	b.WriteString("# services; first boot takes a few minutes). Read its public IP with\n")
	b.WriteString("#   openstack server show \"$NAME\"\n")
	b.WriteString("# then repoint the migrated DNS at it — e.g. flareover prepare --edge-ip <that-ip>.\n")
	return []byte(b.String())
}
