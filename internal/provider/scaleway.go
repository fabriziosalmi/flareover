// SPDX-License-Identifier: AGPL-3.0-only

package provider

import (
	"fmt"
	"strings"
)

// ScalewayInstanceScript renders a `scw` script that creates and boots a
// flareover edge on Scaleway Instances (EU-owned), feeding it the generated
// cloud-init as the instance's user-data. flareover generates the mechanics;
// running it — which provisions a *paid* server — stays an explicit, reviewed
// operator step, in keeping with the same discipline the DNS/registrar cutover
// follows: automate the mechanics, never the irreversible decision.
//
// Verified against the Scaleway CLI: `scw instance server create` with
// cloud-init=@<file> (the @ prefix loads the argument value from a file). Auth
// and placement come from the environment (SCW_SECRET_KEY, SCW_DEFAULT_PROJECT_ID,
// SCW_DEFAULT_ZONE), never argv.
func ScalewayInstanceScript(edgeName, cloudInitFile string) []byte {
	name := "flareover-edge-" + edgeName
	var b strings.Builder
	b.WriteString("#!/usr/bin/env sh\n")
	b.WriteString("# flareover — create the edge instance on Scaleway Instances (EU-owned).\n")
	b.WriteString("# Deterministically generated; review before running — it provisions a PAID server.\n")
	b.WriteString("# Verified against the Scaleway CLI (scw instance server create, cloud-init=@file).\n")
	b.WriteString("set -eu\n\n")

	b.WriteString("# Placement + sizing — override via env. Pick a current commercial type (the\n")
	b.WriteString("# first boot compiles Caddy with xcaddy, so give it >=2GB RAM):\n")
	b.WriteString("#   https://www.scaleway.com/en/docs/instances/reference-content/choosing-instance-type/\n")
	b.WriteString("ZONE=\"${SCW_DEFAULT_ZONE:-fr-par-1}\"\n")
	b.WriteString("TYPE=\"${SCW_EDGE_TYPE:-DEV1-S}\"\n")
	b.WriteString("IMAGE=\"${SCW_EDGE_IMAGE:-ubuntu_jammy}\"\n")
	fmt.Fprintf(&b, "NAME=%q\n", name)
	fmt.Fprintf(&b, "CLOUD_INIT=\"$(dirname \"$0\")/%s\"\n\n", cloudInitFile)

	b.WriteString("# Auth is env-only (never on argv): SCW_SECRET_KEY + SCW_DEFAULT_PROJECT_ID.\n")
	b.WriteString(": \"${SCW_SECRET_KEY:?set SCW_SECRET_KEY (and SCW_DEFAULT_PROJECT_ID)}\"\n")
	b.WriteString("if ! command -v scw >/dev/null 2>&1; then\n")
	b.WriteString("  echo \"error: scw CLI not found — install: https://github.com/scaleway/scaleway-cli\" >&2\n")
	b.WriteString("  exit 127\n")
	b.WriteString("fi\n")
	b.WriteString("if [ ! -f \"$CLOUD_INIT\" ]; then\n")
	b.WriteString("  echo \"error: cloud-init not found at $CLOUD_INIT\" >&2\n")
	b.WriteString("  exit 1\n")
	b.WriteString("fi\n\n")

	b.WriteString("# Create + boot the edge with the generated cloud-init as user-data.\n")
	b.WriteString("scw instance server create \\\n")
	b.WriteString("  zone=\"$ZONE\" type=\"$TYPE\" image=\"$IMAGE\" name=\"$NAME\" \\\n")
	b.WriteString("  ip=new cloud-init=@\"$CLOUD_INIT\"\n\n")

	b.WriteString("# The server boots and runs cloud-init (builds Caddy + brings up WireGuard, starts\n")
	b.WriteString("# services; first boot takes a few minutes). Take the public IP printed above and\n")
	b.WriteString("# repoint the migrated DNS at it — e.g. flareover prepare --edge-ip <that-ip>.\n")
	return []byte(b.String())
}
