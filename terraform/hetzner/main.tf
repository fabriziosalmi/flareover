# flareover — Hetzner Cloud edge node.
#
# Boots a Caddy + WireGuard edge from the cloud-init flareover generates with
#   flareover prepare … --edge-provider hetzner --mesh-edge <ip>:<port>
# which writes <out>/edge/cloud-init.yaml. That file installs Caddy and
# WireGuard and drops the generated config in place; this module just stands up
# the server, firewall and SSH key to run it on Hetzner (EU-owned, sovereign).
#
# The cloud-init carries the mesh WireGuard private key, so it is a SECRET —
# keep <out>/ out of version control.

terraform {
  required_version = ">= 1.5"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

# Break-glass admin key for the edge (cloud-init also configures WireGuard).
resource "hcloud_ssh_key" "edge" {
  name       = "${var.name}-key"
  public_key = var.ssh_public_key
}

# The edge serves HTTP/HTTPS (+ HTTP/3 over UDP 443) and terminates the
# WireGuard mesh. Origin traffic rides the tunnel, so no origin ports are
# exposed. SSH is closed by default — set ssh_source_ips to your admin CIDRs.
resource "hcloud_firewall" "edge" {
  name = "${var.name}-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "443" # HTTP/3 (QUIC)
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  rule {
    direction  = "in"
    protocol   = "udp"
    port       = tostring(var.wireguard_port)
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  dynamic "rule" {
    for_each = length(var.ssh_source_ips) > 0 ? [1] : []
    content {
      direction  = "in"
      protocol   = "tcp"
      port       = "22"
      source_ips = var.ssh_source_ips
    }
  }
}

resource "hcloud_server" "edge" {
  name         = var.name
  server_type  = var.server_type
  image        = var.image
  location     = var.location
  ssh_keys     = [hcloud_ssh_key.edge.id]
  firewall_ids = [hcloud_firewall.edge.id]

  # The flareover-generated cloud-init (edge/cloud-init.yaml). Secret input.
  user_data = file(var.cloud_init_path)

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  labels = {
    managed_by = "flareover"
    role       = "edge"
  }
}
