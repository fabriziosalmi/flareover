output "edge_ipv4" {
  description = "Public IPv4 of the edge: pass it to `flareover prepare --edge-ip <this>` and use it as the WireGuard endpoint."
  value       = hcloud_server.edge.ipv4_address
}

output "edge_ipv6" {
  description = "Public IPv6 of the edge."
  value       = hcloud_server.edge.ipv6_address
}

output "next_steps" {
  description = "What to do after apply."
  value = join(" ", [
    "Edge booting at ${hcloud_server.edge.ipv4_address}.",
    "Point the mesh/DNS at it, then run `flareover present --after-addr ${hcloud_server.edge.ipv4_address}:443`",
    "(the parity gate) before any cutover.",
  ])
}
