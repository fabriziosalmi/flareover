variable "hcloud_token" {
  description = "Hetzner Cloud API token (project-scoped). Export as TF_VAR_hcloud_token; never commit it."
  type        = string
  sensitive   = true
}

variable "cloud_init_path" {
  description = "Path to the cloud-init flareover emits (prepare --edge-provider hetzner → <out>/edge/cloud-init.yaml). Carries the mesh private key: keep it secret."
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key for break-glass admin access to the edge."
  type        = string
}

variable "name" {
  description = "Server + resource name."
  type        = string
  default     = "flareover-edge"
}

variable "server_type" {
  description = "Hetzner server type (e.g. cx22, cpx11)."
  type        = string
  default     = "cx22"
}

variable "image" {
  description = "Base image. The cloud-init assumes a Debian/Ubuntu family (apt)."
  type        = string
  default     = "debian-12"
}

variable "location" {
  description = "Hetzner location: keep it in the EU for sovereignty (nbg1/fsn1 = Germany, hel1 = Finland)."
  type        = string
  default     = "fsn1"
}

variable "wireguard_port" {
  description = "UDP port the edge WireGuard listens on (match --mesh-edge <ip>:<port>)."
  type        = number
  default     = 51820
}

variable "ssh_source_ips" {
  description = "CIDRs allowed to reach SSH (22/tcp). Default: none (manage via the Hetzner console). Set to your admin IPs."
  type        = list(string)
  default     = []
}
