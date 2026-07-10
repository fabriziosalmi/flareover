# Scenario: keep your origin, re-tunnel it off Cloudflare

The lowest-risk way to leave Cloudflare, and the one most self-hosters actually need.

## When this is you

You run **Cloudflare in front of an origin you reach with a Cloudflare Tunnel** (`cloudflared`):
a homelab box, an on-prem server, a VM that has no public inbound. You want off Cloudflare, but
the origin **can't or shouldn't move**: it's where your app lives.

You don't migrate the origin. You **swap the edge and the tunnel**, and leave the origin where it is.

## Topology

```
              visitors
                  │  DNS: A/AAAA → edge IP(s)   (round-robin for HA)
                  ▼
        ┌──────────────┐   ┌──────────────┐
        │  EDGE node 1 │   │  EDGE node 2 │   Caddy + caddy-waf + souin
        │  (EU VPS)    │   │  (EU VPS)    │   generated from your Cloudflare zone
        └──────┬───────┘   └──────┬───────┘
               └────────┬─────────┘
                        │  WireGuard mesh  =  a sovereign Cloudflare Tunnel
                        ▼
               ┌──────────────────┐
               │  ORIGIN (on-prem)│   UNCHANGED. still zero inbound.
               │   your app       │   only the tunnel agent changes:
               └──────────────────┘   cloudflared → wg-quick
```

## Why it's the safest migration

The origin (the app, the risky part) **is not touched**. The only behavioural surface that
changes is the edge, which flareover rebuilds deterministically from your zone, and the tunnel,
which becomes WireGuard. Nothing about how your app runs changes. Honest scope: the app is
identical; the *tunnel agent* on the origin swaps from `cloudflared` to WireGuard: one service
in, one service out.

## Steps

1. **Generate** the edge + tunnel. One edge:

   ```bash
   flareover prepare zone.snapshot.json --edge-ip <edge-public-ip> \
     --mesh-edge <edge-public-ip>:51820 --out ./out
   ```

   HA: several edges, one per public entry point (name them for readable configs):

   ```bash
   flareover prepare zone.snapshot.json \
     --mesh-edge hetzner=5.9.1.1:51820 \
     --mesh-edge aws-milano=18.2.3.4:51820 --out ./out
   ```

2. **Deploy each edge** on an EU node. Pick a provider with eyes open: `flareover providers` lists
   them by honest sovereignty tier (EU-owned vs a hyperscaler's EU region under US jurisdiction).
   Add `--edge-provider <key>` to step 1 and flareover emits a ready-to-paste **cloud-init** per edge
   (`edge/cloud-init[-<name>].yaml`) that installs the Caddy build, writes the generated Caddyfile +
   `wg0.conf`, opens a fail-closed firewall, and starts everything. Name each edge after its provider
   (`--mesh-edge hetzner=…`) and every node is stamped with its own tier:

   ```bash
   flareover prepare zone.snapshot.json \
     --mesh-edge hetzner=5.9.1.1:51820 --mesh-edge aws-milano=18.2.3.4:51820 \
     --edge-provider hetzner --out ./out
   # → out/edge/cloud-init-hetzner.yaml (sovereign) and cloud-init-aws-milano.yaml (flagged: US CLOUD Act)
   ```

   Prefer to do it by hand? Install the generated Caddy config, open `udp/51820`, `wg-quick up wg0`.

3. **Re-tunnel the origin** (nothing else on it changes):

   ```bash
   # on the origin
   systemctl disable --now cloudflared      # stop the old tunnel
   cp origin.wg0.conf /etc/wireguard/wg0.conf
   wg-quick up wg0                          # dials every edge, keepalive holds it
   ```

   The origin now answers the edge(s) at its mesh IP (`10.99.0.254:80`), outbound-only, zero
   inbound, exactly as under Cloudflare Tunnel.

4. **Parity-gate, then cut over.** `flareover present --after-addr <edge-ip>:443` proves the new
   edge behaves like the old one before you move DNS; then flip the records to the edge IP(s).

5. **Guard it.** `flareover guard --url https://<host> --on-unhealthy "<rollback-or-failover>"`
   health-checks the edge and fires your trigger. With multiple edges, pull a failed one from
   round-robin DNS and the survivors keep serving.

## What's HA and what isn't (no faking)

Multiple edges make the **edge** highly available: several public front doors, all meshed to the
same origin, distributed by DNS and health-gated by `guard`. The **origin's** own redundancy is
yours to provide: if it's a single box, it's a single point of failure, and flareover says so
rather than inventing redundancy that isn't there.
