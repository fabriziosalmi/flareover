# Hardened Proxmox landing zone

The reference deployment flareover targets, and the exact topology used to
migrate a real domain off Cloudflare end-to-end. It is optional (a plain single
host works too), but it is how you deploy the sovereign edge with a **zero-inbound
origin**: the backend is reachable only through the edge, never from the internet.

```
            internet
               │  :80/:443
        ┌──────▼───────────────────────────┐
        │  Host (public IP)                 │   DNAT :80/:443 → edge
        │  Ubuntu / Proxmox                 │
        │   ┌───────────────┐  ┌──────────┐ │
        │   │ EDGE (Caddy)  │  │ ORIGIN   │ │
        │   │ vmbr0 public  │  │ nginx/…  │ │
        │   │ vmbr1 internal├──┤ vmbr1    │ │   origin has NO public leg
        │   └───────────────┘  └──────────┘ │
        │      caddy-waf          isolated  │   vmbr1 = internal, NAT-out only
        │      souin cache        zero-in   │
        └───────────────────────────────────┘
```

## The two tiers

- **`vmbr0`**: routable/public tier. The **edge** LXC (Caddy + caddy-waf + souin)
  has a leg here and is the only thing the host forwards public :80/:443 to.
- **`vmbr1` (e.g. `10.44.44.0/24`)**: isolated internal tier, NAT-out only (a
  single `MASQUERADE -s 10.44.44.0/24 -o vmbr0` on the host). The **origin** lives
  *only* here: it can reach out (apt, ACME callbacks aren't needed on the origin),
  but nothing on the internet can reach it. The edge reaches it over its `vmbr1`
  leg. This is the zero-inbound guarantee.

Both LXCs are **unprivileged** with minimal `features` (nesting only where a
workload needs it): Fabrizio's standard isolation posture.

## Bringing it up

1. **Origin LXC** on `vmbr1` only (static IP, gw = the internal bridge). Run the
   app (nginx, an app server, …) on `:80`. No public NIC.
2. **Edge LXC** dual-homed: `net0` on `vmbr0` (public-facing), `net1` on `vmbr1`
   (to the origin). Install the flareover-generated Caddy (custom build:
   `xcaddy build --with github.com/fabriziosalmi/caddy-waf --with github.com/darkweak/souin/plugins/caddy`).
3. **Expose the edge** on the host's public IP with a one-hop DNAT:
   ```
   iptables -t nat -A PREROUTING -i <pubif> -p tcp --dport 443 -j DNAT --to <edge>:443
   iptables -t nat -A PREROUTING -i <pubif> -p tcp --dport 80  -j DNAT --to <edge>:80
   ```
   Prefer one-hop (host → edge directly): the host is the LXC's gateway, so the
   return path is symmetric and the **real client IP is preserved** (better for
   WAF/geo).
4. **Certificates**: with DNS pointing at the public IP and :80 forwarded,
   Caddy's automatic ACME (HTTP-01) issues real Let's Encrypt certs. **Wildcards
   need DNS-01**: use CertMate against PowerDNS for `*.zone`.
5. **Migrate**: `flareover prepare` → deploy the config → `flareover execute`
   (parity gate) → flip DNS. Rollback stays one command away.

## Gotchas (learned the hard way, so you don't)

- **`ufw` / Docker own the FORWARD chain** (policy DROP). Appended ACCEPT rules
  never run: **insert at the top** (`iptables -I FORWARD 1 …`) plus a
  `--ctstate ESTABLISHED,RELATED -j ACCEPT` for the return path.
- **Cloudflare Tunnel over a nested NAT**: QUIC (UDP/7844) is often blocked, so
  `cloudflared` hangs on `dial to edge with quic`. Force TCP with
  `protocol: http2` in the tunnel config. flareover's tunnel tooling sets this
  by default.
- **`https://origin:80` is invalid**: an origin answer may carry an explicit
  scheme (`http://host:80`); flareover honors it so `caddy validate` passes.
- **A `*.zone` site defers all subdomain certs to the wildcard cert**: if that
  needs DNS-01 and it isn't set up, the named subdomains get no cert. Handle the
  wildcard via CertMate DNS-01, or exclude it.
- **Pre-cutover certs must use the *source* DNS provider.** DNS-01 writes the
  `_acme-challenge` TXT where the zone actually resolves. Before you move the NS
  to PowerDNS, the zone still answers at the source (e.g. Cloudflare), so the
  bootstrap cert has to be issued through *that* provider. Pass
  `flareover provision --certmate-dns cloudflare`; re-issue with `powerdns` only
  after the NS have moved. The default is `powerdns` (the post-cutover steady
  state).
- **CertMate shells out to `certbot`**: the container needs `certbot` **and**
  the matching DNS plugin (`python3-certbot-dns-cloudflare`,
  `…-dns-rfc2136` for PowerDNS) on `PATH`, or issuance fails with
  `No such file or directory: 'certbot'` even though the API call was correct.
- **CertMate's API bearer token must be 32–512 chars.** A shorter token is
  silently rejected on save and the instance falls back to **unauthenticated
  admin** (every request served as admin). Set a ≥32-char `API_BEARER_TOKEN`
  *and* create an admin user before exposing it; keep it on an isolated,
  inbound-only-from-your-mesh network regardless.
- **MinIO lifecycle rule IDs are not preserved.** `mc ilm rule add` lets MinIO
  assign a fresh rule ID, so a rule extracted as `media/expire-tmp` re-provisions
  as `media/<random>`. The **semantics are identical** (same prefix, same expiry):
  the ID is an internal handle, not behavior. So this stays inside the 0%FP
  contract, but don't be surprised the IDs differ across a round-trip.
