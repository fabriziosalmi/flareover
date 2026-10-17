# deploy/: turnkey EU landing zone

The #1 friction in a migration is *"where do I run the target?"*. This is a
`docker compose` stack that stands the whole EU target up in one command and
consumes the artifacts `flareover prepare` generates, so `provision` has
something to talk to.

It is the containerized twin of [Hardened Proxmox landing zone](https://www.flareover.com/docs/hardened-deploy/)
(the bare-metal / Proxmox hardening guide).

## What it runs

| Service | Role | Port (localhost) |
|---------|------|------------------|
| **PowerDNS** | authoritative DNS + REST API | `8081` (API), `53` (DNS) |
| **Caddy** | reverse proxy · caddy-waf · souin · HTTP/3 (custom build) | `80`, `443` |
| **CertMate** | DNS-01 wildcard certificates | `8000` (API) |
| **Garage** | S3-compatible object storage (replaces MinIO, archived upstream) | `3900` (S3 API), `3902` (web endpoint), `3903` (admin) |
| **secure-proxy-manager** | outbound egress shield (optional) | `3128` |

Caddy (`80`/`443`) and PowerDNS (`53`, authoritative: it must be publicly
reachable to serve the zone) are internet-facing; every admin/API surface
(PowerDNS `8081`, CertMate `8000`, Garage `3900`/`3902`/`3903`, SPM `3128`) is bound to
`127.0.0.1`.

## Use it

```sh
# 1. generate the target config
flareover prepare snap.json --decisions decisions.lock --edge-ip <public-ip> --out ./out

# 2. secrets
cp .env.example .env && $EDITOR .env      # PDNS_API_KEY, CERTMATE_TOKEN, GARAGE_RPC_SECRET, GARAGE_ADMIN_TOKEN

# 3. stand it up (the --build compiles the custom Caddy once)
docker compose up -d --build

# 3b. once: give Garage its cluster layout and create the key `flareover`
#     (optional argument: the node's capacity, default 100G; safe to re-run)
./garage-init.sh

# 4. provision your target (the DNS zone + certs) via its APIs.
#    Secrets come from the environment only, never argv (the .env already
#    defines PDNS_API_KEY / CERTMATE_TOKEN):
set -a; . ./.env; set +a
flareover provision --snapshot snap.json --decisions decisions.lock \
  --pdns-url http://localhost:8081 \
  --certmate-url http://localhost:8000

# object storage, if any: export what garage-init.sh printed, then
export GARAGE_CLI="docker compose exec -T garage /garage" GARAGE_KEY=flareover
#   GARAGE_ACCESS_KEY / GARAGE_SECRET_KEY from:
#   docker compose exec -T garage /garage key info flareover --show-secret
flareover storage buckets.json --minio-endpoint http://127.0.0.1:3900 --out ./out
bash ./out/garage/provision.sh       # needs the AWS CLI v2 (`aws`) on PATH
```

Caddy live-reloads the bind-mounted Caddyfile; re-run `prepare --out ./out` and it
picks up the change.

## Gotchas

**Object storage is Garage, not MinIO.** MinIO is archived upstream and
`quay.io/minio/minio` answers `401`, so an older copy of this compose or `.env`
no longer starts. The `garage` service runs `dxflrs/garage:v2.4.1`, pinned via
`GARAGE_IMAGE`. Its secrets live in `.env`: `GARAGE_RPC_SECRET` must be 32 bytes
as hex (`openssl rand -hex 32`), and `GARAGE_ADMIN_TOKEN` guards the admin API.

**Garage serves nothing until `./garage-init.sh` has run.** A fresh node has no
cluster layout, and `/health` on `127.0.0.1:3903` answers `503` until it does.
The script applies the layout, creates the key `flareover` (override with
`GARAGE_KEY`) with permission to create buckets, and prints the exports the
generated `garage/provision.sh` needs; `/health` then answers `200`.

**Set the web root domain.** [`garage.toml`](garage.toml) is a single node with
`replication_factor = 1` and S3 signing region `garage`. Buckets confirmed
public are served by Garage's web endpoint as `<bucket>.<web root domain>`
(port `3902`), not by anonymous S3 GETs. The shipped web root domain is
`.web.garage.localhost`: change it to your own domain and route that domain to
`3902` from Caddy.

**Port 53 is probably already taken.** Ubuntu, Debian and Fedora run
systemd-resolved, whose stub listener holds `127.0.0.53:53`. Publishing DNS on
`0.0.0.0:53` collides with it and the container never starts:

```
Error response from daemon: failed to set up container networking: driver failed
programming external connectivity ... failed to bind host port for 0.0.0.0:53:
address already in use
```

Two ways out. Bind only the address that will actually serve DNS —
`DNS_BIND=203.0.113.10` in `.env` — or free port 53 on the host, which is what
an edge dedicated to this stack wants:

```sh
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

(Found by the smoke workflow, on a runner that has exactly this configuration.)

## Keep the guard running

After the cutover the guard is the entire recovery mechanism, and started from a
shell it dies with a closed terminal, an SSH drop or a reboot — silently, since
a guard that is quietly healthy and a guard that is gone produce the same absent
output. [`flareover-guard.service`](flareover-guard.service) supervises it:

```sh
sudo cp flareover-guard.service /etc/systemd/system/
sudo systemctl edit flareover-guard     # set FLAREOVER_GUARD_URL and the rollback hook
sudo systemctl enable --now flareover-guard
systemctl is-active flareover-guard     # the answer to "is anything still watching?"
```

It runs with `--keep-watching` (the default fire-once behaviour is right for a
CI gate, not for a watchdog) and `--log-json`, so journald gets structured
records including `trigger-completed` / `trigger-failed` with the elapsed time.

## Back it up

The eight volumes are not equal, and which is which is not guessable. The five
in this table hold state that cannot be regenerated from anything else you have:

| Volume | Holds | If you lose it |
|--------|-------|----------------|
| `pdns-data` | the authoritative zone **and the DNSSEC signing keys** | the zone stops resolving, and the DS record at your registrar points at keys that no longer exist |
| `certmate-data` + `certs` | issued certificates and issuance state | re-issuance, and rate limits at the CA |
| `garage-meta` + `garage-data` | the migrated objects and the index that finds them (back up both, together) | possibly the only remaining copy, once the source bucket is gone |

`caddy-data`, `caddy-config` and `spm-data` are disposable: re-running
`flareover prepare` plus a restart rebuilds them.

Snapshot the five that matter, with the stack stopped (sqlite and Garage both
dislike being copied mid-write):

```sh
docker compose stop
for v in pdns-data certmate-data certs garage-meta garage-data; do
  docker run --rm -v flareover_$v:/data -v "$PWD/backup:/backup" alpine \
    tar czf "/backup/$v.tgz" -C /data .
done
docker compose start
```

Restore is the same in reverse (`tar xzf` into a fresh volume) — do it before
the first `docker compose up`, so `pdns-init` sees an existing database and
leaves it alone.

**What a good restore looks like:** the zone is back *and its DNSSEC signing key
is the one you backed up*. The zone alone is not enough — a zone that returns
with a new key is a zone whose DS record at your registrar no longer validates,
which fails silently for every resolver that checks. Confirm both:

```sh
curl -sf -H "X-API-Key: $PDNS_API_KEY" \
  "http://localhost:8081/api/v1/servers/localhost/zones/<zone>./cryptokeys" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["dnskey"])'
```

`deploy-smoke.yml` runs exactly this round trip on every change to this
directory and fails the build if the key differs.

## Upgrading

Image versions are pinned in `.env`, not floating on `:latest`. To upgrade, edit
the version there, `docker compose up -d`, and check the service. To go back,
put the previous version back and do the same — which only works because the
previous version is written down. Take the backup above first: a major version
of PowerDNS or Garage may migrate its on-disk format, and that is not reversible.

## Confirm before you trust it (the live-proof)

**The PowerDNS half is now proven, not assumed.** Bringing this stack up
revealed that the API had never worked: the compose set `PDNS_api_key` /
`PDNS_webserver*`, names this image reads nowhere, so
`provision --pdns-url http://localhost:8081` met a closed port. With
`PDNS_AUTH_API_KEY` and the webserver arguments on the command line, a real run
against the shipped stack now gets:

```
✓ DNS zone  4 records (PowerDNS (self-hosted)), DNSSEC signed (3 DS)
```

— zone created, records applied, zone signed with ECDSAP256SHA256, and the API
restricted to `127.0.0.1,172.28.0.0/16` rather than `0.0.0.0/0`, with every
service under `cap_drop: ALL` and `no-new-privileges`.
`.github/workflows/deploy-smoke.yml` re-runs that assertion on every change to
this directory, so it cannot silently regress.

The rest still wants a lab run — the same Tier-A bar the rest of flareover meets
(see [`../docs/live-proof.md`](../docs/live-proof.md)):

- **The capability tightening.** Every service runs with `no-new-privileges` and
  `cap_drop: ALL`, with capabilities added back only where the image's entrypoint
  needs them (binding 53/80/443, and the privilege drop PowerDNS does itself).
  The smoke test covers PowerDNS and Garage; if you swap `CERTMATE_IMAGE` or
  `SPM_IMAGE` for an image with a different entrypoint, confirm it still starts.
- **CertMate image + certbot plugins.** Point `CERTMATE_IMAGE` at your published
  image; it must carry `certbot` and the matching DNS plugin
  (`certbot-dns-rfc2136` for PowerDNS) on `PATH`, or issuance fails.
- **secure-proxy-manager image.** Set `SPM_IMAGE`, or comment the `spm` service out.
- **Wildcards need DNS-01.** Pre-cutover the zone still answers at the source, so
  issue against it first: `provision --certmate-dns cloudflare`; switch to
  `powerdns` after the nameservers have moved.

`docker compose config` validates the file; `docker compose up` proves it.
