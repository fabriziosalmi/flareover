# Live-proof runbook (Tier A)

Every DNS, storage, and edge adapter in flareover is **unit-tested and
wire-verified** (the request shapes are asserted against each provider's
documented API / SDK, and a CLI end-to-end drives the real binary against a mock).
That is **Tier B**. It is not proof.

The bar is **Tier A: proven against the real running service.** Mocks have missed
9 real bugs before — a provider's actual API rejects a value a mock happily
accepted, normalizes a name, requires a field, or applies a change on a delay.
This runbook makes that bar executable: run it against **throwaway accounts and a
disposable test domain** before trusting an adapter in a real migration.

Each adapter section lists the **specific assumption** the mock could not
confirm — watch those first.

---

## 0. Setup (once)

```sh
# Build the binary under test.
go build -o flareover ./cmd/flareover

# A disposable snapshot to drive everything. Either the sanitized fixture…
SNAP=testdata/fixtures/conformance.snapshot.json
DEC=testdata/fixtures/conformance.decisions.json
# …or a real read-only extract of a THROWAWAY zone you control:
#   CLOUDFLARE_API_TOKEN=<read-only> ./flareover extract test.example > snap.json
```

Use a **test domain you can delegate and throw away** (e.g. a spare
`flareover-proof.<tld>`). Never run the provisioners against a production zone
until the adapter is Tier-A green here.

Ground rule for every DNS adapter: **run `provision` twice.** A correct adapter
is idempotent — the second run must converge with **no duplicate records**. This
is the single most important check (it exercises the REPLACE semantics a mock
cannot).

---

## 1. bunny.net DNS  (`prepare --dns bunny` → `apply.sh`)

**Assumption to confirm:** `bunny dns records import` idempotency — flareover's
note warns a re-import *may duplicate* records. Confirm or refute it.

```sh
# Install the CLI (or: npm i -g @bunny.net/cli)
curl -fsSL https://cli.bunny.net/install.sh | sh
export BUNNYNET_API_KEY=<throwaway key>

./flareover prepare "$SNAP" --decisions "$DEC" --dns bunny --out out/
sh out/bunny-dns/apply.sh          # zones add + records import + (dnssec) + nameservers
```

**Expect:** the zone is created; every record from `out/bunny-dns/<zone>.zone`
appears in `bunny dns records list <zone>`; the printed nameservers match.

**Watch / prove:**
- Re-run `sh out/bunny-dns/apply.sh`. Inspect `bunny dns records list`. **If
  records duplicated**, the note is correct → keep the "fresh zone only" caveat.
  **If not**, import is idempotent → relax the note.
- If the zone requested DNSSEC: `bunny dns zones dnssec enable` printed a DS —
  publish it at the registrar and verify with `dig +dnssec DS <zone>`.

---

## 2. Scaleway DNS  (`provision --dns scaleway`)

**Assumption to confirm:** zone **auto-create vs. 409** tolerance, and the
`set`/`id_fields` REPLACE (re-run must not duplicate).

```sh
export SCW_SECRET_KEY=<throwaway> SCW_DEFAULT_PROJECT_ID=<project-uuid>
./flareover provision --snapshot "$SNAP" --decisions "$DEC" --dns scaleway
./flareover provision --snapshot "$SNAP" --decisions "$DEC" --dns scaleway   # idempotency
```

**Expect:** `✓ DNS zone  N records (Scaleway) · delegate NS at registrar: …`.
Both runs succeed; the second is a no-op REPLACE.

**Watch / prove:**
- First run on a brand-new external domain: does the explicit `POST /dns-zones`
  create succeed, or return a conflict the code tolerates? Confirm the zone lands
  in the right project.
- `dig @<scaleway-ns> <apex> A` and an MX/TXT/SRV each — confirm values match the
  preview `out/scaleway-dns/<zone>.zone`, and the **apex name is empty** (not `@`)
  in the Scaleway console.
- Re-run → `bunny`/console shows **no duplicate rrsets**.

---

## 3. OVHcloud DNS  (`provision --dns ovh`)

**Assumption to confirm:** the **signed-request clock skew** (`/auth/time`
delta) and the **refresh timing** (records visible only after the zone refresh).

```sh
export OVH_APPLICATION_KEY=<k> OVH_APPLICATION_SECRET=<s> OVH_CONSUMER_KEY=<c>
# OVH_ENDPOINT defaults to https://eu.api.ovh.com/1.0
./flareover provision --snapshot "$SNAP" --decisions "$DEC" --dns ovh
./flareover provision --snapshot "$SNAP" --decisions "$DEC" --dns ovh   # idempotency (delete+recreate+refresh)
```

**Expect:** `✓ DNS zone  N records (OVHcloud) · delegate NS at registrar: …`.

**Watch / prove:**
- The signature must be accepted — a wrong `/auth/time` delta yields HTTP 403.
  Confirm on a machine whose clock is a few minutes off, too.
- After the run, `dig @<ovh-ns> <record>` — records appear only because the code
  issued `POST …/refresh`. Confirm nothing is stale.
- Re-run → per-(subDomain,fieldType) delete-then-create leaves **exactly one**
  set (no accumulation).

---

## 4. Gandi LiveDNS  (`provision --dns gandi`)

**Assumption to confirm:** **TXT quoting** (flareover sends BIND-quoted values via
`rrset_values`), the **apex `@`** path, and the **TTL clamp** to ≥300.

```sh
export GANDI_PAT=<personal access token>
# The domain must be attached to LiveDNS first.
./flareover provision --snapshot "$SNAP" --decisions "$DEC" --dns gandi
./flareover provision --snapshot "$SNAP" --decisions "$DEC" --dns gandi   # PUT is REPLACE → idempotent
```

**Watch / prove:**
- `dig @<gandi-ns> <apex> TXT` — the SPF/TXT value must round-trip **without
  double-quoting**. If Gandi stored `"\"v=spf1…\""`, the quoting is wrong → send
  the raw value instead.
- A record with a sub-300 TTL was clamped to 300 — confirm Gandi accepted it
  (no 4xx) and `dig` shows TTL 300.
- The apex rrset is `PUT …/records/@/A` — confirm it lands on the apex, not a
  literal `@` label.

---

## 5. Leaseweb DNS  (`provision --dns leaseweb`)

**Assumption to confirm:** **TXT raw** (unquoted) `content`, the **POST-dotted /
DELETE-undotted** name asymmetry, and **404-on-delete** tolerance on a fresh zone.

```sh
export LEASEWEB_API_KEY=<throwaway>
# The Leaseweb DNS domain must already exist.
./flareover provision --snapshot "$SNAP" --decisions "$DEC" --dns leaseweb
./flareover provision --snapshot "$SNAP" --decisions "$DEC" --dns leaseweb   # delete-then-create REPLACE
```

**Watch / prove:**
- First run on an empty zone: the `DELETE …/resourceRecordSets/<name>/<type>`
  returns 404 and must be **tolerated** (not abort). Confirm the POSTs still run.
- Re-run: the DELETE (undotted name) must match the record the POST created
  (dotted name). If the second run **duplicates** instead of replacing, the
  name form is off → align POST and DELETE naming.
- `dig <apex> TXT` — value unquoted and correct.

---

## 6. Scaleway / OVH Object Storage  (`storage --dest <p>`)

**Assumption to confirm:** the generated `mc` script drives the provider's S3 for
**versioning / lifecycle / CORS / public-read** (all standard S3 ops, but confirm
the endpoint accepts each). The **0%-FP public guard** must hold — a public
bucket stays private unless explicitly answered `yes`.

```sh
# Scaleway
export SCW_ACCESS_KEY=<k> SCW_SECRET_KEY=<s>
./flareover storage buckets.json --dest scaleway --region fr-par --out out/
sh out/scaleway-object-storage/provision.sh    # needs the `mc` client on PATH

# OVH (EU regions only: gra|sbg|de|waw)
export OVH_S3_ACCESS_KEY=<k> OVH_S3_SECRET_KEY=<s>
./flareover storage buckets.json --dest ovh --region gra --out out/
sh out/ovh-object-storage/provision.sh
```

**Watch / prove:**
- `mc ls <alias>` — buckets exist; `mc version info` — versioning where expected;
  `mc ilm rule ls` — lifecycle; `mc cors get` — CORS.
- A bucket that was public at the source stays **private** unless you answered
  `public-read:<bucket>=yes`. This is the storage 0%-FP guard — verify it holds.
- Then seed data with `sh out/rclone/migrate.sh` (two rclone remotes configured).

---

## 7. Scaleway / OVH edge instance  (`--edge-provider <p>`)

**Assumption to confirm:** the create script actually boots a working edge —
cloud-init compiles Caddy (caddy-waf + souin), brings up the WireGuard mesh, and
the firewall is fail-closed. **A paid server is created — use the smallest flavor
and destroy it after.**

```sh
# Scaleway (scw CLI)
export SCW_SECRET_KEY=<k> SCW_DEFAULT_PROJECT_ID=<uuid>
./flareover prepare "$SNAP" --decisions "$DEC" --edge-ip 0.0.0.0 \
  --mesh-edge scaleway=<origin-ip>:51820 --edge-provider scaleway --out out/
sh out/edge/create-scaleway.scaleway.sh    # prints the public IP

# OVH (openstack CLI + sourced openrc.sh)
export OVH_EDGE_FLAVOR=d2-4
./flareover prepare "$SNAP" --decisions "$DEC" --edge-ip 0.0.0.0 \
  --mesh-edge ovh=<origin-ip>:51820 --edge-provider ovh --out out/
sh out/edge/create-ovh.ovh.sh
```

**Watch / prove:**
- The instance reaches `running`; SSH/console shows cloud-init finished without
  error (`cloud-init status --wait`), Caddy built and started
  (`/usr/local/bin/caddy version`), `wg show` has a peer.
- `ufw status` is fail-closed: only 22/80/443 tcp + 51820 udp.
- `curl -I http://<edge-ip>` reaches Caddy; the mesh carries traffic to the
  origin (origin has **no public inbound**).
- **Destroy the instance** when done.

---

## Pass criteria (an adapter is Tier-A green when…)

- [ ] `provision`/`apply` succeeds against the real API on a fresh test zone.
- [ ] `dig`/`mc`/`curl` confirms the applied state **matches the preview** byte-for-intent.
- [ ] **Re-running converges** — no duplicate records / rrsets / buckets.
- [ ] The adapter's named **assumption** (above) is confirmed, or the code/notes
      are corrected to match reality.
- [ ] Any capability gap (DNSSEC not automated, etc.) is surfaced honestly, never silent.

Record the result per adapter (date, provider, pass/notes) — that log is what
turns "wire-verified" into "proven live", the standard the rest of flareover
already meets.
