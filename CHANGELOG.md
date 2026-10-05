# Changelog

Notable changes per release, written for somebody upgrading. The generated
release notes list every commit; this lists what you have to do about them.

flareover is pre-1.0: a minor version may change an exit code or raise the Go
floor, and this file says so when it does. Nothing changes the meaning of an
existing flag without a deprecation first.

## Unreleased

### Changed

- **The release archive ships the hardened-deploy guide as
  `docs/hardened-deploy.md`**, not `docs/deploy-hardened.md`. The guide moved
  into the docs site ([Hardened Proxmox landing zone](https://www.flareover.com/docs/hardened-deploy/)),
  alongside the keep-your-origin walkthrough
  ([Keep your origin](https://www.flareover.com/docs/keep-your-origin/)), which
  was only on GitHub before. A script that reads the old path from an unpacked
  archive needs the new name.

## v0.4.0 — 2026-09-16

### Breaking

- **`extract` now exits `10` on a partial capture.** It previously exited `0`
  whether or not it had read everything, with the unreadable surfaces reported
  only on stderr — which a shell pipeline routinely discards. A chain like
  `flareover extract example.com > zone.json && flareover assess zone.json` now
  stops at the extraction rather than two commands later. The snapshot is still
  written and records each gap. If you want the old behaviour, branch on the
  code: `flareover extract … || [ $? -eq 10 ]`.
- **Go 1.26 is now the floor** (was 1.25), and the toolchain is pinned to
  `go1.26.8` in `go.mod`. This only affects building from source; released
  binaries are unaffected. The move was not cosmetic: `govulncheck` reported
  eighteen reachable standard-library advisories against the toolchain
  previously in use, and none against this one.
- **`--ca` is now validated** against the two values it has always documented
  (`letsencrypt`, `actalis`). A typo used to travel to CertMate as a certificate
  authority name and fail at issuance time; it now fails at parse time with
  exit 2.
- **`--edge-ip` is now validated** as an IPv4 address. A malformed value used to
  become the content of every de-proxied A record.

### Security

- The deploy stack's PowerDNS API **never started**: the compose set
  `PDNS_api_key` / `PDNS_webserver*`, names that image does not read, so
  `provision --pdns-url http://localhost:8081` met a closed port. Fixed, and a
  CI job now asserts the API answers and a zone can be created.
- `PDNS_webserver_allow_from` was `0.0.0.0/0`, held off the internet only by the
  port binding — every container on the internal network could reach the zone's
  control plane. It is now restricted to loopback plus the declared subnet.
- Every deploy service runs with `no-new-privileges` and `cap_drop: ALL`, with
  capabilities added back only where the image's entrypoint needs them.
- **The deploy stack could not pull MinIO at all**: `minio/minio` no longer
  resolves on Docker Hub. `MINIO_IMAGE` now points at `quay.io/minio/minio`,
  where MinIO actually publishes.
- Service images are pinned in `.env` instead of floating on `:latest`. PowerDNS
  moves to 4.9.17; 4.9.9 printed "Security Update Mandatory" on every start.
- `prepare` writes a `mesh/.gitignore` beside the generated WireGuard keys, and
  the docs that tell you to review `./out` in git now say in the same sentence
  that the mesh configs must not be committed.
- The guard no longer echoes your `--on-unhealthy` command into its event
  stream; it emits the program name and a length instead. A rollback hook often
  carries a token, and `--log-json` ships that to a collector.
- `provision` and `doctor` warn when `--pdns-url` or `--certmate-url` is plain
  `http` to a non-local host, because the API key crosses the network in
  cleartext.

### Fixed

- A snapshot written before `schema_version` 2 could not declare an extraction
  gap, so an unread Cloudflare Access surface was indistinguishable from a zone
  with no Access apps — and the plan builder reads that emptiness to decide a
  host needs no identity gate. Such a snapshot is now reported MANUAL.
- A Cloudflare rule scoped to a path containing whitespace rendered as
  `path /a b*`, which Caddy reads as **two** patterns — broader than the rule it
  came from, and classified AUTO. Such a scope now degrades to MANUAL.
- An Access app on a wildcard domain (`*.internal.example.com`) gated nothing,
  because the domain was stored verbatim as a map key.
- Header names reached the Caddyfile through a bare `%s` while their values were
  quoted; they are now validated as RFC 7230 tokens.
- `cost --vps` discarded its parse error, so `--vps 12,50` became 12 and
  `--vps twelve` silently compared against a stack costing nothing.
- A `decisions.lock` key matching no question in the snapshot behaved exactly
  like an unanswered question; it is now reported.
- Object-storage extraction recorded a failed read of a bucket's versioning,
  CORS, lifecycle or policy as the feature being **absent**. Those are now
  recorded as gaps and reported MANUAL. A bucket snapshot loaded from a file is
  also decoded strictly, version-checked and validated, as the zone snapshot
  already was.
- `429` and `5xx` from the Cloudflare API are retried with bounded backoff and
  then named as themselves; the extraction-gap remedy is chosen from the cause
  rather than telling you to widen a token for every failure.
- The Leaseweb provisioner reads an rrset before its delete-then-create
  replacement and restores it if the create fails.
- The guard resolves `bash` (then `sh`) with `LookPath` before it starts
  watching, instead of discovering it missing when the rollback fires.
- Port 53 collides with `systemd-resolved` on most Linux hosts; `DNS_BIND` lets
  the compose stack bind a specific address, and the collision is documented.

### Added

- `deploy/flareover-guard.service`: a supervised guard, with `Restart=always`.
- Backup and restore procedures for the deploy stack, with the volumes
  classified into what cannot be regenerated and what can.
- `govulncheck` in CI and in the release workflow; `make vuln` runs the same
  pinned version.
- `flareover version` reports the commit, whether the tree was dirty, and when.
- `extract` reports how long it took.
- The ten DNS endpoint-override environment variables, and the ceilings the tool
  imposes on itself, are documented in the DNS Targets page.

## v0.3.0

See the [release notes](https://github.com/fabriziosalmi/flareover/releases/tag/v0.3.0).

## v0.2.0

See the [release notes](https://github.com/fabriziosalmi/flareover/releases/tag/v0.2.0).
