---
title: "Object Storage"
description: "Migrate Cloudflare R2 or any S3 bucket to self-hosted Garage (default), an existing MinIO, or an EU provider (Scaleway, OVH, Contabo, Aruba): buckets, versioning, lifecycle, CORS, and an rclone data copy."
---

flareover migrates object storage (Cloudflare **R2** or any **S3**-compatible source) to self-hosted **Garage** (the default), an existing **MinIO** server, or a managed EU **S3** provider. It generates a `provision.sh` that uses the **AWS CLI v2** (`aws s3api ... --endpoint-url`), which speaks plain S3 to any endpoint, plus an **rclone** plan to copy the data as a separate step.

```bash
# default destination: self-hosted Garage (here, the deploy/ compose stack)
flareover storage buckets.json --minio-endpoint http://127.0.0.1:3900 --out ./out
bash ./out/garage/provision.sh   # creates buckets + grants + lifecycle + CORS
# then run ./out/rclone/migrate.sh to copy the objects
```

Buckets can be captured first with `--extract-r2` / `--extract-s3`.

> **Why Garage, not MinIO.** MinIO is archived upstream (the `minio/minio` and `minio/mc` repositories are archived), the `mc` client download answers `410` and `quay.io/minio/minio` answers `401`. flareover therefore defaults to Garage and no longer needs `mc` for any destination. `--dest minio` remains for an existing MinIO server you already run.

## Destinations

| `--dest` | Provider | Endpoint | Regions | Env |
|----------|----------|----------|---------|-----|
| `garage` (default) | Self-hosted Garage | `--minio-endpoint <url>` | signing region `garage` | `GARAGE_ACCESS_KEY`, `GARAGE_SECRET_KEY`, `GARAGE_KEY`, `GARAGE_CLI` |
| `minio` | An existing self-hosted MinIO | `--minio-endpoint <url>` | signing region `us-east-1` | `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` |
| `scaleway` | Scaleway (EU-owned) | `s3.<region>.scw.cloud` | `fr-par`, `nl-ams`, `pl-waw`, `it-mil` | `SCW_ACCESS_KEY`, `SCW_SECRET_KEY` |
| `ovh` | OVHcloud (EU-owned) | `s3.<region>.io.cloud.ovh.net` | `gra`, `sbg`, `de`, `waw` | `OVH_S3_ACCESS_KEY`, `OVH_S3_SECRET_KEY` |
| `contabo` | Contabo (EU-owned, DE) | `eu2.contabostorage.com` | `eu2` | `CONTABO_S3_ACCESS_KEY`, `CONTABO_S3_SECRET_KEY`, `S3_REGION` |
| `aruba` | Aruba (EU-owned, IT) | **operator-supplied** via `--minio-endpoint` | n/a | `ARUBA_S3_ACCESS_KEY`, `ARUBA_S3_SECRET_KEY`, `S3_REGION` |

`--minio-endpoint` keeps its historical name but sets the S3 endpoint for any destination.

> **Aruba's endpoint is account-specific.** Aruba publishes no fixed region host: its S3 endpoint is the *Service Point URL* from your Object Storage account page. flareover requires you to pass it (`--minio-endpoint`) rather than guessing it; if it's missing, the command errors clearly. (Guessing an endpoint would risk emitting wrong config, against the whole contract.)

All managed destinations are **EU-region-scoped**: non-EU regions are rejected so the migration provably stays in the EU.

### Signing region

The script signs its S3 requests with a region. `S3_REGION` in the environment always overrides it. Without it, the defaults are `garage` for Garage, `us-east-1` for MinIO, and the selected region for Scaleway and OVH. **Contabo and Aruba require `S3_REGION`**: their signing region is not guessed, and the script stops with an error naming the variable if it is unset.

## Verdicts per destination

What is AUTO depends on what the destination implements. The Garage column was measured against Garage v2.4.1.

| Bucket feature | Garage | MinIO, Scaleway, OVH, Contabo, Aruba |
|----------------|--------|--------------------------------------|
| Bucket | **AUTO**: `garage bucket create` (global alias) + `garage bucket allow --read --write --owner` to `GARAGE_KEY` | **AUTO**: `aws s3api create-bucket` |
| Versioning | **MANUAL**: Garage answers `NotImplemented` to `PutBucketVersioning` | **AUTO**: `put-bucket-versioning` |
| CORS rules | **AUTO**: `put-bucket-cors` | **AUTO**: `put-bucket-cors` |
| Lifecycle **expiry** (> 0 days) | **AUTO**: `put-bucket-lifecycle-configuration` | **AUTO**: `put-bucket-lifecycle-configuration` |
| Lifecycle transitions, or no positive expiry | **MANUAL** | **MANUAL** |
| **Public read** | **ASK**: served through Garage's web endpoint (`put-bucket-website`) | **ASK**: a public-read bucket policy (`put-bucket-policy`) |
| Attached bucket / IAM policy | **MANUAL**: Garage has no bucket policies | **MANUAL** |

### Garage specifics

- **Buckets are created with the Garage CLI, not over S3.** A bucket created through S3 `CreateBucket` gets only a key-local alias, invisible to the web endpoint and to every other key. The script creates each bucket with `garage bucket create` (a global alias) and grants it to the key named by `GARAGE_KEY`. Point `GARAGE_CLI` at the Garage CLI (default `garage`); with the bundled compose stack, `GARAGE_CLI="docker compose exec -T garage /garage"`.
- **No versioning.** A versioned source bucket migrates without versioning: earlier versions are not copied and overwrites become final. That is a MANUAL finding, so a snapshot with versioned buckets exits with the MANUAL code (`10`) on the default destination. Choose a destination that versions (`--dest minio|scaleway|ovh|contabo|aruba`), or accept the loss explicitly.
- **Public read goes through the web endpoint.** Garage has no ACLs or bucket policies, and anonymous S3 GETs stay `403`. A confirmed public bucket is put in website mode and served by Garage's web endpoint as `<bucket>.<web root domain>`, so its **public URLs change**. Set the web root domain in `garage.toml` to your own domain and route it to the web port from Caddy (see [Deploy](/docs/deploy/)).
- **Access is per key, per bucket.** An attached S3 policy has no Garage equivalent: translate it into `garage bucket allow` grants by hand.

## What the run produces

Under `--out`, in a folder named after the destination (`garage/`, `minio/`, `scaleway-object-storage/`, `ovh-object-storage/`, `contabo-object-storage/`, `aruba-object-storage/`):

| Artifact | Purpose |
|----------|---------|
| `<dir>/provision.sh` | The bash script that applies the AUTO and answered-ASK settings. Idempotent: safe to re-run. |
| `<dir>/cors/<bucket>.json` | CORS document in the AWS JSON shape `put-bucket-cors` reads |
| `<dir>/lifecycle/<bucket>.json` | Expiry rules in the AWS JSON shape `put-bucket-lifecycle-configuration` reads |
| `<dir>/policy/<bucket>.json` | Public-read bucket policy, only for a confirmed public bucket on a non-Garage destination |
| `rclone/migrate.sh` | The rclone data-copy plan |

## How to run it

1. **Generate.** `flareover storage buckets.json --dest <id> [--region <r>] [--minio-endpoint <url>] --decisions decisions.lock --out ./out`. The report prints every verdict; the exit code is `0` (all AUTO), `11` (ASKs to answer) or `10` (MANUAL items).
2. **Set the environment.** The AWS CLI v2 must be on `PATH`. Export the destination's key pair from the table above, plus `S3_REGION` for Contabo and Aruba. For Garage also `GARAGE_KEY` and, unless the `garage` binary is on `PATH`, `GARAGE_CLI`. With the [`deploy/` stack](/docs/deploy/), `./garage-init.sh` creates the key `flareover` and prints these exports.
3. **Provision.** `bash ./out/<dir>/provision.sh`.
4. **Copy the data.** Configure the two rclone remotes named in `rclone/migrate.sh`, then run it.

## Data copy

flareover generates the **rclone** commands to copy objects between the source and destination; the data movement itself is a separate, explicit step you run when ready (it can be large and slow). Configuration (buckets, grants, versioning, lifecycle, CORS, confirmed public read) is applied by `provision.sh`; objects are moved by rclone. Run `rclone/migrate.sh` once to seed, and again to catch up before cutover.
