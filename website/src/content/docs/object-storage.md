---
title: "Object Storage"
description: "flareover migrates object storage (Cloudflare R2 or any S3-compatible source) to self-hosted MinIO or a managed EU S3 provider. It generates a"
---

flareover migrates object storage (Cloudflare **R2** or any **S3**-compatible source) to self-hosted **MinIO** or a managed EU **S3** provider. It generates a `provision.sh` (using `mc`, the MinIO client, which speaks plain S3) plus an **rclone** plan to copy the data as a separate step.

```bash
flareover storage buckets.json --dest scaleway --region fr-par --out ./out
sh ./out/scaleway-object-storage/provision.sh   # creates buckets + versioning + lifecycle + CORS
# then run the emitted rclone plan to copy the objects
```

Buckets can be captured first with `--extract-r2` / `--extract-s3`.

## Destinations

| `--dest` | Provider | Endpoint | Regions | Env |
|----------|----------|----------|---------|-----|
| `minio` (default) | Self-hosted MinIO | `--minio-endpoint <url>` | — | your MinIO creds |
| `scaleway` | Scaleway (EU-owned) | `s3.<region>.scw.cloud` | `fr-par`, `nl-ams`, `pl-waw`, `it-mil` | `SCW_ACCESS_KEY`, `SCW_SECRET_KEY` |
| `ovh` | OVHcloud (EU-owned) | `s3.<region>.io.cloud.ovh.net` | `gra`, `sbg`, `de`, `waw` | `OVH_S3_ACCESS_KEY`, `OVH_S3_SECRET_KEY` |
| `contabo` | Contabo (EU-owned, DE) | `eu2.contabostorage.com` | `eu2` | `CONTABO_S3_ACCESS_KEY`, `CONTABO_S3_SECRET_KEY` |
| `aruba` | Aruba (EU-owned, IT) | **operator-supplied** via `--minio-endpoint` | — | `ARUBA_S3_ACCESS_KEY`, `ARUBA_S3_SECRET_KEY` |

> **Aruba's endpoint is account-specific.** Aruba publishes no fixed region host — its S3 endpoint is the *Service Point URL* from your Object Storage account page. flareover requires you to pass it (`--minio-endpoint`) rather than guessing it; if it's missing, the command errors clearly. (Guessing an endpoint would risk emitting wrong config — against the whole contract.)

All managed destinations are **EU-region-scoped**: non-EU regions are rejected so the migration provably stays in the EU.

## What maps

| Bucket feature | Becomes |
|----------------|---------|
| Bucket | `mc mb` |
| Versioning | `mc version enable` |
| Lifecycle **expiry** (> 0 days) | `mc ilm rule add --expire-days N` |
| CORS rules | `mc cors set` (a CORS artifact is emitted alongside) |
| **Public read** | An **ASK** — reproduced only on explicit confirmation (`mc anonymous set download`) |

## What does not map (surfaced, never guessed)

- **Lifecycle transitions** (storage-class tiering) — MinIO has no tiering target here → **MANUAL**.
- **Zero-expiry lifecycle rules** (e.g. multipart-abort or noncurrent-version only) — no MinIO ILM equivalent → **MANUAL**.
- **IAM / bucket policies** — S3 policy semantics differ from MinIO's; translate by hand → **MANUAL**.

## Data copy

flareover generates the **rclone** commands to copy objects between the source and destination; the data movement itself is a separate, explicit step you run when ready (it can be large and slow). Configuration (buckets, versioning, lifecycle, CORS) is applied by `provision.sh`; objects are moved by rclone.
