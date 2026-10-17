#!/usr/bin/env bash
# One-time bootstrap of the Garage node in this compose stack, safe to re-run:
#   1. give the node a role in the cluster layout and apply it (until then
#      Garage serves nothing and /health answers 503);
#   2. create the key the generated garage/provision.sh grants buckets to.
# Usage: ./garage-init.sh [capacity]   (default 100G: the node's share, not a quota)
set -euo pipefail
cd "$(dirname "$0")"
capacity="${1:-100G}"
key_name="${GARAGE_KEY:-flareover}"
# RUST_LOG=warn: the CLI logs every connection at INFO, which buries the result.
g() { docker compose exec -T -e RUST_LOG=warn garage /garage "$@"; }

for _ in $(seq 1 30); do
  g status >/dev/null 2>&1 && break
  sleep 1
done
g status >/dev/null

if g status | grep -q "NO ROLE ASSIGNED"; then
  node="$(g status | awk '/NO ROLE ASSIGNED/ {print $1; exit}')"
  current="$(g layout show | awk -F': ' '/Current cluster layout version/ {print $2}')"
  g layout assign -z dc1 -c "$capacity" "$node"
  g layout apply --version "$((current + 1))"
  echo "layout applied: node $node, capacity $capacity"
else
  echo "layout already applied"
fi

if g key info "$key_name" >/dev/null 2>&1; then
  echo "key $key_name already exists"
else
  g key create "$key_name" >/dev/null
  echo "key $key_name created"
fi
g key allow --create-bucket "$key_name" >/dev/null

cat <<MSG
Garage is ready. For the generated garage/provision.sh:
  export GARAGE_CLI="docker compose exec -T garage /garage" GARAGE_KEY=$key_name
  export GARAGE_ACCESS_KEY / GARAGE_SECRET_KEY from:
    docker compose exec -T garage /garage key info $key_name --show-secret
MSG
