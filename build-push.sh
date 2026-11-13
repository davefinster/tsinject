#!/usr/bin/env bash
# build-push.sh — manual escape hatch: build the amd64 operator image and
# push it to GitHub Container Registry. Normal releases go through CI (the
# build workflow pushes :main/:sha-<short>; the promote workflow mints vN),
# so the default here is a scratch tag that cannot clobber a release.
#
#   ./build-push.sh                          # ghcr.io/davefinster/tsinject:dev
#   ./build-push.sh ghcr.io/davefinster/tsinject:v2
#   IMAGE=<ref> ./build-push.sh              # same, via env
#
# One-time setup: a GitHub PAT with the write:packages scope, then
#   docker login ghcr.io -u davefinster
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE="${1:-${IMAGE:-ghcr.io/davefinster/tsinject:dev}}"

runtime=""
command -v docker >/dev/null 2>&1 && runtime=docker
[[ -z "$runtime" ]] && command -v podman >/dev/null 2>&1 && runtime=podman
[[ -n "$runtime" ]] || { echo "ERROR: need docker or podman on PATH" >&2; exit 1; }

echo ">> building $IMAGE (linux/amd64 — cross-compiling Go build stage, no emulation)"
"$runtime" build --platform linux/amd64 -t "$IMAGE" .

echo ">> pushing $IMAGE"
"$runtime" push "$IMAGE"

echo ">> done: $IMAGE"
