#!/usr/bin/env bash
# Build once, then load the exact same images for rollback and promotion.
set -euo pipefail
cd "$(dirname "$0")/../.."

candidate_sha=$(git rev-parse HEAD)
baseline_sha=$(git rev-parse HEAD^)
export CANDIDATE_IMAGE="identity-gateway-gateway:$candidate_sha"
export BASELINE_IMAGE="identity-gateway-gateway:baseline-$baseline_sha"
export UPSTREAM_IMAGE="identity-gateway-upstream:$candidate_sha"

baseline_dir=$(mktemp -d)
trap 'rm -rf "$baseline_dir"' EXIT
git archive "$baseline_sha" | tar -x -C "$baseline_dir"
docker build --build-arg BINARY=gateway --label "org.opencontainers.image.revision=$baseline_sha" -t "$BASELINE_IMAGE" "$baseline_dir"
docker build --build-arg BINARY=gateway --label "org.opencontainers.image.revision=$candidate_sha" -t "$CANDIDATE_IMAGE" .
docker build --build-arg BINARY=upstream --label "org.opencontainers.image.revision=$candidate_sha" -t "$UPSTREAM_IMAGE" .

# Also usable locally: CI_IMAGE_ENV points at an env file to source afterwards.
env_file=${GITHUB_ENV:-${CI_IMAGE_ENV:?Set CI_IMAGE_ENV when running locally}}
printf 'CANDIDATE_IMAGE=%s\nBASELINE_IMAGE=%s\nUPSTREAM_IMAGE=%s\n' \
  "$CANDIDATE_IMAGE" "$BASELINE_IMAGE" "$UPSTREAM_IMAGE" >> "$env_file"
