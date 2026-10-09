#!/usr/bin/env bash
# Validate the Prometheus alert rules: syntax, config wiring, and unit tests.
#
#   ./scripts/check-alerts.sh
#
# Uses a local `promtool` if one is on PATH; otherwise runs promtool from the
# same Prometheus image docker-compose uses (needs Docker, no install).
#
# This checks that the rules are valid and behave as intended on synthetic
# series (deploy/prometheus/alerts_test.yml). It cannot show that they fire on
# real traffic; see docs/runbooks/login-failure-spike.md for what has and has
# not been exercised against a running gateway.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR="deploy/prometheus"
IMAGE="${PROMTOOL_IMAGE:-prom/prometheus:v2.55.1}"

if command -v promtool >/dev/null 2>&1; then
  echo "using local promtool: $(promtool --version | head -1)"
  promtool check rules "$DIR/alerts.yml"
  promtool test rules "$DIR/alerts_test.yml"
elif command -v docker >/dev/null 2>&1; then
  echo "using promtool from $IMAGE"
  promtool() {
    docker run --rm --entrypoint promtool -v "$PWD/$DIR:/etc/prometheus:ro" "$IMAGE" "$@"
  }
  # Inside the container the files sit where prometheus.yml expects them, so the
  # config check also proves rule_files points at a real, valid file.
  promtool check config /etc/prometheus/prometheus.yml
  promtool test rules /etc/prometheus/alerts_test.yml
else
  echo "need either promtool or docker on PATH" >&2
  exit 2
fi
echo "alert rules OK"
