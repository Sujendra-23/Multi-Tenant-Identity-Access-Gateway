#!/usr/bin/env bash
# Disposable local/CI cluster only. Never use a current production context.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${KIND_CLUSTER:?}" "${KUBECONFIG:?}" "${BOOTSTRAP_KEY:?}"
: "${BASELINE_IMAGE:?}" "${CANDIDATE_IMAGE:?}" "${UPSTREAM_IMAGE:?}"

kind create cluster --name "$KIND_CLUSTER" --kubeconfig "$KUBECONFIG" --wait 120s \
  --image kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f
kind load docker-image --name "$KIND_CLUSTER" "$BASELINE_IMAGE" "$CANDIDATE_IMAGE" "$UPSTREAM_IMAGE"
k() { kubectl --context "kind-$KIND_CLUSTER" -n identity-gateway "$@"; }
k apply -f deploy/k8s/00-namespace.yaml
k create secret generic identity-gateway-secrets \
  --from-literal=POSTGRES_USER=postgres_bootstrap \
  --from-literal=POSTGRES_DB=gateway \
  --from-literal="POSTGRES_PASSWORD=$(openssl rand -hex 24)" \
  --from-literal="GATEWAY_APP_PASSWORD=$(openssl rand -hex 24)" \
  --from-literal="REDIS_PASSWORD=$(openssl rand -hex 24)" \
  --from-literal="BOOTSTRAP_KEY=$BOOTSTRAP_KEY"
k apply -f deploy/k8s/02-configmap.yaml
# Only this disposable cluster changes backend/reconciliation/login capacity.
k patch configmap identity-gateway-config --type merge -p \
  '{"data":{"FEATURE_FLAGS_BACKEND":"redis","FEATURE_FLAGS_SYNC_INTERVAL":"1s","LOGIN_RATE_BURST":"100","LOGIN_RATE_LIMIT":"20"}}'
k create configmap postgres-init-scripts --from-file=deploy/postgres-init/01-app-role.sh
k apply -f deploy/k8s/03-postgres.yaml
k apply -f deploy/k8s/04-redis.yaml
k rollout status statefulset/postgres --timeout=180s
k rollout status deployment/redis --timeout=180s

# Render before apply so no pod ever starts with a mutable :latest image.
sed "s#identity-gateway-gateway:latest#$BASELINE_IMAGE#" deploy/k8s/05-gateway.yaml | k apply -f -
sed "s#identity-gateway-upstream:latest#$UPSTREAM_IMAGE#" deploy/k8s/06-upstream.yaml | k apply -f -
k apply -f deploy/k8s/07-networkpolicy.yaml
k rollout status deployment/gateway --timeout=180s
k rollout status deployment/upstream --timeout=180s
