#!/usr/bin/env bash
# End-to-end smoke test against a running docker-compose stack.
#
# Exercises the properties that matter most in this project, against the real
# gateway, real Postgres and real Redis — not mocks:
#   - tenant bootstrap + multi-tenant RBAC (owner vs. read-only member)
#   - zero-trust continuous verification (step-up under the risk engine)
#   - refresh-token rotation with reuse detection and family-wide revocation
#   - the reverse proxy's dual trust model (headers + independently-verified JWT)
#   - the tamper-evident audit chain
#
# Usage:
#   docker compose up -d
#   ./scripts/smoke-test.sh
#
# Requires: curl, python3 (used only for JSON parsing/pretty-printing).
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
BOOTSTRAP_KEY="${BOOTSTRAP_KEY:-local-dev-bootstrap-key-0123456789}"
TENANT_SLUG="smoketest-$(date +%s)"  # unique per run so re-runs never collide on the slug uniqueness constraint
PASS="a-strong-enough-test-password-1"

pass=0
fail=0

note()  { printf '\n\033[1;34m== %s ==\033[0m\n' "$1"; }
ok()    { printf '  \033[1;32mOK\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad()   { printf '  \033[1;31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

json_get() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)"; }

# req METHOD PATH [TENANT] [TOKEN] [BODY] — sets $STATUS and $BODY.
#
# Deliberately does its own curl call and its own status/body split inline,
# rather than returning a value for the caller to pass into a second function
# (the previous shape was `req ...`). The bash shipped on
# macOS is 3.2.57 — frozen there since 2007 over GPLv3 licensing, not a
# hypothetical old version — and it has a real, reproducible bug where a
# `$(functionA ...)` substitution passed directly as an argument to another
# function call silently truncates an inner argument at its first embedded
# comma once that argument contains escaped quotes, instead of erroring. A
# plain local assignment (`local raw; raw=$(...)`) does not trigger it, which
# is what this version relies on throughout.
req() {
  local method="$1" path="$2" tenant="${3:-}" token="${4:-}" body="${5:-}"
  local args=(-s -w '\n%{http_code}' -X "$method" "$BASE_URL$path")
  [ -n "$tenant" ] && args+=(-H "X-Tenant: $tenant")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" -d "$body")
  fi
  local raw
  raw=$(curl "${args[@]}")
  STATUS="${raw##*$'\n'}"
  BODY="${raw%$'\n'*}"
}

# rawreq is req's escape hatch for the couple of calls that need a header req
# can't express (a bad bootstrap key, no X-Tenant at all). Same internal
# capture pattern, same reason.
rawreq() {
  local raw
  raw=$(curl -s -w '\n%{http_code}' "$@")
  STATUS="${raw##*$'\n'}"
  BODY="${raw%$'\n'*}"
}

note "0. Waiting for the gateway to report ready"
for _ in $(seq 1 30); do
  if curl -sf "$BASE_URL/readyz" >/dev/null 2>&1; then break; fi
  sleep 1
done
rawreq "$BASE_URL/readyz"
[ "$STATUS" = "200" ] && ok "gateway is ready" || { bad "gateway never became ready"; exit 1; }

# Built as plain variables rather than inlined across a line-continued
# `$(req ... \` call: bash has a real, documented-by-reproduction parsing
# hazard where a backslash-newline continuation *inside* a $(...) command
# substitution can corrupt a later argument that itself contains escaped
# quotes — it silently truncates at the first embedded comma instead of
# raising an error. Every JSON body in this script is assembled on its own
# line first and referenced by name, which sidesteps the hazard entirely
# rather than fighting it with single-line calls that just move where the
# same trap could reappear.
new_tenant_body() {
  # new_tenant_body SLUG NAME EMAIL PASSWORD
  printf '{"slug":"%s","name":"%s","admin":{"email":"%s","password":"%s"}}' "$1" "$2" "$3" "$4"
}

note "1. Confirming tenant provisioning is gated by the bootstrap key"
BODY1=$(new_tenant_body "should-not-exist" "x" "a@b.test" "$PASS")
req POST /v1/admin/tenants "" "" "$BODY1"
[ "$STATUS" = "401" ] && ok "missing bootstrap key rejected (401)" || bad "expected 401, got $STATUS"
rawreq -X POST "$BASE_URL/v1/admin/tenants" -H "X-Bootstrap-Key: wrong-key" -H "Content-Type: application/json" -d "$BODY1"
[ "$STATUS" = "401" ] && ok "wrong bootstrap key rejected (401)" || bad "expected 401, got $STATUS"

note "2. Provisioning tenant '${TENANT_SLUG}' with an owner (correct key)"
BODY2=$(new_tenant_body "$TENANT_SLUG" "Smoke Test Co B" "owner@${TENANT_SLUG}.test" "$PASS")
rawreq -X POST "$BASE_URL/v1/admin/tenants" -H "X-Bootstrap-Key: $BOOTSTRAP_KEY" -H "Content-Type: application/json" -d "$BODY2"
if [ "$STATUS" = "201" ]; then ok "tenant created"; else bad "tenant creation returned $STATUS: $BODY"; exit 1; fi

OWNER_EMAIL="owner@${TENANT_SLUG}.test"
note "3. Logging in as owner"
req POST /v1/auth/login "${TENANT_SLUG}" "" "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$PASS\"}"
if [ "$STATUS" = "200" ]; then ok "login succeeded"; else bad "login returned $STATUS: $BODY"; exit 1; fi
ACCESS=$(echo "$BODY" | json_get "['access_token']")
REFRESH0=$(echo "$BODY" | json_get "['refresh_token']")

note "4. Wrong password is rejected without revealing whether the account exists"
req POST /v1/auth/login "${TENANT_SLUG}" "" "{\"email\":\"$OWNER_EMAIL\",\"password\":\"wrong-password-entirely\"}"
[ "$STATUS" = "401" ] && ok "wrong password rejected (401)" || bad "expected 401, got $STATUS"
req POST /v1/auth/login "${TENANT_SLUG}" "" "{\"email\":\"nobody-like-this@exists.test\",\"password\":\"whatever12345\"}"
[ "$STATUS" = "401" ] && ok "unknown user also rejected with the same 401 (no user-enumeration oracle)" || bad "expected 401, got $STATUS"

note "5. Creating a read-only member (may require step-up under the risk engine)"
VIEWER_BODY=$(printf '{"email":"viewer@%s.test","password":"%s","display_name":"Viewer"}' "$TENANT_SLUG" "$PASS")
req POST /v1/users "${TENANT_SLUG}" "$ACCESS" "$VIEWER_BODY"
if [ "$STATUS" = "403" ] && echo "$BODY" | grep -q step_up_required; then
  ok "risk engine required step-up for this sensitive action (expected on a fresh session)"
  req POST /v1/auth/step-up "${TENANT_SLUG}" "$ACCESS" "{\"password\":\"$PASS\"}"
  [ "$STATUS" = "200" ] && ok "step-up succeeded" || { bad "step-up failed: $STATUS $BODY"; exit 1; }
  ACCESS=$(echo "$BODY" | json_get "['access_token']")
  req POST /v1/users "${TENANT_SLUG}" "$ACCESS" "$VIEWER_BODY"
fi
if [ "$STATUS" = "201" ]; then ok "member user created"; else bad "user creation returned $STATUS: $BODY"; exit 1; fi
VIEWER_ID=$(echo "$BODY" | json_get "['id']")

note "6. Assigning the built-in read-only 'member' role"
req GET /v1/roles "${TENANT_SLUG}" "$ACCESS"
MEMBER_ROLE_ID=$(echo "$BODY" | python3 -c "import sys,json; print([r['id'] for r in json.load(sys.stdin)['roles'] if r['name']=='member'][0])")
req POST /v1/roles/assignments "${TENANT_SLUG}" "$ACCESS" "{\"user_id\":\"$VIEWER_ID\",\"role_id\":\"$MEMBER_ROLE_ID\"}"
[ "$STATUS" = "200" ] && ok "member role assigned" || bad "role assignment returned $STATUS: $BODY"

note "7. RBAC boundary: member can read, cannot write"
req POST /v1/auth/login "${TENANT_SLUG}" "" "{\"email\":\"viewer@${TENANT_SLUG}.test\",\"password\":\"$PASS\"}"
VACCESS=$(echo "$BODY" | json_get "['access_token']")
req GET /v1/users "${TENANT_SLUG}" "$VACCESS"
[ "$STATUS" = "200" ] && ok "member can read users (200)" || bad "expected 200, got $STATUS"
req POST /v1/users "${TENANT_SLUG}" "$VACCESS" "{\"email\":\"nope@x.test\",\"password\":\"$PASS\"}"
[ "$STATUS" = "403" ] && ok "member cannot create users (403, RBAC deny)" || bad "expected 403, got $STATUS"

note "8. Refresh-token rotation and reuse detection"
req POST /v1/auth/refresh "${TENANT_SLUG}" "" "{\"refresh_token\":\"$REFRESH0\"}"
[ "$STATUS" = "200" ] && ok "normal rotation succeeds" || { bad "rotation failed: $STATUS $BODY"; exit 1; }
T1=$(echo "$BODY" | json_get "['refresh_token']")

req POST /v1/auth/refresh "${TENANT_SLUG}" "" "{\"refresh_token\":\"$REFRESH0\"}"
[ "$STATUS" = "401" ] && ok "replaying the already-consumed token is rejected (401)" || bad "expected 401, got $STATUS"

req POST /v1/auth/refresh "${TENANT_SLUG}" "" "{\"refresh_token\":\"$T1\"}"
if [ "$STATUS" = "401" ]; then
  ok "the legitimately-rotated sibling token is ALSO invalidated by the replay (family-wide revocation)"
else
  bad "sibling token still worked after reuse detection (got $STATUS) — the family was not actually revoked"
fi

note "9. Zero-trust reverse proxy: headers + independently-verified JWT"
req POST /v1/auth/login "${TENANT_SLUG}" "" "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$PASS\"}"
ACCESS=$(echo "$BODY" | json_get "['access_token']")
req POST /v1/auth/step-up "${TENANT_SLUG}" "$ACCESS" "{\"password\":\"$PASS\"}"
ACCESS=$(echo "$BODY" | json_get "['access_token']")
req GET /v1/proxy/demo/hello "${TENANT_SLUG}" "$ACCESS"
if [ "$STATUS" = "200" ] && echo "$BODY" | json_get "['token_independently_verified']" | grep -qi true; then
  ok "upstream received identity headers and independently verified the forwarded JWT via JWKS"
else
  bad "proxy call did not yield an independently-verified token: $STATUS $BODY"
fi

note "10. Audit chain integrity"
# The audit writer batches to Postgres on a timer (AUDIT_FLUSH_INTERVAL,
# 2s by default — see internal/audit/logger.go) rather than writing inline on
# every request, which is what keeps the hash-chain append off the hot path.
# This script runs every step above well within that window, so without
# waiting here, /v1/audit/verify would truthfully report "valid" over zero
# events instead of the dozen-plus this run actually generated.
sleep 3
req GET /v1/audit/verify "${TENANT_SLUG}" "$ACCESS"
if [ "$STATUS" = "200" ] && echo "$BODY" | json_get "['valid']" | grep -qi true; then
  events=$(echo "$BODY" | json_get "['events_checked']")
  ok "hash chain verifies intact across $events events"
else
  bad "chain verification failed or reported invalid: $STATUS $BODY"
fi

echo ""
echo "============================================"
printf ' Results: \033[1;32m%d passed\033[0m, \033[1;31m%d failed\033[0m\n' "$pass" "$fail"
echo "============================================"
[ "$fail" -eq 0 ]
