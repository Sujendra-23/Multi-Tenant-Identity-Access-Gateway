# Multi-Tenant Identity & Access Gateway

A backend service that plays the role Cisco ISE plays in a real network: every
request re-proves who it is and what it's allowed to do, on every hop, rather
than trusting a session token as a standing grant. Built in Go, backed by
Postgres and Redis, deployed on Kubernetes, observed with Prometheus/Grafana.

This exists to demonstrate, with working code rather than a resume line, four
things: multi-tenant RBAC with real database-level isolation, JWT session
management with rotation and reuse detection, continuous (zero-trust) request
verification, and per-tenant rate limiting/audit logging with the observability
stack to watch it happen.

## Table of contents

- [What this actually demonstrates](#what-this-actually-demonstrates)
- [Architecture](#architecture)
- [Quick start (docker compose)](#quick-start-docker-compose)
- [Authentication flows](#authentication-flows)
- [Seeing it work](#seeing-it-work)
- [Kubernetes](#kubernetes)
- [Alerts and on-call runbook](#alerts-and-on-call-runbook)
- [Testing](#testing)
- [API reference](#api-reference)
- [Configuration reference](#configuration-reference)
- [Design decisions and trade-offs](#design-decisions-and-trade-offs)
- [Known limitations](#known-limitations--what-id-do-next)
- [Repository layout](#repository-layout)

## What this actually demonstrates

| Requirement | Where it lives |
|---|---|
| Multi-tenant RBAC, scoped per tenant | Postgres row-level security (`internal/store/postgres/migrations/0002_rls.sql`) is the enforcement boundary, not just an app-layer `WHERE tenant_id = ?`. RBAC evaluation: `internal/authz/rbac.go`. |
| JWT session management with token rotation | Ed25519-signed access tokens with automatic key rotation (`internal/auth/keyring.go`), opaque single-use refresh tokens with atomic rotation and replay detection (`internal/store/redisstore/sessions.go`). |
| Zero-trust request verification | Every authenticated request re-checks token liveness, tenant match, policy currency, and a continuous risk score — not just signature validity. `internal/httpapi/middleware/auth.go`, `internal/authz/risk.go`. |
| Rate limiting + audit logging per tenant | Layered token-bucket limits (IP → user → tenant → login) in Redis (`internal/store/redisstore/ratelimit.go`); an append-only, hash-chained, tamper-evident audit log per tenant (`internal/store/postgres/audit.go`). |
| TLS and mutual TLS | HTTPS on the API (TLS 1.2+, AEAD suites only) and mTLS from the proxy to upstreams, pinned to an internal CA with no fallback to system roots; certificates hot-reload on rotation (`internal/tlsconfig/`). |
| Hot-reloadable tenant feature flags | Stable percentage rollouts and tenant overrides; local `SIGHUP` reloads or revision-checked admin updates propagated through Redis pub/sub with periodic reconciliation (`internal/featureflags/`). |
| Kubernetes/EKS | Full manifest set in `deploy/k8s/`, validated end-to-end against a real cluster (see [Kubernetes](#kubernetes)). |
| Prometheus/Grafana | `internal/observability/`, dashboard at `deploy/grafana/dashboards/identity-gateway.json`, alert rules at `deploy/prometheus/alerts.yml` and an on-call [runbook](docs/runbooks/login-failure-spike.md). |

## Architecture

```mermaid
flowchart LR
    client[Client] -->|"Bearer JWT + X-Tenant"| gw[Gateway]

    subgraph gw[Identity Gateway]
        direction TB
        m1[RequestID / SecurityHeaders] --> m2[IP rate limit]
        m2 --> m3[Tenant resolver]
        m3 --> m4[Authenticate: sig + liveness + tenant match]
        m4 --> m5[Policy-version check]
        m5 --> m6[User / tenant rate limit]
        m6 --> m7[RBAC: RequirePermission]
        m7 --> m8[Risk engine: allow / step-up / deny]
        m8 --> handler[Route handler]
    end

    handler --> pg[(Postgres<br/>source of truth + RLS)]
    handler --> redis[(Redis<br/>sessions, rate limits,<br/>policy cache, risk history)]
    handler -->|"proxy: headers + forwarded JWT"| up[Upstream service]
    up -.->|"verifies JWT independently"| jwks[/.well-known/jwks.json/]
    handler --> audit[Async audit writer] --> pg
```

Two things about this pipeline are load-bearing, not decorative:

- **Every stage can say no**, and each one checks something the earlier stages
  structurally cannot: signature validity doesn't imply the session is still
  alive; a live session doesn't imply the permission wasn't just revoked; a
  granted permission doesn't imply *this particular request* isn't behaving
  like a stolen credential.
- **Postgres enforces tenant isolation itself**, via row-level security with
  `FORCE ROW LEVEL SECURITY` and a fail-closed default (no tenant context set
  → zero rows, not all rows). Application code still scopes every query, but a
  query that forgot its `WHERE` clause is caught by the database, not by code
  review. This is covered by integration tests that intentionally omit the
  `WHERE` clause and confirm the database still returns nothing — see
  `internal/store/postgres/rls_test.go`.

## Quick start (docker compose)

Requires Docker. Nothing else — Go toolchain not required to run it.

```bash
cd "Multi-Tenant Identity & Access Gateway"
cp .env.example .env        # a working .env with local-dev defaults already exists too
docker compose up -d
```

This starts Postgres, Redis, the gateway (ports `8080` API / `9090` metrics), a
demo upstream service, Prometheus (`:9091`), and Grafana (`:3000`,
`admin` / value of `GRAFANA_ADMIN_PASSWORD` in `.env`).

The gateway applies its own database migrations and bootstraps its first
signing key on startup — there's no separate migration step to run.

**Before anything else works**, look at `deploy/postgres-init/01-app-role.sh`.
It creates the restricted Postgres role the gateway actually connects as. This
is not incidental setup — it is the single most important file in the
deployment, explained under [Design decisions](#design-decisions-and-trade-offs).

Check it came up:

```bash
curl -s http://localhost:8080/readyz
# {"checks":{"postgres":"ok","redis":"ok","signing_key":"ok"},"status":"ready"}
```

Everyday commands once it's up:

```bash
docker compose ps                 # status of every service
docker compose logs -f gateway    # follow the gateway's structured JSON logs
docker compose down               # stop everything
docker compose down -v            # stop and also wipe Postgres/Redis data
```

### Running the Go binaries natively (no Docker image rebuild)

Useful while actually changing code: keep Postgres and Redis in Docker, but run
the gateway itself with `go run` so edits take effect on the next run without
a rebuild. Requires Go 1.24+.

```bash
# Start just the data stores (and the init script that creates the
# restricted role — see the callout above for why that matters):
docker compose up -d postgres redis

# Run the gateway against them directly:
export POSTGRES_DSN="postgres://gateway_app:local-dev-app-password@localhost:5432/gateway?sslmode=disable"
export REDIS_ADDR="localhost:6379"
export REDIS_PASSWORD="local-dev-redis-password"
export BOOTSTRAP_KEY="local-dev-bootstrap-key-0123456789"
go run ./cmd/gateway
```

(Those default values come from the `.env` already checked in for local dev —
adjust if you changed it.) The demo upstream and seed tool run the same way:

```bash
go run ./cmd/upstream                       # demo backend on :8090
go run ./cmd/seed -slug=acme -name="Acme"   # bootstrap a tenant directly in the DB
```

Or compile binaries instead of `go run`-ing them:

```bash
go build -o bin/gateway  ./cmd/gateway
go build -o bin/seed     ./cmd/seed
go build -o bin/upstream ./cmd/upstream
./bin/gateway   # same env vars as above
```

## Authentication flows

Sequence diagrams of the two core exchanges, written from the code in
`internal/auth/service.go`, `internal/httpapi/handlers/auth.go` and the rotation
script in `internal/store/redisstore/sessions.go`. The Mermaid sources are also
committed as `docs/diagrams/login.mmd` and `docs/diagrams/refresh.mmd` (the
README blocks below are copies of them).

### Login

Every failure that could reveal whether an account exists returns the same
`401 invalid_credentials`; the unknown-user path burns equivalent hashing time.

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant G as Gateway middleware<br/>(IP limit, TenantResolver,<br/>tenant and login limits)
    participant H as AuthHandler.Login
    participant S as auth.Service
    participant PG as Postgres
    participant R as Redis
    participant A as Audit logger<br/>(buffered)

    C->>G: POST /v1/auth/login<br/>X-Tenant, {email, password}
    G->>R: per-IP token bucket
    G->>PG: tenants.BySlug(X-Tenant)
    alt tenant header missing or unknown
        G-->>C: 400 tenant_required / 404 tenant_not_found
    end
    G->>R: per-tenant bucket, then login bucket (keyed tenant + IP)
    alt any bucket empty
        G-->>C: 429 rate limited
    end
    G->>H: request with resolved tenant
    H->>S: Login(tenant, email, password, ip, ua, deviceHash)
    alt tenant suspended
        S-->>C: 403 tenant_suspended
    end
    S->>PG: users.ByEmail(tenant, email)
    alt no such user
        S->>S: BurnTimingBudget (argon2-equivalent work)
        S->>R: RecordAuthFailure(email)
        S->>A: auth.login deny unknown_user
        S-->>C: 401 invalid_credentials
    end
    alt account locked or inactive
        S->>A: auth.login deny account_locked / user_status
        S-->>C: 423 account_locked / 403 user_inactive
    end
    S->>S: VerifyPassword (argon2)
    alt wrong password
        S->>PG: RecordFailedLogin (locks after MAX_FAILED_LOGINS)
        S->>R: RecordAuthFailure(email)
        S->>A: auth.login deny invalid_password
        S-->>C: 401 invalid_credentials (same body as unknown user)
    end
    S->>PG: RecordSuccessfulLogin (clear failure state)
    S->>R: ClearAuthFailures(email)
    S->>PG: roles.EffectivePermissions(user)
    S->>S: Mint Ed25519 access token<br/>(tenant, session, roles, policy version, AMR=pwd,<br/>device and IP bindings)
    S->>S: NewRefreshToken (opaque, random)
    S->>R: CreateSession in one MULTI: sess key, rt:hash(refresh),<br/>fam set, expiries = refresh TTL
    S->>PG: sessions.Create (durable record, new family id)
    S->>A: auth.login allow
    S-->>H: TokenPair + user
    H-->>C: 200 {access_token, refresh_token, expires_in, session_id, user}
    A-)PG: batched hash-chained append (every AUDIT_FLUSH_INTERVAL)
```

### Refresh-token rotation and reuse detection

Rotation is a single atomic Lua script, so a token can be redeemed exactly once.
Replaying a spent token revokes the whole session family; the legitimate
sibling token then fails as `token_revoked`, because its session is gone.

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant H as AuthHandler.Refresh<br/>(behind tenant resolver, no auth)
    participant S as auth.Service
    participant R as Redis
    participant PG as Postgres
    participant A as Audit logger<br/>(buffered)

    C->>H: POST /v1/auth/refresh<br/>X-Tenant, {refresh_token}
    H->>S: Refresh(token, ip, ua, deviceHash)
    S->>S: NewRefreshToken (the successor)
    S->>R: RotateRefreshToken: one atomic Lua script<br/>KEYS rt:hash(old), rtc:hash(old), rt:hash(new)

    alt old token not found and a consumed tombstone rtc: exists (REUSE)
        R-->>S: REUSE + the old record (family id, tenant, user)
        S->>R: RevokeFamily: DEL every sess: key in fam:{family}
        S->>PG: sessions.RevokeFamily(reason refresh_token_reuse)
        S->>A: auth.refresh_reuse_detected deny, risk 100
        S-->>C: 401 session_revoked (log in again)
    else old token not found, no tombstone (MISSING)
        R-->>S: MISSING
        S-->>C: 401 invalid_credentials
    else token present but its sess: key is gone (SESSION_REVOKED)
        R-->>S: SESSION_REVOKED (old token deleted)
        S-->>C: 401 token_revoked
    else token present and session live (OK)
        Note over R: DEL rt:old, SET rtc:old (tombstone, TTL),<br/>SET rt:new with generation + 1
        R-->>S: OK + successor record
        S->>PG: tenants.ByID, users.ByID (source of truth, not the token)
        alt tenant suspended, user inactive, or account locked
            S-->>C: 403 tenant_suspended / 403 user_inactive / 423 account_locked
        end
        S->>PG: roles.EffectivePermissions (current roles)
        S->>S: Mint new access token<br/>(current roles, current policy version)
        S->>R: TouchSession (extend session TTL)
        S->>PG: sessions.Touch (failure only logged)
        S->>A: auth.refresh allow (session, generation)
        S-->>C: 200 {access_token, refresh_token (new), session_id}
    end
```

## Seeing it work

Two ways, from easiest to most hands-on:

**1. Automated walkthrough** — provisions a tenant, exercises RBAC, forces a
refresh-token replay, verifies the audit chain, all in one run:

```bash
./scripts/smoke-test.sh
```

**2. Manual walkthrough:**

```bash
# Bootstrap a tenant (BOOTSTRAP_KEY is in .env)
curl -s -X POST http://localhost:8080/v1/admin/tenants \
  -H "X-Bootstrap-Key: $(grep BOOTSTRAP_KEY .env | cut -d= -f2)" \
  -H "Content-Type: application/json" \
  -d '{"slug":"acme","name":"Acme Corp","admin":{"email":"owner@acme.test","password":"correct-horse-battery-staple"}}'

# Log in
curl -s -X POST http://localhost:8080/v1/auth/login \
  -H "X-Tenant: acme" -H "Content-Type: application/json" \
  -d '{"email":"owner@acme.test","password":"correct-horse-battery-staple"}'
# -> {"access_token": "...", "refresh_token": "...", ...}

# Use it (swap in the access_token from above)
curl -s http://localhost:8080/v1/auth/me \
  -H "X-Tenant: acme" -H "Authorization: Bearer <access_token>"
```

Alternatively, `cmd/seed` bootstraps a demo tenant with an owner and a
read-only member directly against the database:

```bash
docker compose run --rm seed
```

**Things worth deliberately trying**, because each demonstrates a specific
mechanism rather than just "the happy path":

- Create a second user and assign it the built-in `member` role (read-only).
  Log in as that user and try `POST /v1/users` — expect `403 forbidden`
  naming the exact missing permission.
- Take a fresh login's `refresh_token`, exchange it once at `/v1/auth/refresh`,
  then replay the *original* token a second time. Expect `401 session_revoked`
  — and the token you got from the legitimate exchange stops working too. That
  second part is the interesting one: a compromised refresh token can't be
  used quietly alongside the legitimate one, because reuse burns the whole
  session family, not just the replayed token.
- Call a sensitive endpoint (e.g. `POST /v1/users`) as a fresh login. On a new
  device/network/off-hours the risk engine may return `403 step_up_required`
  — resolve it with `POST /v1/auth/step-up` (re-enter the password), then
  retry.
- `GET /v1/audit/verify` replays the tenant's entire audit log and recomputes
  every hash. It's genuinely tamper-evident: `internal/store/postgres/audit_integration_test.go`
  has a test that edits a row directly in Postgres and confirms verification
  catches it, naming the exact sequence number where the chain breaks.
- `GET /v1/proxy/demo/hello` forwards through to the bundled demo backend
  (`cmd/upstream`), which independently verifies the forwarded JWT against the
  gateway's own JWKS endpoint rather than just trusting the `X-Gateway-*`
  headers — the response body shows `"token_independently_verified": true`
  plus the decoded claims it checked.

Grafana (`localhost:3000`) has a provisioned dashboard — request rate/latency,
auth outcomes, refresh-token reuse detections, authorization decisions,
permission-cache hit rate, risk score distribution, rate-limit rejections, and
audit buffer health.

## Kubernetes

Manifests are in `deploy/k8s/`, applied in numeric order. They were validated
end-to-end against a real (local `kind`) cluster while building this, not just
written and assumed correct — see the note on `runAsNonRoot` below for what
that caught.

```bash
kubectl apply -f deploy/k8s/00-namespace.yaml

# Secrets: use your platform's secret manager in real deployments. For a local
# try-it-out cluster:
kubectl create secret generic identity-gateway-secrets -n identity-gateway \
  --from-literal=POSTGRES_USER=postgres_bootstrap \
  --from-literal=POSTGRES_PASSWORD=<generate-one> \
  --from-literal=POSTGRES_DB=gateway \
  --from-literal=GATEWAY_APP_PASSWORD=<generate-one> \
  --from-literal=REDIS_PASSWORD=<generate-one> \
  --from-literal=BOOTSTRAP_KEY=<generate-one>

kubectl apply -f deploy/k8s/02-configmap.yaml

# The Postgres init script is generated from the single source of truth at
# deploy/postgres-init/ rather than duplicated as static YAML — see that
# script's own comments for why keeping this in one place matters here
# specifically.
kubectl create configmap postgres-init-scripts -n identity-gateway \
  --from-file=deploy/postgres-init/01-app-role.sh

kubectl apply -f deploy/k8s/03-postgres.yaml
kubectl apply -f deploy/k8s/04-redis.yaml

# Build and load your images (or push to a registry and edit the `image:`
# fields in 05-gateway.yaml / 06-upstream.yaml first):
docker compose build gateway upstream
kind load docker-image identity-gateway-gateway:latest   # if using kind
kind load docker-image identity-gateway-upstream:latest

kubectl apply -f deploy/k8s/05-gateway.yaml
kubectl apply -f deploy/k8s/06-upstream.yaml
kubectl apply -f deploy/k8s/07-networkpolicy.yaml

kubectl -n identity-gateway rollout status deployment/gateway
kubectl -n identity-gateway port-forward svc/gateway 8080:8080
```

**Two real bugs this validation caught**, worth knowing about if you extend
these manifests:

1. `runAsNonRoot: true` alone fails every pod on this project's distroless
   image with `cannot verify user is non-root`. The image's `USER
   nonroot:nonroot` is a *name*, and some kubelet versions won't resolve it to
   a UID to verify against. Fix: pin `runAsUser: 65532` /
   `runAsGroup: 65532` explicitly (distroless's documented UID for `nonroot`)
   — already done in `05-gateway.yaml` / `06-upstream.yaml`.
2. Kubernetes expands a `$(VAR_NAME)` reference inside one `env[].value`
   using only variables defined *earlier in the same list* — unlike
   `command`/`args`, which see the fully-resolved environment regardless of
   order. `POSTGRES_DSN`'s construction in `05-gateway.yaml` depends on this:
   `POSTGRES_DB` and `GATEWAY_APP_PASSWORD` are listed before it on purpose.

**On `NetworkPolicy` enforcement**: the manifests in `07-networkpolicy.yaml`
were confirmed to apply cleanly against the Kubernetes API (they're
well-formed), but `kind`'s default CNI (`kindnet`) doesn't actually *enforce*
NetworkPolicy — so that validation covers correctness of the policy objects,
not proof that traffic is actually blocked. EKS with the Amazon VPC CNI (or
Calico/Cilium on any cluster) does enforce them; if you're demonstrating this
live, a real enforcement test needs one of those.

A managed Postgres/Redis (RDS, Cloud SQL, ElastiCache) is a better fit than
the bare `StatefulSet`/`Deployment` here for anything beyond a demo — see
comments in `03-postgres.yaml` / `04-redis.yaml`.

### Terraform for EKS + RDS + ElastiCache

`deploy/terraform/` is a Terraform module for that managed setup (VPC, EKS with
NetworkPolicy enforcement enabled, RDS Postgres, ElastiCache Redis). See
[`deploy/terraform/README.md`](deploy/terraform/README.md). **It has only been
validated and planned offline (`terraform validate`, and `terraform plan` with
mock credentials: 46 resources to add) — it has never been applied to an AWS
account, and the cluster in "validated end-to-end against a real cluster"
above is the local `kind` cluster, not EKS.**

## Alerts and on-call runbook

`deploy/prometheus/alerts.yml` holds 15 Prometheus alert rules built only on metrics the gateway already exports: availability (`up`, `/readyz`), 5xx ratio and p99 latency per route, login-failure spikes per tenant, rate-limiter surges, refresh-token reuse, and dependency trouble (audit drops and backlog, permission-lookup and session-check failures, refresh-rotation errors, missing signing keys). Compose mounts the file into Prometheus (`:9091`), and its Alerts tab shows rule state. **There is no Alertmanager in this repo**, so nothing is routed to a pager until you add one.

```bash
./scripts/check-alerts.sh   # promtool check + 15 unit tests on synthetic series (uses Docker if promtool is not installed)
```

The unit tests prove the rules do what their comments say on hand-built series. The only test against real traffic so far was a local run: one gateway with Docker Postgres and Redis, a scripted login attack from one address, a Redis outage and a killed process; the results, including what did *not* get exercised, are at the end of the runbook. Thresholds come from the code's defaults, not production data, and are expected to need tuning.

There are no Postgres or Redis client metrics, so the dependency alerts infer trouble from the gateway's own error outcomes. Two registered metrics (`gateway_token_verify_failures_total`, `gateway_active_sessions`) are never written to, and the `tenant` label on `gateway_http_requests_total` is always `none`; the runbook lists these and works around them.

**[Runbook: login failure spike](docs/runbooks/login-failure-spike.md)** explains how to tell credential stuffing from a bad deploy from a dependency outage, with the PromQL and audit-log SQL to run, the mitigations that exist (and the ones that do not), escalation, and post-incident steps.

## Testing

```bash
# Pure unit tests — RBAC evaluation, password hashing, audit-hash
# determinism, config validation. No external services needed.
go test ./internal/authz/... ./internal/auth/... ./internal/config/...

# Integration tests against real Postgres and Redis (not mocks — the
# properties under test are enforced by Postgres/Redis themselves: row-level
# security, atomic Lua scripts for token rotation and rate limiting).
docker run -d --name gw-test-pg -e POSTGRES_USER=gateway -e POSTGRES_PASSWORD=gateway \
  -e POSTGRES_DB=gateway_test -p 15432:5432 postgres:16-alpine
docker run -d --name gw-test-redis -p 16380:6379 redis:7-alpine

# The Postgres test role must NOT be a superuser (see below for why) — the
# default postgres image's bootstrap user is, so create a restricted role:
docker exec gw-test-pg psql -U gateway -d gateway_test -c "
  CREATE ROLE gateway_app LOGIN PASSWORD 'gateway_app_pw' NOSUPERUSER NOBYPASSRLS;
  ALTER DATABASE gateway_test OWNER TO gateway_app;
  ALTER SCHEMA public OWNER TO gateway_app;"

POSTGRES_TEST_DSN="postgres://gateway_app:gateway_app_pw@localhost:15432/gateway_test?sslmode=disable" \
POSTGRES_TEST_ADMIN_DSN="postgres://gateway:gateway@localhost:15432/gateway_test?sslmode=disable" \
REDIS_TEST_ADDR="localhost:16380" \
go test ./...
```

What's covered and why each area was worth a real test rather than a
by-inspection review:

- **RBAC** (`internal/authz/rbac_test.go`): deny-by-default, explicit deny
  beating a wildcard allow regardless of grant ordering, wildcard matching,
  which grant gets reported as the reason for an allow.
- **Row-level security** (`internal/store/postgres/rls_test.go`): a
  cross-tenant lookup by valid-but-wrong-tenant ID returns not-found; a raw
  query that forgets its own tenant filter still returns only that tenant's
  rows; a connection with no tenant context set sees nothing; pooled
  connections don't leak tenant context between requests.
- **The audit chain** (`internal/store/postgres/audit_integration_test.go`):
  appends verify end-to-end; a row edited directly in the database (bypassing
  the append-only trigger, the way a compromised admin credential might) is
  caught by chain verification at the exact sequence number; the immutability
  trigger itself blocks `UPDATE`/`DELETE` through the normal application role.
- **Refresh-token rotation** (`internal/store/redisstore/sessions_test.go`):
  single-use enforcement under 20 concurrent goroutines (exactly one wins);
  reuse detection distinct from "unknown token"; and two regression tests for
  a bug found while building this — see below.
- **The RLS self-check** (`internal/store/postgres/rls_selfcheck_test.go`):
  confirms `VerifyRLSEnforceable` actually rejects a superuser connection and
  accepts a properly-restricted one.

### Two real bugs found by testing this against live services, not just reading the code

**Refresh-token rotation wasn't actually tied to session liveness.**
`RevokeSession`/`RevokeFamily` deleted the session's liveness key in Redis, but
never touched the refresh token itself — there's no fixed key for "this
session's current refresh token" since it changes on every rotation. A
still-valid, not-yet-rotated refresh token from a *just-revoked* session could
therefore rotate right past the revocation — and because a successful rotation
re-registers the session, doing so silently **resurrected** the session that
logout, an admin revoke, or reuse-detection's own family-burn had just killed.
Found by manually replaying a token during end-to-end testing and noticing a
sibling token still worked afterward. Fixed by checking session liveness
*inside* the same atomic Lua script that performs the rotation
(`internal/store/redisstore/sessions.go`), so nothing derived from a dead
session can rotate again. Regression tests:
`TestRotateRefreshToken_RefusesAfterSessionRevoked`,
`TestRotateRefreshToken_FamilyRevokeBlocksSiblingTokens`.

**The database role a container connects as can silently disable every
row-level-security policy.** Postgres unconditionally skips RLS for
superusers and for any role with `BYPASSRLS` — `FORCE ROW LEVEL SECURITY`
does not override this, by design. The official Postgres Docker image's
`POSTGRES_USER` is the bootstrap role that ran `initdb`, which Postgres
requires to stay a superuser (`ALTER ROLE ... NOSUPERUSER` is refused outright
for it). So the "obvious" setup — point the app straight at `POSTGRES_USER` —
looks completely fine (every query works) while quietly having no tenant
isolation at all. Confirmed by connecting as that bootstrap role directly and
finding every tenant's rows visible with no `app.current_tenant` set. Fixed
two ways: `deploy/postgres-init/01-app-role.sh` creates a dedicated,
non-superuser role the app actually uses, and
`postgres.DB.VerifyRLSEnforceable` (called at gateway startup) refuses to
serve traffic at all if the connected role could bypass RLS — so a
regression here is a startup crash with a clear message, not a silent gap.
Regression tests: `TestVerifyRLSEnforceable_DetectsSuperuser`,
`TestVerifyRLSEnforceable_AllowsRestrictedRole`, plus every test in
`rls_test.go` runs against the restricted role specifically to keep proving
this stays true.

## API reference

All routes except `/healthz`, `/readyz`, `/.well-known/jwks.json`, and
`/v1/admin/tenants` / `/v1/admin/feature-flags` require `X-Tenant: <slug>`. Routes under the second
`/v1` group additionally require `Authorization: Bearer <access_token>`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/healthz` / `/readyz` | none | Liveness / readiness (checks Postgres, Redis, signing key). |
| GET | `/.well-known/jwks.json` | none | Public keys for independent JWT verification. |
| POST | `/v1/admin/tenants` | `X-Bootstrap-Key` | Provision a tenant + owner user + default roles. |
| GET | `/v1/admin/tenants` | `X-Bootstrap-Key` | List tenants. |
| GET | `/v1/admin/feature-flags` | `X-Bootstrap-Key` | Read shared flags and their ETag (Redis mode only). |
| PUT | `/v1/admin/feature-flags` | `X-Bootstrap-Key` + `If-Match` | Replace the shared snapshot and notify replicas (Redis mode only). |
| POST | `/v1/auth/login` | tenant only | Credential exchange → token pair. |
| POST | `/v1/auth/refresh` | tenant only | Rotate a refresh token. |
| POST | `/v1/auth/logout` | bearer | Revoke the current session immediately. |
| POST | `/v1/auth/step-up` | bearer | Re-verify credential; adds `mfa` to the session's AMR. |
| GET | `/v1/auth/me` | bearer | Current identity, roles, risk score. |
| GET/POST | `/v1/users` | bearer + `users:read`/`write` | List / create users. |
| GET/PATCH | `/v1/users/{id}`, `/v1/users/{id}/status` | bearer + permission | Get user / enable-disable (disabling revokes all sessions). |
| GET/POST | `/v1/roles`, `/v1/roles/catalogue` | bearer + `roles:read`/`write` | Roles and the global permission vocabulary. |
| POST/DELETE | `/v1/roles/{id}/permissions` | bearer + `roles:write` | Grant/revoke a permission (allow or explicit deny). |
| POST/DELETE | `/v1/roles/assignments`, `/v1/roles/{id}/assignments/{userID}` | bearer + `roles:write` | Assign/unassign a role. |
| GET | `/v1/sessions`, `/v1/users/{id}/sessions` | bearer + permission | List own / any user's sessions. |
| DELETE | `/v1/sessions/{id}` | bearer + `sessions:revoke` | Revoke one session immediately. |
| GET | `/v1/audit`, `/v1/audit/verify` | bearer + `audit:read` | Query the audit log / verify its hash chain. |
| ANY | `/v1/proxy/{service}/*` | bearer + `upstream:access` | Zero-trust reverse proxy to a configured backend. |

## Configuration reference

Every setting has a safe default (`internal/config/config.go`); production
deployments should review at least these:

| Variable | Default | Notes |
|---|---|---|
| `POSTGRES_DSN` | — | Must point at the restricted `gateway_app` role, never a superuser. |
| `REDIS_ADDR`, `REDIS_PASSWORD` | — | |
| `JWT_ISSUER`, `JWT_AUDIENCE` | — | |
| `ACCESS_TOKEN_TTL` | `5m` | Capped at 1h by config validation. |
| `REFRESH_TOKEN_TTL` | `720h` (30d) | Must exceed the access TTL. |
| `SIGNING_KEY_MAX_AGE` | `24h` | How long one key signs before rotating; old keys stay valid for verification until every token they signed expires. |
| `BIND_TOKENS_TO_IP` / `_DEVICE` | `true` | Zero trust is opt-out here, not opt-in. |
| `RISK_STEPUP_THRESHOLD` / `RISK_DENY_THRESHOLD` | `50` / `80` | Must stay ordered; see `internal/authz/risk.go` for the weighted signals. |
| `IP_RATE_LIMIT`/`BURST`, `USER_...`, `TENANT_...`, `LOGIN_...` | see config.go | Layered token buckets — each dimension closes a gap the others leave open. |
| `MAX_FAILED_LOGINS`, `LOCKOUT_DURATION` | `5`, `15m` | |
| `TRUSTED_PROXY_CIDRS` | RFC1918 ranges | Only trust `X-Forwarded-For` from these peers. |
| `BOOTSTRAP_KEY` | — | Gates tenant provisioning; treat as a root credential. |
| `FEATURE_FLAGS_BACKEND` | `file` | `file` for local reloads; `redis` for shared snapshots and the admin API. |
| `FEATURE_FLAGS_FILE` | unset | Local JSON proxy flags, or a first-start seed in Redis mode. |
| `FEATURE_FLAGS_REDIS_KEY` | `identity-gateway:feature-flags` | Shared Redis key; use a unique namespace per deployment. |
| `FEATURE_FLAGS_SYNC_INTERVAL` | `5s` | Positive reconciliation interval; repairs missed pub/sub notifications. |
| `UPSTREAMS` | — | `name=url,name2=url2` — backends the proxy can reach. |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | unset | Serve the API over HTTPS. Set both or neither; unset means plain HTTP behind a TLS-terminating ingress. |
| `UPSTREAM_CA_FILE` | unset | Enables mTLS to upstreams: the only CA trusted for upstream certificates. Every upstream must then be `https://`. |
| `UPSTREAM_CLIENT_CERT_FILE`, `UPSTREAM_CLIENT_KEY_FILE` | unset | Client certificate the gateway presents to upstreams. |
| `UPSTREAM_SERVER_NAME` | dialed host | Override the name verified in upstream certificates. |

### TLS and mutual TLS

With `TLS_CERT_FILE`/`TLS_KEY_FILE` set, the API listener serves HTTPS with a
TLS 1.2 floor and only forward-secret AEAD cipher suites. With
`UPSTREAM_CA_FILE` set, every proxied call is mutual TLS 1.3: the upstream must
present a certificate that chains to that CA (system roots are never consulted,
so a publicly-issued or self-signed certificate cannot impersonate an internal
service), and the gateway authenticates itself with its client certificate.
The demo upstream requires that client certificate and reports the verified
caller in `mtls_client`. This layers transport identity under the existing
forwarded-JWT check, so neither depends on the network boundary alone.

Certificates are re-read when their files change (checked at most once per
second, per handshake), so a rotated Kubernetes Secret takes effect without a
restart; an invalid replacement is ignored and the last good pair stays in
service. Startup fails fast on unreadable certificates or CA bundles. The
container healthcheck probes over HTTPS and accepts only the exact certificate
the gateway is configured to serve.

```sh
./scripts/gen-dev-certs.sh            # throwaway CA + server/client certs in deploy/tls/dev
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d --build
CURL_CA_BUNDLE=deploy/tls/dev/ca.pem BASE_URL=https://localhost:8443 \
  EXPECT_UPSTREAM_MTLS=1 ./scripts/smoke-test.sh
```

`internal/tlsconfig` tests (in-memory CAs, no fixtures) cover: a successful
TLS 1.3 mTLS exchange; rejection of upstream certificates that are
self-signed, issued by another CA, or for the wrong hostname; no fallback to
system roots; the server rejecting a missing, self-signed, or foreign-CA client
certificate; refusal of TLS 1.1 and plaintext; and certificate hot-reload,
including keeping the old pair when a rotation is broken. Proxy tests confirm a
502 (and zero upstream requests) when the upstream is an impostor.

### Hot-reloadable proxy feature flags

With the default `FEATURE_FLAGS_BACKEND=file`, set `FEATURE_FLAGS_FILE` to a JSON file before starting the gateway. If unset,
proxy access keeps its existing behavior. If set, an unreadable or invalid file
prevents startup. For example:

```bash
cp deploy/feature-flags.example.json /tmp/gateway-flags.json
FEATURE_FLAGS_FILE=/tmp/gateway-flags.json go run ./cmd/gateway
```

The file contains a required global default and optional tenant-slug overrides:

```json
{
  "proxy_enabled": false,
  "tenants": { "acme": true }
}
```

This enables proxy access only for `acme`. An explicit `false` override can
also disable one tenant while the global default is `true`. Evaluation uses
the tenant established by the authentication pipeline. Flags never grant RBAC
permissions or bypass token, rate-limit, or risk checks. Disabled requests
return HTTP `503` with error code `feature_disabled` without calling upstream.

To progressively enable proxy access for a stable percentage of tenants, use:

```json
{
  "proxy_enabled": true,
  "rollout_percent": 10,
  "tenants": {}
}
```

`rollout_percent` is an optional integer from 0 to 100 (omitted or `null`
means 100). Each authenticated tenant is assigned a bucket using SHA-256 of
its immutable tenant ID, a NUL separator, and the flag name `proxy_enabled`;
the first eight digest bytes, interpreted as an unsigned big-endian integer,
modulo 100 determine the bucket. Buckets below the percentage are enabled.
The percentage is approximate across tenants, not a percentage of requests.
Increasing it from 10 to 100 keeps the initial cohort enabled and adds the
remaining tenants. Tenant renames do not change the cohort, and processes
using the same configuration make the same decision without coordination.
Explicit slug overrides take precedence over both the percentage and global
default. A global `proxy_enabled: false` still disables tenants without an
explicit enable override. Invalid percentages reject the entire reload.

To change flags without restarting, replace the file atomically (write a
sibling file and rename it over the configured path), then signal the gateway:

```bash
kill -HUP <gateway-process-pid>
# Docker Compose, after mounting the file's parent directory and setting
# FEATURE_FLAGS_FILE in the gateway service:
docker compose kill -s SIGHUP gateway
```

When using `go run`, signal the compiled gateway child process, not the Go
launcher. Only send `SIGHUP` in file mode when `FEATURE_FLAGS_FILE` is configured.
The supplied Compose/Kubernetes manifests do not mount this optional file.
Mount its parent directory rather than a single file so atomic replacements
remain visible inside the container.

Each request reads one immutable snapshot. Invalid reloads retain the last
valid snapshot and emit an error log; successful reloads emit an info log.
Already-forwarded requests finish normally. This reloads only proxy feature
flags, not environment settings or upstream URLs. In file mode, distribute the
file and signal each process yourself. Restrict file write access to trusted
operators. For automatic propagation, use Redis mode below.

### Shared flag updates across replicas

Set `FEATURE_FLAGS_BACKEND=redis` on every gateway replica, using the same
Redis database and `FEATURE_FLAGS_REDIS_KEY`. Compose passes these settings
from `.env`; Kubernetes exposes them in `deploy/k8s/02-configmap.yaml`.
Both manifests retain file mode by default. Restart the gateways once after
changing the backend; subsequent flag updates use the API without restarts.

At startup, the first replica seeds a missing Redis key atomically from
`FEATURE_FLAGS_FILE`, or from `{"proxy_enabled":true}` if no file is supplied.
Other replicas load the existing shared snapshot before serving traffic.
A seed file never overwrites existing shared state. Supply the same seed on
all replicas; concurrent first starts use whichever seed wins `SETNX`.
Unreadable/invalid configured seed files and unavailable/invalid shared state
prevent startup. In Redis mode, `SIGHUP` is not a reload mechanism: use the API.

The API is a global operator surface protected by the existing
`X-Bootstrap-Key` secret and per-IP rate limiter. Tenant bearer tokens do not
grant access, and an unset bootstrap key disables administration. Use HTTPS
outside local development and keep this credential with trusted operators.
For example, with `BOOTSTRAP_KEY` already exported in your shell:

```bash
# Read the authoritative snapshot and its opaque revision (requires jq).
revision=$(curl -fsS http://localhost:8080/v1/admin/feature-flags \
  -H "X-Bootstrap-Key: $BOOTSTRAP_KEY" | jq -r '.revision')

# Replace the entire configuration with a 10% rollout.
curl -fsS -X PUT http://localhost:8080/v1/admin/feature-flags \
  -H "X-Bootstrap-Key: $BOOTSTRAP_KEY" \
  -H "If-Match: \"$revision\"" \
  -H "Content-Type: application/json" \
  -d '{"proxy_enabled":true,"rollout_percent":10,"tenants":{}}'
```

GET and successful PUT return `{"revision":"<uuid>","flags":{...}}` and a
quoted `ETag` header. PUT requires that ETag in `If-Match`: missing revisions
return `428`, stale revisions `412`, malformed revisions or flags `400`, and
bodies over one MiB `413`. Redis failures return `503`. A network error can
leave the write outcome uncertain; read the current snapshot before retrying.
To advance to 100% or roll back, GET the latest revision and PUT the complete
desired configuration. Omitted tenant overrides are removed.

Each accepted update checks the revision, writes the snapshot without expiry,
and publishes a notification in one Redis Lua script. The handling replica
applies it locally; other replicas fetch the shared key on notification.
Notifications carry only a revision, and replicas never apply their payload
as configuration. Polling every `FEATURE_FLAGS_SYNC_INTERVAL` (default five
seconds) repairs missed notifications and reconnect gaps. A restarted replica
loads the persisted snapshot. Applied revisions and operator changes are
logged without credentials or full flag contents.

Propagation is **eventually consistent**, not a simultaneous all-replica
switch: HTTP success confirms the shared write and the handling replica's
update, not acknowledgements from every replica. Failed reads and invalid
snapshots retain the last valid local flags and log an error; new shared-mode
processes refuse to start when Redis is unavailable. Already-forwarded
requests finish normally. File mode and Redis mode are separate sources;
file-mode replicas will not receive shared updates.

Redis persistence determines whether flags survive Redis data loss. Compose
uses an AOF-backed volume; the demo Kubernetes Redis uses `emptyDir`, which
is lost on pod replacement. Use persistent Redis storage and backups before
relying on shared flags there. Deleting/evicting the key makes running replicas
retain their last snapshot and reject admin writes; a subsequent gateway
startup seeds an absent key again. Restore the saved configuration before
restarting gateways if the default seed would be inappropriate.

The Redis integration tests exercise two independent replicas, concurrent
revision conflicts, restart loading, missed notifications, reconnects, and an
HTTP admin update changing another replica's proxy behavior:

```bash
# Use a scratch Redis instance. Run separately from redisstore tests, which FLUSHDB.
REDIS_TEST_ADDR=localhost:16389 go test -race ./internal/featureflags ./internal/httpapi/handlers
```


## Design decisions and trade-offs

**Why row-level security instead of just scoping every query.** Application
code forgetting a `WHERE tenant_id = ?` is exactly the kind of mistake that
survives code review and only shows up when a customer notices someone else's
data. RLS moves the boundary into the database itself: `FORCE ROW LEVEL
SECURITY` means even the owning role is restricted, and the default is closed
— no `app.current_tenant` set means zero rows, not every row. The cost is
real: it only works if the connecting role isn't a superuser (see the bug
above), and every tenant-scoped query has to run inside `db.InTenant(...)`,
which is a discipline the codebase enforces by making that the only exported
way to get a `Querier` for tenant data (`internal/store/postgres/db.go`).

**Why an opaque refresh token instead of a second JWT.** A JWT refresh token
would be independently verifiable, which sounds convenient but doesn't
actually buy anything: revocation still needs a server-side lookup regardless,
so making it self-contained mostly adds a way for it to look valid when it
isn't. An opaque, 256-bit random token that's just a reference into Redis is
more honest about that, and makes single-use rotation with reuse detection
straightforward to implement atomically in one Lua script
(`internal/store/redisstore/sessions.go`).

**Why the risk engine's weights are visible constants, not a trained model.**
A security control an operator can't explain to an auditor — or to themselves,
six months later, debugging a false positive — is one that gets disabled the
first time it's inconvenient. `internal/authz/risk.go` scores new
device/network, token-binding mismatches, recent auth failures, sensitive
actions, single-factor sessions, and off-hours activity, and every decision
records exactly which signals fired and their weights, both in the API
response and the audit log.

**Why the audit log is hash-chained instead of just being an append-only
table.** Append-only (enforced by a trigger blocking `UPDATE`/`DELETE`) stops
casual tampering through the app's own credentials. It does not stop someone
with direct database access — a compromised admin account, a bad restore, a
rogue migration. Hash-chaining means *removing or editing any record breaks
verification from that point forward*, which is a much stronger claim:
`GET /v1/audit/verify` doesn't just check the table looks fine, it replays the
whole chain and would name the exact sequence number where history stopped
matching itself.

**Why permission checks are cached but revocation is still instant.** Loading
a user's effective permissions is a join across three tables — too much for
every single request. So it's cached in Redis, but keyed by the tenant's
current `policy_version`: any change that affects authorization bumps that
version in the same transaction as the change (`postgres.BumpPolicyVersion`),
which makes every previously-cached entry for that tenant unreachable in the
same instant, no invalidation fan-out required. `RequirePolicyCurrent`
middleware backs this up by rejecting any token whose embedded policy version
has gone stale, independent of what the cache says.

**Why metrics are on a separate port from the API.** `/metrics` was
originally on the same port as tenant traffic; moved to its own listener
(`METRICS_ADDR`, `internal/observability/server.go`) specifically so it never
shares the tenant-facing rate limiter or needs its own auth story — it's an
operational surface for in-cluster scraping, not a tenant-facing endpoint, and
`deploy/k8s/07-networkpolicy.yaml` restricts who can reach it accordingly.

## Known limitations / what I'd do next

Said plainly, because a project that only lists what it does well isn't
credible:

- **Step-up "MFA" re-checks the password**, not a second factor (TOTP,
  WebAuthn). It exercises the actual mechanism the risk engine keys on (AMR
  gaining `mfa`), but isn't real multi-factor auth. Wiring in TOTP would mean
  storing a secret on the user record and verifying a code in
  `AuthHandler.StepUp` instead of re-checking the password.
- **Single-replica Postgres and Redis** in both the compose file and the k8s
  manifests. Fine for a demo; a real deployment needs a managed database or
  an operator (see comments in `deploy/k8s/03-postgres.yaml`) and Redis
  replication/Sentinel — losing Redis loses every live session (inconvenient:
  re-login) but not correctness, since Postgres remains the durable source of
  truth for tenant data. Redis-backed feature flags also need persistent
  Redis storage and backups; see the shared flag section above.
- **`NetworkPolicy` enforcement wasn't validated against real traffic** — see
  the Kubernetes section above. The policies are syntactically correct and
  accepted by the API server; proving they actually block traffic needs a
  CNI that enforces them.
- **The audit writer can lose its buffer on a hard crash** (not a graceful
  shutdown, which does flush — see `cmd/gateway/main.go`). This is a
  deliberate trade for keeping the chain append off the request hot path;
  `gateway_audit_events_dropped_total` should alert if it's ever non-zero.
  Acceptable for access-decision logging; would not be for financial records.
- **No email verification or password reset flow** — user creation sets a
  password directly. Fine for an admin provisioning users internally, not for
  self-service signup.
- **The reverse proxy is a thin demonstration**, not a general-purpose API
  gateway — no request/response transformation, no circuit breaking, no
  per-upstream retry policy. It exists to show the identity/authorization
  handoff pattern, not to replace something like Envoy.

## Repository layout

```
cmd/
  gateway/    Main server: wires config, stores, auth, and the HTTP router.
  seed/       CLI to bootstrap a demo tenant directly against the database.
  upstream/   Demo backend showing independent JWT verification via JWKS.
internal/
  domain/     Core entities and sentinel errors — no I/O.
  config/     Environment-driven config with validation.
  featureflags/  Percentage evaluation, file reloads, Redis snapshots and propagation.
  auth/       Password hashing, JWT keyring + rotation, the login/refresh/
              step-up service.
  authz/      RBAC evaluation and the continuous risk-scoring engine.
  audit/      Async, batched writer for the hash-chained audit log.
  observability/  Prometheus metrics, structured logging, the metrics server.
  store/
    postgres/   Connection pool, tenant-scoped transaction helpers, all
                repositories, embedded SQL migrations.
    redisstore/ Sessions, atomic refresh rotation, rate limiting, policy
                cache, risk-signal history — all as Lua scripts where
                atomicity matters.
  httpapi/
    reqctx/     Request-scoped context keys shared by router/middleware/handlers.
    middleware/ The verification pipeline itself.
    handlers/   Route handlers.
    router.go   Wires middleware order and routes — read this first.
deploy/
  postgres-init/  The restricted-role script — read this second.
  k8s/            Kubernetes manifests, applied in numeric order.
  prometheus/, grafana/  Scrape config, alert rules (+ unit tests), dashboard, provisioning.
docs/
  runbooks/       On-call runbooks (login failure spike).
  diagrams/       Mermaid sources for the auth flows.
scripts/
  smoke-test.sh   Automated end-to-end walkthrough against a running stack.
  check-alerts.sh Validates and unit-tests the Prometheus alert rules.
```
