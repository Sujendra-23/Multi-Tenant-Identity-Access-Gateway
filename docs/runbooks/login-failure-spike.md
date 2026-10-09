# Runbook: login failure spike

Use this when `GatewayLoginFailureSpike`, `GatewayLoginRateLimitSurge`, `GatewayHigh5xxRatio` on `/v1/auth/login`, or any of the dependency alerts fires, or when someone reports that people cannot log in. The alert rules live in [`deploy/prometheus/alerts.yml`](../../deploy/prometheus/alerts.yml).

The first job is to decide which of three different problems this is, because the right responses conflict: blocking traffic is correct for an attack and harmful during a bad deploy, and rolling back is pointless during an outage.

## What has and has not been verified

Be skeptical of numbers in this document that are not marked as measured.

| Claim | Status |
|---|---|
| Rules parse (`promtool check rules` / `check config`) and behave as intended on synthetic series (`promtool test rules`, 15 cases, checked to fail when the rules are mutated) | Verified. Run `./scripts/check-alerts.sh`. |
| Rules load and evaluate without error in a real Prometheus 2.55.1 scraping a real gateway | Verified once, locally. |

| Thresholds are right for your traffic | **No.** They come from the code's defaults (login limiter 1 request/s per tenant and IP, audit buffer 4096) and one laptop. Nothing was tuned against production, and there is no Alertmanager in this repo, so nothing here has paged anyone. |
| Mitigations in [Mitigations](#mitigations) | Session, user-disable and tenant-suspension behaviour was checked against a running gateway. Rate-limit and lockout tuning, edge blocking, rollbacks and the escalation steps were not exercised. |

Known weaknesses of the instrumentation, which shape every investigation below:

- **`tenant` on `gateway_http_requests_total` is always `none`**, and the gateway's own access-log lines have empty `tenant` and `ip`. The request logger and the metrics middleware read those values from a request object that handlers never write back to. Use `gateway_auth_attempts_total` and the audit table for per-tenant and per-IP questions.
- **There are no Postgres or Redis client metrics.** Dependency alerts infer trouble from the gateway's own error outcomes, so they say "something is failing", and the table in [A dependency outage](#a-dependency-outage) says how to tell which.
- **`gateway_token_verify_failures_total` and `gateway_active_sessions` are never written.** The dashboard's "Active sessions by tenant" panel is empty and expected to stay so. Do not read an absence there as meaning anything.
- **Rate-limited (429) requests, and anything rejected before a tenant is resolved, never reach the audit log.** The audit table understates an attack that the limiter is absorbing. The 429 count is in the metrics and in your ingress logs.

## Triage: what kind of spike is this?

Work through these in order; each takes about a minute. Replace `<slug>` with the tenant on the alert, or drop the label to look across all tenants.

### 1. Is login failing as an error, or being refused?

```promql
sum by (status) (rate(gateway_http_requests_total{route="/v1/auth/login"}[5m]))
```

- Mostly `401` (and `429`, `423`): the gateway is working and refusing credentials. Go to credential stuffing or bad deploy.
- `5xx` on login, or `/readyz` returning 503: the gateway is failing. Go to a dependency outage.

### 2. Compare outcomes

```promql
sum by (outcome) (rate(gateway_auth_attempts_total{tenant="<slug>"}[5m]))
```

```promql
# Failure share of login attempts (alert fires above 0.5)
sum(rate(gateway_auth_attempts_total{outcome=~"bad_password|unknown_user|locked"}[5m]))
/ sum(rate(gateway_auth_attempts_total[5m]))
```

Outcomes are `success`, `bad_password`, `unknown_user`, `locked`, `inactive` and `tenant_suspended`. Login errors (database or Redis failures) do not appear here at all, so a drop in `success` with no matching rise in denials is itself a signal.

### Credential stuffing

Typical shape:

- `unknown_user` and `bad_password` rise while `success` stays at its usual level: real users can still log in.
- Many distinct email addresses per source address, or very many sources with a few attempts each.
- `429`s on login from the login limiter, if one address is pushing hard. A spread-out botnet stays under the limiter, so absence of 429s does not rule an attack out.
- Onset is abrupt and unrelated to a deploy; one or a few User-Agent strings.
- `locked` outcomes appear for real accounts after five wrong passwords (`MAX_FAILED_LOGINS`, 15-minute lockout by default). Unknown emails do not lock anything, so a high `unknown_user` share points at a list-based attack rather than a typo storm.

Confirm in the audit table. Run as a role that can read across tenants (the bootstrap/owner role, or after `SET app.bypass_rls = 'on'`; the application role is restricted by row-level security and sees nothing without `SET app.current_tenant`).

```sql
-- Outcome mix: what is failing, and why
SELECT action, decision, reason, count(*) AS n
FROM audit_events
WHERE tenant_id = (SELECT id FROM tenants WHERE slug = '<slug>')
  AND action IN ('auth.login', 'auth.refresh', 'auth.refresh_reuse_detected')
  AND occurred_at > now() - interval '15 minutes'
GROUP BY 1, 2, 3 ORDER BY n DESC;

-- Sources: many distinct emails per address is stuffing
SELECT ip, count(*) AS attempts, count(DISTINCT actor_email) AS distinct_emails,
       count(*) FILTER (WHERE decision = 'allow') AS successes
FROM audit_events
WHERE tenant_id = (SELECT id FROM tenants WHERE slug = '<slug>')
  AND action = 'auth.login' AND occurred_at > now() - interval '15 minutes'
GROUP BY ip ORDER BY attempts DESC LIMIT 10;

-- Accounts being hit (existing users with repeated denials)
SELECT actor_email,
       count(*) FILTER (WHERE reason = 'invalid_password') AS bad_password,
       count(*) FILTER (WHERE reason = 'account_locked')   AS locked
FROM audit_events
WHERE tenant_id = (SELECT id FROM tenants WHERE slug = '<slug>')
  AND action = 'auth.login' AND decision = 'deny'
  AND occurred_at > now() - interval '15 minutes'
GROUP BY 1 HAVING count(*) FILTER (WHERE reason IN ('invalid_password', 'account_locked')) > 0
ORDER BY 2 DESC LIMIT 20;

-- Client fingerprints of the failures
SELECT left(user_agent, 60) AS user_agent, count(*)
FROM audit_events
WHERE tenant_id = (SELECT id FROM tenants WHERE slug = '<slug>')
  AND action = 'auth.login' AND decision = 'deny' AND occurred_at > now() - interval '15 minutes'
GROUP BY 1 ORDER BY 2 DESC LIMIT 5;
```

The same data without database access: `GET /v1/audit?action=auth.login&decision=deny&limit=200` as a tenant user holding `audit:read`.

**The question that decides severity:** did any *successful* login come from an address that also produced failures? That is account takeover, not nuisance.

```sql
SELECT ip, actor_email, min(occurred_at) AS first_success
FROM audit_events
WHERE tenant_id = (SELECT id FROM tenants WHERE slug = '<slug>')
  AND action = 'auth.login' AND decision = 'allow'
  AND ip IN (<addresses with many failures from the query above>)
GROUP BY 1, 2;
```

### A bad deploy

Typical shape:

- Onset lines up with a rollout (`kubectl -n identity-gateway rollout history deployment/gateway`, or your pipeline), and `success` drops sharply at that moment instead of declining gradually.
- Failures are `bad_password` for *known* users from their usual addresses and clients, across many tenants at once, rather than guesses at unknown addresses.
- Or the symptom is errors, not refusals: `5xx` on login, or `401 invalid_token` / `policy_changed` on authenticated routes right after rollout. Candidates in this codebase: a change to password hashing (valid passwords stop verifying), a signing-key or JWT issuer/audience change (tokens stop verifying), a migration, or a config change to a limit.
- Only the new replicas misbehave: compare per instance.

```promql
# per-replica error and failure share
sum by (instance) (rate(gateway_http_requests_total{route="/v1/auth/login", status=~"5.."}[5m]))
/ sum by (instance) (rate(gateway_http_requests_total{route="/v1/auth/login"}[5m]))
```

```sql
-- Successes versus denials per minute: a bad deploy shows a cliff, an attack shows a plateau of denials
SELECT date_trunc('minute', occurred_at) AS minute,
       count(*) FILTER (WHERE decision = 'allow') AS ok,
       count(*) FILTER (WHERE decision = 'deny')  AS denied
FROM audit_events
WHERE tenant_id = (SELECT id FROM tenants WHERE slug = '<slug>')
  AND action = 'auth.login' AND occurred_at > now() - interval '60 minutes'
GROUP BY 1 ORDER BY 1 DESC LIMIT 30;
```

If this is a deploy, roll it back first and investigate afterwards. Blocking addresses or tightening limits will not help and will lock out real users.

### A dependency outage

Typical shape:

- `/readyz` returns 503 (`GatewayNotReady`); its JSON body names the failing check (`postgres`, `redis` or `signing_key`):
  ```bash
  curl -s http://<gateway>:8080/readyz
  ```
- Login returns 5xx, not 401, and `success` stops rising even though users are typing correct passwords. With Redis down the password verifies but the session cannot be created, so no outcome is recorded; with Postgres down the tenant lookup fails before the login handler runs. Wrong-password outcomes can keep counting during a Redis outage, so `success` falling to zero while denials continue looks like a bad deploy; check `/readyz` and the 5xx share before concluding.
- Audit rows for the window are missing, or `gateway_audit_events_dropped_total` rises.

Telling Redis from Postgres with the metrics available:

| What you see | Most likely |
|---|---|
| `GatewayAuthzEvaluationFailing`, or `gateway_authz_decisions_total{decision="error"}` rising; 503 `authorization_unavailable` | **Postgres.** The effective-permissions query is failing. A Redis cache failure does not do this; it falls back to Postgres. |
| `GatewayAuthenticatedRequests503` without authz errors; 503 `session_check_failed` | **Redis.** The token-denylist or session lookup failed. Every authenticated call fails. |
| `GatewayRefreshRotationErrors` (`gateway_token_refresh_total{outcome="error"}`) | **Redis.** Rotation is a Redis script. |
| `GatewayPolicyCacheErrors` | **Redis**, degraded: requests still succeed through Postgres, slower. |
| `GatewayAuditEventsDropped` / `GatewayAuditBufferNearlyFull` | **Postgres** write path (or an event rate that has outgrown `AUDIT_BUFFER_SIZE`). Audit events from that window are lost: the chain has a gap. |
| 500 on `/v1/*` for every route including login, `readyz` shows `postgres` unreachable | **Postgres.** Tenant lookup is the first thing every `/v1` request does. |
| `GatewayNoSigningKeys` | Signing-key table empty or unreadable. |

Two effects specific to a Redis outage:

- **The rate limiters fail open.** Requests are let through when Redis cannot be reached, so an attack is not slowed and `GatewayLoginRateLimitSurge` goes quiet. Silence on that alert during a Redis outage means nothing.
- **Logins cannot complete.** Creating a session needs Redis, so valid logins also fail with 5xx. Do not mistake that for a credential problem.

Compare with the previous hour to see whether traffic itself changed:

```promql
sum(rate(gateway_http_requests_total{route="/v1/auth/login"}[5m]))
/ sum(rate(gateway_http_requests_total{route="/v1/auth/login"}[5m] offset 1h))
```

Dependency recovery is the platform team's job (RDS/ElastiCache or the in-cluster pods; see [`deploy/terraform/README.md`](../../deploy/terraform/README.md) and `deploy/k8s/`). Your job is to confirm the gateway recovers on its own once the dependency does (readiness returns, error counters stop), not to restart it into a still-broken dependency.

### Something else

A single tenant with a client that has an old password cached (after a rotation), an SSO or password-manager integration retrying, or a load test. Look for one User-Agent and a few addresses repeating the same email. Contact the tenant; no mitigation is needed beyond avoiding lockout of the real user.

## Dashboards and where to look

Grafana dashboard **Identity Gateway** (`deploy/grafana/dashboards/identity-gateway.json`, `localhost:3000` under compose):

| Panel | Use for |
|---|---|
| Authentication attempts by outcome | Stuffing (denial outcomes rise) versus deploy (success falls). |
| Request rate by status class | 401/429 versus 5xx on login. |
| Rate limit rejections by dimension | `login`, `ip`, `user`, `tenant`: which limiter is working. |
| P50 / P95 / P99 request latency | Saturation and slow dependencies. |
| Refresh-token reuse detections | Token theft, separate from password guessing. |
| Permission cache hit rate | A drop in hits with errors means Redis trouble. |
| Audit buffer depth / Audit events dropped | Postgres write health. |

The gateway's logs are structured JSON: `kubectl -n identity-gateway logs deploy/gateway --since=15m | grep '"path":"/v1/auth/login"'`. As noted above, `tenant` and `ip` are empty in those lines; use them for status codes and timing, and get source addresses from the ingress or load balancer logs and the audit table.

## Mitigations

Ordered from least to most disruptive. Take the least that stops the harm.

**1. Block at the edge.** The gateway has no address denylist. Block offending addresses or networks at the WAF, load balancer or ingress. This is the right response to a focused stuffing source and does nothing for a distributed one. The 429 rate-limit responses carry no address; take addresses from the audit queries above and ingress logs.

**2. Tighten rate limits.** Environment variables read at startup, so a change needs a rolling restart: `LOGIN_RATE_LIMIT` (default 1/s) and `LOGIN_RATE_BURST` (5) per tenant and address, `IP_RATE_LIMIT` (50) and `IP_RATE_BURST` (100), `TENANT_RATE_LIMIT` (200) and `TENANT_RATE_BURST` (400). Limits are enforced in Redis, so they do nothing while Redis is down. The `rate_limit_rps` column on tenants is stored but not used by the limiter; setting it changes nothing.

**3. Lockout settings.** `MAX_FAILED_LOGINS` (5) and `LOCKOUT_DURATION` (15m). Shortening the threshold slows guessing against known accounts but lets an attacker lock real users out deliberately. Guesses at unknown emails never lock anything.

**4. End sessions.** Needed when an attacker got in. Access tokens stay valid until their session is gone, so revoke sessions, not just passwords. Each of these was checked against a running gateway:
- One session: `DELETE /v1/sessions/{id}` (needs `sessions:revoke`; the risk engine may ask for `POST /v1/auth/step-up` first). The token is rejected on its next request.
- All of one user's sessions: `PATCH /v1/users/{id}/status` with `{"status":"disabled"}`. Revokes every session of that user immediately. Re-enable later with `"active"`.
- A whole refresh-token family: happens automatically on a replayed refresh token (`auth.refresh_reuse_detected`). The legitimate sibling token then fails as `token_revoked`, so expect affected users to log in again.
- Every session of a tenant, as a break-glass step, by deleting its session keys from Redis (keys are `sess:<tenant-uuid>:<session-uuid>`). Both the access token (`401 session_revoked`) and the refresh token (`token_revoked`) stop working:
  ```bash
  redis-cli --scan --pattern 'sess:<tenant-uuid>:*' | xargs -r redis-cli DEL
  ```
  This affects every user of that tenant. Use `--scan`, never `KEYS`, on a live instance.

**5. Isolate a tenant.** Contains an incident to one tenant while the others carry on. There is no admin endpoint for this; it is a database change by a privileged operator. Checked behaviour:
- `UPDATE tenants SET status = 'suspended' WHERE slug = '<slug>'` blocks new logins and refresh (`403 tenant_suspended`) but **does not invalidate access tokens already issued**: they kept working until they expired.
- Add `policy_version = policy_version + 1` to the same statement and existing access tokens are rejected with `401` on their next request as well:
  ```sql
  UPDATE tenants SET status = 'suspended', policy_version = policy_version + 1 WHERE slug = '<slug>';
  ```
  Reverse with `status = 'active'` (users then refresh or log in again). Tenant data is untouched by either step. The `tenants` table is under row-level security, so run this as the owner/bootstrap role.

**6. Roll back the deploy** if triage points there.

None of these touch the audit log, which is append-only (a database trigger refuses updates and deletes).

## Escalation

Fill in your own names and channels; none are encoded in this repository.

| Condition | Who |
|---|---|
| Alert fired, cause not yet clear | On-call engineer owns triage and records a timeline from the first alert. |
| A successful login from an address that also produced failures, any sign of a takeover, or refresh-token reuse clusters across several users | **Security incident.** Engage security/incident response now; do not wait for the spike to end. Preserve the audit rows and ingress logs for the window. |
| Dependency outage (Postgres, Redis, signing keys) | Platform/infrastructure on-call; the gateway owner stays engaged for recovery checks. |
| Bad deploy | Owner of the change; roll back first. |
| More than one tenant affected, or a tenant suspension is being considered | Incident commander, and whoever owns the customer relationship, before suspending. |
| `GET /v1/audit/verify` returns `409` (chain invalid), or `gateway_audit_events_dropped_total` rose during an attack | Security: the audit evidence for that window is incomplete or has been tampered with. |

## After the incident

1. Write down the timeline from the first alert: onset, detection, each action and its effect, resolution.
2. Verify the audit chain for each affected tenant: `GET /v1/audit/verify` (replays the hash chain and names the sequence number where it breaks). Remember that dropped events and 429-rejected requests are not in the log.
3. For an attack, list every account with a successful login from an attacking address and force those sessions closed and the passwords reset. Tell affected tenants.
4. Undo temporary measures: tenant suspension, tightened limits, edge blocks you no longer need.
5. Tune what you learned. Were thresholds too low (noise) or too high (late)? Did the alert fire before users noticed? Change `deploy/prometheus/alerts.yml`, update `alerts_test.yml` to match, and run `./scripts/check-alerts.sh`.
6. File follow-ups for the gaps above. The highest value ones: fix the `tenant`/`ip` context bug in the metrics and access-log middleware, add Postgres and Redis client metrics so dependency alerts stop being proxies, write or remove the never-written metrics, add an address denylist or an admin tenant-suspend endpoint, and add Alertmanager routing.

## What the live exercise showed

One scripted run on a laptop: a gateway process, Docker Postgres 16 and Redis 7, and Prometheus 2.55.1 evaluating `alerts.yml` as committed (10s scrape and evaluation). Times are since the start of each phase; they include each rule's `for:` delay and the 5-minute `rate()` window, so they show lag, not best case.

| Phase | What was done | Observed |
|---|---|---|
| Healthy control, 150s | Successful logins every 2s | No login or 5xx alerts. |
| Refresh replays | 6 replays of a spent refresh token | `GatewayRefreshTokenReuseDetected` firing by 120s. |
| Login attack, 540s | About 3 unknown-user logins per second from one address; the login limiter admitted about 1/s and rejected about 2/s | `GatewayLoginFailureSpike` and `GatewayLoginRateLimitSurge` pending at 90s into the attack and firing by about 390s into it. Both cleared after the attack ended. |
| Redis stopped, 420s | Readiness probes, valid logins, bogus refreshes | `GatewayNotReady` and `GatewayRefreshRotationErrors` pending within 30s, firing within about 150s and 300s; `GatewayHigh5xxRatio` firing for `/v1/auth/login` and `/v1/auth/refresh` after about 360s. `GatewayNotReady` cleared about 2 minutes after Redis returned; the 5xx and refresh alerts took longer to clear because of the 5-minute window. |
| Gateway process killed, after recovery | `kill -9` of the gateway | `GatewayTargetDown` pending 14s later and firing about 134s after the kill (the rule's `for: 2m` plus scrape and evaluation lag). |

Not exercised live, and unit-tested only: `GatewayAuthenticatedRequests503` (the outage script sent a bogus bearer token, which is rejected with 401 before the Redis check, so it never produced the 503s), `GatewayAuthzEvaluationFailing`, `GatewayAuditEventsDropped`, `GatewayAuditBufferNearlyFull`, `GatewayPolicyCacheErrors`, `GatewayNoSigningKeys`, `GatewayHighLatencyP99` and `GatewayRateLimitRejectionsHigh`. No Postgres outage was run. No real production traffic or Alertmanager was involved.
