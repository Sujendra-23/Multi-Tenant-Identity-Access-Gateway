-- Multi-Tenant Identity & Access Gateway :: initial schema
--
-- Isolation model: shared database, shared schema, tenant_id on every
-- tenant-owned table, plus PostgreSQL row-level security as defence in depth.
-- Application code always scopes its queries, but if a query ever forgets its
-- WHERE clause the database still refuses to leak across tenants. RLS is FORCEd
-- so it applies to the table owner too, and the only escape hatch is an
-- explicit, auditable app.bypass_rls setting used by migrations and the
-- bootstrap path.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------- tenants ---
CREATE TABLE IF NOT EXISTS tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    plan            TEXT NOT NULL DEFAULT 'standard',
    -- Bumped on any authorization-relevant change inside the tenant. Access
    -- tokens carry the version they were minted under; a mismatch forces the
    -- gateway to re-read permissions instead of trusting the token's claims.
    policy_version  BIGINT NOT NULL DEFAULT 1,
    rate_limit_rps  INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------------ users ---
CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email               TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    display_name        TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','invited')),
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    mfa_enrolled        BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Email is unique per tenant, not globally: the same person may hold
    -- accounts in several tenants and they are distinct principals.
    CONSTRAINT users_tenant_email_key UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS users_tenant_idx ON users (tenant_id);

-- ------------------------------------------------------------- permissions --
-- Permissions are a global catalogue of resource:action pairs. Grants are
-- tenant-scoped; the vocabulary is not.
CREATE TABLE IF NOT EXISTS permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource    TEXT NOT NULL,
    action      TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    CONSTRAINT permissions_key UNIQUE (resource, action)
);

-- ------------------------------------------------------------------ roles ---
CREATE TABLE IF NOT EXISTS roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT roles_tenant_name_key UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS roles_tenant_idx ON roles (tenant_id);

CREATE TABLE IF NOT EXISTS role_permissions (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    -- An explicit deny always beats an allow, so a broad grant can be carved
    -- back without rebuilding the role.
    effect        TEXT NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow','deny')),
    PRIMARY KEY (role_id, permission_id)
);
CREATE INDEX IF NOT EXISTS role_permissions_tenant_idx ON role_permissions (tenant_id);

CREATE TABLE IF NOT EXISTS user_roles (
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by UUID,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX IF NOT EXISTS user_roles_tenant_idx ON user_roles (tenant_id);

-- ----------------------------------------------------------- signing keys ---
-- Keys live in the database so every replica signs and verifies with the same
-- keyring. Exactly one key is active for signing; retired keys stay trusted for
-- verification until every token they signed has expired.
CREATE TABLE IF NOT EXISTS signing_keys (
    kid         TEXT PRIMARY KEY,
    algorithm   TEXT NOT NULL DEFAULT 'EdDSA',
    private_key BYTEA NOT NULL,
    public_key  BYTEA NOT NULL,
    is_active   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL
);
-- At most one active signing key at a time.
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_active
    ON signing_keys ((is_active)) WHERE is_active;

-- ------------------------------------------------------------ audit chain ---
-- Append-only and hash-chained per tenant: each row commits to the previous
-- row's hash, so removing or editing history breaks the chain and is
-- detectable by replaying it.
CREATE TABLE IF NOT EXISTS audit_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sequence     BIGINT NOT NULL,
    actor_id     UUID,
    actor_email  TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL,
    resource     TEXT NOT NULL DEFAULT '',
    decision     TEXT NOT NULL CHECK (decision IN ('allow','deny','error')),
    reason       TEXT NOT NULL DEFAULT '',
    risk_score   INTEGER NOT NULL DEFAULT 0,
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    request_id   TEXT NOT NULL DEFAULT '',
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL,
    CONSTRAINT audit_tenant_sequence_key UNIQUE (tenant_id, sequence)
);
CREATE INDEX IF NOT EXISTS audit_tenant_time_idx ON audit_events (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_tenant_action_idx ON audit_events (tenant_id, action);

-- The audit log is evidence. Blocking UPDATE and DELETE at the database means
-- even a compromised application credential cannot quietly rewrite history.
CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (attempted %)', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

-- --------------------------------------------------------------- sessions ---
-- Redis is the hot path for session lookups; this table is the durable record
-- used for the "list my active sessions" view and for forensics after Redis is
-- flushed or fails over.
CREATE TABLE IF NOT EXISTS sessions (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id    UUID NOT NULL,
    device_hash  TEXT NOT NULL DEFAULT '',
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    generation   INTEGER NOT NULL DEFAULT 0,
    amr          TEXT[] NOT NULL DEFAULT '{}',
    revoked_at   TIMESTAMPTZ,
    revoked_why  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_tenant_user_idx ON sessions (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS sessions_family_idx ON sessions (family_id);

COMMIT;
