-- Row-level security: the database-level tenant boundary.
--
-- Every tenant-owned table gets a policy keyed on the app.current_tenant GUC,
-- which the application sets per transaction via set_config(). Two properties
-- matter:
--
--   1. FORCE ROW LEVEL SECURITY makes the policy apply to the table owner too,
--      so connecting as the owning role is not an accidental bypass.
--   2. The default is closed. With no app.current_tenant set, the policy
--      expression is NULL, no rows match, and a query that forgot to scope
--      itself returns nothing rather than everything.
--
-- app.bypass_rls is the single, explicit escape hatch, used only by migrations
-- and tenant bootstrap where there is by definition no current tenant yet.

BEGIN;

CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
    SELECT NULLIF(current_setting('app.current_tenant', true), '')::uuid;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION rls_bypassed() RETURNS BOOLEAN AS $$
    SELECT coalesce(current_setting('app.bypass_rls', true), 'off') = 'on';
$$ LANGUAGE sql STABLE;

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'users', 'roles', 'role_permissions', 'user_roles', 'audit_events', 'sessions'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format($f$
            CREATE POLICY tenant_isolation ON %I
                USING (tenant_id = current_tenant_id() OR rls_bypassed())
                WITH CHECK (tenant_id = current_tenant_id() OR rls_bypassed())
        $f$, t);
    END LOOP;
END $$;

-- The tenants table itself is scoped to the row for the current tenant, so a
-- request handled in one tenant's context cannot enumerate the customer list.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_self ON tenants;
CREATE POLICY tenant_self ON tenants
    USING (id = current_tenant_id() OR rls_bypassed())
    WITH CHECK (id = current_tenant_id() OR rls_bypassed());

COMMIT;
