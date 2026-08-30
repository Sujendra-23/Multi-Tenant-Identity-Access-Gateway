package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sujendra/identity-gateway/internal/domain"
)

// TestRLS_CrossTenantUserLookupFails is the core multi-tenancy guarantee: a
// user id that is completely valid, just in the wrong tenant, must come back as
// not-found rather than as the row. Application code enforces this too (every
// query is scoped), but this test goes around that and asks the database
// directly, which is the whole point of defence in depth.
func TestRLS_CrossTenantUserLookupFails(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenants := NewTenantRepo(db)
	users := NewUserRepo(db)

	tenantA, err := tenants.Create(ctx, uniqueSlug(t, "tenant-a"), "Tenant A", "standard")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tenantB, err := tenants.Create(ctx, uniqueSlug(t, "tenant-b"), "Tenant B", "standard")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	userA, err := users.Create(ctx, tenantA.ID, "alice@a.test", "hash", "Alice")
	if err != nil {
		t.Fatalf("create user in tenant A: %v", err)
	}

	// Ask for tenant A's user while scoped to tenant B's transaction context.
	// The row exists; RLS must still hide it.
	_, err = users.ByID(ctx, tenantB.ID, userA.ID)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-tenant lookup returned err=%v, want domain.ErrNotFound", err)
	}

	// Sanity check: the same lookup scoped to the correct tenant succeeds, so
	// the failure above is RLS doing its job and not just a broken query.
	got, err := users.ByID(ctx, tenantA.ID, userA.ID)
	if err != nil {
		t.Fatalf("same-tenant lookup should succeed: %v", err)
	}
	if got.Email != "alice@a.test" {
		t.Fatalf("got wrong user back: %+v", got)
	}
}

// TestRLS_RawQueryWithoutTenantFilterIsClosedByDefault simulates the exact
// mistake RLS exists to catch: application code that runs a query scoped to one
// tenant's transaction but forgets to add "WHERE tenant_id = ..." itself. If RLS
// is doing its job, the missing clause is irrelevant — the session-level policy
// filters the rows regardless of what the query text says.
func TestRLS_RawQueryWithoutTenantFilterIsClosedByDefault(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenants := NewTenantRepo(db)
	users := NewUserRepo(db)

	tenantA, err := tenants.Create(ctx, uniqueSlug(t, "tenant-forgetful-a"), "A", "standard")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tenantB, err := tenants.Create(ctx, uniqueSlug(t, "tenant-forgetful-b"), "B", "standard")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	if _, err := users.Create(ctx, tenantA.ID, "a@test.example", "hash", "A"); err != nil {
		t.Fatalf("create user in A: %v", err)
	}
	if _, err := users.Create(ctx, tenantB.ID, "b@test.example", "hash", "B"); err != nil {
		t.Fatalf("create user in B: %v", err)
	}

	var count int
	err = db.InTenant(ctx, tenantA.ID, func(ctx context.Context, q Querier) error {
		// Deliberately no "AND tenant_id = $1" here — this is the bug RLS is
		// supposed to make harmless.
		return q.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&count)
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Fatalf("unscoped query inside tenant A's transaction returned %d rows, want exactly 1 (tenant A's own user only)", count)
	}
}

// TestRLS_NoTenantContextSeesNothing checks the fail-closed default directly: a
// query issued without ever calling InTenant or InSystem (so app.current_tenant
// is unset) must return zero rows rather than every tenant's data.
func TestRLS_NoTenantContextSeesNothing(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenants := NewTenantRepo(db)
	users := NewUserRepo(db)

	tenant, err := tenants.Create(ctx, uniqueSlug(t, "tenant-noctx"), "NoCtx", "standard")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := users.Create(ctx, tenant.ID, "someone@test.example", "hash", "Someone"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	conn, err := db.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire raw connection: %v", err)
	}
	defer conn.Release()

	var count int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("query on a connection with no tenant context set: %v", err)
	}
	if count != 0 {
		t.Fatalf("query with no app.current_tenant set returned %d rows, want 0 (fail closed)", count)
	}
}

// TestRLS_ConnectionResetBetweenBorrows confirms AfterRelease actually clears
// both GUCs, so a connection that served tenant A's request cannot leak tenant
// context to whichever request the pool hands it to next.
func TestRLS_ConnectionResetBetweenBorrows(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenants := NewTenantRepo(db)

	tenant, err := tenants.Create(ctx, uniqueSlug(t, "tenant-reset"), "Reset", "standard")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// Run a tenant-scoped transaction and let the connection return to the pool.
	if err := db.InTenant(ctx, tenant.ID, func(ctx context.Context, q Querier) error {
		_, err := q.Exec(ctx, `SELECT 1`)
		return err
	}); err != nil {
		t.Fatalf("tenant transaction: %v", err)
	}

	// Acquire directly (likely, though not guaranteed, the same connection) and
	// check the GUC was actually reset rather than left at tenant.ID.
	conn, err := db.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	var setting string
	if err := conn.QueryRow(ctx, `SELECT coalesce(current_setting('app.current_tenant', true), '')`).Scan(&setting); err != nil {
		t.Fatalf("read setting: %v", err)
	}
	if setting != "" {
		t.Fatalf("app.current_tenant leaked between borrows: got %q, want empty", setting)
	}
}

var slugCounter int

// uniqueSlug keeps repeated test runs against a persistent database (the tests
// do not truncate tables between runs) from colliding on the tenant slug
// uniqueness constraint. The slug check constraint only allows
// [a-z0-9][a-z0-9-]*, so t.Name()'s uppercase letters and underscores have to
// be normalised rather than embedded verbatim.
func uniqueSlug(t *testing.T, base string) string {
	t.Helper()
	slugCounter++
	// Keep well under the 63-char slug check constraint: a full (possibly
	// subtest) test name plus base plus counter can otherwise overflow it.
	// Uniqueness only needs to hold within one test run, since each run's
	// database is disposable.
	return base + "-" + itoa(int(time.Now().UnixNano()%1_000_000)) + "-" + itoa(slugCounter)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
