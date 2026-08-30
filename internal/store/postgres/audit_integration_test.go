package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/domain"
)

// TestAuditChain_AppendAndVerify exercises the append path end to end: several
// batches, from different logical "requests", extending one tenant's chain, and
// confirms VerifyChain replays cleanly across all of them with sequence numbers
// contiguous from 1.
func TestAuditChain_AppendAndVerify(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenants := NewTenantRepo(db)
	audit := NewAuditRepo(db)

	tenant, err := tenants.Create(ctx, uniqueSlug(t, "audit-chain"), "Audit Chain Co", "standard")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	actor := uuid.New()
	batch1 := []*domain.AuditEvent{
		{ActorID: &actor, ActorEmail: "a@test.example", Action: "auth.login", Decision: domain.DecisionAllow},
		{ActorID: &actor, ActorEmail: "a@test.example", Action: "user.create", Decision: domain.DecisionAllow, Resource: "users:1"},
	}
	if err := audit.AppendBatch(ctx, tenant.ID, batch1); err != nil {
		t.Fatalf("append batch 1: %v", err)
	}
	batch2 := []*domain.AuditEvent{
		{ActorID: &actor, ActorEmail: "a@test.example", Action: "role.grant", Decision: domain.DecisionAllow},
	}
	if err := audit.AppendBatch(ctx, tenant.ID, batch2); err != nil {
		t.Fatalf("append batch 2: %v", err)
	}

	result, err := audit.VerifyChain(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected a valid chain, got %+v", result)
	}
	if result.EventsChecked != 3 {
		t.Fatalf("EventsChecked = %d, want 3", result.EventsChecked)
	}

	events, err := audit.List(ctx, tenant.ID, AuditQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("List returned %d events, want 3", len(events))
	}
	// List orders newest first.
	if events[0].Sequence != 3 || events[2].Sequence != 1 {
		t.Fatalf("unexpected sequence ordering: %+v", []int64{events[0].Sequence, events[1].Sequence, events[2].Sequence})
	}
}

// TestAuditChain_DetectsTamperedRecord is the end-to-end version of the pure
// ChainHash unit tests: it writes real rows, reaches into the database to edit
// one exactly the way an attacker with a stray UPDATE privilege might (bypassing
// the immutability trigger via the same bypass-RLS path migrations use, since
// the trigger blocks this from the application role entirely — see
// TestAuditChain_ImmutabilityTriggerBlocksUpdate for that guarantee), and
// confirms VerifyChain notices.
func TestAuditChain_DetectsTamperedRecord(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenants := NewTenantRepo(db)
	audit := NewAuditRepo(db)

	tenant, err := tenants.Create(ctx, uniqueSlug(t, "audit-tamper"), "Tamper Co", "standard")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := audit.AppendBatch(ctx, tenant.ID, []*domain.AuditEvent{
		{Action: "auth.login", Decision: domain.DecisionAllow, RiskScore: 5},
		{Action: "user.create", Decision: domain.DecisionAllow, RiskScore: 10},
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	// The immutability trigger fires regardless of RLS bypass (it is a BEFORE
	// UPDATE trigger on the table itself, not a policy), so simulating tampering
	// has to go around it the way a real attacker with raw storage access or a
	// restore-from-backup would: by disabling the trigger first. This is
	// intentionally not something the application code path can do — it is only
	// reachable here, as a superuser, to construct the test scenario.
	admin := testDBWithDSN(t, adminDSNOrSkip(t))
	_, err = admin.Pool().Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update`)
	if err != nil {
		t.Fatalf("disable trigger for test setup: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Pool().Exec(context.Background(), `ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update`)
	})
	_, err = admin.Pool().Exec(ctx,
		`UPDATE audit_events SET risk_score = 999 WHERE tenant_id = $1 AND sequence = 2`, tenant.ID)
	if err != nil {
		t.Fatalf("tamper with row: %v", err)
	}

	result, err := audit.VerifyChain(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if result.Valid {
		t.Fatal("expected VerifyChain to detect the tampered risk_score, but it reported the chain valid")
	}
	if result.BrokenAtSeq == nil || *result.BrokenAtSeq != 2 {
		t.Fatalf("expected the break to be reported at sequence 2, got %+v", result.BrokenAtSeq)
	}
}

// TestAuditChain_ImmutabilityTriggerBlocksUpdate confirms the database-level
// guarantee that TestAuditChain_DetectsTamperedRecord above had to specifically
// work around: through the ordinary, non-superuser application role, UPDATE and
// DELETE on audit_events are rejected outright, before RLS or application logic
// even enters into it.
func TestAuditChain_ImmutabilityTriggerBlocksUpdate(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenants := NewTenantRepo(db)
	audit := NewAuditRepo(db)

	tenant, err := tenants.Create(ctx, uniqueSlug(t, "audit-immutable"), "Immutable Co", "standard")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if err := audit.AppendBatch(ctx, tenant.ID, []*domain.AuditEvent{
		{Action: "auth.login", Decision: domain.DecisionAllow},
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	err = db.InTenant(ctx, tenant.ID, func(ctx context.Context, q Querier) error {
		_, err := q.Exec(ctx, `UPDATE audit_events SET decision = 'deny' WHERE tenant_id = $1`, tenant.ID)
		return err
	})
	if err == nil {
		t.Fatal("expected UPDATE on audit_events to be rejected by the immutability trigger")
	}

	err = db.InTenant(ctx, tenant.ID, func(ctx context.Context, q Querier) error {
		_, err := q.Exec(ctx, `DELETE FROM audit_events WHERE tenant_id = $1`, tenant.ID)
		return err
	})
	if err == nil {
		t.Fatal("expected DELETE on audit_events to be rejected by the immutability trigger")
	}
}

func adminDSNOrSkip(t *testing.T) string {
	t.Helper()
	dsn := getenvOrSkip(t, "POSTGRES_TEST_ADMIN_DSN")
	return dsn
}
