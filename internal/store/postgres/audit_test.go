package postgres

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/domain"
)

func sampleEvent() *domain.AuditEvent {
	actor := uuid.New()
	return &domain.AuditEvent{
		TenantID: uuid.New(), Sequence: 1, ActorID: &actor, ActorEmail: "alice@example.com",
		Action: "user.create", Resource: "users:123", Decision: domain.DecisionAllow,
		Reason: "", RiskScore: 10, IP: "203.0.113.1", UserAgent: "test-agent",
		RequestID: "req-1", Metadata: map[string]string{"key": "value"},
		OccurredAt: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
	}
}

func TestChainHash_Deterministic(t *testing.T) {
	e := sampleEvent()
	h1 := ChainHash(GenesisHash, e)
	h2 := ChainHash(GenesisHash, e)
	if h1 != h2 {
		t.Fatal("hashing the same event twice produced different results")
	}
}

// TestChainHash_DetectsFieldTampering is the property the whole audit design
// rests on: changing anything about a recorded event — even a field that looks
// cosmetic — must change its hash, which is what makes silent tampering
// detectable by VerifyChain.
func TestChainHash_DetectsFieldTampering(t *testing.T) {
	base := sampleEvent()
	baseHash := ChainHash(GenesisHash, base)

	mutations := map[string]func(*domain.AuditEvent){
		"decision":       func(e *domain.AuditEvent) { e.Decision = domain.DecisionDeny },
		"resource":       func(e *domain.AuditEvent) { e.Resource = "users:456" },
		"risk_score":     func(e *domain.AuditEvent) { e.RiskScore = 99 },
		"reason":         func(e *domain.AuditEvent) { e.Reason = "tampered" },
		"actor_email":    func(e *domain.AuditEvent) { e.ActorEmail = "mallory@example.com" },
		"metadata_value": func(e *domain.AuditEvent) { e.Metadata = map[string]string{"key": "different"} },
		"metadata_key":   func(e *domain.AuditEvent) { e.Metadata = map[string]string{"other": "value"} },
		"occurred_at":    func(e *domain.AuditEvent) { e.OccurredAt = e.OccurredAt.Add(time.Second) },
		"sequence":       func(e *domain.AuditEvent) { e.Sequence = 2 },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e := sampleEvent()
			mutate(e)
			if got := ChainHash(GenesisHash, e); got == baseHash {
				t.Errorf("mutating %s did not change the hash; tampering would go undetected", name)
			}
		})
	}
}

func TestChainHash_DetectsPredecessorTampering(t *testing.T) {
	e := sampleEvent()
	h1 := ChainHash(GenesisHash, e)
	h2 := ChainHash("a-different-predecessor-hash", e)
	if h1 == h2 {
		t.Fatal("changing the predecessor hash did not change the result; deleting an earlier record would go undetected")
	}
}

func TestChainHash_MetadataOrderIndependent(t *testing.T) {
	// Metadata comes back from a map with no guaranteed iteration order (both in
	// Go and after a JSONB round trip through Postgres); the hash must not
	// depend on which order the keys happened to be visited in.
	//
	// e1 and e2 must be identical apart from metadata key order — sampleEvent()
	// mints a fresh random tenant and actor id on every call, so two independent
	// calls would differ for reasons that have nothing to do with metadata.
	e1 := sampleEvent()
	e2 := *e1
	e1.Metadata = map[string]string{"a": "1", "b": "2", "c": "3"}
	e2.Metadata = map[string]string{"c": "3", "a": "1", "b": "2"}

	if ChainHash(GenesisHash, e1) != ChainHash(GenesisHash, &e2) {
		t.Fatal("hash depends on metadata map iteration order, which is not guaranteed stable")
	}
}

func TestChainHash_TimestampTruncationStable(t *testing.T) {
	// Postgres timestamptz has microsecond resolution. A value carrying
	// sub-microsecond precision must hash the same before and after truncation,
	// or the chain would fail to verify purely from the storage round trip
	// (see AppendBatch, which truncates before hashing).
	e := sampleEvent()
	e.OccurredAt = time.Date(2025, 1, 1, 12, 0, 0, 500, time.UTC) // 500ns
	truncated := *e
	truncated.OccurredAt = e.OccurredAt.Truncate(time.Microsecond)

	if ChainHash(GenesisHash, e) == ChainHash(GenesisHash, &truncated) {
		t.Fatal("expected nanosecond precision to affect the hash before truncation is applied")
	}
	// This documents *why* AppendBatch truncates before hashing: without it,
	// the in-memory hash would never match what a later VerifyChain recomputes
	// from the truncated value read back out of the database.
}

func TestChainHash_NilActorHandled(t *testing.T) {
	e := sampleEvent()
	e.ActorID = nil
	// Must not panic, and must still be deterministic.
	h1 := ChainHash(GenesisHash, e)
	h2 := ChainHash(GenesisHash, e)
	if h1 != h2 {
		t.Fatal("nil actor id produced a non-deterministic hash")
	}
}
