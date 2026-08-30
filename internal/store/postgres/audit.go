package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sujendra/identity-gateway/internal/domain"
)

type AuditRepo struct{ db *DB }

func NewAuditRepo(db *DB) *AuditRepo { return &AuditRepo{db: db} }

// GenesisHash anchors every tenant's chain. The first record commits to this
// constant, so a chain that has had its opening records removed no longer
// verifies from the genesis.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// canonicalPayload builds the exact byte string that a record's hash covers.
// It is field-ordered and explicitly delimited rather than JSON-marshalled:
// Go's map iteration order and Postgres's JSONB normalisation would each make a
// JSON encoding unstable, and an unstable encoding means an unverifiable chain.
// Metadata is folded in as key-sorted pairs for the same reason.
func canonicalPayload(e *domain.AuditEvent) string {
	var b strings.Builder
	write := func(parts ...string) {
		for _, p := range parts {
			b.WriteString(p)
			b.WriteByte(0x1f) // unit separator, not present in any input
		}
	}
	actor := ""
	if e.ActorID != nil {
		actor = e.ActorID.String()
	}
	write(
		e.TenantID.String(),
		strconv.FormatInt(e.Sequence, 10),
		actor,
		e.ActorEmail,
		e.Action,
		e.Resource,
		e.Decision,
		e.Reason,
		strconv.Itoa(e.RiskScore),
		e.IP,
		e.UserAgent,
		e.RequestID,
		e.OccurredAt.UTC().Format(time.RFC3339Nano),
	)
	keys := make([]string, 0, len(e.Metadata))
	for k := range e.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		write(k, e.Metadata[k])
	}
	return b.String()
}

// ChainHash computes hash(prev_hash || canonical(record)).
func ChainHash(prevHash string, e *domain.AuditEvent) string {
	sum := sha256.Sum256([]byte(prevHash + "\x1e" + canonicalPayload(e)))
	return hex.EncodeToString(sum[:])
}

// AppendBatch writes a batch of events for one tenant, extending the tenant's
// hash chain.
//
// A transaction-scoped advisory lock keyed on the tenant serialises appenders,
// which is what makes "read the tip, then extend it" safe under concurrency:
// without it two writers could both read sequence N and produce a fork. The
// lock is per tenant, so tenants never block each other.
func (r *AuditRepo) AppendBatch(ctx context.Context, tenantID uuid.UUID, events []*domain.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	return r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1::text)::bigint)`, tenantID.String()); err != nil {
			return fmt.Errorf("audit lock: %w", err)
		}

		var seq int64
		prevHash := GenesisHash
		err := q.QueryRow(ctx,
			`SELECT sequence, hash FROM audit_events
			  WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT 1`, tenantID).Scan(&seq, &prevHash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read chain tip: %w", err)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			seq, prevHash = 0, GenesisHash
		}

		for _, e := range events {
			e.TenantID = tenantID
			seq++
			e.Sequence = seq
			if e.Metadata == nil {
				e.Metadata = map[string]string{}
			}
			metaJSON, err := json.Marshal(e.Metadata)
			if err != nil {
				return fmt.Errorf("marshal metadata: %w", err)
			}
			// Postgres timestamptz resolves to microseconds. Truncating before
			// hashing means the value we hash is the value that comes back out,
			// so the chain still verifies after a round trip.
			e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
			e.PrevHash = prevHash
			e.Hash = ChainHash(prevHash, e)

			if _, err := q.Exec(ctx,
				`INSERT INTO audit_events
				   (tenant_id, sequence, actor_id, actor_email, action, resource, decision,
				    reason, risk_score, ip, user_agent, request_id, metadata, occurred_at,
				    prev_hash, hash)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
				tenantID, e.Sequence, e.ActorID, e.ActorEmail, e.Action, e.Resource, e.Decision,
				e.Reason, e.RiskScore, e.IP, e.UserAgent, e.RequestID, metaJSON, e.OccurredAt,
				e.PrevHash, e.Hash); err != nil {
				return fmt.Errorf("insert audit event: %w", err)
			}
			prevHash = e.Hash
		}
		return nil
	})
}

type AuditQuery struct {
	Action   string
	Decision string
	ActorID  *uuid.UUID
	Limit    int
	Offset   int
}

func (r *AuditRepo) List(ctx context.Context, tenantID uuid.UUID, qy AuditQuery) ([]domain.AuditEvent, error) {
	if qy.Limit <= 0 || qy.Limit > 500 {
		qy.Limit = 100
	}
	var out []domain.AuditEvent
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		rows, err := q.Query(ctx,
			`SELECT id, tenant_id, sequence, actor_id, actor_email, action, resource, decision,
			        reason, risk_score, ip, user_agent, request_id, metadata, occurred_at,
			        prev_hash, hash
			   FROM audit_events
			  WHERE tenant_id = $1
			    AND ($2 = '' OR action = $2)
			    AND ($3 = '' OR decision = $3)
			    AND ($4::uuid IS NULL OR actor_id = $4)
			  ORDER BY sequence DESC
			  LIMIT $5 OFFSET $6`,
			tenantID, qy.Action, qy.Decision, qy.ActorID, qy.Limit, qy.Offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.AuditEvent
			var meta []byte
			if err := rows.Scan(&e.ID, &e.TenantID, &e.Sequence, &e.ActorID, &e.ActorEmail,
				&e.Action, &e.Resource, &e.Decision, &e.Reason, &e.RiskScore, &e.IP,
				&e.UserAgent, &e.RequestID, &meta, &e.OccurredAt, &e.PrevHash, &e.Hash); err != nil {
				return err
			}
			if len(meta) > 0 {
				_ = json.Unmarshal(meta, &e.Metadata)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// ChainVerification is the result of replaying a tenant's audit chain.
type ChainVerification struct {
	Valid         bool   `json:"valid"`
	EventsChecked int    `json:"events_checked"`
	BrokenAtSeq   *int64 `json:"broken_at_sequence,omitempty"`
	Detail        string `json:"detail,omitempty"`
	HeadHash      string `json:"head_hash,omitempty"`
}

// VerifyChain replays every record in sequence order, recomputing each hash from
// the record's own contents plus its predecessor's hash. It catches three
// distinct kinds of tampering: an edited record (hash mismatch), a deleted
// record (sequence gap and broken link), and an inserted record (link mismatch).
func (r *AuditRepo) VerifyChain(ctx context.Context, tenantID uuid.UUID) (*ChainVerification, error) {
	res := &ChainVerification{Valid: true}
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		rows, err := q.Query(ctx,
			`SELECT tenant_id, sequence, actor_id, actor_email, action, resource, decision,
			        reason, risk_score, ip, user_agent, request_id, metadata, occurred_at,
			        prev_hash, hash
			   FROM audit_events WHERE tenant_id=$1 ORDER BY sequence ASC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()

		expectedPrev := GenesisHash
		var expectedSeq int64 = 1
		for rows.Next() {
			var e domain.AuditEvent
			var meta []byte
			if err := rows.Scan(&e.TenantID, &e.Sequence, &e.ActorID, &e.ActorEmail, &e.Action,
				&e.Resource, &e.Decision, &e.Reason, &e.RiskScore, &e.IP, &e.UserAgent,
				&e.RequestID, &meta, &e.OccurredAt, &e.PrevHash, &e.Hash); err != nil {
				return err
			}
			// Metadata is part of the hashed payload, so it has to be rehydrated
			// before the hash is recomputed.
			e.Metadata = map[string]string{}
			if len(meta) > 0 {
				if err := json.Unmarshal(meta, &e.Metadata); err != nil {
					return fmt.Errorf("decode metadata at sequence %d: %w", e.Sequence, err)
				}
			}
			res.EventsChecked++

			if e.Sequence != expectedSeq {
				res.Valid = false
				seq := e.Sequence
				res.BrokenAtSeq = &seq
				res.Detail = fmt.Sprintf("sequence gap: expected %d, found %d (records removed?)", expectedSeq, e.Sequence)
				return nil
			}
			if e.PrevHash != expectedPrev {
				res.Valid = false
				seq := e.Sequence
				res.BrokenAtSeq = &seq
				res.Detail = "predecessor link mismatch"
				return nil
			}
			if got := ChainHash(e.PrevHash, &e); got != e.Hash {
				res.Valid = false
				seq := e.Sequence
				res.BrokenAtSeq = &seq
				res.Detail = "record contents do not match stored hash (record modified?)"
				return nil
			}
			expectedPrev = e.Hash
			expectedSeq++
		}
		res.HeadHash = expectedPrev
		return rows.Err()
	})
	return res, err
}
