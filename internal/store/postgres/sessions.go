package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/domain"
)

type SessionRepo struct{ db *DB }

func NewSessionRepo(db *DB) *SessionRepo { return &SessionRepo{db: db} }

// Redis is the hot path for session checks. This table is the durable mirror:
// it backs the "where am I signed in" view and survives a Redis failover, at
// which point sessions can be rehydrated rather than every user being logged out.

func (r *SessionRepo) Create(ctx context.Context, s *domain.Session) error {
	return r.db.InTenant(ctx, s.TenantID, func(ctx context.Context, q Querier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO sessions (id, tenant_id, user_id, family_id, device_hash, ip,
			                       user_agent, generation, amr, expires_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			s.ID, s.TenantID, s.UserID, s.FamilyID, s.DeviceHash, s.IP,
			s.UserAgent, s.Generation, s.AMR, s.ExpiresAt)
		return err
	})
}

func (r *SessionRepo) Touch(ctx context.Context, tenantID, sessionID uuid.UUID, generation int) error {
	return r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		_, err := q.Exec(ctx,
			`UPDATE sessions SET last_seen_at=now(), generation=$3
			  WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, tenantID, sessionID, generation)
		return err
	})
}

func (r *SessionRepo) Revoke(ctx context.Context, tenantID, sessionID uuid.UUID, why string) error {
	return r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		tag, err := q.Exec(ctx,
			`UPDATE sessions SET revoked_at=now(), revoked_why=$3
			  WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, tenantID, sessionID, why)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

// RevokeFamily kills every session descended from one login. This is the
// response to refresh-token reuse: if a token is replayed we cannot tell the
// attacker's branch from the victim's, so the whole family goes.
func (r *SessionRepo) RevokeFamily(ctx context.Context, tenantID, familyID uuid.UUID, why string) (int64, error) {
	var n int64
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		tag, err := q.Exec(ctx,
			`UPDATE sessions SET revoked_at=now(), revoked_why=$3
			  WHERE tenant_id=$1 AND family_id=$2 AND revoked_at IS NULL`, tenantID, familyID, why)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return nil
	})
	return n, err
}

func (r *SessionRepo) RevokeAllForUser(ctx context.Context, tenantID, userID uuid.UUID, why string) (int64, error) {
	var n int64
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		tag, err := q.Exec(ctx,
			`UPDATE sessions SET revoked_at=now(), revoked_why=$3
			  WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL`, tenantID, userID, why)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return nil
	})
	return n, err
}

type SessionView struct {
	domain.Session
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedWhy string     `json:"revoked_why,omitempty"`
}

func (r *SessionRepo) ListForUser(ctx context.Context, tenantID, userID uuid.UUID, includeRevoked bool) ([]SessionView, error) {
	var out []SessionView
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		rows, err := q.Query(ctx,
			`SELECT id, tenant_id, user_id, family_id, device_hash, ip, user_agent,
			        generation, amr, created_at, last_seen_at, expires_at, revoked_at, revoked_why
			   FROM sessions
			  WHERE tenant_id=$1 AND user_id=$2
			    AND ($3 OR (revoked_at IS NULL AND expires_at > now()))
			  ORDER BY last_seen_at DESC`, tenantID, userID, includeRevoked)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v SessionView
			if err := rows.Scan(&v.ID, &v.TenantID, &v.UserID, &v.FamilyID, &v.DeviceHash,
				&v.IP, &v.UserAgent, &v.Generation, &v.AMR, &v.CreatedAt, &v.LastSeenAt,
				&v.ExpiresAt, &v.RevokedAt, &v.RevokedWhy); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

// CountActive backs the active-sessions gauge.
func (r *SessionRepo) CountActive(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	var n int64
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM sessions
			  WHERE tenant_id=$1 AND revoked_at IS NULL AND expires_at > now()`, tenantID).Scan(&n)
	})
	return n, err
}
