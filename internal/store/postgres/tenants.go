package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sujendra/identity-gateway/internal/domain"
)

type TenantRepo struct{ db *DB }

func NewTenantRepo(db *DB) *TenantRepo { return &TenantRepo{db: db} }

const tenantCols = `id, slug, name, status, plan, policy_version, rate_limit_rps, created_at, updated_at`

func scanTenant(row pgx.Row) (*domain.Tenant, error) {
	var t domain.Tenant
	err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.Plan, &t.PolicyVersion,
		&t.RateLimitRPS, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// BySlug resolves the tenant for an incoming request. This runs in system scope
// because tenant resolution is what establishes the tenant context in the first
// place; there is nothing to scope to yet.
func (r *TenantRepo) BySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	var t *domain.Tenant
	err := r.db.InSystem(ctx, func(ctx context.Context, q Querier) error {
		var err error
		t, err = scanTenant(q.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE slug = $1`, slug))
		return err
	})
	return t, err
}

func (r *TenantRepo) ByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	var t *domain.Tenant
	err := r.db.InSystem(ctx, func(ctx context.Context, q Querier) error {
		var err error
		t, err = scanTenant(q.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id = $1`, id))
		return err
	})
	return t, err
}

func (r *TenantRepo) Create(ctx context.Context, slug, name, plan string) (*domain.Tenant, error) {
	var t *domain.Tenant
	err := r.db.InSystem(ctx, func(ctx context.Context, q Querier) error {
		var err error
		t, err = scanTenant(q.QueryRow(ctx,
			`INSERT INTO tenants (slug, name, plan) VALUES ($1,$2,$3)
			 ON CONFLICT (slug) DO NOTHING
			 RETURNING `+tenantCols, slug, name, plan))
		if errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("tenant %q: %w", slug, domain.ErrConflict)
		}
		return err
	})
	return t, err
}

func (r *TenantRepo) List(ctx context.Context) ([]domain.Tenant, error) {
	var out []domain.Tenant
	err := r.db.InSystem(ctx, func(ctx context.Context, q Querier) error {
		rows, err := q.Query(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY created_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t domain.Tenant
			if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.Plan,
				&t.PolicyVersion, &t.RateLimitRPS, &t.CreatedAt, &t.UpdatedAt); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

func (r *TenantRepo) SetStatus(ctx context.Context, id uuid.UUID, status domain.TenantStatus) error {
	return r.db.InSystem(ctx, func(ctx context.Context, q Querier) error {
		tag, err := q.Exec(ctx, `UPDATE tenants SET status=$2, updated_at=now() WHERE id=$1`, id, status)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

// BumpPolicyVersion invalidates every cached authorization decision for the
// tenant. Callers invoke it inside the same transaction as the change that made
// the old decisions wrong, so a permission edit and its invalidation commit
// atomically and there is no window where a stale grant is still honoured.
func BumpPolicyVersion(ctx context.Context, q Querier, tenantID uuid.UUID) (int64, error) {
	var version int64
	err := q.QueryRow(ctx,
		`UPDATE tenants SET policy_version = policy_version + 1, updated_at = now()
		 WHERE id = $1 RETURNING policy_version`, tenantID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, domain.ErrNotFound
	}
	return version, err
}
