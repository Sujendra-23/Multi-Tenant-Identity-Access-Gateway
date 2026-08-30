package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sujendra/identity-gateway/internal/domain"
)

type UserRepo struct{ db *DB }

func NewUserRepo(db *DB) *UserRepo { return &UserRepo{db: db} }

const userCols = `id, tenant_id, email, password_hash, display_name, status,
	failed_login_count, locked_until, last_login_at, mfa_enrolled, created_at, updated_at`

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	err := row.Scan(&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Status,
		&u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt, &u.MFAEnrolled, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// NormalizeEmail lower-cases and trims so that lookups are stable regardless of
// how the client typed the address.
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func (r *UserRepo) ByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*domain.User, error) {
	var u *domain.User
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		var err error
		u, err = scanUser(q.QueryRow(ctx,
			`SELECT `+userCols+` FROM users WHERE tenant_id=$1 AND email=$2`, tenantID, NormalizeEmail(email)))
		return err
	})
	return u, err
}

func (r *UserRepo) ByID(ctx context.Context, tenantID, id uuid.UUID) (*domain.User, error) {
	var u *domain.User
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		var err error
		u, err = scanUser(q.QueryRow(ctx,
			`SELECT `+userCols+` FROM users WHERE tenant_id=$1 AND id=$2`, tenantID, id))
		return err
	})
	return u, err
}

func (r *UserRepo) Create(ctx context.Context, tenantID uuid.UUID, email, passwordHash, displayName string) (*domain.User, error) {
	var u *domain.User
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		var err error
		u, err = scanUser(q.QueryRow(ctx,
			`INSERT INTO users (tenant_id, email, password_hash, display_name)
			 VALUES ($1,$2,$3,$4)
			 ON CONFLICT (tenant_id, email) DO NOTHING
			 RETURNING `+userCols,
			tenantID, NormalizeEmail(email), passwordHash, displayName))
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrConflict
		}
		return err
	})
	return u, err
}

func (r *UserRepo) List(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]domain.User, error) {
	var out []domain.User
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		rows, err := q.Query(ctx,
			`SELECT `+userCols+` FROM users WHERE tenant_id=$1
			 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, tenantID, limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u domain.User
			if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.DisplayName,
				&u.Status, &u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt, &u.MFAEnrolled,
				&u.CreatedAt, &u.UpdatedAt); err != nil {
				return err
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	return out, err
}

func (r *UserRepo) SetStatus(ctx context.Context, tenantID, userID uuid.UUID, status domain.UserStatus) error {
	return r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		tag, err := q.Exec(ctx,
			`UPDATE users SET status=$3, updated_at=now() WHERE tenant_id=$1 AND id=$2`,
			tenantID, userID, status)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

// RecordFailedLogin increments the failure counter and locks the account once
// it crosses the threshold. Counter and lock move together in one statement so
// concurrent guesses cannot race past the limit.
func (r *UserRepo) RecordFailedLogin(ctx context.Context, tenantID, userID uuid.UUID, maxFailures int, lockFor time.Duration) (locked bool, err error) {
	err = r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		var lockedUntil *time.Time
		scanErr := q.QueryRow(ctx,
			`UPDATE users
			    SET failed_login_count = failed_login_count + 1,
			        locked_until = CASE
			            WHEN failed_login_count + 1 >= $3 THEN now() + $4::interval
			            ELSE locked_until
			        END,
			        updated_at = now()
			  WHERE tenant_id = $1 AND id = $2
			  RETURNING locked_until`,
			tenantID, userID, maxFailures, lockFor.String()).Scan(&lockedUntil)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		if scanErr != nil {
			return scanErr
		}
		locked = lockedUntil != nil && lockedUntil.After(time.Now())
		return nil
	})
	return locked, err
}

// RecordSuccessfulLogin clears the lockout state and stamps the login time.
func (r *UserRepo) RecordSuccessfulLogin(ctx context.Context, tenantID, userID uuid.UUID) error {
	return r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		_, err := q.Exec(ctx,
			`UPDATE users SET failed_login_count=0, locked_until=NULL,
			                  last_login_at=now(), updated_at=now()
			  WHERE tenant_id=$1 AND id=$2`, tenantID, userID)
		return err
	})
}

func (r *UserRepo) UpdatePassword(ctx context.Context, tenantID, userID uuid.UUID, hash string) error {
	return r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		tag, err := q.Exec(ctx,
			`UPDATE users SET password_hash=$3, failed_login_count=0, locked_until=NULL, updated_at=now()
			  WHERE tenant_id=$1 AND id=$2`, tenantID, userID, hash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}
