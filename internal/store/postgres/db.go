// Package postgres implements the durable store. Access is deliberately funnel
// shaped: callers cannot get a raw connection, they get one through InTenant or
// InSystem, which decide what row-level security will allow.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed all:migrations
var migrationFS embed.FS

// Querier is the subset of pgx shared by *pgxpool.Pool and pgx.Tx, so
// repository methods work inside or outside an explicit transaction.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type DB struct {
	pool *pgxpool.Pool
}

func Connect(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	// A connection returning to the pool must not carry the previous request's
	// tenant with it. Resetting both GUCs here means a leaked setting can never
	// widen a later query's visibility.
	cfg.AfterRelease = func(c *pgx.Conn) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := c.Exec(ctx, "SELECT set_config('app.current_tenant','',false), set_config('app.bypass_rls','off',false)")
		return err == nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (d *DB) Close() { d.pool.Close() }

func (d *DB) Ping(ctx context.Context) error { return d.pool.Ping(ctx) }

func (d *DB) Pool() *pgxpool.Pool { return d.pool }

// VerifyRLSEnforceable checks that the connected role cannot bypass row-level
// security, and returns an error naming exactly why if it can.
//
// This exists because of a sharp edge in Postgres that is very easy to
// reintroduce by accident: row security is unconditionally skipped for
// superusers and for any role with the BYPASSRLS attribute, and neither
// ENABLE ROW LEVEL SECURITY nor FORCE ROW LEVEL SECURITY can override that —
// it is not a bug, it is documented Postgres behaviour. The catch is that the
// bootstrap role the official postgres Docker image creates from POSTGRES_USER
// is a superuser by default and cannot even have that attribute removed (it is
// the role that ran initdb). So the "obvious" docker-compose setup — point
// POSTGRES_DSN straight at POSTGRES_USER — silently turns every tenant
// isolation guarantee in migrations/0002_rls.sql into a no-op, with no error
// anywhere: queries keep working, they just quietly stop being scoped.
//
// The fix is operational (a dedicated, restricted role — see
// deploy/postgres-init/01-app-role.sql and the README), but a misconfiguration
// this consequential and this easy to make should not depend on everyone
// remembering it. The gateway calls this at startup and refuses to serve
// traffic if it fails.
func (d *DB) VerifyRLSEnforceable(ctx context.Context) error {
	var isSuperuser, canBypassRLS bool
	err := d.pool.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&isSuperuser, &canBypassRLS)
	if err != nil {
		return fmt.Errorf("check current role's RLS attributes: %w", err)
	}
	if isSuperuser {
		return errors.New(
			"the database role the gateway connected as has SUPERUSER, which makes Postgres " +
				"skip row-level security for every query regardless of policy — tenant isolation " +
				"is not actually enforced. Connect as a dedicated non-superuser role instead " +
				"(see deploy/postgres-init/01-app-role.sql)")
	}
	if canBypassRLS {
		return errors.New(
			"the database role the gateway connected as has BYPASSRLS, which makes Postgres " +
				"skip row-level security for every query regardless of policy — tenant isolation " +
				"is not actually enforced. Run ALTER ROLE <name> NOBYPASSRLS, or connect as a " +
				"different role (see deploy/postgres-init/01-app-role.sql)")
	}
	return nil
}

// InTenant runs fn in a transaction pinned to one tenant. set_config with
// is_local=true scopes the setting to this transaction, so it unwinds on commit
// or rollback and cannot leak to the next borrower of the connection.
//
// This is the only sanctioned way to touch tenant-owned data on a request path.
func (d *DB) InTenant(ctx context.Context, tenantID uuid.UUID, fn func(context.Context, Querier) error) error {
	if tenantID == uuid.Nil {
		return errors.New("postgres: refusing to open a tenant transaction with a nil tenant id")
	}
	return d.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant', $1, true)", tenantID.String()); err != nil {
			return fmt.Errorf("set tenant context: %w", err)
		}
		return fn(ctx, tx)
	})
}

// InSystem runs fn with row-level security bypassed. It exists for the handful
// of operations that legitimately have no tenant context: migrations, tenant
// creation, cross-tenant key management and the login lookup that resolves a
// tenant slug in the first place. Every call site should be obvious on sight.
func (d *DB) InSystem(ctx context.Context, fn func(context.Context, Querier) error) error {
	return d.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.bypass_rls', 'on', true)"); err != nil {
			return fmt.Errorf("set bypass: %w", err)
		}
		return fn(ctx, tx)
	})
}

func (d *DB) inTx(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		// Rollback on a committed transaction is a no-op, so this is safe as an
		// unconditional guard against an early return leaving the tx open.
		_ = tx.Rollback(context.WithoutCancel(ctx))
	}()

	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// Migrate applies every embedded migration in filename order, inside a single
// bypass transaction. Migrations are written to be idempotent so re-running
// them on an existing database is safe.
func (d *DB) Migrate(ctx context.Context) ([]string, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	applied := make([]string, 0, len(names))
	for _, name := range names {
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return applied, fmt.Errorf("read %s: %w", name, err)
		}
		// Each file manages its own BEGIN/COMMIT, so it runs on a raw
		// connection with the bypass set at session scope for the duration.
		conn, err := d.pool.Acquire(ctx)
		if err != nil {
			return applied, fmt.Errorf("acquire for %s: %w", name, err)
		}
		_, err = conn.Exec(ctx, "SELECT set_config('app.bypass_rls','on',false)")
		if err == nil {
			_, err = conn.Exec(ctx, string(body))
		}
		conn.Release()
		if err != nil {
			return applied, fmt.Errorf("apply %s: %w", name, err)
		}
		applied = append(applied, name)
	}
	return applied, nil
}
