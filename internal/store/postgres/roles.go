package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sujendra/identity-gateway/internal/domain"
)

type RoleRepo struct{ db *DB }

func NewRoleRepo(db *DB) *RoleRepo { return &RoleRepo{db: db} }

func (r *RoleRepo) Create(ctx context.Context, tenantID uuid.UUID, name, description string, isSystem bool) (*domain.Role, error) {
	var role *domain.Role
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		var out domain.Role
		err := q.QueryRow(ctx,
			`INSERT INTO roles (tenant_id, name, description, is_system)
			 VALUES ($1,$2,$3,$4)
			 ON CONFLICT (tenant_id, name) DO NOTHING
			 RETURNING id, tenant_id, name, description, is_system, created_at`,
			tenantID, name, description, isSystem).
			Scan(&out.ID, &out.TenantID, &out.Name, &out.Description, &out.IsSystem, &out.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrConflict
		}
		if err != nil {
			return err
		}
		// A new role changes what the tenant's policy can express, so every
		// cached decision for the tenant is retired in the same transaction.
		if _, err := BumpPolicyVersion(ctx, q, tenantID); err != nil {
			return err
		}
		role = &out
		return nil
	})
	return role, err
}

func (r *RoleRepo) ByName(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Role, error) {
	var role *domain.Role
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		var out domain.Role
		err := q.QueryRow(ctx,
			`SELECT id, tenant_id, name, description, is_system, created_at
			   FROM roles WHERE tenant_id=$1 AND name=$2`, tenantID, name).
			Scan(&out.ID, &out.TenantID, &out.Name, &out.Description, &out.IsSystem, &out.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		if err != nil {
			return err
		}
		role = &out
		return nil
	})
	return role, err
}

// List returns the tenant's roles together with their grants, in a single
// round trip rather than one query per role.
func (r *RoleRepo) List(ctx context.Context, tenantID uuid.UUID) ([]domain.Role, error) {
	var out []domain.Role
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		rows, err := q.Query(ctx,
			`SELECT r.id, r.tenant_id, r.name, r.description, r.is_system, r.created_at,
			        coalesce(
			          array_agg(p.resource || ':' || p.action || ':' || rp.effect)
			            FILTER (WHERE p.id IS NOT NULL),
			          '{}'
			        ) AS grants
			   FROM roles r
			   LEFT JOIN role_permissions rp ON rp.role_id = r.id
			   LEFT JOIN permissions p       ON p.id = rp.permission_id
			  WHERE r.tenant_id = $1
			  GROUP BY r.id
			  ORDER BY r.name`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var role domain.Role
			var grants []string
			if err := rows.Scan(&role.ID, &role.TenantID, &role.Name, &role.Description,
				&role.IsSystem, &role.CreatedAt, &grants); err != nil {
				return err
			}
			role.Permissions = parseGrants(grants)
			out = append(out, role)
		}
		return rows.Err()
	})
	return out, err
}

// parseGrants decodes the "resource:action:effect" triples produced by the
// aggregate above.
func parseGrants(raw []string) []domain.Permission {
	perms := make([]domain.Permission, 0, len(raw))
	for _, g := range raw {
		var resource, action, effect string
		// Split from the right: resource and action never contain ':', but
		// splitting explicitly keeps this readable.
		parts := splitN3(g)
		if parts == nil {
			continue
		}
		resource, action, effect = parts[0], parts[1], parts[2]
		perms = append(perms, domain.Permission{Resource: resource, Action: action, Effect: effect})
	}
	return perms
}

func splitN3(s string) []string {
	out := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(s) && len(out) < 2; i++ {
		if s[i] == ':' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if len(out) != 2 {
		return nil
	}
	return append(out, s[start:])
}

// GrantPermission attaches a permission to a role. The permission must already
// exist in the global catalogue; tenants pick from a vocabulary rather than
// inventing resource names, which keeps audit queries meaningful across tenants.
func (r *RoleRepo) GrantPermission(ctx context.Context, tenantID, roleID uuid.UUID, resource, action, effect string) error {
	return r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		var permID uuid.UUID
		err := q.QueryRow(ctx,
			`SELECT id FROM permissions WHERE resource=$1 AND action=$2`, resource, action).Scan(&permID)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		if err != nil {
			return err
		}
		// Verify the role belongs to this tenant before granting. RLS would
		// block a cross-tenant role anyway; this turns a silent no-op into a
		// clear error.
		var owned bool
		if err := q.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM roles WHERE id=$1 AND tenant_id=$2)`, roleID, tenantID).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return domain.ErrNotFound
		}
		if _, err := q.Exec(ctx,
			`INSERT INTO role_permissions (tenant_id, role_id, permission_id, effect)
			 VALUES ($1,$2,$3,$4)
			 ON CONFLICT (role_id, permission_id) DO UPDATE SET effect = EXCLUDED.effect`,
			tenantID, roleID, permID, effect); err != nil {
			return err
		}
		_, err = BumpPolicyVersion(ctx, q, tenantID)
		return err
	})
}

func (r *RoleRepo) RevokePermission(ctx context.Context, tenantID, roleID uuid.UUID, resource, action string) error {
	return r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		tag, err := q.Exec(ctx,
			`DELETE FROM role_permissions rp
			  USING permissions p
			  WHERE rp.permission_id = p.id
			    AND rp.role_id = $1 AND rp.tenant_id = $2
			    AND p.resource = $3 AND p.action = $4`, roleID, tenantID, resource, action)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		_, err = BumpPolicyVersion(ctx, q, tenantID)
		return err
	})
}

func (r *RoleRepo) AssignRole(ctx context.Context, tenantID, userID, roleID uuid.UUID, grantedBy *uuid.UUID) error {
	return r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		tag, err := q.Exec(ctx,
			`INSERT INTO user_roles (tenant_id, user_id, role_id, granted_by)
			 SELECT $1, $2, $3, $4
			  WHERE EXISTS (SELECT 1 FROM users u WHERE u.id=$2 AND u.tenant_id=$1)
			    AND EXISTS (SELECT 1 FROM roles r WHERE r.id=$3 AND r.tenant_id=$1)
			 ON CONFLICT (user_id, role_id) DO NOTHING`,
			tenantID, userID, roleID, grantedBy)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			// Either the pair already existed or one side is not in this
			// tenant. Distinguish so the caller gets an honest answer.
			var exists bool
			if err := q.QueryRow(ctx,
				`SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id=$1 AND role_id=$2)`,
				userID, roleID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return domain.ErrNotFound
			}
			return nil
		}
		_, err = BumpPolicyVersion(ctx, q, tenantID)
		return err
	})
}

func (r *RoleRepo) UnassignRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) error {
	return r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		tag, err := q.Exec(ctx,
			`DELETE FROM user_roles WHERE tenant_id=$1 AND user_id=$2 AND role_id=$3`,
			tenantID, userID, roleID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		_, err = BumpPolicyVersion(ctx, q, tenantID)
		return err
	})
}

// EffectivePermissions resolves everything a user is granted through every role
// they hold, in one query. This is the authoritative answer that the permission
// cache stores and that a stale policy version forces us back to.
func (r *RoleRepo) EffectivePermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]domain.Permission, []string, error) {
	var perms []domain.Permission
	var roleNames []string
	err := r.db.InTenant(ctx, tenantID, func(ctx context.Context, q Querier) error {
		rows, err := q.Query(ctx,
			`SELECT DISTINCT p.resource, p.action, rp.effect
			   FROM user_roles ur
			   JOIN role_permissions rp ON rp.role_id = ur.role_id
			   JOIN permissions p       ON p.id = rp.permission_id
			  WHERE ur.tenant_id = $1 AND ur.user_id = $2`, tenantID, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p domain.Permission
			if err := rows.Scan(&p.Resource, &p.Action, &p.Effect); err != nil {
				return err
			}
			perms = append(perms, p)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		nameRows, err := q.Query(ctx,
			`SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id
			  WHERE ur.tenant_id=$1 AND ur.user_id=$2 ORDER BY r.name`, tenantID, userID)
		if err != nil {
			return err
		}
		defer nameRows.Close()
		for nameRows.Next() {
			var n string
			if err := nameRows.Scan(&n); err != nil {
				return err
			}
			roleNames = append(roleNames, n)
		}
		return nameRows.Err()
	})
	return perms, roleNames, err
}

// ListPermissionCatalogue returns the global vocabulary of resource:action pairs.
func (r *RoleRepo) ListPermissionCatalogue(ctx context.Context) ([]domain.Permission, error) {
	var out []domain.Permission
	err := r.db.InSystem(ctx, func(ctx context.Context, q Querier) error {
		rows, err := q.Query(ctx, `SELECT id, resource, action FROM permissions ORDER BY resource, action`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p domain.Permission
			if err := rows.Scan(&p.ID, &p.Resource, &p.Action); err != nil {
				return err
			}
			p.Effect = domain.EffectAllow
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}
