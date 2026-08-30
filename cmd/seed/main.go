// Command seed bootstraps a demo tenant, roles and users directly against the
// database, for local development and for the walkthrough in the project
// README. It exercises the same repositories the HTTP server uses, so what it
// creates is exactly what the API would have produced — this is a convenience
// for setup, not a parallel code path.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/config"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
)

func main() {
	slug := flag.String("slug", "acme", "tenant slug to create")
	name := flag.String("name", "Acme Corp", "tenant display name")
	adminEmail := flag.String("admin-email", "owner@acme.test", "admin user email")
	adminPassword := flag.String("admin-password", "correct-horse-battery-staple", "admin user password (min 12 chars)")
	memberEmail := flag.String("member-email", "member@acme.test", "read-only member email, or empty to skip")
	memberPassword := flag.String("member-password", "correct-horse-battery-staple", "read-only member password")
	flag.Parse()

	if err := run(*slug, *name, *adminEmail, *adminPassword, *memberEmail, *memberPassword); err != nil {
		fmt.Fprintln(os.Stderr, "seed: fatal:", err)
		os.Exit(1)
	}
}

func run(slug, name, adminEmail, adminPassword, memberEmail, memberPassword string) error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := postgres.Connect(ctx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer db.Close()

	if _, err := db.Migrate(ctx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	// Unlike the gateway server, seed does not refuse to run against a
	// superuser/BYPASSRLS role — it is a local dev convenience tool that may
	// legitimately be the first thing pointed at a freshly started container
	// before deploy/postgres-init/01-app-role.sql's restricted role exists. It
	// still warns loudly, because the same misconfiguration would silently
	// defeat tenant isolation if it made it into a real deployment.
	if err := db.VerifyRLSEnforceable(ctx); err != nil {
		log.Warn("this database role can bypass row-level security; fine for local seeding, "+
			"but the gateway server itself will refuse to start against it", "detail", err)
	}

	tenants := postgres.NewTenantRepo(db)
	users := postgres.NewUserRepo(db)
	roles := postgres.NewRoleRepo(db)
	keyRepo := postgres.NewKeyRepo(db)

	// Ensure a signing key exists before the server's own bootstrap gets to it,
	// so `seed` followed immediately by a login works even against a database
	// the gateway process has never touched.
	if _, err := keyRepo.Active(ctx); err != nil {
		kr := auth.NewKeyring(keyRepo, cfg.SigningKeyMaxAge, log)
		if err := kr.Load(ctx); err != nil {
			return fmt.Errorf("bootstrap signing key: %w", err)
		}
	}

	tenant, err := tenants.Create(ctx, slug, name, "standard")
	if err != nil {
		return fmt.Errorf("create tenant %q: %w", slug, err)
	}
	log.Info("tenant ready", "id", tenant.ID, "slug", tenant.Slug)

	owner, err := roles.Create(ctx, tenant.ID, "owner", "Full access to every resource in this organization", true)
	if err != nil {
		return fmt.Errorf("create owner role: %w", err)
	}
	if err := roles.GrantPermission(ctx, tenant.ID, owner.ID, "*", "*", "allow"); err != nil {
		return fmt.Errorf("grant owner permissions: %w", err)
	}

	member, err := roles.Create(ctx, tenant.ID, "member", "Read-only access to most resources", true)
	if err != nil {
		return fmt.Errorf("create member role: %w", err)
	}
	for _, res := range []string{"users", "roles", "reports", "settings"} {
		if err := roles.GrantPermission(ctx, tenant.ID, member.ID, res, "read", "allow"); err != nil {
			return fmt.Errorf("grant member permission %s:read: %w", res, err)
		}
	}
	// A worked example of an explicit deny carved out of a broad grant: members
	// can read most things but never billing, even though nothing in this
	// tenant's default policy would otherwise say so.
	if err := roles.GrantPermission(ctx, tenant.ID, member.ID, "billing", "read", "deny"); err != nil {
		return fmt.Errorf("deny member billing access: %w", err)
	}

	adminHash, err := auth.HashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	adminUser, err := users.Create(ctx, tenant.ID, adminEmail, adminHash, "Owner")
	if err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}
	if err := roles.AssignRole(ctx, tenant.ID, adminUser.ID, owner.ID, nil); err != nil {
		return fmt.Errorf("assign owner role: %w", err)
	}
	log.Info("admin user ready", "email", adminUser.Email, "role", "owner")

	if memberEmail != "" {
		memberHash, err := auth.HashPassword(memberPassword)
		if err != nil {
			return fmt.Errorf("hash member password: %w", err)
		}
		memberUser, err := users.Create(ctx, tenant.ID, memberEmail, memberHash, "Member")
		if err != nil {
			return fmt.Errorf("create member user: %w", err)
		}
		if err := roles.AssignRole(ctx, tenant.ID, memberUser.ID, member.ID, nil); err != nil {
			return fmt.Errorf("assign member role: %w", err)
		}
		log.Info("member user ready", "email", memberUser.Email, "role", "member")
	}

	fmt.Println()
	fmt.Println("Seed complete. Try it:")
	fmt.Println()
	fmt.Printf("  curl -s -X POST http://localhost:8080/v1/auth/login \\\n")
	fmt.Printf("    -H 'X-Tenant: %s' -H 'Content-Type: application/json' \\\n", tenant.Slug)
	fmt.Printf("    -d '{\"email\":\"%s\",\"password\":\"%s\"}' | jq\n", adminEmail, adminPassword)
	fmt.Println()
	return nil
}
