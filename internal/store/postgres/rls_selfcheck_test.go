package postgres

import (
	"os"
	"testing"
)

// TestVerifyRLSEnforceable_DetectsSuperuser connects with the raw admin DSN
// (POSTGRES_TEST_ADMIN_DSN, expected to be a superuser — e.g. the Docker image's
// default bootstrap role) and confirms the self-check actually flags it. This is
// the regression test for the finding that shaped this file's sibling tests:
// the "obvious" docker-compose setup of pointing the app straight at
// POSTGRES_USER is a superuser and silently disables every RLS policy.
func TestVerifyRLSEnforceable_DetectsSuperuser(t *testing.T) {
	dsn := os.Getenv("POSTGRES_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_ADMIN_DSN not set; skipping")
	}
	db := testDBWithDSN(t, dsn)
	if err := db.VerifyRLSEnforceable(t.Context()); err == nil {
		t.Fatal("expected VerifyRLSEnforceable to reject a superuser role")
	}
}

// TestVerifyRLSEnforceable_AllowsRestrictedRole is the mirror check: the
// dedicated application role (POSTGRES_TEST_DSN, matching what production
// should use) must pass. If this one starts failing, the deployment role
// picked up an attribute it should not have.
func TestVerifyRLSEnforceable_AllowsRestrictedRole(t *testing.T) {
	db := testDB(t) // skips if POSTGRES_TEST_DSN is unset, same as every other test here
	if err := db.VerifyRLSEnforceable(t.Context()); err != nil {
		t.Fatalf("expected the restricted test role to pass the RLS self-check: %v", err)
	}
}
