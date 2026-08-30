package postgres

import "testing"

// TestMigrate_AppliesCleanly is the smoke test that the embedded SQL actually
// runs against a real server: syntax errors, missing extensions, or an
// out-of-order dependency between files would all surface here rather than
// only at first deploy.
func TestMigrate_AppliesCleanly(t *testing.T) {
	db := testDB(t) // runs Migrate() as part of setup; failure there fails this test
	if err := db.Ping(t.Context()); err != nil {
		t.Fatalf("ping after migrate: %v", err)
	}

	// Migrations must also be idempotent: re-running them against an
	// already-migrated database (the same thing that happens every time the
	// gateway process restarts) must not error.
	if _, err := db.Migrate(t.Context()); err != nil {
		t.Fatalf("re-running migrations was not idempotent: %v", err)
	}
}
