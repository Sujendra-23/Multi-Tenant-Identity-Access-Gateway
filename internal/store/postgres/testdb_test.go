package postgres

import (
	"context"
	"os"
	"testing"
	"time"
)

// testDB connects to a real Postgres instance for integration-level tests: RLS
// enforcement lives entirely in the database, so a mock or in-memory fake would
// test nothing about the property that actually matters. Point
// POSTGRES_TEST_DSN at a scratch database; tests skip themselves when it is
// unset rather than failing a normal `go test ./...` run in an environment
// with no database available.
func testDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set; skipping integration test")
	}
	return testDBWithDSN(t, dsn)
}

// testDBWithDSN is the shared connector behind testDB, factored out so tests
// that specifically need the admin/superuser connection (to prove the RLS
// self-check catches it) can reuse the same setup and migration logic against
// a different DSN.
func testDBWithDSN(t *testing.T, dsn string) *DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	if _, err := db.Migrate(ctx); err != nil {
		db.Close()
		t.Fatalf("migrate test database: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func getenvOrSkip(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set; skipping", key)
	}
	return v
}
