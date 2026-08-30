package redisstore

import (
	"context"
	"os"
	"testing"
	"time"
)

// testClient connects to a real Redis instance. The properties under test here
// — atomic token-bucket refill, single-use refresh rotation, reuse detection —
// are all implemented as Lua scripts specifically because they need to be
// atomic under concurrency; a fake or mock would test the Go plumbing around
// them and nothing about the property that actually matters. Point
// REDIS_TEST_ADDR at a scratch instance; tests skip themselves when it is unset.
func testClient(t *testing.T) *Client {
	t.Helper()
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("REDIS_TEST_ADDR not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := Connect(ctx, addr, os.Getenv("REDIS_TEST_PASSWORD"), 0)
	if err != nil {
		t.Fatalf("connect to test redis: %v", err)
	}
	// Each test gets a clean keyspace: FLUSHDB rather than a shared database
	// with prefix bookkeeping, since this is a scratch instance dedicated to
	// tests and never anything a developer would mind losing.
	if err := c.Raw().FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush test redis: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
