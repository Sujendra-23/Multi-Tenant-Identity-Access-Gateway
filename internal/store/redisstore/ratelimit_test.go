package redisstore

import (
	"context"
	"testing"
)

func TestAllow_BurstThenThrottle(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// burst=3 tokens available immediately; the 4th request in the same instant
	// must be rejected since no meaningful time has passed to refill.
	for i := 0; i < 3; i++ {
		res, err := c.Allow(ctx, "test-burst", 1, 3)
		if err != nil {
			t.Fatalf("Allow #%d: %v", i, err)
		}
		if !res.Allowed {
			t.Fatalf("request #%d should be allowed within the burst, remaining=%d", i, res.Remaining)
		}
	}
	res, err := c.Allow(ctx, "test-burst", 1, 3)
	if err != nil {
		t.Fatalf("Allow (over burst): %v", err)
	}
	if res.Allowed {
		t.Fatal("4th request should be rejected once the burst is exhausted")
	}
	if res.RetryAfter <= 0 {
		t.Fatal("a rejected request should report a positive RetryAfter")
	}
}

func TestAllow_IndependentKeysDoNotShareBuckets(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if _, err := c.Allow(ctx, "user-a", 1, 1); err != nil {
		t.Fatalf("Allow user-a: %v", err)
	}
	res, err := c.Allow(ctx, "user-b", 1, 1)
	if err != nil {
		t.Fatalf("Allow user-b: %v", err)
	}
	if !res.Allowed {
		t.Fatal("a different bucket key must not be affected by another key's consumption")
	}
}

func TestAllow_ZeroConfigMeansUnlimited(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	// rate=0/burst=0 is the escape hatch for "this dimension is not configured";
	// it must not silently block everything.
	res, err := c.Allow(ctx, "unconfigured", 0, 0)
	if err != nil {
		t.Fatalf("Allow with zero config: %v", err)
	}
	if !res.Allowed {
		t.Fatal("zero rate/burst should mean unlimited, not blocked")
	}
}
