package redisstore

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// tokenBucketScript implements a token bucket entirely inside Redis.
//
// Doing the read-modify-write in a script rather than in Go is what makes it
// correct under concurrency: with N gateway replicas hitting one Redis, a
// GET/compute/SET round trip would interleave and let bursts through. The script
// runs atomically, so the bucket is consistent no matter how many replicas share it.
//
// The current time is passed in rather than read via redis.call('TIME') so the
// script stays deterministic and safe to replicate; the cost is a dependence on
// replicas' clocks being roughly in sync, which NTP already gives us.
var tokenBucketScript = redis.NewScript(`
local key   = KEYS[1]
local rate  = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now   = tonumber(ARGV[3])
local cost  = tonumber(ARGV[4])

local data   = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts     = tonumber(data[2])

if tokens == nil or ts == nil then
  tokens = burst
  ts = now
end

-- Refill for the time that has passed, capped at the bucket size.
local elapsed = math.max(0, now - ts) / 1000.0
tokens = math.min(burst, tokens + (elapsed * rate))

local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end

redis.call('HSET', key, 'tokens', tokens, 'ts', now)
-- Expire once the bucket would have refilled completely: an idle client's key
-- removes itself instead of accumulating forever.
redis.call('EXPIRE', key, math.ceil(burst / rate) + 1)

local retry_ms = 0
if allowed == 0 then
  retry_ms = math.ceil(((cost - tokens) / rate) * 1000)
end

return {allowed, math.floor(tokens), retry_ms}
`)

// LimitResult describes one rate-limit decision.
type LimitResult struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
	Limit      int
}

// Allow consumes one token from the named bucket.
func (c *Client) Allow(ctx context.Context, key string, ratePerSec, burst int) (*LimitResult, error) {
	if ratePerSec <= 0 || burst <= 0 {
		return &LimitResult{Allowed: true, Remaining: burst, Limit: burst}, nil
	}
	res, err := tokenBucketScript.Run(ctx, c.rdb,
		[]string{"rl:" + key},
		ratePerSec, burst, time.Now().UnixMilli(), 1,
	).Slice()
	if err != nil {
		return nil, fmt.Errorf("rate limit script: %w", err)
	}
	if len(res) != 3 {
		return nil, fmt.Errorf("rate limit script returned %d values, want 3", len(res))
	}
	allowed, _ := res[0].(int64)
	remaining, _ := res[1].(int64)
	retryMS, _ := res[2].(int64)

	return &LimitResult{
		Allowed:    allowed == 1,
		Remaining:  int(remaining),
		RetryAfter: time.Duration(retryMS) * time.Millisecond,
		Limit:      burst,
	}, nil
}
