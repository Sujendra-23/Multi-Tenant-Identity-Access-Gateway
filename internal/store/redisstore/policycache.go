package redisstore

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/sujendra/identity-gateway/internal/domain"
)

// CachedPolicy is a user's fully resolved authorization state.
type CachedPolicy struct {
	Permissions   []domain.Permission `json:"perms"`
	Roles         []string            `json:"roles"`
	PolicyVersion int64               `json:"pv"`
	CachedAt      int64               `json:"at"`
}

// The tenant's policy version is part of the cache key rather than something we
// compare after reading. Any change that alters authorization bumps the version,
// which moves every affected user to a new key, so the stale entries are
// unreachable the instant the bump commits. No invalidation fan-out, no
// scanning, no window where a revoked grant is still served from cache.
func policyKey(tenantID uuid.UUID, policyVersion int64, userID uuid.UUID) string {
	return "pol:" + tenantID.String() + ":" + strconv.FormatInt(policyVersion, 10) + ":" + userID.String()
}

func (c *Client) GetPolicy(ctx context.Context, tenantID uuid.UUID, policyVersion int64, userID uuid.UUID) (*CachedPolicy, error) {
	raw, err := c.rdb.Get(ctx, policyKey(tenantID, policyVersion, userID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var p CachedPolicy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// SetPolicy caches a resolved policy. The TTL is a backstop only: correctness
// comes from the version in the key, not from expiry. It exists so that entries
// for versions nobody uses any more do not linger in memory.
func (c *Client) SetPolicy(ctx context.Context, tenantID uuid.UUID, policyVersion int64, userID uuid.UUID, p *CachedPolicy, ttl time.Duration) error {
	p.PolicyVersion = policyVersion
	p.CachedAt = time.Now().Unix()
	payload, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, policyKey(tenantID, policyVersion, userID), payload, ttl).Err()
}

// InvalidateUserPolicy drops a single user's cached entry at the current
// version. Used when a change affects one user rather than the whole tenant,
// so the tenant-wide version does not have to move.
func (c *Client) InvalidateUserPolicy(ctx context.Context, tenantID uuid.UUID, policyVersion int64, userID uuid.UUID) error {
	return c.rdb.Del(ctx, policyKey(tenantID, policyVersion, userID)).Err()
}
