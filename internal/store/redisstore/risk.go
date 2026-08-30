package redisstore

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// The risk engine needs to answer "have we seen this before for this user?".
// Redis sets give that in one round trip. Everything stored here is a hash, not
// a raw address or fingerprint, so the behavioural history is useful for scoring
// but is not a location log tied to a person.

func knownIPKey(tenantID, userID uuid.UUID) string {
	return "risk:ip:" + tenantID.String() + ":" + userID.String()
}
func knownDeviceKey(tenantID, userID uuid.UUID) string {
	return "risk:dev:" + tenantID.String() + ":" + userID.String()
}
func failureKey(tenantID uuid.UUID, subject string) string {
	return "risk:fail:" + tenantID.String() + ":" + subject
}

// KnownIP reports whether this network has been seen for the user before, and
// records it either way. The write is what makes the first sighting the only
// one that scores as new.
func (c *Client) KnownIP(ctx context.Context, tenantID, userID uuid.UUID, ipHash string, retain time.Duration) (bool, error) {
	pipe := c.rdb.Pipeline()
	member := pipe.SIsMember(ctx, knownIPKey(tenantID, userID), ipHash)
	pipe.SAdd(ctx, knownIPKey(tenantID, userID), ipHash)
	pipe.Expire(ctx, knownIPKey(tenantID, userID), retain)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, err
	}
	return member.Val(), nil
}

func (c *Client) KnownDevice(ctx context.Context, tenantID, userID uuid.UUID, deviceHash string, retain time.Duration) (bool, error) {
	pipe := c.rdb.Pipeline()
	member := pipe.SIsMember(ctx, knownDeviceKey(tenantID, userID), deviceHash)
	pipe.SAdd(ctx, knownDeviceKey(tenantID, userID), deviceHash)
	pipe.Expire(ctx, knownDeviceKey(tenantID, userID), retain)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, err
	}
	return member.Val(), nil
}

// RecordAuthFailure counts recent failures for a subject (an email or an IP).
// The counter drives both the risk score and the pre-authentication throttle,
// and it decays on its own rather than needing a sweeper.
func (c *Client) RecordAuthFailure(ctx context.Context, tenantID uuid.UUID, subject string, window time.Duration) (int64, error) {
	key := failureKey(tenantID, subject)
	pipe := c.rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

func (c *Client) AuthFailureCount(ctx context.Context, tenantID uuid.UUID, subject string) (int64, error) {
	n, err := c.rdb.Get(ctx, failureKey(tenantID, subject)).Int64()
	if err != nil {
		return 0, nil // absent means zero; a Redis miss must not fail the request
	}
	return n, nil
}

func (c *Client) ClearAuthFailures(ctx context.Context, tenantID uuid.UUID, subject string) error {
	return c.rdb.Del(ctx, failureKey(tenantID, subject)).Err()
}
