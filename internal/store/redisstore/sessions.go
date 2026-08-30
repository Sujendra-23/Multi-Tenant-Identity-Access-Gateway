package redisstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/sujendra/identity-gateway/internal/domain"
)

// RefreshRecord is what a refresh token dereferences to. The token itself is an
// opaque random string; all of the meaning lives here, server-side, where it can
// be revoked.
type RefreshRecord struct {
	SessionID  uuid.UUID `json:"sid"`
	FamilyID   uuid.UUID `json:"fid"`
	TenantID   uuid.UUID `json:"tid"`
	UserID     uuid.UUID `json:"uid"`
	Generation int       `json:"gen"`
	DeviceHash string    `json:"dev"`
	IssuedAt   int64     `json:"iat"`
}

func sessionKey(tenantID, sessionID uuid.UUID) string {
	return "sess:" + tenantID.String() + ":" + sessionID.String()
}
func refreshKey(tokenHash string) string  { return "rt:" + tokenHash }
func consumedKey(tokenHash string) string { return "rtc:" + tokenHash }
func familyKey(familyID uuid.UUID) string { return "fam:" + familyID.String() }
func denyKey(jti string) string           { return "deny:" + jti }

// CreateSession registers a live session and its first refresh token.
func (c *Client) CreateSession(ctx context.Context, s *domain.Session, tokenHash string, ttl time.Duration) error {
	rec := RefreshRecord{
		SessionID: s.ID, FamilyID: s.FamilyID, TenantID: s.TenantID, UserID: s.UserID,
		Generation: s.Generation, DeviceHash: s.DeviceHash, IssuedAt: time.Now().Unix(),
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	sessionPayload, err := json.Marshal(s)
	if err != nil {
		return err
	}

	pipe := c.rdb.TxPipeline()
	pipe.Set(ctx, sessionKey(s.TenantID, s.ID), sessionPayload, ttl)
	pipe.Set(ctx, refreshKey(tokenHash), payload, ttl)
	// The family index lets a reuse event revoke every descendant session in
	// one pass instead of scanning the keyspace.
	pipe.SAdd(ctx, familyKey(s.FamilyID), s.TenantID.String()+":"+s.ID.String())
	pipe.Expire(ctx, familyKey(s.FamilyID), ttl)
	_, err = pipe.Exec(ctx)
	return err
}

// SessionLive reports whether the session still exists. Every authenticated
// request checks this, which is what makes logout take effect immediately
// instead of at access-token expiry.
func (c *Client) SessionLive(ctx context.Context, tenantID, sessionID uuid.UUID) (bool, error) {
	n, err := c.rdb.Exists(ctx, sessionKey(tenantID, sessionID)).Result()
	return n == 1, err
}

// rotateScript exchanges a refresh token for its successor, atomically.
//
// The security property it enforces is single use with reuse detection. A
// refresh token is deleted the moment it is redeemed and its hash is recorded in
// a tombstone. If that same token is ever presented again, the tombstone is
// still there and we know the token was captured: either the legitimate client
// is replaying, or an attacker stole it and one of the two has already used it.
// We cannot tell which, so the safe response is to burn the whole family.
//
// The successor record is derived here rather than being passed in, so the read,
// the delete and the write of the new token are one indivisible step. Computing
// it in Go would mean a read, then a swap, with a window in between where two
// concurrent redemptions could both observe the token as unused.
//
// Critically, rotation also requires the record's own session key
// (sess:<tid>:<sid>) to still exist. Without this check, revocation has a hole:
// RevokeSession and RevokeFamily delete only the session's liveness key, never
// the refresh-token key itself (a token can be handed off between a family's
// sessions across rotations, so there is no single fixed key for them to find
// and delete). A session's refresh token surviving a revocation would then let
// it rotate right past that revocation — and the rotated token's own session
// gets re-registered via TouchSession afterwards, which would silently
// resurrect a session that logout, an admin revoke, or reuse-detection's
// family burn had just killed. Checking liveness as part of the same atomic
// step closes that: once the session is gone, nothing derived from it can rotate
// again, no matter how many still-valid-looking refresh tokens it left behind.
var rotateScript = redis.NewScript(`
local old_key      = KEYS[1]
local consumed_key = KEYS[2]
local new_key      = KEYS[3]
local ttl          = tonumber(ARGV[1])
local now          = tonumber(ARGV[2])

local rec = redis.call('GET', old_key)
if not rec then
  if redis.call('EXISTS', consumed_key) == 1 then
    -- The tombstone still holds the record, so the caller knows which family
    -- to burn even though the token itself is long gone.
    return {'REUSE', redis.call('GET', consumed_key)}
  end
  return {'MISSING', ''}
end

local decoded = cjson.decode(rec)
local session_key = 'sess:' .. decoded['tid'] .. ':' .. decoded['sid']
if redis.call('EXISTS', session_key) == 0 then
  -- The session behind this token was revoked (logout, admin action, or a
  -- sibling token's reuse having burned the family) since this token was
  -- issued. Refuse to rotate rather than silently reviving it, and drop the
  -- now-meaningless token so it cannot be tried again.
  redis.call('DEL', old_key)
  return {'SESSION_REVOKED', ''}
end

decoded['gen'] = (decoded['gen'] or 0) + 1
decoded['iat'] = now
local new_payload = cjson.encode(decoded)

redis.call('DEL', old_key)
redis.call('SET', consumed_key, rec, 'EX', ttl)
redis.call('SET', new_key, new_payload, 'EX', ttl)
return {'OK', new_payload}
`)

// RotateRefreshToken redeems oldToken and installs newToken in its place,
// returning the successor record with its generation already advanced.
//
// On replay it returns domain.ErrTokenReused together with the record the
// replayed token pointed at, so the caller can revoke the family and write an
// audit event that names the session.
func (c *Client) RotateRefreshToken(ctx context.Context, oldToken, newToken string, ttl time.Duration) (*RefreshRecord, error) {
	oldHash, newHash := HashToken(oldToken), HashToken(newToken)

	res, err := rotateScript.Run(ctx, c.rdb,
		[]string{refreshKey(oldHash), consumedKey(oldHash), refreshKey(newHash)},
		int(ttl.Seconds()), time.Now().Unix(),
	).Slice()
	if err != nil {
		return nil, fmt.Errorf("rotate script: %w", err)
	}
	if len(res) != 2 {
		return nil, fmt.Errorf("rotate script returned %d values, want 2", len(res))
	}
	status, _ := res[0].(string)
	raw, _ := res[1].(string)

	switch status {
	case "MISSING":
		return nil, domain.ErrNotFound
	case "SESSION_REVOKED":
		// The token itself was intact and unused, but the session behind it is
		// gone — distinct from both "never issued" (MISSING) and "captured and
		// replayed" (REUSE), so callers and logs can tell the three apart.
		return nil, domain.ErrTokenRevoked
	case "REUSE":
		var rec RefreshRecord
		if raw != "" {
			_ = json.Unmarshal([]byte(raw), &rec)
		}
		return &rec, domain.ErrTokenReused
	case "OK":
		var rec RefreshRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return nil, fmt.Errorf("decode rotated refresh record: %w", err)
		}
		return &rec, nil
	default:
		return nil, fmt.Errorf("rotate script returned unexpected status %q", status)
	}
}

// LookupRefresh reads a refresh record without consuming it.
func (c *Client) LookupRefresh(ctx context.Context, token string) (*RefreshRecord, error) {
	raw, err := c.rdb.Get(ctx, refreshKey(HashToken(token))).Result()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec RefreshRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// RevokeSession deletes one session. Access tokens for it stop working on their
// next request, without waiting for expiry.
func (c *Client) RevokeSession(ctx context.Context, tenantID, sessionID uuid.UUID) error {
	return c.rdb.Del(ctx, sessionKey(tenantID, sessionID)).Err()
}

// RevokeFamily deletes every session descended from a single login. This is the
// blast-radius containment for a detected token replay.
func (c *Client) RevokeFamily(ctx context.Context, familyID uuid.UUID) (int, error) {
	members, err := c.rdb.SMembers(ctx, familyKey(familyID)).Result()
	if err != nil {
		return 0, err
	}
	if len(members) == 0 {
		return 0, nil
	}
	keys := make([]string, 0, len(members)+1)
	for _, m := range members {
		keys = append(keys, "sess:"+m)
	}
	keys = append(keys, familyKey(familyID))
	if err := c.rdb.Del(ctx, keys...).Err(); err != nil {
		return 0, err
	}
	return len(members), nil
}

// DenyToken adds an access token's jti to the revocation list for the remainder
// of its lifetime. The TTL matches the token's own expiry, so the list stays
// proportional to tokens in flight rather than growing without bound.
func (c *Client) DenyToken(ctx context.Context, jti string, until time.Time) error {
	ttl := time.Until(until)
	if ttl <= 0 {
		return nil // already expired; the signature check will reject it
	}
	return c.rdb.Set(ctx, denyKey(jti), "1", ttl).Err()
}

// IsTokenDenied is checked on every authenticated request.
func (c *Client) IsTokenDenied(ctx context.Context, jti string) (bool, error) {
	n, err := c.rdb.Exists(ctx, denyKey(jti)).Result()
	return n == 1, err
}

// TouchSession extends a session's lifetime and refreshes its stored metadata.
func (c *Client) TouchSession(ctx context.Context, s *domain.Session, ttl time.Duration) error {
	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, sessionKey(s.TenantID, s.ID), payload, ttl).Err()
}

// GetSession reads the cached session record.
func (c *Client) GetSession(ctx context.Context, tenantID, sessionID uuid.UUID) (*domain.Session, error) {
	raw, err := c.rdb.Get(ctx, sessionKey(tenantID, sessionID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var s domain.Session
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, err
	}
	return &s, nil
}
