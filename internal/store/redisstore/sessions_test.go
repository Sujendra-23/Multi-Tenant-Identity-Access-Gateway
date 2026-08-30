package redisstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/domain"
)

func newTestSession() *domain.Session {
	return &domain.Session{
		ID: uuid.New(), TenantID: uuid.New(), UserID: uuid.New(), FamilyID: uuid.New(),
		DeviceHash: "device-1", IP: "203.0.113.5", UserAgent: "test",
		CreatedAt: time.Now(), LastSeenAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestSessionLifecycle(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	session := newTestSession()

	live, err := c.SessionLive(ctx, session.TenantID, session.ID)
	if err != nil {
		t.Fatalf("SessionLive before creation: %v", err)
	}
	if live {
		t.Fatal("a session that was never created should not be live")
	}

	if err := c.CreateSession(ctx, session, HashToken("initial-refresh-token"), time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	live, err = c.SessionLive(ctx, session.TenantID, session.ID)
	if err != nil {
		t.Fatalf("SessionLive after creation: %v", err)
	}
	if !live {
		t.Fatal("session should be live immediately after creation")
	}

	if err := c.RevokeSession(ctx, session.TenantID, session.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	live, err = c.SessionLive(ctx, session.TenantID, session.ID)
	if err != nil {
		t.Fatalf("SessionLive after revoke: %v", err)
	}
	if live {
		t.Fatal("session should not be live after revocation — this is what makes logout immediate")
	}
}

// TestRotateRefreshToken_SingleUse is the normal path: a token, once rotated,
// no longer works a second time even before any replay-specific handling.
func TestRotateRefreshToken_SingleUse(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	session := newTestSession()
	oldToken := "token-v1"

	if err := c.CreateSession(ctx, session, HashToken(oldToken), time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	newToken := "token-v2"
	rec, err := c.RotateRefreshToken(ctx, oldToken, newToken, time.Hour)
	if err != nil {
		t.Fatalf("first rotation should succeed: %v", err)
	}
	if rec.Generation != 1 {
		t.Fatalf("Generation = %d, want 1 (advanced from the initial record's 0)", rec.Generation)
	}
	if rec.SessionID != session.ID || rec.FamilyID != session.FamilyID {
		t.Fatalf("rotated record does not point at the original session/family: %+v", rec)
	}

	// The new token must now work for lookups/rotation...
	if _, err := c.LookupRefresh(ctx, newToken); err != nil {
		t.Fatalf("new token should be resolvable: %v", err)
	}
	// ...and the old one must not, with a MISSING (ErrNotFound) rather than
	// ErrTokenReused, since nothing has actually replayed it yet at this point.
	if _, err := c.LookupRefresh(ctx, oldToken); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("looking up an already-rotated token: got err=%v, want domain.ErrNotFound", err)
	}
}

// TestRotateRefreshToken_ReuseDetected is the security property the whole
// rotation design exists for: presenting a token a second time, after it has
// already been exchanged once, must be distinguishable from an ordinary
// "expired/unknown token" error — because the correct response (burn the whole
// session family) is only appropriate for reuse, not for an unrelated garbage
// token.
func TestRotateRefreshToken_ReuseDetected(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	session := newTestSession()
	oldToken := "token-v1"

	if err := c.CreateSession(ctx, session, HashToken(oldToken), time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := c.RotateRefreshToken(ctx, oldToken, "token-v2", time.Hour); err != nil {
		t.Fatalf("first rotation: %v", err)
	}

	// Replay the already-consumed token.
	rec, err := c.RotateRefreshToken(ctx, oldToken, "token-v3-attacker", time.Hour)
	if !errors.Is(err, domain.ErrTokenReused) {
		t.Fatalf("replaying a consumed token: got err=%v, want domain.ErrTokenReused", err)
	}
	if rec == nil || rec.FamilyID != session.FamilyID {
		t.Fatalf("reuse response should still identify the family to revoke, got %+v", rec)
	}

	// And the attacker's replay must not have actually installed token-v3: it
	// must not be possible to rotate again *from* it.
	if _, err := c.LookupRefresh(ctx, "token-v3-attacker"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a token submitted alongside a replay must not become valid: err=%v", err)
	}
}

func TestRotateRefreshToken_UnknownTokenIsNotReuse(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	_, err := c.RotateRefreshToken(ctx, "never-issued-token", "whatever", time.Hour)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a token that was never issued: got err=%v, want domain.ErrNotFound (not ErrTokenReused)", err)
	}
}

// TestRotateRefreshToken_ConcurrentRedemptionOnlyOneWins is the concurrency
// property behind "single use": if the same token is redeemed from two
// goroutines at once (simulating two requests racing on a stolen-and-shared
// token), exactly one must succeed and the other must see it as already
// consumed. This is what the Lua script's atomicity is for — a
// read-then-write implemented in Go instead would let both through.
func TestRotateRefreshToken_ConcurrentRedemptionOnlyOneWins(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	session := newTestSession()
	oldToken := "concurrent-token"
	if err := c.CreateSession(ctx, session, HashToken(oldToken), time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	const attempts = 20
	results := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			_, err := c.RotateRefreshToken(ctx, oldToken, "new-"+HashToken(oldToken)[:8]+string(rune('a'+i)), time.Hour)
			results <- err
		}(i)
	}

	successes, reuses := 0, 0
	for i := 0; i < attempts; i++ {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, domain.ErrTokenReused):
			reuses++
		default:
			t.Fatalf("unexpected error from concurrent rotation: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1 (single-use must hold under concurrency)", successes)
	}
	if reuses != attempts-1 {
		t.Fatalf("reuses = %d, want %d", reuses, attempts-1)
	}
}

// TestRotateRefreshToken_RefusesAfterSessionRevoked is the regression test for
// a real bug found via manual end-to-end testing: RevokeSession/RevokeFamily
// only ever deleted the session's liveness key, never the refresh token itself
// (there is no fixed key for "the current refresh token of this session" to
// delete — the token changes on every rotation). A still-valid, not-yet-used
// refresh token from a revoked session could therefore rotate right past the
// revocation — and because a successful rotation re-registers the session via
// TouchSession, doing so silently resurrected the very session that had just
// been killed. Logout, admin-initiated revocation and reuse-triggered family
// burns all revoke exactly this way, so all three were affected.
func TestRotateRefreshToken_RefusesAfterSessionRevoked(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	session := newTestSession()
	token := "still-valid-token"

	if err := c.CreateSession(ctx, session, HashToken(token), time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Revoke the session directly — the same call Logout and admin revocation
	// make. The refresh token above was never touched by it.
	if err := c.RevokeSession(ctx, session.TenantID, session.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	// The still-intact, never-rotated token must now be refused, not honoured.
	_, err := c.RotateRefreshToken(ctx, token, "attempted-successor", time.Hour)
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Fatalf("rotating a token whose session was revoked: got err=%v, want domain.ErrTokenRevoked", err)
	}

	// And the failed rotation attempt must not have resurrected the session —
	// this is the specific failure mode that made the bug dangerous rather than
	// just inconvenient.
	live, err := c.SessionLive(ctx, session.TenantID, session.ID)
	if err != nil {
		t.Fatalf("SessionLive: %v", err)
	}
	if live {
		t.Fatal("a rejected rotation must not resurrect the revoked session")
	}
}

// TestRotateRefreshToken_FamilyRevokeBlocksSiblingTokens is the reuse-detection
// version of the same regression: a family revoked because ONE of its tokens
// was replayed must also invalidate every OTHER still-valid token in that
// family, not just the specific one that was replayed.
func TestRotateRefreshToken_FamilyRevokeBlocksSiblingTokens(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	session := newTestSession()
	tokenA := "session-token-a"

	if err := c.CreateSession(ctx, session, HashToken(tokenA), time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// Rotate once to get a second, sibling token in the same family/session —
	// tokenA is now consumed, tokenB is the current, legitimately-valid one.
	if _, err := c.RotateRefreshToken(ctx, tokenA, "session-token-b", time.Hour); err != nil {
		t.Fatalf("initial rotation: %v", err)
	}
	tokenB := "session-token-b"

	// Simulate what a real attacker replay of tokenA triggers: burn the family.
	if _, err := c.RevokeFamily(ctx, session.FamilyID); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	// tokenB was never replayed and was never itself presented twice — before
	// this fix, it would rotate successfully and reinstate the session.
	_, err := c.RotateRefreshToken(ctx, tokenB, "attacker-or-victim-next", time.Hour)
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Fatalf("rotating a sibling token after its family was revoked: got err=%v, want domain.ErrTokenRevoked", err)
	}
	live, err := c.SessionLive(ctx, session.TenantID, session.ID)
	if err != nil {
		t.Fatalf("SessionLive: %v", err)
	}
	if live {
		t.Fatal("the session must stay dead — a sibling token must not be able to resurrect it")
	}
}

func TestRevokeFamily(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	family := uuid.New()

	s1 := newTestSession()
	s1.FamilyID = family
	s2 := newTestSession()
	s2.FamilyID = family
	s2.TenantID = s1.TenantID // RevokeFamily's member keys are tenant:session pairs
	unrelated := newTestSession()

	for i, s := range []*domain.Session{s1, s2, unrelated} {
		if err := c.CreateSession(ctx, s, HashToken(uuid.NewString()), time.Hour); err != nil {
			t.Fatalf("CreateSession %d: %v", i, err)
		}
	}

	killed, err := c.RevokeFamily(ctx, family)
	if err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if killed != 2 {
		t.Fatalf("RevokeFamily reported %d sessions killed, want 2", killed)
	}

	for name, s := range map[string]*domain.Session{"s1": s1, "s2": s2} {
		live, err := c.SessionLive(ctx, s.TenantID, s.ID)
		if err != nil {
			t.Fatalf("SessionLive(%s): %v", name, err)
		}
		if live {
			t.Fatalf("%s should have been revoked along with its family", name)
		}
	}
	live, err := c.SessionLive(ctx, unrelated.TenantID, unrelated.ID)
	if err != nil {
		t.Fatalf("SessionLive(unrelated): %v", err)
	}
	if !live {
		t.Fatal("a session outside the compromised family must not be touched")
	}
}
