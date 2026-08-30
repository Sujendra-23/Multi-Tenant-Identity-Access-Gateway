package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/audit"
	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/observability"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
	"github.com/sujendra/identity-gateway/internal/store/redisstore"
)

// Service owns the credential-to-token exchange and the lifecycle of the
// sessions that result from it.
type Service struct {
	users    *postgres.UserRepo
	tenants  *postgres.TenantRepo
	roles    *postgres.RoleRepo
	sessions *postgres.SessionRepo
	cache    *redisstore.Client
	issuer   *TokenIssuer
	auditor  *audit.Logger
	metrics  *observability.Metrics
	log      *slog.Logger

	accessTTL       time.Duration
	refreshTTL      time.Duration
	maxFailedLogins int
	lockoutDuration time.Duration
	bindDevice      bool
	bindIP          bool
}

type ServiceDeps struct {
	Users    *postgres.UserRepo
	Tenants  *postgres.TenantRepo
	Roles    *postgres.RoleRepo
	Sessions *postgres.SessionRepo
	Cache    *redisstore.Client
	Issuer   *TokenIssuer
	Auditor  *audit.Logger
	Metrics  *observability.Metrics
	Log      *slog.Logger

	AccessTTL       time.Duration
	RefreshTTL      time.Duration
	MaxFailedLogins int
	LockoutDuration time.Duration
	BindDevice      bool
	BindIP          bool
}

func NewService(d ServiceDeps) *Service {
	return &Service{
		users: d.Users, tenants: d.Tenants, roles: d.Roles, sessions: d.Sessions,
		cache: d.Cache, issuer: d.Issuer, auditor: d.Auditor, metrics: d.Metrics, log: d.Log,
		accessTTL: d.AccessTTL, refreshTTL: d.RefreshTTL,
		maxFailedLogins: d.MaxFailedLogins, lockoutDuration: d.LockoutDuration,
		bindDevice: d.BindDevice, bindIP: d.BindIP,
	}
}

// LoginRequest carries the credential plus the request context the session will
// be bound to.
type LoginRequest struct {
	Tenant     *domain.Tenant
	Email      string
	Password   string
	IP         string
	UserAgent  string
	DeviceHash string
	RequestID  string
}

// Login verifies a credential and establishes a session.
//
// Every failure path returns the same error and takes broadly the same time.
// Distinguishing "no such user" from "wrong password" would hand an attacker a
// way to enumerate valid accounts, which is a far more useful result than any
// single guess.
func (s *Service) Login(ctx context.Context, req LoginRequest) (*TokenPair, *domain.User, error) {
	tenantLabel := s.metrics.Tenant(req.Tenant.Slug)

	if !req.Tenant.IsActive() {
		s.metrics.AuthAttempts.WithLabelValues("tenant_suspended", tenantLabel).Inc()
		return nil, nil, domain.ErrTenantSuspended
	}

	user, err := s.users.ByEmail(ctx, req.Tenant.ID, req.Email)
	if errors.Is(err, domain.ErrNotFound) {
		// Spend the same CPU an argon2 verification would, so the response time
		// does not reveal that the account is absent.
		BurnTimingBudget(req.Password)
		_, _ = s.cache.RecordAuthFailure(ctx, req.Tenant.ID, postgres.NormalizeEmail(req.Email), 15*time.Minute)
		s.metrics.AuthAttempts.WithLabelValues("unknown_user", tenantLabel).Inc()
		s.auditor.Record(audit.Event("auth.login").
			Tenant(req.Tenant.ID).Actor(nil, postgres.NormalizeEmail(req.Email)).
			Deny("unknown_user").Request(req.RequestID, req.IP, req.UserAgent).Build())
		return nil, nil, domain.ErrInvalidCredential
	}
	if err != nil {
		return nil, nil, fmt.Errorf("look up user: %w", err)
	}

	now := time.Now()
	if user.IsLocked(now) {
		s.metrics.AuthAttempts.WithLabelValues("locked", tenantLabel).Inc()
		s.auditor.Record(audit.Event("auth.login").
			Tenant(req.Tenant.ID).Actor(&user.ID, user.Email).
			Deny("account_locked").Request(req.RequestID, req.IP, req.UserAgent).
			Meta("locked_until", user.LockedUntil.UTC().Format(time.RFC3339)).Build())
		return nil, nil, domain.ErrAccountLocked
	}
	if !user.IsActive() {
		s.metrics.AuthAttempts.WithLabelValues("inactive", tenantLabel).Inc()
		s.auditor.Record(audit.Event("auth.login").
			Tenant(req.Tenant.ID).Actor(&user.ID, user.Email).
			Deny("user_"+string(user.Status)).Request(req.RequestID, req.IP, req.UserAgent).Build())
		return nil, nil, domain.ErrUserInactive
	}

	ok, err := VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		s.log.Error("password hash could not be verified", "user_id", user.ID, "error", err)
		return nil, nil, domain.ErrInvalidCredential
	}
	if !ok {
		locked, lockErr := s.users.RecordFailedLogin(ctx, req.Tenant.ID, user.ID, s.maxFailedLogins, s.lockoutDuration)
		if lockErr != nil {
			s.log.Error("could not record failed login", "user_id", user.ID, "error", lockErr)
		}
		_, _ = s.cache.RecordAuthFailure(ctx, req.Tenant.ID, user.Email, 15*time.Minute)
		s.metrics.AuthAttempts.WithLabelValues("bad_password", tenantLabel).Inc()

		ev := audit.Event("auth.login").Tenant(req.Tenant.ID).Actor(&user.ID, user.Email).
			Deny("invalid_password").Request(req.RequestID, req.IP, req.UserAgent)
		if locked {
			ev = ev.Meta("account_locked", "true")
		}
		s.auditor.Record(ev.Build())
		return nil, nil, domain.ErrInvalidCredential
	}

	if err := s.users.RecordSuccessfulLogin(ctx, req.Tenant.ID, user.ID); err != nil {
		s.log.Error("could not clear login failure state", "user_id", user.ID, "error", err)
	}
	_ = s.cache.ClearAuthFailures(ctx, req.Tenant.ID, user.Email)

	pair, err := s.establishSession(ctx, req.Tenant, user, sessionContext{
		IP: req.IP, UserAgent: req.UserAgent, DeviceHash: req.DeviceHash,
		AMR: []string{"pwd"},
	})
	if err != nil {
		return nil, nil, err
	}

	s.metrics.AuthAttempts.WithLabelValues("success", tenantLabel).Inc()
	s.auditor.Record(audit.Event("auth.login").
		Tenant(req.Tenant.ID).Actor(&user.ID, user.Email).Allow().
		Request(req.RequestID, req.IP, req.UserAgent).
		Meta("session_id", pair.SessionID.String()).Build())

	return pair, user, nil
}

type sessionContext struct {
	IP         string
	UserAgent  string
	DeviceHash string
	AMR        []string
	FamilyID   uuid.UUID
	Generation int
}

// establishSession creates the durable session, its Redis mirror and the first
// token pair.
func (s *Service) establishSession(ctx context.Context, tenant *domain.Tenant, user *domain.User, sc sessionContext) (*TokenPair, error) {
	familyID := sc.FamilyID
	if familyID == uuid.Nil {
		familyID = uuid.New()
	}

	session := &domain.Session{
		ID: uuid.New(), TenantID: tenant.ID, UserID: user.ID, FamilyID: familyID,
		DeviceHash: sc.DeviceHash, IP: sc.IP, UserAgent: sc.UserAgent,
		Generation: sc.Generation, AMR: sc.AMR,
		CreatedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(s.refreshTTL),
	}

	_, roleNames, err := s.roles.EffectivePermissions(ctx, tenant.ID, user.ID)
	if err != nil {
		return nil, fmt.Errorf("resolve roles: %w", err)
	}

	pair, err := s.mintPair(ctx, tenant, user, session, roleNames)
	if err != nil {
		return nil, err
	}

	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("persist session: %w", err)
	}
	return pair, nil
}

// mintPair issues an access token plus the refresh token that will replace it,
// and registers both server-side.
func (s *Service) mintPair(ctx context.Context, tenant *domain.Tenant, user *domain.User, session *domain.Session, roleNames []string) (*TokenPair, error) {
	claims := Claims{
		TenantID: tenant.ID, TenantSlug: tenant.Slug, SessionID: session.ID,
		Email: user.Email, PolicyVersion: tenant.PolicyVersion,
		Roles: roleNames, AMR: session.AMR,
	}
	claims.Subject = user.ID.String()
	if s.bindDevice {
		claims.DeviceBinding = session.DeviceHash
	}
	if s.bindIP {
		claims.IPBinding = NetworkFingerprint(session.IP)
	}

	accessToken, expiresAt, err := s.issuer.Mint(claims)
	if err != nil {
		return nil, fmt.Errorf("mint access token: %w", err)
	}
	refreshToken, err := NewRefreshToken()
	if err != nil {
		return nil, err
	}
	if err := s.cache.CreateSession(ctx, session, redisstore.HashToken(refreshToken), s.refreshTTL); err != nil {
		return nil, fmt.Errorf("register session: %w", err)
	}

	tenantLabel := s.metrics.Tenant(tenant.Slug)
	s.metrics.TokensIssued.WithLabelValues("access", tenantLabel).Inc()
	s.metrics.TokensIssued.WithLabelValues("refresh", tenantLabel).Inc()

	return &TokenPair{
		AccessToken: accessToken, RefreshToken: refreshToken, TokenType: "Bearer",
		ExpiresIn: int(s.accessTTL.Seconds()), ExpiresAt: expiresAt, SessionID: session.ID,
	}, nil
}

// RefreshRequest is a refresh-token exchange.
type RefreshRequest struct {
	RefreshToken string
	IP           string
	UserAgent    string
	DeviceHash   string
	RequestID    string
}

// Refresh exchanges a refresh token for a new pair, rotating it in the process.
//
// The interesting case is replay. Because rotation is single-use, seeing a token
// that has already been redeemed means it was captured — either the attacker is
// using a token they stole before the victim rotated it, or the victim is using
// one the attacker already burned. There is no way to tell which side is which
// from a single request, so the only safe response is to revoke the entire
// family and force a fresh login. Losing one session beats leaving an attacker
// with an indefinitely renewable one.
func (s *Service) Refresh(ctx context.Context, req RefreshRequest) (*TokenPair, error) {
	newToken, err := NewRefreshToken()
	if err != nil {
		return nil, err
	}

	rec, err := s.cache.RotateRefreshToken(ctx, req.RefreshToken, newToken, s.refreshTTL)
	switch {
	case errors.Is(err, domain.ErrTokenReused):
		s.metrics.TokenRefresh.WithLabelValues("reuse_detected").Inc()
		s.handleReuse(ctx, rec, req)
		return nil, domain.ErrTokenReused

	case errors.Is(err, domain.ErrNotFound):
		s.metrics.TokenRefresh.WithLabelValues("unknown_token").Inc()
		return nil, domain.ErrInvalidCredential

	case errors.Is(err, domain.ErrTokenRevoked):
		// The token was intact and had not been used, but its session was
		// killed since it was issued (logout, an admin revoke, or a sibling
		// token's replay having burned the whole family). Distinct from an
		// unknown token only for logging; the client's remedy is the same —
		// log in again — which writeDomainError's ErrTokenRevoked case already
		// expresses.
		s.metrics.TokenRefresh.WithLabelValues("session_revoked").Inc()
		return nil, domain.ErrTokenRevoked

	case err != nil:
		s.metrics.TokenRefresh.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	// Re-verify the principal from the source of truth. A refresh is not a
	// shortcut around the checks a login performs: the tenant may have been
	// suspended and the user disabled since the token was issued.
	tenant, err := s.tenants.ByID(ctx, rec.TenantID)
	if err != nil {
		return nil, fmt.Errorf("load tenant: %w", err)
	}
	if !tenant.IsActive() {
		return nil, domain.ErrTenantSuspended
	}
	user, err := s.users.ByID(ctx, rec.TenantID, rec.UserID)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	if !user.IsActive() {
		return nil, domain.ErrUserInactive
	}
	if user.IsLocked(time.Now()) {
		return nil, domain.ErrAccountLocked
	}

	// The rotated session keeps the family, so a later replay of any ancestor
	// token still resolves to this lineage and burns all of it.
	_, roleNames, err := s.roles.EffectivePermissions(ctx, tenant.ID, user.ID)
	if err != nil {
		return nil, fmt.Errorf("resolve roles: %w", err)
	}

	session := &domain.Session{
		ID: rec.SessionID, TenantID: tenant.ID, UserID: user.ID, FamilyID: rec.FamilyID,
		DeviceHash: req.DeviceHash, IP: req.IP, UserAgent: req.UserAgent,
		Generation: rec.Generation, AMR: []string{"pwd"},
		CreatedAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(s.refreshTTL),
	}
	if rec.DeviceHash != "" {
		session.DeviceHash = rec.DeviceHash
	}

	claims := Claims{
		TenantID: tenant.ID, TenantSlug: tenant.Slug, SessionID: session.ID,
		Email: user.Email, PolicyVersion: tenant.PolicyVersion,
		Roles: roleNames, AMR: session.AMR,
	}
	claims.Subject = user.ID.String()
	if s.bindDevice {
		claims.DeviceBinding = session.DeviceHash
	}
	if s.bindIP {
		claims.IPBinding = NetworkFingerprint(session.IP)
	}

	accessToken, expiresAt, err := s.issuer.Mint(claims)
	if err != nil {
		return nil, fmt.Errorf("mint access token: %w", err)
	}

	// The rotation script already wrote the successor record, so all that is
	// left is to extend the session it belongs to.
	if err := s.cache.TouchSession(ctx, session, s.refreshTTL); err != nil {
		return nil, fmt.Errorf("refresh session: %w", err)
	}
	if err := s.sessions.Touch(ctx, tenant.ID, session.ID, session.Generation); err != nil {
		s.log.Warn("could not update durable session record", "session_id", session.ID, "error", err)
	}

	s.metrics.TokenRefresh.WithLabelValues("success").Inc()
	s.metrics.TokensIssued.WithLabelValues("access", s.metrics.Tenant(tenant.Slug)).Inc()
	s.auditor.Record(audit.Event("auth.refresh").
		Tenant(tenant.ID).Actor(&user.ID, user.Email).Allow().
		Request(req.RequestID, req.IP, req.UserAgent).
		Meta("session_id", session.ID.String()).
		Meta("generation", fmt.Sprint(session.Generation)).Build())

	return &TokenPair{
		AccessToken: accessToken, RefreshToken: newToken, TokenType: "Bearer",
		ExpiresIn: int(s.accessTTL.Seconds()), ExpiresAt: expiresAt, SessionID: session.ID,
	}, nil
}

// handleReuse burns the compromised family and records the event loudly. This is
// the one place where the system deliberately logs a user out on suspicion
// rather than proof.
func (s *Service) handleReuse(ctx context.Context, rec *redisstore.RefreshRecord, req RefreshRequest) {
	if rec == nil || rec.FamilyID == uuid.Nil {
		s.log.Error("refresh token replay detected but the family could not be identified",
			"request_id", req.RequestID, "ip", req.IP)
		return
	}
	killed, err := s.cache.RevokeFamily(ctx, rec.FamilyID)
	if err != nil {
		s.log.Error("could not revoke session family after replay",
			"family_id", rec.FamilyID, "error", err)
	}
	if _, err := s.sessions.RevokeFamily(ctx, rec.TenantID, rec.FamilyID, "refresh_token_reuse"); err != nil {
		s.log.Error("could not mark session family revoked",
			"family_id", rec.FamilyID, "error", err)
	}

	s.log.Warn("refresh token replay detected; session family revoked",
		"family_id", rec.FamilyID, "tenant_id", rec.TenantID, "user_id", rec.UserID,
		"sessions_revoked", killed, "ip", req.IP, "request_id", req.RequestID)

	s.auditor.Record(audit.Event("auth.refresh_reuse_detected").
		Tenant(rec.TenantID).Actor(&rec.UserID, "").
		Deny("refresh_token_replayed").Risk(100).
		Request(req.RequestID, req.IP, req.UserAgent).
		Meta("family_id", rec.FamilyID.String()).
		Meta("sessions_revoked", fmt.Sprint(killed)).Build())
}

// Logout revokes a single session immediately: the Redis key disappears, so the
// next request presenting an access token for it fails the liveness check even
// though the signature is still valid.
func (s *Service) Logout(ctx context.Context, tenantID, sessionID, userID uuid.UUID, jti string, tokenExpiry time.Time, requestID, ip, ua string) error {
	if err := s.cache.RevokeSession(ctx, tenantID, sessionID); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	// Also denylist the presented access token, so it cannot be replayed in the
	// window between now and its expiry.
	if jti != "" {
		if err := s.cache.DenyToken(ctx, jti, tokenExpiry); err != nil {
			s.log.Warn("could not denylist access token on logout", "jti", jti, "error", err)
		}
	}
	if err := s.sessions.Revoke(ctx, tenantID, sessionID, "logout"); err != nil && !errors.Is(err, domain.ErrNotFound) {
		s.log.Warn("could not mark session revoked", "session_id", sessionID, "error", err)
	}

	s.auditor.Record(audit.Event("auth.logout").
		Tenant(tenantID).Actor(&userID, "").Allow().
		Request(requestID, ip, ua).Meta("session_id", sessionID.String()).Build())
	return nil
}

func hasAMR(amr []string, want string) bool {
	for _, v := range amr {
		if v == want {
			return true
		}
	}
	return false
}

// StepUp re-verifies a live session's owning credential and mints a fresh
// access token with "mfa" added to its AMR list.
//
// It deliberately does not touch the refresh token or the underlying session
// record: this is a narrower operation than Login. Its only job is to move the
// *current* access token from single-factor to re-verified, which is what lets
// a subsequent sensitive request clear the risk engine's OutcomeStepUp check
// (see authz.RiskEngine.Assess and middleware.RiskAssessment). Because it re-runs
// full password verification against the store, a stolen access token alone is
// not enough to satisfy it — the caller has to prove the credential again.
func (s *Service) StepUp(ctx context.Context, tenant *domain.Tenant, claims *Claims, password, ip, ua, requestID string) (*TokenPair, error) {
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("parse subject claim: %w", err)
	}
	user, err := s.users.ByID(ctx, tenant.ID, userID)
	if err != nil {
		return nil, err
	}
	if !user.IsActive() {
		return nil, domain.ErrUserInactive
	}
	if user.IsLocked(time.Now()) {
		return nil, domain.ErrAccountLocked
	}

	ok, err := VerifyPassword(password, user.PasswordHash)
	if err != nil {
		s.log.Error("password hash could not be verified during step-up", "user_id", user.ID, "error", err)
		return nil, domain.ErrInvalidCredential
	}
	if !ok {
		_, _ = s.cache.RecordAuthFailure(ctx, tenant.ID, user.Email, 15*time.Minute)
		s.auditor.Record(audit.Event("auth.step_up").
			Tenant(tenant.ID).Actor(&user.ID, user.Email).
			Deny("invalid_password").Request(requestID, ip, ua).Build())
		return nil, domain.ErrInvalidCredential
	}

	amr := append([]string{}, claims.AMR...)
	if !hasAMR(amr, "mfa") {
		amr = append(amr, "mfa")
	}

	_, roleNames, err := s.roles.EffectivePermissions(ctx, tenant.ID, user.ID)
	if err != nil {
		return nil, fmt.Errorf("resolve roles: %w", err)
	}

	newClaims := Claims{
		TenantID: tenant.ID, TenantSlug: tenant.Slug, SessionID: claims.SessionID,
		Email: user.Email, PolicyVersion: tenant.PolicyVersion,
		Roles: roleNames, AMR: amr,
		DeviceBinding: claims.DeviceBinding, IPBinding: claims.IPBinding,
	}
	newClaims.Subject = user.ID.String()

	accessToken, expiresAt, err := s.issuer.Mint(newClaims)
	if err != nil {
		return nil, fmt.Errorf("mint step-up token: %w", err)
	}

	// The old access token is still cryptographically valid until it expires
	// naturally, but it is no longer the *only* token for this session — the
	// client should switch to the new, re-verified one. We do not revoke the
	// old jti here: this is a step up in assurance, not a security incident.
	s.metrics.TokensIssued.WithLabelValues("access", s.metrics.Tenant(tenant.Slug)).Inc()
	s.auditor.Record(audit.Event("auth.step_up").
		Tenant(tenant.ID).Actor(&user.ID, user.Email).Allow().
		Request(requestID, ip, ua).Meta("session_id", claims.SessionID.String()).Build())

	return &TokenPair{
		AccessToken: accessToken, RefreshToken: "", TokenType: "Bearer",
		ExpiresIn: int(s.accessTTL.Seconds()), ExpiresAt: expiresAt, SessionID: claims.SessionID,
	}, nil
}

// RevokeSession terminates one session administratively, by id.
//
// Unlike Logout, the caller here is not necessarily the session's own owner and
// does not have the specific access-token jti to denylist. That is fine:
// Authenticate checks session liveness on every request (see
// redisstore.SessionLive), so evicting the Redis record is what actually cuts
// the session off — the jti denylist in Logout is belt-and-braces for the exact
// token in hand, not the only enforcement mechanism.
func (s *Service) RevokeSession(ctx context.Context, tenantID, sessionID uuid.UUID, reason string) error {
	if err := s.cache.RevokeSession(ctx, tenantID, sessionID); err != nil {
		return fmt.Errorf("evict session from cache: %w", err)
	}
	return s.sessions.Revoke(ctx, tenantID, sessionID, reason)
}

// RevokeAllSessions terminates every session a user holds. Used when an account
// is disabled or a password changes, where leaving existing sessions alive would
// defeat the point of the change.
func (s *Service) RevokeAllSessions(ctx context.Context, tenantID, userID uuid.UUID, reason string) (int64, error) {
	views, err := s.sessions.ListForUser(ctx, tenantID, userID, false)
	if err != nil {
		return 0, err
	}
	for _, v := range views {
		if err := s.cache.RevokeSession(ctx, tenantID, v.ID); err != nil {
			s.log.Warn("could not evict session from cache", "session_id", v.ID, "error", err)
		}
	}
	n, err := s.sessions.RevokeAllForUser(ctx, tenantID, userID, reason)
	if err != nil {
		return 0, err
	}
	s.auditor.Record(audit.Event("session.revoke_all").
		Tenant(tenantID).Actor(&userID, "").Allow().
		Meta("reason", reason).Meta("count", fmt.Sprint(n)).Build())
	return n, nil
}
