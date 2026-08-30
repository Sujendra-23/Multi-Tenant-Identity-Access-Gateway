// Package domain holds the core entities and the tenant-scoped invariants that
// the rest of the system enforces. Nothing here talks to a database or an HTTP
// request; it is the vocabulary the other packages share.
package domain

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors. Handlers map these to status codes; nothing else in the
// codebase should invent its own "not found" string.
var (
	ErrNotFound          = errors.New("not found")
	ErrConflict          = errors.New("conflict")
	ErrInvalidCredential = errors.New("invalid credentials")
	ErrAccountLocked     = errors.New("account locked")
	ErrTenantSuspended   = errors.New("tenant suspended")
	ErrUserInactive      = errors.New("user inactive")
	ErrForbidden         = errors.New("forbidden")
	ErrTokenRevoked      = errors.New("token revoked")
	ErrTokenReused       = errors.New("refresh token reuse detected")
	ErrStepUpRequired    = errors.New("step-up authentication required")
	ErrRateLimited       = errors.New("rate limit exceeded")
)

type TenantStatus string

const (
	TenantActive    TenantStatus = "active"
	TenantSuspended TenantStatus = "suspended"
)

// Tenant is the isolation boundary. Every other tenant-owned row carries its
// id, and Postgres row-level security enforces that at the database rather than
// trusting application code to remember the WHERE clause.
type Tenant struct {
	ID     uuid.UUID    `json:"id"`
	Slug   string       `json:"slug"`
	Name   string       `json:"name"`
	Status TenantStatus `json:"status"`
	Plan   string       `json:"plan"`

	// PolicyVersion is bumped on any change to roles, permissions or
	// assignments within the tenant. Access tokens embed the version they were
	// minted under; a stale version forces the gateway to re-read authorization
	// state instead of trusting the token's cached claims. That is what makes a
	// permission revocation take effect immediately rather than at token expiry.
	PolicyVersion int64 `json:"policy_version"`

	// RateLimitRPS overrides the global per-tenant quota, zero meaning "use the
	// configured default".
	RateLimitRPS int       `json:"rate_limit_rps"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (t *Tenant) IsActive() bool { return t.Status == TenantActive }

type UserStatus string

const (
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
	UserInvited  UserStatus = "invited"
)

type User struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	DisplayName  string     `json:"display_name"`
	Status       UserStatus `json:"status"`

	FailedLoginCount int        `json:"-"`
	LockedUntil      *time.Time `json:"locked_until,omitempty"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	MFAEnrolled      bool       `json:"mfa_enrolled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

func (u *User) IsActive() bool { return u.Status == UserActive }

// Role groups permissions. Roles are tenant-scoped: two tenants may both have
// an "admin" role and they are entirely separate objects with separate grants.
type Role struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	// System roles ship with every tenant and cannot be deleted, only extended.
	IsSystem    bool         `json:"is_system"`
	Permissions []Permission `json:"permissions,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
}

// Permission is a resource/action pair such as "billing:read". Both halves
// accept "*" as a wildcard, so "billing:*" grants every action on billing and
// "*:*" is full access.
type Permission struct {
	ID       uuid.UUID `json:"id"`
	Resource string    `json:"resource"`
	Action   string    `json:"action"`
	// Effect is "allow" or "deny". An explicit deny always beats any allow,
	// which lets a tenant carve an exception out of a broad grant.
	Effect string `json:"effect"`
}

const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

func (p Permission) String() string { return p.Resource + ":" + p.Action }

// ParsePermission turns "billing:read" into a Permission with allow effect.
func ParsePermission(s string) (Permission, error) {
	resource, action, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || resource == "" || action == "" {
		return Permission{}, errors.New("permission must be in resource:action form")
	}
	return Permission{Resource: resource, Action: action, Effect: EffectAllow}, nil
}

// Matches reports whether this permission covers the requested resource and
// action, honouring wildcards on either side.
func (p Permission) Matches(resource, action string) bool {
	return (p.Resource == "*" || p.Resource == resource) &&
		(p.Action == "*" || p.Action == action)
}

// AuditEvent is one append-only record. Records are hash-chained per tenant so
// that deleting or editing history is detectable: each row commits to the one
// before it.
type AuditEvent struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Sequence   int64      `json:"sequence"`
	ActorID    *uuid.UUID `json:"actor_id,omitempty"`
	ActorEmail string     `json:"actor_email,omitempty"`
	Action     string     `json:"action"`
	Resource   string     `json:"resource"`
	Decision   string     `json:"decision"`
	Reason     string     `json:"reason,omitempty"`
	RiskScore  int        `json:"risk_score"`
	IP         string     `json:"ip,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`
	RequestID  string     `json:"request_id,omitempty"`
	// Metadata is deliberately string-to-string. The chain hash must be
	// reproducible after a JSONB round trip, and Postgres normalises numbers and
	// reorders object keys on the way back out. Constraining values to strings
	// and hashing a key-sorted encoding removes that ambiguity entirely.
	Metadata   map[string]string `json:"metadata,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`

	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Audit decisions.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionError = "error"
)

// Session is the server-side record backing a refresh-token family. Killing the
// session revokes access immediately rather than waiting for token expiry,
// which is the whole point of keeping server-side state alongside stateless JWTs.
type Session struct {
	ID         uuid.UUID `json:"id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	UserID     uuid.UUID `json:"user_id"`
	FamilyID   uuid.UUID `json:"family_id"`
	DeviceHash string    `json:"device_hash"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	Generation int       `json:"generation"`
	AMR        []string  `json:"amr"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}
