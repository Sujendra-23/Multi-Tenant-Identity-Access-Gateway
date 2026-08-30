// Package reqctx holds the request-scoped context keys and accessors shared by
// the middleware chain, the router and the handlers.
//
// It exists as its own leaf package (rather than living in package httpapi
// alongside the router) specifically to avoid an import cycle: the router
// imports both middleware and handlers, middleware sets these values, and
// handlers read them, so the type owning them cannot live in either.
package reqctx

import (
	"context"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/domain"
)

type key int

const (
	keyRequestID key = iota
	keyClientIP
	keyUserAgent
	keyDeviceHash
	keyTenant
	keyClaims
	keyRiskScore
)

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyRequestID, id)
}
func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(keyRequestID).(string)
	return v
}

func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, keyClientIP, ip)
}
func ClientIP(ctx context.Context) string {
	v, _ := ctx.Value(keyClientIP).(string)
	return v
}

func WithUserAgent(ctx context.Context, ua string) context.Context {
	return context.WithValue(ctx, keyUserAgent, ua)
}
func UserAgent(ctx context.Context) string {
	v, _ := ctx.Value(keyUserAgent).(string)
	return v
}

func WithDeviceHash(ctx context.Context, d string) context.Context {
	return context.WithValue(ctx, keyDeviceHash, d)
}
func DeviceHash(ctx context.Context) string {
	v, _ := ctx.Value(keyDeviceHash).(string)
	return v
}

// WithTenant attaches the tenant resolved for this request. Everything behind
// the tenant-resolution middleware treats this as the only trustworthy tenant
// identifier — never a path or body parameter.
func WithTenant(ctx context.Context, t *domain.Tenant) context.Context {
	return context.WithValue(ctx, keyTenant, t)
}
func Tenant(ctx context.Context) *domain.Tenant {
	t, _ := ctx.Value(keyTenant).(*domain.Tenant)
	return t
}

// WithClaims attaches the verified access-token claims.
func WithClaims(ctx context.Context, c *auth.Claims) context.Context {
	return context.WithValue(ctx, keyClaims, c)
}
func Claims(ctx context.Context) *auth.Claims {
	c, _ := ctx.Value(keyClaims).(*auth.Claims)
	return c
}

// UserID reads the authenticated principal's id, returning uuid.Nil when there
// are no claims on the context.
func UserID(ctx context.Context) uuid.UUID {
	c := Claims(ctx)
	if c == nil {
		return uuid.Nil
	}
	id, err := uuid.Parse(c.Subject)
	if err != nil {
		return uuid.Nil
	}
	return id
}

func WithRiskScore(ctx context.Context, score int) context.Context {
	return context.WithValue(ctx, keyRiskScore, score)
}
func RiskScore(ctx context.Context) int {
	v, _ := ctx.Value(keyRiskScore).(int)
	return v
}
