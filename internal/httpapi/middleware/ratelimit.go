package middleware

import (
	"net/http"
	"strconv"

	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/observability"
	"github.com/sujendra/identity-gateway/internal/store/redisstore"
)

// RateLimit builds a token-bucket middleware over one dimension of the request
// (IP, authenticated user, or tenant). keyFn extracts the bucket key; a request
// for which it returns "" skips limiting on this dimension entirely (used for
// the per-user limiter on unauthenticated routes).
//
// Layering several of these — IP, then user, then tenant — is deliberate: an IP
// limit alone is defeated by a botnet, a user limit alone is defeated by
// spinning up new accounts, and a tenant limit alone lets one compromised user
// exhaust a whole organization's quota. Each dimension closes the gap the others
// leave open.
func RateLimit(cache *redisstore.Client, m *observability.Metrics, dimension string, rate, burst int, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			result, err := cache.Allow(r.Context(), dimension+":"+key, rate, burst)
			if err != nil {
				// Redis being down must not take the gateway down with it. Let
				// the request through and rely on the layers that do not depend
				// on this dimension (and on Redis recovering) to contain abuse.
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))

			if !result.Allowed {
				tenantLabel := "none"
				if t := reqctx.Tenant(r.Context()); t != nil {
					tenantLabel = m.Tenant(t.Slug)
				}
				m.RateLimitHits.WithLabelValues(dimension, tenantLabel).Inc()
				w.Header().Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())+1))
				writeErr(w, r, http.StatusTooManyRequests, "rate_limited",
					"too many requests; dimension="+dimension)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ByIP keys the bucket on the resolved client IP.
func ByIP(r *http.Request) string { return reqctx.ClientIP(r.Context()) }

// ByUser keys the bucket on the authenticated principal, and is a no-op (no
// limiting) for requests that have not reached Authenticate yet.
func ByUser(r *http.Request) string {
	claims := reqctx.Claims(r.Context())
	if claims == nil {
		return ""
	}
	return claims.TenantID.String() + ":" + claims.Subject
}

// ByTenant keys the bucket on the resolved tenant.
func ByTenant(r *http.Request) string {
	t := reqctx.Tenant(r.Context())
	if t == nil {
		return ""
	}
	return t.ID.String()
}

// ByLoginIP keys the pre-authentication login limiter on tenant plus IP.
//
// It is deliberately not keyed on the email in the request body: middleware
// runs before the handler parses the body, and peeking it here would mean
// buffering and re-attaching the body for every login attempt just to extract
// one field. Per-identity brute-force protection already exists one layer down
// — auth.Service locks the account after MaxFailedLogins and the risk engine
// weighs recent failures for that email (see authz.RiskEngine) — so this
// dimension's job is narrower: stop one IP from hammering the login endpoint
// across many different email addresses, which the per-account lockout alone
// would not catch.
func ByLoginIP(r *http.Request) string {
	t := reqctx.Tenant(r.Context())
	if t == nil {
		return ""
	}
	return t.ID.String() + ":" + reqctx.ClientIP(r.Context())
}
