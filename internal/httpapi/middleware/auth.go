package middleware

import (
	"net/http"
	"strings"

	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/store/redisstore"
)

// Authenticate is the zero-trust checkpoint every protected route passes
// through. It treats the bearer token as a claim to be re-verified, never as a
// standing grant, which is the whole distinction between this and a
// conventional "trust the session" model:
//
//  1. Signature, issuer, audience and expiry — cryptographic validity.
//  2. The token's tenant claim must match the tenant this request resolved to
//     from X-Tenant. A token cannot be replayed against a different tenant by
//     changing a header, because the two are cross-checked here.
//  3. The token's jti must not be on the denylist (explicit revocation, e.g.
//     logout).
//  4. The session it belongs to must still be live in Redis. This is what
//     makes logout and session revocation take effect immediately rather than
//     waiting out the access token's TTL — the signature stays valid, but the
//     session backing it is gone.
//
// A valid signature alone never reaches a handler; every one of these has to
// pass on every single request.
func Authenticate(issuer *auth.TokenIssuer, cache *redisstore.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r)
			if raw == "" {
				writeErr(w, r, http.StatusUnauthorized, "missing_token", "an Authorization: Bearer token is required")
				return
			}

			claims, err := issuer.Parse(raw)
			if err != nil {
				writeErr(w, r, http.StatusUnauthorized, "invalid_token", "the access token is invalid or expired")
				return
			}

			tenant := reqctx.Tenant(r.Context())
			if tenant == nil || claims.TenantID != tenant.ID {
				// A signature that verifies for the wrong tenant is not a
				// bureaucratic mismatch, it is a cross-tenant replay attempt.
				writeErr(w, r, http.StatusUnauthorized, "tenant_mismatch", "this token was not issued for the requested organization")
				return
			}

			denied, err := cache.IsTokenDenied(r.Context(), claims.ID)
			if err != nil {
				writeErr(w, r, http.StatusServiceUnavailable, "session_check_failed", "could not verify token status")
				return
			}
			if denied {
				writeErr(w, r, http.StatusUnauthorized, "token_revoked", "this token has been revoked")
				return
			}

			live, err := cache.SessionLive(r.Context(), claims.TenantID, claims.SessionID)
			if err != nil {
				writeErr(w, r, http.StatusServiceUnavailable, "session_check_failed", "could not verify session status")
				return
			}
			if !live {
				writeErr(w, r, http.StatusUnauthorized, "session_revoked", "this session is no longer active; please log in again")
				return
			}

			ctx := reqctx.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// RequirePolicyCurrent rejects a token minted under a policy version older than
// the tenant's current one.
//
// This is the second half of instant revocation: PolicyVersion in the claims is
// only a hint used to key the permission cache (see authz.Evaluator). This check
// is what actually enforces it — a token surviving from before a role or grant
// changed is refused outright rather than being allowed to fall back to a
// slightly-stale cached decision.
func RequirePolicyCurrent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := reqctx.Tenant(r.Context())
		claims := reqctx.Claims(r.Context())
		if tenant == nil || claims == nil {
			writeErr(w, r, http.StatusInternalServerError, "internal_error", "authentication context missing")
			return
		}
		if claims.PolicyVersion < tenant.PolicyVersion {
			writeErr(w, r, http.StatusUnauthorized, "policy_changed", "permissions have changed since this token was issued; please refresh")
			return
		}
		next.ServeHTTP(w, r)
	})
}
