package middleware

import (
	"net/http"

	"github.com/sujendra/identity-gateway/internal/authz"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/observability"
)

// RequirePermission builds middleware that authorizes resource:action against
// the caller's effective permissions, resolved fresh (subject to cache, keyed by
// policy version — see authz.Evaluator) on every request rather than trusted
// from the token.
//
// This, together with Authenticate's liveness check, is the two-part answer to
// "zero trust": a request must present a currently-valid credential *and* the
// permission it is exercising must still be granted right now. Revoking a role
// takes effect on the very next request from that user, not at token expiry.
func RequirePermission(eval *authz.Evaluator, m *observability.Metrics, resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := reqctx.Tenant(r.Context())
			claims := reqctx.Claims(r.Context())
			if tenant == nil || claims == nil {
				writeErr(w, r, http.StatusInternalServerError, "internal_error", "authorization context missing")
				return
			}

			userID := reqctx.UserID(r.Context())
			decision, err := eval.Check(r.Context(), tenant.ID, tenant.PolicyVersion, userID, resource, action)
			tenantLabel := m.Tenant(tenant.Slug)
			if err != nil {
				m.AuthzDecisions.WithLabelValues("error", "evaluation_failed", tenantLabel).Inc()
				writeErr(w, r, http.StatusServiceUnavailable, "authorization_unavailable", "could not evaluate permissions")
				return
			}

			if !decision.Allowed {
				m.AuthzDecisions.WithLabelValues("deny", decision.Reason, tenantLabel).Inc()
				writeErr(w, r, http.StatusForbidden, "forbidden", "you do not have the "+resource+":"+action+" permission")
				return
			}

			m.AuthzDecisions.WithLabelValues("allow", decision.Reason, tenantLabel).Inc()
			next.ServeHTTP(w, r)
		})
	}
}
