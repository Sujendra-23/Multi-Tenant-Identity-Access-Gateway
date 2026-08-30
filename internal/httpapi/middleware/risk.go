package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/sujendra/identity-gateway/internal/audit"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/authz"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/observability"
)

// RiskAssessment scores every authenticated request against the principal's
// behavioural history and the sensitivity of what it is trying to do, then
// either lets it through, demands step-up authentication, or denies it outright.
//
// This is what makes the gateway "continuous" verification rather than
// point-in-time: a request can carry a perfectly valid, live, correctly
// authorized token and still be refused because it looks nothing like how this
// principal normally behaves — a brand-new device, a network never seen before,
// attempting a destructive action, right after a burst of failed logins
// elsewhere. None of those alone would be cause for concern; together they are
// exactly what credential theft looks like from the outside.
func RiskAssessment(engine *authz.RiskEngine, auditor *audit.Logger, m *observability.Metrics, resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := reqctx.Tenant(r.Context())
			claims := reqctx.Claims(r.Context())
			if tenant == nil || claims == nil {
				writeErr(w, r, http.StatusInternalServerError, "internal_error", "risk assessment context missing")
				return
			}

			deviceHash := reqctx.DeviceHash(r.Context())
			ipHash := auth.NetworkFingerprint(reqctx.ClientIP(r.Context()))
			sessionAge := time.Since(claims.IssuedAt.Time)

			assessment, err := engine.Assess(r.Context(), authz.Input{
				TenantID: tenant.ID, UserID: reqctx.UserID(r.Context()), Email: claims.Email,
				DeviceHash: deviceHash, IPHash: ipHash,
				BoundDevice: claims.DeviceBinding, BoundIP: claims.IPBinding,
				AMR: claims.AMR, SessionAge: sessionAge,
				Resource: resource, Action: action,
			})
			if err != nil {
				// A scoring failure degrades to "allow" rather than blocking
				// traffic: risk assessment sharpens authorization, it is not
				// itself the authorization decision. RequirePermission has
				// already run by this point in the chain.
				next.ServeHTTP(w, r.WithContext(reqctx.WithRiskScore(r.Context(), 0)))
				return
			}

			tenantLabel := m.Tenant(tenant.Slug)
			m.RiskScore.WithLabelValues(string(assessment.Outcome)).Observe(float64(assessment.Score))

			switch assessment.Outcome {
			case authz.OutcomeDeny:
				m.AuthzDecisions.WithLabelValues("deny", "risk_threshold_exceeded", tenantLabel).Inc()
				auditor.Record(audit.Event("access.risk_denied").
					Tenant(tenant.ID).Actor(ptr(reqctx.UserID(r.Context())), claims.Email).
					Resource(resource+":"+action).Deny("risk_threshold_exceeded").Risk(assessment.Score).
					Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).
					Meta("signals", assessment.Explain).Build())
				writeErr(w, r, http.StatusForbidden, "risk_denied",
					"this request was blocked due to unusual account activity ("+assessment.Explain+")")
				return

			case authz.OutcomeStepUp:
				if hasAMR(claims.AMR, "mfa") {
					// Already re-verified this session; do not loop the client
					// through step-up on every subsequent sensitive call.
					break
				}
				m.AuthzDecisions.WithLabelValues("deny", "step_up_required", tenantLabel).Inc()
				auditor.Record(audit.Event("access.step_up_required").
					Tenant(tenant.ID).Actor(ptr(reqctx.UserID(r.Context())), claims.Email).
					Resource(resource+":"+action).Deny("step_up_required").Risk(assessment.Score).
					Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).
					Meta("signals", assessment.Explain).Build())
				w.Header().Set("X-StepUp-Required", "mfa")
				writeErr(w, r, http.StatusForbidden, "step_up_required",
					"this action requires re-authentication ("+assessment.Explain+")")
				return
			}

			next.ServeHTTP(w, r.WithContext(reqctx.WithRiskScore(r.Context(), assessment.Score)))
		})
	}
}

func hasAMR(amr []string, want string) bool {
	for _, v := range amr {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func ptr[T any](v T) *T { return &v }
