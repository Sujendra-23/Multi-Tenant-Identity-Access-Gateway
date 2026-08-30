package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/observability"
)

// AccessLog writes one structured line per request. It runs after Observe in
// the chain so the status recorder is already in place; here it just reads back
// what was recorded plus the identifiers useful for tracing a request across
// the audit log and the metrics.
func AccessLog(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()

			reqLogger := base.With("request_id", reqctx.RequestID(r.Context()))
			ctx := observability.WithLogger(r.Context(), reqLogger)
			next.ServeHTTP(rec, r.WithContext(ctx))

			tenantSlug := ""
			if t := reqctx.Tenant(r.Context()); t != nil {
				tenantSlug = t.Slug
			}
			reqLogger.Info("http_request",
				"method", r.Method, "path", r.URL.Path, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"tenant", tenantSlug, "ip", reqctx.ClientIP(r.Context()),
			)
		})
	}
}
