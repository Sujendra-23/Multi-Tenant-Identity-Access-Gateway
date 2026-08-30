package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/observability"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Observe records latency and status for every request, labelled by route
// pattern rather than the raw path so that e.g. /users/{id} for a thousand
// different ids collapses to one time series instead of a thousand.
func Observe(m *observability.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.HTTPInFlight.Inc()
			defer m.HTTPInFlight.Dec()

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()
			next.ServeHTTP(rec, r)
			elapsed := time.Since(start)

			route := chi.RouteContext(r.Context()).RoutePattern()
			if route == "" {
				route = "unmatched"
			}
			tenantLabel := "none"
			if t := reqctx.Tenant(r.Context()); t != nil {
				tenantLabel = m.Tenant(t.Slug)
			}

			m.HTTPDuration.WithLabelValues(r.Method, route).Observe(elapsed.Seconds())
			m.HTTPRequests.WithLabelValues(r.Method, route, strconv.Itoa(rec.status), tenantLabel).Inc()
		})
	}
}
