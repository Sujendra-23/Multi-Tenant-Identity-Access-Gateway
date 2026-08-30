package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
)

// TenantResolver looks up the tenant named by a request header and attaches it
// to the context.
//
// Resolving the tenant is the first identity-bearing decision on the request
// path, and everything downstream — rate-limit buckets, permission lookups, the
// audit chain — is scoped to whatever this middleware puts on the context. A
// tenant named in a JWT is re-validated here too (see Authenticate), so a token
// for a tenant that has since been suspended is caught before it reaches a
// handler.
func TenantResolver(tenants *postgres.TenantRepo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slug := strings.TrimSpace(r.Header.Get("X-Tenant"))
			if slug == "" {
				writeErr(w, r, http.StatusBadRequest, "tenant_required", "the X-Tenant header is required")
				return
			}

			tenant, err := tenants.BySlug(r.Context(), strings.ToLower(slug))
			if errors.Is(err, domain.ErrNotFound) {
				writeErr(w, r, http.StatusNotFound, "tenant_not_found", "no organization matches the given tenant")
				return
			}
			if err != nil {
				writeErr(w, r, http.StatusInternalServerError, "internal_error", "could not resolve tenant")
				return
			}

			next.ServeHTTP(w, r.WithContext(reqctx.WithTenant(r.Context(), tenant)))
		})
	}
}

// writeErr is a minimal local responder so middleware does not depend on the
// parent httpapi package (which would reintroduce the cycle reqctx was built to
// avoid). Handlers use the richer writer in package httpapi; this one exists
// only for the handful of failures middleware itself can produce.
func writeErr(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	requestID := reqctx.RequestID(r.Context())
	body := `{"error":"` + code + `","message":"` + message + `","request_id":"` + requestID + `"}`
	_, _ = w.Write([]byte(body))
}
