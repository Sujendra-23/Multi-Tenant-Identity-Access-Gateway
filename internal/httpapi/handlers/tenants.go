package handlers

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"

	"github.com/sujendra/identity-gateway/internal/audit"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
)

// TenantAdminHandler manages tenants themselves: a system-level operation with
// no tenant context to scope it to. It is gated by a bootstrap key rather than
// the per-tenant RBAC everything else in this package uses, because "create a
// new organization" is definitionally a question no organization's own
// permissions can answer.
type TenantAdminHandler struct {
	tenants      *postgres.TenantRepo
	roles        *postgres.RoleRepo
	users        *postgres.UserRepo
	auditor      *audit.Logger
	bootstrapKey string
	log          *slog.Logger
}

func NewTenantAdminHandler(tenants *postgres.TenantRepo, roles *postgres.RoleRepo, users *postgres.UserRepo, auditor *audit.Logger, bootstrapKey string, log *slog.Logger) *TenantAdminHandler {
	return &TenantAdminHandler{tenants: tenants, roles: roles, users: users, auditor: auditor, bootstrapKey: bootstrapKey, log: log}
}

// RequireBootstrapKey guards the operator-admin routes with a static shared
// secret from configuration (X-Bootstrap-Key), checked in constant time.
// This key belongs to whoever operates the gateway, not to any tenant, and
// should be rotated the same way any other root credential would be.
func (h *TenantAdminHandler) RequireBootstrapKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.bootstrapKey == "" {
			writeError(w, r, http.StatusServiceUnavailable, "bootstrap_disabled", "operator administration is not configured on this deployment")
			return
		}
		given := r.Header.Get("X-Bootstrap-Key")
		if subtle.ConstantTimeCompare([]byte(given), []byte(h.bootstrapKey)) != 1 {
			writeError(w, r, http.StatusUnauthorized, "invalid_bootstrap_key", "missing or invalid X-Bootstrap-Key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type createTenantRequest struct {
	Slug  string `json:"slug"`
	Name  string `json:"name"`
	Plan  string `json:"plan"`
	Admin struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	} `json:"admin"`
}

// Create provisions a new tenant with its default system roles ("owner" with
// full access, "member" with read-only access) and its first user. A tenant
// with no way to log in and no way to grant further roles would be a dead end,
// so this single call produces something immediately usable rather than
// leaving several manual setup steps between here and a working login.
func (h *TenantAdminHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_body", "could not parse request body")
		return
	}
	if req.Slug == "" || req.Name == "" || req.Admin.Email == "" || len(req.Admin.Password) < 12 {
		writeError(w, r, http.StatusBadRequest, "invalid_fields",
			"slug, name, admin.email are required and admin.password must be at least 12 characters")
		return
	}
	if req.Plan == "" {
		req.Plan = "standard"
	}

	tenant, err := h.tenants.Create(r.Context(), strings.ToLower(strings.TrimSpace(req.Slug)), req.Name, req.Plan)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}

	owner, err := h.roles.Create(r.Context(), tenant.ID, "owner", "Full access to every resource in this organization", true)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	if err := h.roles.GrantPermission(r.Context(), tenant.ID, owner.ID, "*", "*", "allow"); err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	member, err := h.roles.Create(r.Context(), tenant.ID, "member", "Read-only access", true)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	for _, res := range []string{"users", "roles", "reports", "settings"} {
		if err := h.roles.GrantPermission(r.Context(), tenant.ID, member.ID, res, "read", "allow"); err != nil {
			writeDomainError(w, r, err, h.log)
			return
		}
	}

	hash, err := auth.HashPassword(req.Admin.Password)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	adminUser, err := h.users.Create(r.Context(), tenant.ID, req.Admin.Email, hash, "Owner")
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	if err := h.roles.AssignRole(r.Context(), tenant.ID, adminUser.ID, owner.ID, nil); err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}

	h.auditor.Record(audit.Event("tenant.create").
		Tenant(tenant.ID).Resource("tenants:"+tenant.ID.String()).Allow().
		Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).
		Meta("slug", tenant.Slug).Meta("admin_email", adminUser.Email).Build())

	writeJSON(w, http.StatusCreated, map[string]any{
		"tenant": tenant, "admin_user": toUserView(*adminUser),
	})
}

func (h *TenantAdminHandler) List(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.tenants.List(r.Context())
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
}
