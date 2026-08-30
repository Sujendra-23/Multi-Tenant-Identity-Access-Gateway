package handlers

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/audit"
	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
)

type RoleHandler struct {
	roles   *postgres.RoleRepo
	auditor *audit.Logger
	log     *slog.Logger
}

func NewRoleHandler(roles *postgres.RoleRepo, auditor *audit.Logger, log *slog.Logger) *RoleHandler {
	return &RoleHandler{roles: roles, auditor: auditor, log: log}
}

func (h *RoleHandler) List(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	roles, err := h.roles.List(r.Context(), tenant.ID)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

// Catalogue returns the global resource:action vocabulary a tenant can grant
// from. It is the same list for every tenant, which is what keeps "who can
// read billing" a meaningful cross-tenant audit question.
func (h *RoleHandler) Catalogue(w http.ResponseWriter, r *http.Request) {
	perms, err := h.roles.ListPermissionCatalogue(r.Context())
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": perms})
}

type createRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *RoleHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	var req createRoleRequest
	if err := decodeJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_body", "name is required")
		return
	}
	role, err := h.roles.Create(r.Context(), tenant.ID, req.Name, req.Description, false)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	h.auditor.Record(audit.Event("role.create").
		Tenant(tenant.ID).Actor(actorPtr(r), reqctx.Claims(r.Context()).Email).
		Resource("roles:"+role.ID.String()).Allow().
		Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).
		Meta("role_name", role.Name).Build())
	writeJSON(w, http.StatusCreated, role)
}

type grantRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Effect   string `json:"effect"`
}

// Grant attaches a permission to a role, optionally as an explicit deny. Every
// grant or revoke bumps the tenant's policy version inside the same transaction
// (see postgres.RoleRepo), so the change is live for every affected user's very
// next request — there is no propagation delay to reason about.
func (h *RoleHandler) Grant(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "role id is not a valid uuid")
		return
	}
	var req grantRequest
	if err := decodeJSON(r, &req); err != nil || req.Resource == "" || req.Action == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_body", "resource and action are required")
		return
	}
	if req.Effect == "" {
		req.Effect = domain.EffectAllow
	}
	if req.Effect != domain.EffectAllow && req.Effect != domain.EffectDeny {
		writeError(w, r, http.StatusBadRequest, "invalid_effect", "effect must be 'allow' or 'deny'")
		return
	}

	if err := h.roles.GrantPermission(r.Context(), tenant.ID, roleID, req.Resource, req.Action, req.Effect); err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	h.auditor.Record(audit.Event("role.grant").
		Tenant(tenant.ID).Actor(actorPtr(r), reqctx.Claims(r.Context()).Email).
		Resource("roles:"+roleID.String()).Allow().
		Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).
		Meta("permission", req.Resource+":"+req.Action).Meta("effect", req.Effect).Build())
	writeJSON(w, http.StatusOK, map[string]string{"status": "granted"})
}

func (h *RoleHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "role id is not a valid uuid")
		return
	}
	resource, action := r.URL.Query().Get("resource"), r.URL.Query().Get("action")
	if resource == "" || action == "" {
		writeError(w, r, http.StatusBadRequest, "missing_fields", "resource and action query parameters are required")
		return
	}

	if err := h.roles.RevokePermission(r.Context(), tenant.ID, roleID, resource, action); err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	h.auditor.Record(audit.Event("role.revoke").
		Tenant(tenant.ID).Actor(actorPtr(r), reqctx.Claims(r.Context()).Email).
		Resource("roles:"+roleID.String()).Allow().
		Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).
		Meta("permission", resource+":"+action).Build())
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

type assignRequest struct {
	UserID uuid.UUID `json:"user_id"`
	RoleID uuid.UUID `json:"role_id"`
}

func (h *RoleHandler) Assign(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	var req assignRequest
	if err := decodeJSON(r, &req); err != nil || req.UserID == uuid.Nil || req.RoleID == uuid.Nil {
		writeError(w, r, http.StatusBadRequest, "invalid_body", "user_id and role_id are required")
		return
	}
	grantedBy := actorPtr(r)
	if err := h.roles.AssignRole(r.Context(), tenant.ID, req.UserID, req.RoleID, grantedBy); err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	h.auditor.Record(audit.Event("role.assign").
		Tenant(tenant.ID).Actor(grantedBy, reqctx.Claims(r.Context()).Email).
		Resource("users:"+req.UserID.String()).Allow().
		Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).
		Meta("role_id", req.RoleID.String()).Build())
	writeJSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

func (h *RoleHandler) Unassign(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	userID, err1 := uuid.Parse(chi.URLParam(r, "userID"))
	roleID, err2 := uuid.Parse(chi.URLParam(r, "roleID"))
	if err1 != nil || err2 != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "user id or role id is not a valid uuid")
		return
	}
	if err := h.roles.UnassignRole(r.Context(), tenant.ID, userID, roleID); err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	h.auditor.Record(audit.Event("role.unassign").
		Tenant(tenant.ID).Actor(actorPtr(r), reqctx.Claims(r.Context()).Email).
		Resource("users:"+userID.String()).Allow().
		Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).
		Meta("role_id", roleID.String()).Build())
	writeJSON(w, http.StatusOK, map[string]string{"status": "unassigned"})
}
