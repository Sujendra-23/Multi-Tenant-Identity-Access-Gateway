package handlers

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/audit"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
)

type UserHandler struct {
	users    *postgres.UserRepo
	sessions *auth.Service
	auditor  *audit.Logger
	log      *slog.Logger
}

func NewUserHandler(users *postgres.UserRepo, sessions *auth.Service, auditor *audit.Logger, log *slog.Logger) *UserHandler {
	return &UserHandler{users: users, sessions: sessions, auditor: auditor, log: log}
}

func toUserView(u domain.User) userView {
	return userView{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, MFAEnrolled: u.MFAEnrolled}
}

// List returns users in the caller's tenant only — the tenant id comes from
// reqctx, resolved by middleware, never from a query parameter. There is no
// path in this handler that lets a caller ask for another tenant's users.
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	limit, offset := pagination(r)

	users, err := h.users.List(r.Context(), tenant.ID, limit, offset)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	out := make([]userView, 0, len(users))
	for _, u := range users {
		out = append(out, toUserView(u))
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "limit": limit, "offset": offset})
}

type createUserRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_body", "could not parse request body")
		return
	}
	if req.Email == "" || len(req.Password) < 12 {
		writeError(w, r, http.StatusBadRequest, "invalid_fields", "email is required and password must be at least 12 characters")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	user, err := h.users.Create(r.Context(), tenant.ID, req.Email, hash, req.DisplayName)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}

	h.auditor.Record(audit.Event("user.create").
		Tenant(tenant.ID).Actor(actorPtr(r), reqctx.Claims(r.Context()).Email).
		Resource("users:"+user.ID.String()).Allow().
		Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).
		Meta("created_email", user.Email).Build())

	writeJSON(w, http.StatusCreated, toUserView(*user))
}

func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "user id is not a valid uuid")
		return
	}
	user, err := h.users.ByID(r.Context(), tenant.ID, id)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	writeJSON(w, http.StatusOK, toUserView(*user))
}

type setStatusRequest struct {
	Status string `json:"status"`
}

// SetStatus disables or re-enables a user. Disabling revokes every live
// session for that user in the same call: leaving existing tokens valid after
// disabling the account would make "disabled" purely cosmetic until each token
// happened to expire on its own.
func (h *UserHandler) SetStatus(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "user id is not a valid uuid")
		return
	}
	var req setStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_body", "could not parse request body")
		return
	}
	status := domain.UserStatus(req.Status)
	if status != domain.UserActive && status != domain.UserDisabled {
		writeError(w, r, http.StatusBadRequest, "invalid_status", "status must be 'active' or 'disabled'")
		return
	}

	if err := h.users.SetStatus(r.Context(), tenant.ID, id, status); err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	if status == domain.UserDisabled {
		if _, err := h.sessions.RevokeAllSessions(r.Context(), tenant.ID, id, "account_disabled"); err != nil {
			h.log.Error("could not revoke sessions after disabling user", "user_id", id, "error", err)
		}
	}

	h.auditor.Record(audit.Event("user.set_status").
		Tenant(tenant.ID).Actor(actorPtr(r), reqctx.Claims(r.Context()).Email).
		Resource("users:"+id.String()).Allow().
		Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).
		Meta("new_status", string(status)).Build())

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func pagination(r *http.Request) (limit, offset int) {
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// actorPtr returns the authenticated user's id for audit attribution. Every
// handler behind Authenticate has claims on the context, so this is safe to
// call unconditionally from admin routes.
func actorPtr(r *http.Request) *uuid.UUID {
	id := reqctx.UserID(r.Context())
	if id == uuid.Nil {
		return nil
	}
	return &id
}
