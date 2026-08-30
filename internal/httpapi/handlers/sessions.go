package handlers

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/audit"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
)

type SessionHandler struct {
	sessions *postgres.SessionRepo
	svc      *auth.Service
	auditor  *audit.Logger
	log      *slog.Logger
}

func NewSessionHandler(sessions *postgres.SessionRepo, svc *auth.Service, auditor *audit.Logger, log *slog.Logger) *SessionHandler {
	return &SessionHandler{sessions: sessions, svc: svc, auditor: auditor, log: log}
}

// ListMine returns every session for the caller's own account — the visibility
// a user needs to notice "I don't recognize this device" and revoke it
// themselves, without needing an administrator.
func (h *SessionHandler) ListMine(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	userID := reqctx.UserID(r.Context())
	views, err := h.sessions.ListForUser(r.Context(), tenant.ID, userID, false)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": views, "current_session_id": reqctx.Claims(r.Context()).SessionID})
}

// ListForUser is the administrative view: any user's sessions, gated by the
// sessions:read permission rather than "is this my own session".
func (h *SessionHandler) ListForUser(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "user id is not a valid uuid")
		return
	}
	views, err := h.sessions.ListForUser(r.Context(), tenant.ID, userID, true)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": views})
}

// Revoke terminates one session by id, gated by sessions:revoke. Going through
// auth.Service.RevokeSession (rather than the postgres repo directly) is what
// makes this take effect immediately: it evicts the live Redis record that
// Authenticate checks on every request, instead of merely marking the durable
// row revoked and waiting for the access token to expire on its own.
func (h *SessionHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "session id is not a valid uuid")
		return
	}
	if err := h.svc.RevokeSession(r.Context(), tenant.ID, sessionID, "revoked_by_admin"); err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	h.auditor.Record(audit.Event("session.revoke").
		Tenant(tenant.ID).Actor(actorPtr(r), reqctx.Claims(r.Context()).Email).
		Resource("sessions:"+sessionID.String()).Allow().
		Request(reqctx.RequestID(r.Context()), reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context())).Build())
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
