package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

type apiError struct {
	Error     string `json:"error"`
	Message   string `json:"message,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, apiError{Error: code, Message: message, RequestID: reqctx.RequestID(r.Context())})
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// writeDomainError maps a domain sentinel to the HTTP status that does not leak
// more than the caller is entitled to know. A cross-tenant resource, for
// instance, collapses "forbidden" and "not found" into the same 404: telling
// the two apart would confirm the resource exists in someone else's tenant.
func writeDomainError(w http.ResponseWriter, r *http.Request, err error, log *slog.Logger) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "the requested resource does not exist")
	case errors.Is(err, domain.ErrConflict):
		writeError(w, r, http.StatusConflict, "conflict", "the resource already exists")
	case errors.Is(err, domain.ErrInvalidCredential):
		writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
	case errors.Is(err, domain.ErrAccountLocked):
		writeError(w, r, http.StatusLocked, "account_locked", "the account is temporarily locked due to repeated failed logins")
	case errors.Is(err, domain.ErrTenantSuspended):
		writeError(w, r, http.StatusForbidden, "tenant_suspended", "this organization's access has been suspended")
	case errors.Is(err, domain.ErrUserInactive):
		writeError(w, r, http.StatusForbidden, "user_inactive", "this account is not active")
	case errors.Is(err, domain.ErrForbidden):
		writeError(w, r, http.StatusForbidden, "forbidden", "you do not have permission to perform this action")
	case errors.Is(err, domain.ErrTokenRevoked):
		writeError(w, r, http.StatusUnauthorized, "token_revoked", "this token is no longer valid")
	case errors.Is(err, domain.ErrTokenReused):
		writeError(w, r, http.StatusUnauthorized, "session_revoked", "this session was terminated because a refresh token was reused; please log in again")
	case errors.Is(err, domain.ErrStepUpRequired):
		writeError(w, r, http.StatusForbidden, "step_up_required", "this action requires re-authentication")
	case errors.Is(err, domain.ErrRateLimited):
		writeError(w, r, http.StatusTooManyRequests, "rate_limited", "too many requests")
	default:
		log.Error("unhandled error", "error", err, "request_id", reqctx.RequestID(r.Context()))
		writeError(w, r, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
	}
}
