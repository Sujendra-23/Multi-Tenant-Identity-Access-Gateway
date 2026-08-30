package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
)

type AuthHandler struct {
	svc    *auth.Service
	issuer *auth.TokenIssuer
	log    *slog.Logger
}

func NewAuthHandler(svc *auth.Service, issuer *auth.TokenIssuer, log *slog.Logger) *AuthHandler {
	return &AuthHandler{svc: svc, issuer: issuer, log: log}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	auth.TokenPair
	User userView `json:"user"`
}

type userView struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	MFAEnrolled bool      `json:"mfa_enrolled"`
}

// Login exchanges an email/password credential for a token pair.
//
// This is a public, pre-authentication endpoint: it runs behind tenant
// resolution and rate limiting only, never behind Authenticate. Everything
// about timing and error shape is chosen in auth.Service to avoid handing back
// an oracle for which emails exist.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_body", "could not parse request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, r, http.StatusBadRequest, "missing_fields", "email and password are required")
		return
	}

	tenant := reqctx.Tenant(r.Context())
	pair, user, err := h.svc.Login(r.Context(), auth.LoginRequest{
		Tenant: tenant, Email: req.Email, Password: req.Password,
		IP: reqctx.ClientIP(r.Context()), UserAgent: reqctx.UserAgent(r.Context()),
		DeviceHash: reqctx.DeviceHash(r.Context()), RequestID: reqctx.RequestID(r.Context()),
	})
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		TokenPair: *pair,
		User:      userView{ID: user.ID, Email: user.Email, DisplayName: user.DisplayName, MFAEnrolled: user.MFAEnrolled},
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh rotates a refresh token. See auth.Service.Refresh for the reuse
// detection this wraps — a replayed token here does not just fail, it revokes
// the entire session family and reports StatusUnauthorized with a distinct code
// so the client knows to send the user back through a full login rather than
// silently retrying.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil || req.RefreshToken == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_body", "refresh_token is required")
		return
	}

	pair, err := h.svc.Refresh(r.Context(), auth.RefreshRequest{
		RefreshToken: req.RefreshToken,
		IP:           reqctx.ClientIP(r.Context()), UserAgent: reqctx.UserAgent(r.Context()),
		DeviceHash: reqctx.DeviceHash(r.Context()), RequestID: reqctx.RequestID(r.Context()),
	})
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

// Logout revokes the session behind the presented access token immediately.
// Runs behind Authenticate, so claims are already verified and live.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	claims := reqctx.Claims(r.Context())
	if tenant == nil || claims == nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "authentication context missing")
		return
	}

	err := h.svc.Logout(r.Context(), tenant.ID, claims.SessionID, reqctx.UserID(r.Context()),
		claims.ID, claims.ExpiresAt.Time, reqctx.RequestID(r.Context()),
		reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context()))
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// Me returns the authenticated principal's identity and current effective
// roles, letting a client confirm what a token is actually good for right now
// rather than trusting whatever it locally remembers from login time.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := reqctx.Claims(r.Context())
	if claims == nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "authentication context missing")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":        claims.Subject,
		"email":          claims.Email,
		"tenant":         claims.TenantSlug,
		"roles":          claims.Roles,
		"amr":            claims.AMR,
		"session_id":     claims.SessionID,
		"policy_version": claims.PolicyVersion,
		"risk_score":     reqctx.RiskScore(r.Context()),
	})
}

// StepUpRequest simulates re-authentication for a session that already holds a
// valid, live token. A real deployment would verify a TOTP code or WebAuthn
// assertion here; this demo re-checks the password, which is enough to
// demonstrate the mechanism the risk engine keys on: the AMR list gaining
// "mfa" is what lets a subsequent sensitive request clear OutcomeStepUp.
type stepUpRequest struct {
	Password string `json:"password"`
}

func (h *AuthHandler) StepUp(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	claims := reqctx.Claims(r.Context())
	if tenant == nil || claims == nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "authentication context missing")
		return
	}
	var req stepUpRequest
	if err := decodeJSON(r, &req); err != nil || req.Password == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_body", "password is required")
		return
	}

	pair, err := h.svc.StepUp(r.Context(), tenant, claims, req.Password,
		reqctx.ClientIP(r.Context()), reqctx.UserAgent(r.Context()), reqctx.RequestID(r.Context()))
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredential) {
			writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "re-authentication failed")
			return
		}
		writeDomainError(w, r, err, h.log)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}
