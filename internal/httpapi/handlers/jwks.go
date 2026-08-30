package handlers

import (
	"net/http"

	"github.com/sujendra/identity-gateway/internal/auth"
)

type JWKSHandler struct{ keyring *auth.Keyring }

func NewJWKSHandler(keyring *auth.Keyring) *JWKSHandler { return &JWKSHandler{keyring: keyring} }

// Serve publishes the public half of every currently-trusted signing key.
//
// This is what lets the upstream services behind the gateway (see cmd/upstream)
// verify a forwarded identity assertion themselves, independently, without
// calling back to the gateway on every request and without ever being handed a
// private key. Standard endpoint path so any off-the-shelf JWT/OIDC library can
// consume it unmodified.
func (h *JWKSHandler) Serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, h.keyring.JWKS())
}
