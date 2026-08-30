// Package handlers implements the gateway's HTTP endpoints. Handlers assume the
// middleware chain in package httpapi has already run: tenant resolution,
// authentication and authorization are not re-checked here, only used.
package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
	"github.com/sujendra/identity-gateway/internal/store/redisstore"
)

type HealthHandler struct {
	db      *postgres.DB
	cache   *redisstore.Client
	keyring *auth.Keyring
}

func NewHealthHandler(db *postgres.DB, cache *redisstore.Client, keyring *auth.Keyring) *HealthHandler {
	return &HealthHandler{db: db, cache: cache, keyring: keyring}
}

// Live answers whether the process itself is up, independent of its
// dependencies. Kubernetes uses this to decide whether to restart the pod, so
// it must not fail just because Postgres had a blip — that is what Ready is for.
func (h *HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "live"})
}

// Ready answers whether the gateway can actually serve traffic: both stores
// reachable and a signing key loaded. Kubernetes uses this to decide whether to
// send traffic to the pod, so a dependency outage here correctly pulls the pod
// out of rotation instead of returning errors to users.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := map[string]string{}
	ready := true

	if err := h.db.Ping(ctx); err != nil {
		checks["postgres"] = "unreachable: " + err.Error()
		ready = false
	} else {
		checks["postgres"] = "ok"
	}

	if err := h.cache.Ping(ctx); err != nil {
		checks["redis"] = "unreachable: " + err.Error()
		ready = false
	} else {
		checks["redis"] = "ok"
	}

	if _, err := h.keyring.Active(); err != nil {
		checks["signing_key"] = "not loaded: " + err.Error()
		ready = false
	} else {
		checks["signing_key"] = "ok"
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"status": readyLabel(ready), "checks": checks})
}

func readyLabel(ready bool) string {
	if ready {
		return "ready"
	}
	return "not_ready"
}
