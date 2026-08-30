package handlers

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
)

type AuditHandler struct {
	audit *postgres.AuditRepo
	log   *slog.Logger
}

func NewAuditHandler(audit *postgres.AuditRepo, log *slog.Logger) *AuditHandler {
	return &AuditHandler{audit: audit, log: log}
}

// List returns the tenant's audit trail, filterable by action, decision and
// actor. Every entry returned belongs to the caller's own tenant: the query is
// scoped by RLS at the database layer, not just by this handler's WHERE clause.
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	limit, offset := pagination(r)

	q := postgres.AuditQuery{
		Action:   r.URL.Query().Get("action"),
		Decision: r.URL.Query().Get("decision"),
		Limit:    limit, Offset: offset,
	}
	if actor := r.URL.Query().Get("actor_id"); actor != "" {
		if id, err := uuid.Parse(actor); err == nil {
			q.ActorID = &id
		}
	}

	events, err := h.audit.List(r.Context(), tenant.ID, q)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "limit": limit, "offset": offset})
}

// Verify replays the tenant's entire hash chain and reports whether it is
// intact. This is the audit log proving its own integrity on demand: a passing
// result means no record has been edited, removed, or inserted out of sequence
// since the genesis, not merely that the database file looks fine.
func (h *AuditHandler) Verify(w http.ResponseWriter, r *http.Request) {
	tenant := reqctx.Tenant(r.Context())
	result, err := h.audit.VerifyChain(r.Context(), tenant.ID)
	if err != nil {
		writeDomainError(w, r, err, h.log)
		return
	}
	status := http.StatusOK
	if !result.Valid {
		status = http.StatusConflict
	}
	writeJSON(w, status, result)
}
