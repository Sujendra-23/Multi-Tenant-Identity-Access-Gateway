package handlers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/featureflags"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
)

type FlagManager interface {
	Read(context.Context) (featureflags.Document, error)
	Update(context.Context, string, []byte) (featureflags.Document, error)
}

type FeatureFlagsHandler struct {
	manager FlagManager
	log     *slog.Logger
}

func NewFeatureFlagsHandler(manager FlagManager, log *slog.Logger) *FeatureFlagsHandler {
	return &FeatureFlagsHandler{manager: manager, log: log}
}

func (h *FeatureFlagsHandler) Get(w http.ResponseWriter, r *http.Request) {
	doc, err := h.manager.Read(r.Context())
	if err != nil {
		h.failure(w, r, err)
		return
	}
	h.respond(w, doc)
}

// Put replaces the complete snapshot and requires a strong ETag from Get.
func (h *FeatureFlagsHandler) Put(w http.ResponseWriter, r *http.Request) {
	etag := r.Header.Get("If-Match")
	if etag == "" {
		writeError(w, r, http.StatusPreconditionRequired, "revision_required", "read the flags and supply their ETag in If-Match")
		return
	}
	revision := strings.Trim(etag, `"`)
	if etag != `"`+revision+`"` {
		writeError(w, r, http.StatusBadRequest, "invalid_revision", "If-Match must contain one quoted revision")
		return
	}
	if _, err := uuid.Parse(revision); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_revision", "If-Match must contain one quoted revision")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, featureflags.MaxConfigBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "flags exceed one MiB")
		} else {
			writeError(w, r, http.StatusBadRequest, "invalid_body", "could not read feature flags")
		}
		return
	}
	doc, err := h.manager.Update(r.Context(), revision, body)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	h.log.Info("operator updated feature flags", "revision", doc.Revision, "previous_revision", revision, "request_id", reqctx.RequestID(r.Context()))
	h.respond(w, doc)
}

func (h *FeatureFlagsHandler) respond(w http.ResponseWriter, doc featureflags.Document) {
	w.Header().Set("ETag", `"`+doc.Revision+`"`)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, doc)
}

func (h *FeatureFlagsHandler) failure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, featureflags.ErrConflict):
		writeError(w, r, http.StatusPreconditionFailed, "revision_conflict", "flags changed; read the latest revision before retrying")
	case errors.Is(err, featureflags.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "invalid_flags", err.Error())
	default:
		h.log.Error("shared feature flags unavailable", "error", err)
		writeError(w, r, http.StatusServiceUnavailable, "flags_unavailable", "shared feature flags are unavailable")
	}
}
