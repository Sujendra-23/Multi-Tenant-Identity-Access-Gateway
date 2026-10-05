package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/featureflags"
)

type testFlagManager struct {
	doc    featureflags.Document
	err    error
	writes int
}

func (m *testFlagManager) Read(context.Context) (featureflags.Document, error) { return m.doc, m.err }
func (m *testFlagManager) Update(_ context.Context, expected string, body []byte) (featureflags.Document, error) {
	m.writes++
	if m.err != nil {
		return featureflags.Document{}, m.err
	}
	if expected != m.doc.Revision {
		return featureflags.Document{}, featureflags.ErrConflict
	}
	m.doc = featureflags.Document{Revision: uuid.NewString(), Flags: append([]byte(nil), body...)}
	return m.doc, nil
}

func TestFeatureFlagsAdminAPI(t *testing.T) {
	m := &testFlagManager{doc: featureflags.Document{Revision: uuid.NewString(), Flags: json.RawMessage(`{"proxy_enabled":true}`)}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewFeatureFlagsHandler(m, log)
	auth := NewTenantAdminHandler(nil, nil, nil, nil, "operator-secret", log)
	r := chi.NewRouter()
	r.Use(auth.RequireBootstrapKey)
	r.Get("/", h.Get)
	r.Put("/", h.Put)
	request := func(method, key, etag, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/", strings.NewReader(body))
		req.Header.Set("X-Bootstrap-Key", key)
		req.Header.Set("If-Match", etag)
		req.Header.Set("Authorization", "Bearer tenant-token")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("got %d want %d: %s", w.Code, want, w.Body.String())
		}
		return w
	}
	etag := `"` + m.doc.Revision + `"`
	for _, key := range []string{"", "wrong"} {
		request("GET", key, "", "", 401)
		request("PUT", key, etag, `{"proxy_enabled":false}`, 401)
	}
	if m.writes != 0 {
		t.Fatal("unauthorized request reached writer")
	}
	got := request("GET", "operator-secret", "", "", 200)
	if got.Header().Get("ETag") != etag || got.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing cache/revision headers")
	}
	request("PUT", "operator-secret", "", `{}`, 428)
	for _, invalid := range []string{"*", "W/" + etag, etag + ", " + etag, m.doc.Revision} {
		request("PUT", "operator-secret", invalid, `{}`, 400)
	}
	request("PUT", "operator-secret", etag, strings.Repeat(" ", featureflags.MaxConfigBytes+1), 413)
	if m.writes != 0 {
		t.Fatal("invalid precondition/body reached writer")
	}
	response := request("PUT", "operator-secret", etag, `{"proxy_enabled":false}`, 200)
	if response.Header().Get("ETag") == etag {
		t.Fatal("successful write did not change revision")
	}
	request("PUT", "operator-secret", etag, `{"proxy_enabled":true}`, 412)
	m.err = featureflags.ErrInvalid
	request("PUT", "operator-secret", response.Header().Get("ETag"), `{}`, 400)
	m.err = errors.New("redis unavailable")
	request("GET", "operator-secret", "", "", 503)
	request("PUT", "operator-secret", response.Header().Get("ETag"), `{}`, 503)
	auth.bootstrapKey = ""
	request("GET", "", "", "", 503)
}
