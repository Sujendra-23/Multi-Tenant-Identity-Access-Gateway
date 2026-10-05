package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/featureflags"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
)

func TestProxyFeatureFlagReload(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/hello" {
			t.Errorf("unexpected upstream path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	flags := &featureflags.Flags{}
	h, err := NewProxyHandler(map[string]string{"demo": upstream.URL}, slog.Default(), flags)
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.HandleFunc("/v1/proxy/{service}/*", h.Forward)
	request := func(slug string, want int) {
		t.Helper()
		r := httptest.NewRequest("GET", "/v1/proxy/demo/hello", nil)
		ctx := reqctx.WithTenant(r.Context(), &domain.Tenant{Slug: slug})
		ctx = reqctx.WithClaims(ctx, &auth.Claims{})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r.WithContext(ctx))
		if w.Code != want {
			t.Fatalf("tenant %s: got %d, want %d: %s", slug, w.Code, want, w.Body.String())
		}
	}
	request("acme", 204)
	path := filepath.Join(t.TempDir(), "flags.json")
	if err := os.WriteFile(path, []byte(`{"proxy_enabled":false,"tenants":{"pilot":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := flags.Reload(path); err != nil {
		t.Fatal(err)
	}
	request("acme", 503)
	request("pilot", 204)
	if calls.Load() != 2 {
		t.Fatalf("disabled request reached upstream: %d calls", calls.Load())
	}
	if err := os.WriteFile(path, []byte(`{"proxy_enabled":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := flags.Reload(path); err != nil {
		t.Fatal(err)
	}
	request("acme", 204)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"proxy_enabled":true,"rollout_percent":0}`, 503},
		{`{"proxy_enabled":true,"rollout_percent":100}`, 204},
	} {
		before := calls.Load()
		if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := flags.Reload(path); err != nil {
			t.Fatal(err)
		}
		request("acme", tc.status)
		if tc.status == 503 && calls.Load() != before {
			t.Fatal("excluded tenant reached upstream")
		}
	}
}
