package handlers

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/featureflags"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
)

// An operator writes through replica A's HTTP API; replica B's proxy then
// enforces that configuration without a restart or a local file change.
func TestFeatureFlagsAdminPropagatesToProxy(t *testing.T) {
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("REDIS_TEST_ADDR not set; skipping Redis integration test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c1 := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("REDIS_TEST_PASSWORD")})
	c2 := redis.NewClient(c1.Options())
	defer c1.Close()
	defer c2.Close()
	key := "test:feature-flags:http:" + uuid.NewString()
	defer c1.Del(context.Background(), key)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f1, f2 := &featureflags.Flags{}, &featureflags.Flags{}
	d1 := featureflags.NewDistributed(c1, f1, key, time.Second, log)
	d2 := featureflags.NewDistributed(c2, f2, key, 20*time.Millisecond, log)
	for _, d := range []*featureflags.Distributed{d1, d2} {
		if err := d.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); d2.Run(ctx) }()
	defer func() { cancel(); <-done }()

	admin := NewFeatureFlagsHandler(d1, log)
	operator := NewTenantAdminHandler(nil, nil, nil, nil, "operator-secret", log)
	a := chi.NewRouter()
	a.Use(operator.RequireBootstrapKey)
	a.Get("/v1/admin/feature-flags", admin.Get)
	a.Put("/v1/admin/feature-flags", admin.Put)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer upstream.Close()
	proxy, err := NewProxyHandler(map[string]string{"demo": upstream.URL}, nil, log, f2)
	if err != nil {
		t.Fatal(err)
	}
	b := chi.NewRouter()
	b.HandleFunc("/v1/proxy/{service}/*", proxy.Forward)
	tenantID := uuid.New()
	proxyStatus := func() int {
		r := httptest.NewRequest("GET", "/v1/proxy/demo/hello", nil)
		c := reqctx.WithTenant(r.Context(), &domain.Tenant{ID: tenantID, Slug: "acme"})
		c = reqctx.WithClaims(c, &auth.Claims{})
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r.WithContext(c))
		return w.Code
	}
	if got := proxyStatus(); got != 204 {
		t.Fatalf("initial proxy status %d", got)
	}
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"proxy_enabled":true,"rollout_percent":0}`, 503},
		{`{"proxy_enabled":true,"rollout_percent":100}`, 204},
	} {
		get := httptest.NewRequest("GET", "/v1/admin/feature-flags", nil)
		get.Header.Set("X-Bootstrap-Key", "operator-secret")
		got := httptest.NewRecorder()
		a.ServeHTTP(got, get)
		if got.Code != 200 {
			t.Fatalf("GET: %s", got.Body.String())
		}
		put := httptest.NewRequest("PUT", "/v1/admin/feature-flags", strings.NewReader(tc.body))
		put.Header.Set("X-Bootstrap-Key", "operator-secret")
		put.Header.Set("If-Match", got.Header().Get("ETag"))
		wrote := httptest.NewRecorder()
		a.ServeHTTP(wrote, put)
		if wrote.Code != 200 {
			t.Fatalf("PUT: %s", wrote.Body.String())
		}
		deadline := time.Now().Add(3 * time.Second)
		for proxyStatus() != tc.status {
			if time.Now().After(deadline) {
				t.Fatalf("remote proxy never reached status %d", tc.status)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
