package handlers

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
	"github.com/sujendra/identity-gateway/internal/tlsconfig"
	"github.com/sujendra/identity-gateway/internal/tlsconfig/tlstest"
)

// mtlsUpstream serves cert and requires client certificates from clientCA.
func mtlsUpstream(t *testing.T, cert tlstest.Pair, clientCA string, calls *atomic.Int32) string {
	t.Helper()
	cfg, err := tlsconfig.Server(tlsconfig.ServerOptions{CertFile: cert.CertFile, KeyFile: cert.KeyFile, ClientCAFile: clientCA})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, "client="+r.TLS.PeerCertificates[0].Subject.CommonName+" tenant="+r.Header.Get("X-Gateway-Tenant-Slug"))
	}))
	srv.Listener = tls.NewListener(srv.Listener, cfg)
	srv.Start()
	t.Cleanup(srv.Close)
	return strings.Replace(srv.URL, "http://", "https://", 1)
}

func proxyThrough(t *testing.T, upstreamURL string, clientTLS *tls.Config) *httptest.ResponseRecorder {
	t.Helper()
	h, err := NewProxyHandler(map[string]string{"demo": upstreamURL}, clientTLS, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.HandleFunc("/v1/proxy/{service}/*", h.Forward)
	r := httptest.NewRequest("GET", "/v1/proxy/demo/hello", nil)
	ctx := reqctx.WithTenant(r.Context(), &domain.Tenant{Slug: "acme"})
	ctx = reqctx.WithClaims(ctx, &auth.Claims{})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r.WithContext(ctx))
	return w
}

func TestProxyUsesMutualTLSToUpstream(t *testing.T) {
	ca := tlstest.NewCA(t, "internal")
	var calls atomic.Int32
	url := mtlsUpstream(t, ca.Server(t, "upstream", "127.0.0.1"), ca.CertFile, &calls)
	gw := ca.Client(t, "identity-gateway")
	clientTLS, err := tlsconfig.Client(tlsconfig.ClientOptions{CAFile: ca.CertFile, CertFile: gw.CertFile, KeyFile: gw.KeyFile})
	if err != nil {
		t.Fatal(err)
	}

	w := proxyThrough(t, url, clientTLS)
	if w.Code != http.StatusOK || w.Body.String() != "client=identity-gateway tenant=acme" {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}

	// Without a client certificate the upstream refuses the handshake.
	noCert, err := tlsconfig.Client(tlsconfig.ClientOptions{CAFile: ca.CertFile})
	if err != nil {
		t.Fatal(err)
	}
	if w := proxyThrough(t, url, noCert); w.Code != http.StatusBadGateway {
		t.Fatalf("upstream accepted a gateway without a client cert: %d", w.Code)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream handler ran %d times, want 1", calls.Load())
	}
}

func TestProxyRejectsUpstreamWithoutExpectedCA(t *testing.T) {
	ca := tlstest.NewCA(t, "internal")
	gw := ca.Client(t, "identity-gateway")
	clientTLS, err := tlsconfig.Client(tlsconfig.ClientOptions{CAFile: ca.CertFile, CertFile: gw.CertFile, KeyFile: gw.KeyFile})
	if err != nil {
		t.Fatal(err)
	}
	other := tlstest.NewCA(t, "other")
	for name, cert := range map[string]tlstest.Pair{
		"self-signed": tlstest.SelfSigned(t, "impostor", "127.0.0.1"),
		"other CA":    other.Server(t, "impostor", "127.0.0.1"),
	} {
		t.Run(name, func(t *testing.T) {
			// The impostor would happily accept the gateway's certificate; the
			// gateway must still refuse to send it the request.
			var calls atomic.Int32
			url := mtlsUpstream(t, cert, ca.CertFile, &calls)
			w := proxyThrough(t, url, clientTLS)
			if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "upstream_unavailable") {
				t.Fatalf("got %d %q, want 502 upstream_unavailable", w.Code, w.Body.String())
			}
			if calls.Load() != 0 {
				t.Fatal("request reached an upstream outside the trusted CA")
			}
		})
	}
}
