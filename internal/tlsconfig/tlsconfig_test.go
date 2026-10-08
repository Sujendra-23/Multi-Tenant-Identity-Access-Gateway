package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sujendra/identity-gateway/internal/tlsconfig/tlstest"
)

// upstream starts an HTTPS server with the given server certificate that
// requires client certificates from clientCA.
func upstream(t *testing.T, cert tlstest.Pair, clientCA string) *httptest.Server {
	t.Helper()
	cfg, err := Server(ServerOptions{CertFile: cert.CertFile, KeyFile: cert.KeyFile, ClientCAFile: clientCA})
	if err != nil {
		t.Fatal(err)
	}
	return serveTLS(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
}

// serveTLS serves handler with exactly cfg. httptest's StartTLS would add its
// own certificate to cfg.Certificates, which Go prefers over GetCertificate
// whenever the client sends no SNI (as when dialing an IP address).
func serveTLS(t *testing.T, cfg *tls.Config, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = tls.NewListener(srv.Listener, cfg)
	srv.Start()
	srv.URL = strings.Replace(srv.URL, "http://", "https://", 1)
	t.Cleanup(srv.Close)
	return srv
}

func client(t *testing.T, opts ClientOptions) *http.Client {
	t.Helper()
	cfg, err := Client(opts)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

func TestMutualTLSAcceptsCertificatesFromTheExpectedCA(t *testing.T) {
	ca := tlstest.NewCA(t, "internal")
	srv := upstream(t, ca.Server(t, "upstream", "127.0.0.1"), ca.CertFile)
	gw := ca.Client(t, "gateway")

	resp, err := client(t, ClientOptions{CAFile: ca.CertFile, CertFile: gw.CertFile, KeyFile: gw.KeyFile}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "gateway" {
		t.Fatalf("upstream saw client %q, want gateway", body)
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated %x, want TLS 1.3", resp.TLS.Version)
	}
}

func TestClientRejectsServerCertificatesWithoutTheExpectedCA(t *testing.T) {
	ca := tlstest.NewCA(t, "internal")
	gw := ca.Client(t, "gateway")
	other := tlstest.NewCA(t, "other")
	for name, cert := range map[string]tlstest.Pair{
		"self-signed":    tlstest.SelfSigned(t, "impostor", "127.0.0.1"),
		"other CA":       other.Server(t, "impostor", "127.0.0.1"),
		"wrong hostname": ca.Server(t, "upstream-elsewhere", "upstream.internal"),
	} {
		t.Run(name, func(t *testing.T) {
			srv := upstream(t, cert, ca.CertFile)
			_, err := client(t, ClientOptions{CAFile: ca.CertFile, CertFile: gw.CertFile, KeyFile: gw.KeyFile}).Get(srv.URL)
			var unknown x509.UnknownAuthorityError
			var hostname x509.HostnameError
			if !errors.As(err, &unknown) && !errors.As(err, &hostname) {
				t.Fatalf("expected certificate verification failure, got %v", err)
			}
		})
	}
}

func TestClientDoesNotFallBackToSystemRoots(t *testing.T) {
	// httptest's built-in certificate is not issued by our CA. Even with the
	// system pool available, only CAFile may be trusted.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	ca := tlstest.NewCA(t, "internal")
	_, err := client(t, ClientOptions{CAFile: ca.CertFile}).Get(srv.URL)
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected unknown authority, got %v", err)
	}
}

func TestServerRejectsMissingOrUntrustedClientCertificates(t *testing.T) {
	ca := tlstest.NewCA(t, "internal")
	srv := upstream(t, ca.Server(t, "upstream", "127.0.0.1"), ca.CertFile)
	other := tlstest.NewCA(t, "other")
	for name, cert := range map[string]tlstest.Pair{
		"none":        {},
		"self-signed": tlstest.SelfSigned(t, "rogue-client"),
		"other CA":    other.Client(t, "rogue-client"),
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := client(t, ClientOptions{CAFile: ca.CertFile, CertFile: cert.CertFile, KeyFile: cert.KeyFile}).Get(srv.URL)
			if err == nil {
				resp.Body.Close()
				t.Fatalf("server accepted client certificate %q", name)
			}
			// TLS 1.3 reports the server's rejection as an alert on first read.
			if !strings.Contains(err.Error(), "certificate") {
				t.Fatalf("expected a certificate alert, got %v", err)
			}
		})
	}
}

func TestServerRefusesLegacyTLSAndPlaintext(t *testing.T) {
	ca := tlstest.NewCA(t, "internal")
	pair := ca.Server(t, "gateway", "127.0.0.1")
	cfg, err := Server(ServerOptions{CertFile: pair.CertFile, KeyFile: pair.KeyFile})
	if err != nil {
		t.Fatal(err)
	}
	var served int
	srv := serveTLS(t, cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served++ }))

	pool, _ := LoadCAPool(ca.CertFile)
	legacy := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11,
	}}}
	if _, err := legacy.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("TLS 1.1 handshake should fail on protocol version, got %v", err)
	}
	// A plaintext request is answered with net/http's canned 400 (or a
	// dropped connection) and never reaches the handler.
	plain := &http.Client{Timeout: 2 * time.Second}
	if resp, err := plain.Get(strings.Replace(srv.URL, "https://", "http://", 1)); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext request got status %d", resp.StatusCode)
		}
	}
	if served != 0 {
		t.Fatal("legacy or plaintext request reached the handler")
	}
	modern := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := modern.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if served != 1 {
		t.Fatalf("handler served %d requests, want 1", served)
	}
}

func TestReloaderPicksUpRotatedCertificate(t *testing.T) {
	old := reloadCheckInterval
	reloadCheckInterval = 0
	defer func() { reloadCheckInterval = old }()

	ca := tlstest.NewCA(t, "internal")
	first := ca.Server(t, "first", "127.0.0.1")
	r, err := NewReloader(first.CertFile, first.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leafName := func() string {
		cert, _ := r.GetCertificate(nil)
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf.Subject.CommonName
	}
	if leafName() != "first" {
		t.Fatal("initial certificate not served")
	}

	second := ca.Server(t, "second", "127.0.0.1")
	copyFile(t, second.CertFile, first.CertFile)
	copyFile(t, second.KeyFile, first.KeyFile)
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(first.CertFile, future, future)
	if leafName() != "second" {
		t.Fatal("rotated certificate not picked up")
	}

	// A broken rotation keeps serving the last good certificate.
	if err := os.WriteFile(first.KeyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	future = future.Add(time.Minute)
	_ = os.Chtimes(first.KeyFile, future, future)
	if leafName() != "second" {
		t.Fatal("invalid rotation replaced the working certificate")
	}
}

func TestOptionValidation(t *testing.T) {
	if _, err := Server(ServerOptions{CertFile: "x"}); err == nil {
		t.Fatal("server without key accepted")
	}
	if _, err := Client(ClientOptions{}); err == nil {
		t.Fatal("client without CA accepted")
	}
	ca := tlstest.NewCA(t, "internal")
	if _, err := Client(ClientOptions{CAFile: ca.CertFile, CertFile: "x"}); err == nil {
		t.Fatal("client certificate without key accepted")
	}
	empty := t.TempDir() + "/empty.pem"
	_ = os.WriteFile(empty, nil, 0o600)
	if _, err := LoadCAPool(empty); err == nil {
		t.Fatal("empty CA bundle accepted")
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
