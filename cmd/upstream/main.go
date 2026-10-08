// Command upstream is a minimal demo backend service, standing in for whatever
// a real organization would put behind the gateway. It exists to demonstrate
// the two independent trust mechanisms the gateway offers a downstream
// service, so a reviewer can see both actually work rather than taking the
// gateway's word for it:
//
//  1. Network-boundary trust: X-Gateway-* headers the gateway attaches after
//     its own verification. Valid only insofar as a NetworkPolicy actually
//     stops anything but the gateway from reaching this service directly (see
//     deploy/k8s/networkpolicy.yaml) — shown here, but flagged as the weaker of
//     the two.
//  2. Cryptographic trust: this service fetches the gateway's public JWKS and
//     verifies the forwarded access token itself. It does not need to trust the
//     network at all for this half — a forged X-Gateway-User-Id header without
//     a token that actually verifies is caught here.
//
// With TLS_CERT_FILE, TLS_KEY_FILE and TLS_CLIENT_CA_FILE set, the service
// also serves HTTPS and requires a client certificate from that CA (mutual
// TLS), so the gateway proves which service is calling at the transport layer
// as well. GATEWAY_CA_FILE pins the CA used to fetch the JWKS over https.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sujendra/identity-gateway/internal/tlsconfig"
)

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Alg string `json:"alg"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// keySet fetches and caches the gateway's public keys, refreshing periodically
// so a rotation on the gateway is picked up without restarting this service.
type keySet struct {
	mu      sync.RWMutex
	keys    map[string]ed25519.PublicKey
	jwksURL string
	client  *http.Client
	log     *slog.Logger
}

func newKeySet(jwksURL string, client *http.Client, log *slog.Logger) *keySet {
	return &keySet{keys: map[string]ed25519.PublicKey{}, jwksURL: jwksURL, client: client, log: log}
}

func (k *keySet) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	var doc jwks
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	next := make(map[string]ed25519.PublicKey, len(doc.Keys))
	for _, key := range doc.Keys {
		if key.Kty != "OKP" || key.Crv != "Ed25519" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			continue
		}
		next[key.Kid] = ed25519.PublicKey(raw)
	}

	k.mu.Lock()
	k.keys = next
	k.mu.Unlock()
	return nil
}

func (k *keySet) run(ctx context.Context) {
	if err := k.refresh(ctx); err != nil {
		k.log.Warn("initial jwks fetch failed; will retry", "error", err)
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := k.refresh(ctx); err != nil {
				k.log.Warn("jwks refresh failed", "error", err)
			}
		}
	}
}

func (k *keySet) lookup(kid string) (ed25519.PublicKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	pub, ok := k.keys[kid]
	return pub, ok
}

// verify independently re-checks the forwarded Authorization token against the
// gateway's published keys. It intentionally does not consult the gateway
// again: that would make this service unavailable whenever the gateway is
// busy, defeating the point of verifying locally.
func (k *keySet) verify(raw string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		pub, ok := k.lookup(kid)
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"EdDSA"}))
	return claims, err
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	addr := getenv("ADDR", ":8090")
	jwksURL := getenv("GATEWAY_JWKS_URL", "http://gateway:8080/.well-known/jwks.json")

	jwksClient := &http.Client{Timeout: 10 * time.Second}
	if caFile := os.Getenv("GATEWAY_CA_FILE"); caFile != "" {
		pool, err := tlsconfig.LoadCAPool(caFile)
		if err != nil {
			log.Error("load gateway CA", "error", err)
			os.Exit(1)
		}
		jwksClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	}
	ks := newKeySet(jwksURL, jwksClient, log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ks.run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"upstream": "demo-service",
			"path":     r.URL.Path,
			"method":   r.Method,
			"received_headers": map[string]string{
				"X-Gateway-Tenant-Id":   r.Header.Get("X-Gateway-Tenant-Id"),
				"X-Gateway-Tenant-Slug": r.Header.Get("X-Gateway-Tenant-Slug"),
				"X-Gateway-User-Id":     r.Header.Get("X-Gateway-User-Id"),
				"X-Gateway-User-Email":  r.Header.Get("X-Gateway-User-Email"),
				"X-Gateway-Roles":       r.Header.Get("X-Gateway-Roles"),
				"X-Gateway-Risk-Score":  r.Header.Get("X-Gateway-Risk-Score"),
				"X-Gateway-Request-Id":  r.Header.Get("X-Gateway-Request-Id"),
			},
		}

		// Under mTLS the verified client certificate names the calling service.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			resp["mtls_client"] = r.TLS.PeerCertificates[0].Subject.CommonName
		}

		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if strings.HasPrefix(auth, prefix) {
			claims, err := ks.verify(strings.TrimPrefix(auth, prefix))
			if err != nil {
				resp["token_independently_verified"] = false
				resp["verification_error"] = err.Error()
			} else {
				resp["token_independently_verified"] = true
				resp["token_claims"] = claims
			}
		} else {
			resp["token_independently_verified"] = false
			resp["verification_error"] = "no bearer token forwarded"
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	var err error
	if certFile := os.Getenv("TLS_CERT_FILE"); certFile != "" {
		srv.TLSConfig, err = tlsconfig.Server(tlsconfig.ServerOptions{
			CertFile: certFile, KeyFile: os.Getenv("TLS_KEY_FILE"),
			ClientCAFile: os.Getenv("TLS_CLIENT_CA_FILE"), MinVersion: tls.VersionTLS13,
		})
		if err != nil {
			log.Error("tls config", "error", err)
			os.Exit(1)
		}
		log.Info("demo upstream listening", "addr", addr, "jwks_url", jwksURL, "tls", true,
			"client_certs_required", srv.TLSConfig.ClientCAs != nil)
		err = srv.ListenAndServeTLS("", "")
	} else {
		log.Info("demo upstream listening", "addr", addr, "jwks_url", jwksURL)
		err = srv.ListenAndServe()
	}
	if err != nil {
		log.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
