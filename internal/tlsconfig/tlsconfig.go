// Package tlsconfig builds the gateway's TLS configurations: HTTPS for the
// public API, and mutual TLS for gateway-to-upstream calls.
//
// Trust is pinned to an explicit CA bundle everywhere a peer is verified. The
// system root store is never consulted for upstream or client certificates, so
// a certificate a public CA issued (or one an attacker self-signed) is not
// enough to impersonate an internal service. Certificates are re-read when
// their files change, so rotated certificates (for example a renewed
// Kubernetes Secret) take effect on the next handshake without a restart.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// ServerOptions configures a TLS listener.
type ServerOptions struct {
	CertFile string
	KeyFile  string
	// ClientCAFile, when set, requires every client to present a certificate
	// chaining to one of these CAs (mutual TLS).
	ClientCAFile string
	// MinVersion defaults to TLS 1.2.
	MinVersion uint16
}

// ClientOptions configures an outbound mutual-TLS connection.
type ClientOptions struct {
	// CAFile is the only trust anchor for the server's certificate.
	CAFile string
	// CertFile and KeyFile are the client certificate presented to the server.
	CertFile string
	KeyFile  string
	// ServerName overrides the name verified against the server certificate;
	// by default it is the host being dialed.
	ServerName string
	// MinVersion defaults to TLS 1.3: both ends of internal calls are ours.
	MinVersion uint16
}

// Server returns a TLS configuration that serves CertFile/KeyFile and, when
// ClientCAFile is set, requires and verifies client certificates.
func Server(opts ServerOptions) (*tls.Config, error) {
	if opts.CertFile == "" || opts.KeyFile == "" {
		return nil, errors.New("tls: certificate and key files are both required")
	}
	cert, err := NewReloader(opts.CertFile, opts.KeyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:     minVersion(opts.MinVersion, tls.VersionTLS12),
		GetCertificate: cert.GetCertificate,
		// TLS 1.2 suites are limited to AEAD ciphers with forward secrecy;
		// TLS 1.3 suites are not configurable and are all acceptable.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	if opts.ClientCAFile != "" {
		pool, err := LoadCAPool(opts.ClientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// Client returns a mutual-TLS client configuration that trusts only CAFile and
// presents CertFile/KeyFile.
func Client(opts ClientOptions) (*tls.Config, error) {
	if opts.CAFile == "" {
		return nil, errors.New("tls: a CA file is required to verify the server")
	}
	if (opts.CertFile == "") != (opts.KeyFile == "") {
		return nil, errors.New("tls: client certificate and key must be set together")
	}
	pool, err := LoadCAPool(opts.CAFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: minVersion(opts.MinVersion, tls.VersionTLS13),
		RootCAs:    pool,
		ServerName: opts.ServerName,
	}
	if opts.CertFile != "" {
		cert, err := NewReloader(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, err
		}
		cfg.GetClientCertificate = cert.GetClientCertificate
	}
	return cfg, nil
}

// LoadCAPool reads a PEM bundle into a new pool (never the system roots).
func LoadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tls: read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls: no certificates found in %s", path)
	}
	return pool, nil
}

func minVersion(v, def uint16) uint16 {
	if v == 0 {
		return def
	}
	return v
}

// Reloader serves a certificate key pair and reloads it when either file's
// modification time changes. A failed reload keeps the last good pair.
type Reloader struct {
	certFile, keyFile string

	mu        sync.Mutex
	cert      *tls.Certificate
	certMod   time.Time
	keyMod    time.Time
	lastCheck time.Time
}

// reloadCheckInterval bounds how often handshakes stat the files.
var reloadCheckInterval = time.Second

// NewReloader loads the pair once, failing if it is invalid.
func NewReloader(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Reloader) load() error {
	certInfo, err := os.Stat(r.certFile)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	keyInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("tls: load key pair: %w", err)
	}
	r.cert, r.certMod, r.keyMod = &cert, certInfo.ModTime(), keyInfo.ModTime()
	return nil
}

func (r *Reloader) current() *tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := time.Now(); now.Sub(r.lastCheck) >= reloadCheckInterval {
		r.lastCheck = now
		certInfo, certErr := os.Stat(r.certFile)
		keyInfo, keyErr := os.Stat(r.keyFile)
		if certErr == nil && keyErr == nil &&
			(!certInfo.ModTime().Equal(r.certMod) || !keyInfo.ModTime().Equal(r.keyMod)) {
			_ = r.load() // keep serving the previous pair if the new one is invalid
		}
	}
	return r.cert
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.current(), nil
}

// GetClientCertificate implements tls.Config.GetClientCertificate.
func (r *Reloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.current(), nil
}
