// Package tlstest issues throwaway CAs and certificates for TLS tests.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is a certificate authority whose PEM certificate is written to CertFile.
type CA struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	CertFile string
	dir      string
}

// Pair holds the file paths of an issued certificate and its key.
type Pair struct{ CertFile, KeyFile string }

var serial int64

func nextSerial() *big.Int { serial++; return big.NewInt(time.Now().UnixNano() + serial) }

// NewCA creates a self-signed CA in a test temp directory.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca := &CA{cert: cert, key: key, dir: dir, CertFile: filepath.Join(dir, name+"-ca.pem")}
	writePEM(t, ca.CertFile, "CERTIFICATE", der)
	return ca
}

// Server issues a server certificate valid for the given DNS names and IPs.
func (ca *CA) Server(t testing.TB, name string, hosts ...string) Pair {
	return ca.issue(t, name, x509.ExtKeyUsageServerAuth, hosts)
}

// Client issues a client certificate with the given common name.
func (ca *CA) Client(t testing.TB, name string) Pair {
	return ca.issue(t, name, x509.ExtKeyUsageClientAuth, nil)
}

func (ca *CA) issue(t testing.TB, name string, usage x509.ExtKeyUsage, hosts []string) Pair {
	t.Helper()
	return issue(t, ca.dir, ca.cert, ca.key, name, usage, hosts)
}

// issue signs a leaf with parent/parentKey, or self-signs it when parent is nil.
func issue(t testing.TB, dir string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, name string, usage x509.ExtKeyUsage, hosts []string) Pair {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p := Pair{
		CertFile: filepath.Join(dir, name+".pem"),
		KeyFile:  filepath.Join(dir, name+"-key.pem"),
	}
	writePEM(t, p.CertFile, "CERTIFICATE", der)
	writePEM(t, p.KeyFile, "EC PRIVATE KEY", keyDER)
	return p
}

// SelfSigned issues a leaf certificate signed by its own key, valid for hosts
// and usable as either a server or a client certificate.
func SelfSigned(t testing.TB, name string, hosts ...string) Pair {
	t.Helper()
	return issue(t, t.TempDir(), nil, nil, name, x509.ExtKeyUsageAny, hosts)
}

func writePEM(t testing.TB, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
