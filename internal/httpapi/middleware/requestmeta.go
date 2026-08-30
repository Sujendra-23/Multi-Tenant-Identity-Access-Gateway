// Package middleware implements the gateway's request pipeline: the ordered
// checks every request passes through before it reaches a handler. Order
// matters and is documented at the call site in router.go — cheap, unauthenticated
// checks (request ID, IP-based rate limiting) run before anything that costs a
// database or Redis round trip.
package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"

	"crypto/rand"
	"encoding/hex"
)

func newRequestID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// RequestID stamps every request with a correlation id, accepting an
// upstream-supplied one (from a load balancer or existing trace) if present.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(reqctx.WithRequestID(r.Context(), id)))
	})
}

// TrustedProxies lists the CIDR ranges allowed to set forwarding headers.
// Configure this to your load balancer's egress range; trusting
// X-Forwarded-For from the public internet lets any client spoof its own IP and
// walk straight around IP-based rate limiting and risk scoring.
type TrustedProxies struct {
	nets []*net.IPNet
}

func NewTrustedProxies(cidrs []string) (*TrustedProxies, error) {
	tp := &TrustedProxies{}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		tp.nets = append(tp.nets, n)
	}
	return tp, nil
}

func (tp *TrustedProxies) trusts(ip net.IP) bool {
	for _, n := range tp.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientContext resolves the real client IP and captures identifying headers
// used later for device fingerprinting and risk scoring.
//
// X-Forwarded-For is only honoured when the immediate peer is a trusted proxy;
// otherwise the socket's own address is used. This is what keeps the header
// from being a free way to forge the address every downstream check relies on.
func ClientContext(tp *TrustedProxies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := reqctx.WithClientIP(r.Context(), realIP(r, tp))
			ctx = reqctx.WithUserAgent(ctx, r.UserAgent())
			ctx = reqctx.WithDeviceHash(ctx, r.Header.Get("X-Device-Fingerprint"))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func realIP(r *http.Request, tp *TrustedProxies) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)

	if tp != nil && peer != nil && tp.trusts(peer) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// The left-most entry is the original client; everything else was
			// appended by proxies we do trust.
			parts := strings.Split(fwd, ",")
			if candidate := net.ParseIP(strings.TrimSpace(parts[0])); candidate != nil {
				return candidate.String()
			}
		}
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			if candidate := net.ParseIP(strings.TrimSpace(realIP)); candidate != nil {
				return candidate.String()
			}
		}
	}
	if peer != nil {
		return peer.String()
	}
	return host
}
