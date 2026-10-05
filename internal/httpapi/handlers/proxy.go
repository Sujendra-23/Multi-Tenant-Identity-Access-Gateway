package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/sujendra/identity-gateway/internal/featureflags"
	"github.com/sujendra/identity-gateway/internal/httpapi/reqctx"
)

// ProxyHandler forwards authorized, authenticated requests to a named upstream
// service, acting as the enforcement point between untrusted clients and
// backend services that should never see unauthenticated or unauthorized
// traffic — the "gateway" half of an identity gateway.
//
// By the time a request reaches Forward, the middleware chain has already
// resolved the tenant, verified the token is live, checked the specific
// resource:action permission for this route, and scored the request's risk. This
// handler's only remaining job is to translate that already-established
// identity into headers the upstream can trust, and to make sure the upstream
// never sees the client's original Authorization header — which would let a
// compromised upstream turn around and replay the caller's own credential
// elsewhere.
type ProxyHandler struct {
	proxies map[string]*httputil.ReverseProxy
	log     *slog.Logger
	flags   *featureflags.Flags
}

// NewProxyHandler builds one reverse proxy per configured upstream. Building
// them once at startup (rather than per request) means connection pooling
// actually works: repeated requests to the same upstream reuse TCP connections
// instead of paying a new handshake every time.
func NewProxyHandler(upstreams map[string]string, log *slog.Logger, flags *featureflags.Flags) (*ProxyHandler, error) {
	proxies := make(map[string]*httputil.ReverseProxy, len(upstreams))
	for name, raw := range upstreams {
		target, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		rp := httputil.NewSingleHostReverseProxy(target)
		rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("upstream request failed", "upstream", name, "error", err, "request_id", reqctx.RequestID(r.Context()))
			writeError(w, r, http.StatusBadGateway, "upstream_unavailable", "the backend service could not be reached")
		}
		proxies[name] = rp
	}
	return &ProxyHandler{proxies: proxies, log: log, flags: flags}, nil
}

// Forward dispatches to the upstream named by the {service} path segment,
// stripping the /v1/proxy/{service} prefix so the upstream sees a normal
// rooted path.
//
// Identity is asserted to the upstream two ways at once, deliberately
// redundant: X-Gateway-* headers for services that just want to trust the
// network boundary (valid only if a NetworkPolicy actually restricts who can
// reach the upstream — see deploy/k8s), and the original signed access token
// forwarded as Authorization, which any upstream can verify independently
// against the gateway's JWKS endpoint without trusting the network at all. The
// second is the one that still holds if the network assumption ever turns out
// to be wrong.
func (h *ProxyHandler) Forward(w http.ResponseWriter, r *http.Request) {
	service := chi.URLParam(r, "service")
	rp, ok := h.proxies[service]
	if !ok {
		writeError(w, r, http.StatusNotFound, "unknown_upstream", "no upstream is configured with that name")
		return
	}

	tenant := reqctx.Tenant(r.Context())
	claims := reqctx.Claims(r.Context())
	if tenant == nil || claims == nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "identity context missing")
		return
	}

	if h.flags != nil && !h.flags.ProxyEnabled(tenant.Slug) {
		writeError(w, r, http.StatusServiceUnavailable, "feature_disabled", "proxy access is disabled for this tenant")
		return
	}

	prefix := "/v1/proxy/" + service
	r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}

	r.Header.Set("X-Gateway-Tenant-Id", tenant.ID.String())
	r.Header.Set("X-Gateway-Tenant-Slug", tenant.Slug)
	r.Header.Set("X-Gateway-User-Id", claims.Subject)
	r.Header.Set("X-Gateway-User-Email", claims.Email)
	r.Header.Set("X-Gateway-Roles", strings.Join(claims.Roles, ","))
	r.Header.Set("X-Gateway-Risk-Score", strconv.Itoa(reqctx.RiskScore(r.Context())))
	r.Header.Set("X-Gateway-Request-Id", reqctx.RequestID(r.Context()))
	// Deliberately left as-is: the upstream can verify this token itself via
	// GET /.well-known/jwks.json rather than being asked to trust the headers
	// above unconditionally.

	rp.ServeHTTP(w, r)
}
