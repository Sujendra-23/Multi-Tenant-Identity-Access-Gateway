// Package httpapi assembles the middleware chain and route table. This file is
// the map of the whole request pipeline; the ordering comments here are load
// bearing — moving a middleware earlier or later changes what it can see and
// what it protects.
package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/sujendra/identity-gateway/internal/audit"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/authz"
	"github.com/sujendra/identity-gateway/internal/config"
	"github.com/sujendra/identity-gateway/internal/featureflags"
	"github.com/sujendra/identity-gateway/internal/httpapi/handlers"
	"github.com/sujendra/identity-gateway/internal/httpapi/middleware"
	"github.com/sujendra/identity-gateway/internal/observability"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
	"github.com/sujendra/identity-gateway/internal/store/redisstore"
)

// Deps bundles everything the router needs to build handlers and middleware.
type Deps struct {
	Flags            *featureflags.Flags
	DistributedFlags *featureflags.Distributed
	Config           *config.Config
	Log              *slog.Logger
	Metrics          *observability.Metrics
	DB               *postgres.DB
	Cache            *redisstore.Client
	Keyring          *auth.Keyring
	Issuer           *auth.TokenIssuer
	AuthSvc          *auth.Service
	Evaluator        *authz.Evaluator
	RiskEngine       *authz.RiskEngine
	Auditor          *audit.Logger

	Tenants  *postgres.TenantRepo
	Users    *postgres.UserRepo
	Roles    *postgres.RoleRepo
	Sessions *postgres.SessionRepo
	Audit    *postgres.AuditRepo

	TrustedProxies *middleware.TrustedProxies
	BootstrapKey   string
}

// NewRouter builds the full route table.
//
// Middleware ordering, outermost first, and why:
//
//  1. SecurityHeaders, RequestID, Observe, AccessLog — unconditional, cheap,
//     apply to every response including errors from everything below.
//  2. ClientContext — resolves the real client IP behind trusted proxies only;
//     every later check that keys on IP depends on this running first.
//  3. Per-IP rate limit — the cheapest possible abuse control, rejected before
//     any tenant lookup or database access happens.
//  4. TenantResolver — establishes which tenant's data this request may touch.
//     Nothing tenant-scoped can run before this.
//  5. Authenticate — verifies the token is cryptographically valid, matches
//     the resolved tenant, and is still live (not logged out, not denylisted).
//  6. RequirePolicyCurrent — rejects tokens minted under a since-superseded
//     policy version, independent of what the permission cache says.
//  7. Per-user and per-tenant rate limits — now that identity is known.
//  8. Per-route RequirePermission — the actual RBAC decision.
//  9. RiskAssessment — continuous evaluation on top of a request that has
//     already passed every static check; this is what can still say no to a
//     valid, authorized, rate-limit-compliant request that simply looks wrong.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(middleware.Observe(d.Metrics))
	r.Use(middleware.AccessLog(d.Log))
	r.Use(middleware.ClientContext(d.TrustedProxies))
	r.Use(chimw.Timeout(30 * time.Second))

	ipLimit := middleware.RateLimit(d.Cache, d.Metrics, "ip", d.Config.IPRateLimit, d.Config.IPRateBurst, middleware.ByIP)
	r.Use(ipLimit)

	health := handlers.NewHealthHandler(d.DB, d.Cache, d.Keyring)
	r.Get("/healthz", health.Live)
	r.Get("/readyz", health.Ready)
	// /metrics is deliberately not registered here. It is served on its own
	// listener (see NewMetricsServer / cfg.MetricsAddr) rather than sharing the
	// tenant-facing port: metrics are an operational surface meant for
	// in-cluster scraping only, and mixing it into the public API port would
	// mean either exposing it to every internet client this router's rate
	// limits and tenant auth are built for, or bolting authentication onto an
	// endpoint that exists for Prometheus, not tenants.

	jwks := handlers.NewJWKSHandler(d.Keyring)
	r.Get("/.well-known/jwks.json", jwks.Serve)

	tenantAdmin := handlers.NewTenantAdminHandler(d.Tenants, d.Roles, d.Users, d.Auditor, d.BootstrapKey, d.Log)
	r.Route("/v1/admin/tenants", func(r chi.Router) {
		r.Use(tenantAdmin.RequireBootstrapKey)
		r.Post("/", tenantAdmin.Create)
		r.Get("/", tenantAdmin.List)
	})

	if d.DistributedFlags != nil {
		flagAdmin := handlers.NewFeatureFlagsHandler(d.DistributedFlags, d.Log)
		r.Route("/v1/admin/feature-flags", func(r chi.Router) {
			r.Use(tenantAdmin.RequireBootstrapKey)
			r.Get("/", flagAdmin.Get)
			r.Put("/", flagAdmin.Put)
		})
	}

	authHandler := handlers.NewAuthHandler(d.AuthSvc, d.Issuer, d.Log)
	userHandler := handlers.NewUserHandler(d.Users, d.AuthSvc, d.Auditor, d.Log)
	roleHandler := handlers.NewRoleHandler(d.Roles, d.Auditor, d.Log)
	auditHandler := handlers.NewAuditHandler(d.Audit, d.Log)
	sessionHandler := handlers.NewSessionHandler(d.Sessions, d.AuthSvc, d.Auditor, d.Log)
	proxyHandler, err := handlers.NewProxyHandler(d.Config.Upstreams, d.Log, d.Flags)
	if err != nil {
		d.Log.Error("could not build upstream proxies", "error", err)
	}

	r.Route("/v1", func(r chi.Router) {
		r.Use(middleware.TenantResolver(d.Tenants))
		tenantLimit := middleware.RateLimit(d.Cache, d.Metrics, "tenant", d.Config.TenantRateLimit, d.Config.TenantRateBurst, middleware.ByTenant)
		r.Use(tenantLimit)

		// Pre-authentication routes: tenant is known, principal is not yet.
		r.Group(func(r chi.Router) {
			loginLimit := middleware.RateLimit(d.Cache, d.Metrics, "login", d.Config.LoginRateLimit, d.Config.LoginRateBurst, middleware.ByLoginIP)
			r.With(loginLimit).Post("/auth/login", authHandler.Login)
			r.Post("/auth/refresh", authHandler.Refresh)
		})

		// Authenticated routes: every one of these re-verifies the token's
		// liveness and policy currency before a handler ever runs.
		r.Group(func(r chi.Router) {
			r.Use(middleware.Authenticate(d.Issuer, d.Cache))
			r.Use(middleware.RequirePolicyCurrent)
			userLimit := middleware.RateLimit(d.Cache, d.Metrics, "user", d.Config.UserRateLimit, d.Config.UserRateBurst, middleware.ByUser)
			r.Use(userLimit)

			r.Post("/auth/logout", authHandler.Logout)
			r.Post("/auth/step-up", authHandler.StepUp)
			r.Get("/auth/me", authHandler.Me)

			r.Get("/sessions", sessionHandler.ListMine)

			perm := func(resource, action string) func(http.Handler) http.Handler {
				return middleware.RequirePermission(d.Evaluator, d.Metrics, resource, action)
			}
			risk := func(resource, action string) func(http.Handler) http.Handler {
				return middleware.RiskAssessment(d.RiskEngine, d.Auditor, d.Metrics, resource, action)
			}

			r.Route("/users", func(r chi.Router) {
				r.With(perm("users", "read"), risk("users", "read")).Get("/", userHandler.List)
				r.With(perm("users", "write"), risk("users", "write")).Post("/", userHandler.Create)
				r.With(perm("users", "read"), risk("users", "read")).Get("/{userID}", userHandler.Get)
				r.With(perm("users", "write"), risk("users", "write")).Patch("/{userID}/status", userHandler.SetStatus)
				r.With(perm("sessions", "read"), risk("sessions", "read")).Get("/{userID}/sessions", sessionHandler.ListForUser)
			})

			r.Route("/roles", func(r chi.Router) {
				r.With(perm("roles", "read"), risk("roles", "read")).Get("/", roleHandler.List)
				r.With(perm("roles", "read"), risk("roles", "read")).Get("/catalogue", roleHandler.Catalogue)
				r.With(perm("roles", "write"), risk("roles", "write")).Post("/", roleHandler.Create)
				r.With(perm("roles", "write"), risk("roles", "write")).Post("/{roleID}/permissions", roleHandler.Grant)
				r.With(perm("roles", "write"), risk("roles", "write")).Delete("/{roleID}/permissions", roleHandler.Revoke)
				r.With(perm("roles", "write"), risk("roles", "write")).Post("/assignments", roleHandler.Assign)
				r.With(perm("roles", "write"), risk("roles", "write")).Delete("/{roleID}/assignments/{userID}", roleHandler.Unassign)
			})

			r.Route("/sessions/{sessionID}", func(r chi.Router) {
				r.With(perm("sessions", "revoke"), risk("sessions", "revoke")).Delete("/", sessionHandler.Revoke)
			})

			r.Route("/audit", func(r chi.Router) {
				r.With(perm("audit", "read"), risk("audit", "read")).Get("/", auditHandler.List)
				r.With(perm("audit", "read"), risk("audit", "read")).Get("/verify", auditHandler.Verify)
			})

			if proxyHandler != nil {
				r.Route("/proxy/{service}", func(r chi.Router) {
					r.With(perm("upstream", "access"), risk("upstream", "access")).
						HandleFunc("/*", proxyHandler.Forward)
				})
			}
		})
	})

	return r
}
