// Command gateway runs the Multi-Tenant Identity & Access Gateway: the HTTP
// server that terminates every request, re-verifies identity and permissions
// against current state, and either serves it directly or forwards it to a
// configured upstream.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sujendra/identity-gateway/internal/audit"
	"github.com/sujendra/identity-gateway/internal/auth"
	"github.com/sujendra/identity-gateway/internal/authz"
	"github.com/sujendra/identity-gateway/internal/config"
	"github.com/sujendra/identity-gateway/internal/featureflags"
	"github.com/sujendra/identity-gateway/internal/httpapi"
	"github.com/sujendra/identity-gateway/internal/httpapi/middleware"
	"github.com/sujendra/identity-gateway/internal/observability"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
	"github.com/sujendra/identity-gateway/internal/store/redisstore"
	"github.com/sujendra/identity-gateway/internal/tlsconfig"
)

func main() {
	// The distroless base image this binary ships in has no shell, no curl, no
	// wget — nothing a Docker HEALTHCHECK's usual CMD-SHELL trick could run. So
	// the binary checks itself: -healthcheck makes it issue one HTTP GET
	// against its own /healthz and exit 0 or 1, entirely bypassing the normal
	// startup path (no point standing up a DB pool just to ask "are you up?").
	if healthcheckRequested() {
		os.Exit(runHealthcheck())
	}

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gateway: fatal:", err)
		os.Exit(1)
	}
}

func healthcheckRequested() bool {
	for _, arg := range os.Args[1:] {
		if arg == "-healthcheck" || arg == "--healthcheck" {
			return true
		}
	}
	return false
}

func runHealthcheck() int {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	// HTTP_ADDR is typically just a port (":8080"), meant for a server's own
	// Listen call — with no host part, that resolves to every interface, none
	// of which is dialable as-is, so an omitted host is filled in as localhost.
	// When it already names a host, that is used unchanged.
	host := addr
	if strings.HasPrefix(addr, ":") {
		host = "localhost" + addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("http://%s/healthz", host)

	// With TLS on, the probe dials https and accepts only the exact leaf
	// certificate this process is configured to serve. That pins the check to
	// our own certificate without needing the CA or a "localhost" SAN.
	if certFile := os.Getenv("TLS_CERT_FILE"); certFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, os.Getenv("TLS_KEY_FILE"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "healthcheck: load certificate:", err)
			return 1
		}
		want := pair.Certificate[0]
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // replaced by the exact-match check below
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, want) {
					return errors.New("server certificate does not match TLS_CERT_FILE")
				}
				return nil
			},
		}}
		url = fmt.Sprintf("https://%s/healthz", host)
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: request failed:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: unexpected status", resp.StatusCode)
		return 1
	}
	return 0
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := observability.NewLogger(cfg.Env)
	log.Info("starting identity gateway", "env", cfg.Env, "http_addr", cfg.HTTPAddr, "tls", cfg.TLSEnabled(), "upstream_mtls", cfg.UpstreamCAFile != "")

	// TLS material is validated before anything else starts, so a bad
	// certificate or CA path fails fast instead of on the first request.
	var serverTLS, upstreamTLS *tls.Config
	if cfg.TLSEnabled() {
		if serverTLS, err = tlsconfig.Server(tlsconfig.ServerOptions{CertFile: cfg.TLSCertFile, KeyFile: cfg.TLSKeyFile}); err != nil {
			return fmt.Errorf("api tls: %w", err)
		}
	}
	if cfg.UpstreamCAFile != "" {
		upstreamTLS, err = tlsconfig.Client(tlsconfig.ClientOptions{
			CAFile: cfg.UpstreamCAFile, CertFile: cfg.UpstreamClientCertFile,
			KeyFile: cfg.UpstreamClientKeyFile, ServerName: cfg.UpstreamServerName,
		})
		if err != nil {
			return fmt.Errorf("upstream mtls: %w", err)
		}
	}

	// Root context cancelled on SIGINT/SIGTERM, which drives every background
	// loop and the graceful HTTP shutdown below.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	flags := &featureflags.Flags{}
	flagsPath := cfg.FeatureFlagsFile
	if flagsPath != "" {
		if err := flags.Reload(flagsPath); err != nil {
			return fmt.Errorf("load feature flags: %w", err)
		}
	}
	if flagsPath != "" && cfg.FeatureFlagsBackend == "file" {
		reload := make(chan os.Signal, 1)
		signal.Notify(reload, syscall.SIGHUP)
		defer signal.Stop(reload)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-reload:
					if err := flags.Reload(flagsPath); err != nil {
						log.Error("feature flags reload rejected; retaining previous configuration", "error", err)
					} else {
						log.Info("feature flags reloaded")
					}
				}
			}
		}()
	}

	db, err := postgres.Connect(ctx, cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer db.Close()

	applied, err := db.Migrate(ctx)
	if err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	log.Info("migrations applied", "count", len(applied), "files", applied)

	// Refuse to serve traffic at all if the connected role could silently
	// bypass every row-level-security policy that the multi-tenant isolation
	// story depends on. See VerifyRLSEnforceable for why this is a real,
	// easy-to-hit misconfiguration rather than a theoretical one.
	if err := db.VerifyRLSEnforceable(ctx); err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	cache, err := redisstore.Connect(ctx, cfg.RedisAddr, cfg.RedisPass, cfg.RedisDB)
	if err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	defer cache.Close()

	var distributedFlags *featureflags.Distributed
	if cfg.FeatureFlagsBackend == "redis" {
		distributedFlags = featureflags.NewDistributed(cache.Raw(), flags, cfg.FeatureFlagsRedisKey, cfg.FeatureFlagsSyncInterval, log)
		initCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := distributedFlags.Initialize(initCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("initialize shared feature flags: %w", err)
		}
		flagCtx, stopFlags := context.WithCancel(ctx)
		flagDone := make(chan struct{})
		go func() { defer close(flagDone); distributedFlags.Run(flagCtx) }()
		defer func() { stopFlags(); <-flagDone }()
	}

	metrics := observability.NewMetrics(cfg.MaxTenantLabels)

	tenants := postgres.NewTenantRepo(db)
	users := postgres.NewUserRepo(db)
	roles := postgres.NewRoleRepo(db)
	sessions := postgres.NewSessionRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	keyRepo := postgres.NewKeyRepo(db)

	keyring := auth.NewKeyring(keyRepo, cfg.SigningKeyMaxAge, log)
	keyring.OnReload(func(count int) { metrics.SigningKeys.Set(float64(count)) })
	if err := keyring.Load(ctx); err != nil {
		return fmt.Errorf("load signing keyring: %w", err)
	}
	go keyring.RunRotation(ctx, 5*time.Minute)

	issuer := auth.NewTokenIssuer(keyring, cfg.Issuer, cfg.Audience, cfg.AccessTokenTTL)
	evaluator := authz.NewEvaluator(roles, cache, metrics)
	riskEngine := authz.NewRiskEngine(cache, cfg.RiskDenyThreshold, cfg.RiskStepUpThreshold)

	auditor := audit.NewLogger(auditRepo, log, metrics, cfg.AuditBufferSize, cfg.AuditBatchSize, cfg.AuditFlushEvery)
	auditCtx, stopAudit := context.WithCancel(context.Background())
	// The explicit call further down controls ordering relative to
	// auditor.Wait on the graceful path (stop after HTTP shutdown, before
	// waiting for the final flush). This defer is the safety net for the
	// early-return error paths above that point, where cancelling twice is a
	// harmless no-op.
	defer stopAudit()
	go auditor.Run(auditCtx)

	authSvc := auth.NewService(auth.ServiceDeps{
		Users: users, Tenants: tenants, Roles: roles, Sessions: sessions,
		Cache: cache, Issuer: issuer, Auditor: auditor, Metrics: metrics, Log: log,
		AccessTTL: cfg.AccessTokenTTL, RefreshTTL: cfg.RefreshTokenTTL,
		MaxFailedLogins: cfg.MaxFailedLogins, LockoutDuration: cfg.LockoutDuration,
		BindDevice: cfg.BindTokensToDevice, BindIP: cfg.BindTokensToIP,
	})

	trustedProxies, err := middleware.NewTrustedProxies(trustedProxyCIDRs())
	if err != nil {
		return fmt.Errorf("parse trusted proxy list: %w", err)
	}

	router := httpapi.NewRouter(httpapi.Deps{
		DistributedFlags: distributedFlags, Flags: flags, Config: cfg, UpstreamTLS: upstreamTLS, Log: log, Metrics: metrics, DB: db, Cache: cache,
		Keyring: keyring, Issuer: issuer, AuthSvc: authSvc,
		Evaluator: evaluator, RiskEngine: riskEngine, Auditor: auditor,
		Tenants: tenants, Users: users, Roles: roles, Sessions: sessions, Audit: auditRepo,
		TrustedProxies: trustedProxies, BootstrapKey: os.Getenv("BOOTSTRAP_KEY"),
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         serverTLS,
	}

	metricsSrv := observability.NewMetricsServer(cfg.MetricsAddr, metrics)

	serveErr := make(chan error, 2)
	go func() {
		log.Info("http server listening", "addr", cfg.HTTPAddr, "tls", serverTLS != nil)
		var err error
		if serverTLS != nil {
			// Certificates come from TLSConfig.GetCertificate (hot-reloaded).
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("api server: %w", err)
		}
	}()
	go func() {
		log.Info("metrics server listening", "addr", cfg.MetricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("metrics server: %w", err)
		}
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	// Order matters here: stop accepting new work first, then drain the audit
	// buffer, so a request that got as far as writing an audit event before
	// shutdown began is not lost by cutting the writer off first.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("http server did not shut down cleanly", "error", err)
	}
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("metrics server did not shut down cleanly", "error", err)
	}

	stopAudit()
	auditor.Wait(cfg.ShutdownTimeout)

	log.Info("shutdown complete")
	return nil
}

// trustedProxyCIDRs reads TRUSTED_PROXY_CIDRS (comma-separated) and falls back
// to the standard RFC1918 ranges, which is the right default inside a
// Kubernetes cluster where the immediate peer is always the ingress or another
// pod, never a public client.
func trustedProxyCIDRs() []string {
	if v := os.Getenv("TRUSTED_PROXY_CIDRS"); v != "" {
		return splitCSV(v)
	}
	return []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/32"}
}

func splitCSV(v string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(v); i++ {
		if i == len(v) || v[i] == ',' {
			if s := v[start:i]; s != "" {
				out = append(out, s)
			}
			start = i + 1
		}
	}
	return out
}
