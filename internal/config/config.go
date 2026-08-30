// Package config loads and validates runtime configuration from the environment.
//
// Every security-relevant knob is explicit and has a safe default. Values that
// weaken the security posture (e.g. disabling IP binding) must be turned on
// deliberately; nothing degrades silently.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env         string
	HTTPAddr    string
	MetricsAddr string

	PostgresDSN string
	RedisAddr   string
	RedisPass   string
	RedisDB     int

	// Token lifetimes. Access tokens are deliberately short: the gateway
	// re-verifies on every request, so a short TTL bounds the blast radius of a
	// leaked token without costing us a database round trip per call.
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	Issuer          string
	Audience        string

	// Key rotation. A signing key is used to sign for SigningKeyMaxAge, then
	// retired but still trusted for verification until every token it signed
	// has expired.
	SigningKeyMaxAge time.Duration

	// Zero-trust enforcement.
	BindTokensToIP      bool
	BindTokensToDevice  bool
	RiskDenyThreshold   int
	RiskStepUpThreshold int

	// Rate limits (token bucket: Burst tokens, refilled at RPS per second).
	IPRateLimit     int
	IPRateBurst     int
	UserRateLimit   int
	UserRateBurst   int
	TenantRateLimit int
	TenantRateBurst int
	LoginRateLimit  int
	LoginRateBurst  int

	// Account lockout after repeated failed authentication.
	MaxFailedLogins int
	LockoutDuration time.Duration

	// Audit pipeline.
	AuditBufferSize int
	AuditBatchSize  int
	AuditFlushEvery time.Duration

	// Upstream services the gateway proxies to, as name=url pairs.
	Upstreams map[string]string

	// Bound Prometheus tenant-label cardinality: only the first N tenants seen
	// get their own label value, everything else is bucketed as "other".
	MaxTenantLabels int

	ShutdownTimeout time.Duration
}

func Load() (*Config, error) {
	c := &Config{
		Env:                 env("ENV", "development"),
		HTTPAddr:            env("HTTP_ADDR", ":8080"),
		MetricsAddr:         env("METRICS_ADDR", ":9090"),
		PostgresDSN:         env("POSTGRES_DSN", "postgres://gateway:gateway@localhost:5432/gateway?sslmode=disable"),
		RedisAddr:           env("REDIS_ADDR", "localhost:6379"),
		RedisPass:           env("REDIS_PASSWORD", ""),
		RedisDB:             envInt("REDIS_DB", 0),
		AccessTokenTTL:      envDur("ACCESS_TOKEN_TTL", 5*time.Minute),
		RefreshTokenTTL:     envDur("REFRESH_TOKEN_TTL", 720*time.Hour),
		Issuer:              env("JWT_ISSUER", "https://gateway.local"),
		Audience:            env("JWT_AUDIENCE", "identity-gateway"),
		SigningKeyMaxAge:    envDur("SIGNING_KEY_MAX_AGE", 24*time.Hour),
		BindTokensToIP:      envBool("BIND_TOKENS_TO_IP", true),
		BindTokensToDevice:  envBool("BIND_TOKENS_TO_DEVICE", true),
		RiskDenyThreshold:   envInt("RISK_DENY_THRESHOLD", 80),
		RiskStepUpThreshold: envInt("RISK_STEPUP_THRESHOLD", 50),
		IPRateLimit:         envInt("IP_RATE_LIMIT", 50),
		IPRateBurst:         envInt("IP_RATE_BURST", 100),
		UserRateLimit:       envInt("USER_RATE_LIMIT", 20),
		UserRateBurst:       envInt("USER_RATE_BURST", 40),
		TenantRateLimit:     envInt("TENANT_RATE_LIMIT", 200),
		TenantRateBurst:     envInt("TENANT_RATE_BURST", 400),
		LoginRateLimit:      envInt("LOGIN_RATE_LIMIT", 1),
		LoginRateBurst:      envInt("LOGIN_RATE_BURST", 5),
		MaxFailedLogins:     envInt("MAX_FAILED_LOGINS", 5),
		LockoutDuration:     envDur("LOCKOUT_DURATION", 15*time.Minute),
		AuditBufferSize:     envInt("AUDIT_BUFFER_SIZE", 4096),
		AuditBatchSize:      envInt("AUDIT_BATCH_SIZE", 128),
		AuditFlushEvery:     envDur("AUDIT_FLUSH_INTERVAL", 2*time.Second),
		MaxTenantLabels:     envInt("MAX_TENANT_LABELS", 50),
		ShutdownTimeout:     envDur("SHUTDOWN_TIMEOUT", 20*time.Second),
		Upstreams:           parseUpstreams(env("UPSTREAMS", "demo=http://localhost:8090")),
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	if c.AccessTokenTTL <= 0 || c.AccessTokenTTL > time.Hour {
		return fmt.Errorf("ACCESS_TOKEN_TTL must be in (0, 1h]; got %s", c.AccessTokenTTL)
	}
	if c.RefreshTokenTTL <= c.AccessTokenTTL {
		return fmt.Errorf("REFRESH_TOKEN_TTL must exceed ACCESS_TOKEN_TTL")
	}
	if c.RiskStepUpThreshold >= c.RiskDenyThreshold {
		return fmt.Errorf("RISK_STEPUP_THRESHOLD must be below RISK_DENY_THRESHOLD")
	}
	// env() substitutes the default whenever the raw variable is empty or
	// unset, so this branch is unreachable from Load() itself — both fields
	// always carry at least their (non-empty) default by the time validate()
	// runs. It stays here as a guard for any caller that builds a Config
	// directly rather than through Load(), where these fields are not
	// defaulted.
	if c.PostgresDSN == "" || c.RedisAddr == "" {
		return fmt.Errorf("POSTGRES_DSN and REDIS_ADDR are required")
	}
	return nil
}

func (c *Config) IsProduction() bool { return c.Env == "production" }

func parseUpstreams(raw string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, url, ok := strings.Cut(pair, "=")
		if ok {
			out[strings.TrimSpace(name)] = strings.TrimSpace(url)
		}
	}
	return out
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(k)); err == nil {
		return v
	}
	return def
}
