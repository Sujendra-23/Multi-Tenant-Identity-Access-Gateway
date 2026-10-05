package config

import (
	"os"
	"testing"
	"time"
)

// withEnv sets environment variables for the duration of the test and restores
// whatever was there before, so tests can run in any order without leaking
// state into each other.
func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		old, existed := os.LookupEnv(k)
		os.Setenv(k, v)
		t.Cleanup(func() {
			if existed {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AccessTokenTTL != 5*time.Minute {
		t.Errorf("default AccessTokenTTL = %s, want 5m", cfg.AccessTokenTTL)
	}
	if !cfg.BindTokensToIP || !cfg.BindTokensToDevice {
		t.Error("token binding should default to enabled: zero trust should be opt-out, not opt-in")
	}
	if cfg.RiskStepUpThreshold >= cfg.RiskDenyThreshold {
		t.Error("default step-up threshold must be below the deny threshold")
	}
}

func TestLoad_RejectsAccessTokenTTLTooLong(t *testing.T) {
	withEnv(t, map[string]string{"ACCESS_TOKEN_TTL": "2h"})
	if _, err := Load(); err == nil {
		t.Fatal("expected an error for an access token TTL over 1 hour")
	}
}

func TestLoad_RejectsRefreshShorterThanAccess(t *testing.T) {
	withEnv(t, map[string]string{"ACCESS_TOKEN_TTL": "10m", "REFRESH_TOKEN_TTL": "5m"})
	if _, err := Load(); err == nil {
		t.Fatal("expected an error when the refresh TTL does not exceed the access TTL")
	}
}

func TestLoad_RejectsInvertedRiskThresholds(t *testing.T) {
	withEnv(t, map[string]string{"RISK_STEPUP_THRESHOLD": "90", "RISK_DENY_THRESHOLD": "50"})
	if _, err := Load(); err == nil {
		t.Fatal("expected an error when the step-up threshold is not below the deny threshold")
	}
}

// TestValidate_RejectsEmptyStoreAddresses exercises validate() directly rather
// than through Load(): env() treats an empty environment variable the same as
// an unset one and substitutes the default, so Load() itself can never produce
// an empty PostgresDSN from the environment. The guard in validate() only
// matters for a Config built by hand rather than through Load() — this test
// documents that distinction and confirms the guard still fires when it can be
// reached.
func TestValidate_RejectsEmptyStoreAddresses(t *testing.T) {
	c := &Config{
		AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour,
		RiskStepUpThreshold: 50, RiskDenyThreshold: 80,
		PostgresDSN: "", RedisAddr: "localhost:6379",
		FeatureFlagsBackend: "file", FeatureFlagsSyncInterval: 5 * time.Second,
	}
	if err := c.validate(); err == nil {
		t.Fatal("expected an error for an empty PostgresDSN")
	}
}

func TestParseUpstreams(t *testing.T) {
	got := parseUpstreams("orders=http://orders:8080, billing = http://billing:9090 ,")
	want := map[string]string{"orders": "http://orders:8080", "billing": "http://billing:9090"}
	if len(got) != len(want) {
		t.Fatalf("got %d upstreams, want %d: %+v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("upstream %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestIsProduction(t *testing.T) {
	c := &Config{Env: "production"}
	if !c.IsProduction() {
		t.Error("Env=production should report IsProduction() == true")
	}
	c.Env = "development"
	if c.IsProduction() {
		t.Error("Env=development should report IsProduction() == false")
	}
}

func TestFeatureFlagsConfiguration(t *testing.T) {
	for _, backend := range []string{"file", "redis"} {
		t.Run(backend, func(t *testing.T) {
			t.Setenv("FEATURE_FLAGS_BACKEND", backend)
			t.Setenv("FEATURE_FLAGS_SYNC_INTERVAL", "2s")
			c, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if c.FeatureFlagsBackend != backend || c.FeatureFlagsSyncInterval != 2*time.Second {
				t.Fatal("flag configuration not loaded")
			}
		})
	}
	t.Setenv("FEATURE_FLAGS_BACKEND", "typo")
	if _, err := Load(); err == nil {
		t.Fatal("accepted unknown backend")
	}
	t.Setenv("FEATURE_FLAGS_BACKEND", "redis")
	for _, interval := range []string{"0s", "-1s", "invalid"} {
		t.Setenv("FEATURE_FLAGS_SYNC_INTERVAL", interval)
		if _, err := Load(); err == nil {
			t.Fatal("accepted nonpositive reconciliation interval")
		}
	}
}
