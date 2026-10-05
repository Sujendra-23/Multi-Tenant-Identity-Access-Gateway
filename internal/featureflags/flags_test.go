package featureflags

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestReload(t *testing.T) {
	var f Flags
	if !f.ProxyEnabled("id-acme", "acme") {
		t.Fatal("default must preserve proxy access")
	}
	path := filepath.Join(t.TempDir(), "flags.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"proxy_enabled":false,"tenants":{"acme":true}}`)
	if err := f.Reload(path); err != nil {
		t.Fatal(err)
	}
	if !f.ProxyEnabled("id-acme", "acme") || f.ProxyEnabled("id-other", "other") {
		t.Fatal("tenant override or global default incorrect")
	}
	for _, body := range []string{`{`, `{}`, `null`, `{"proxy_enabled":null}`, `{"proxy_enabled":true,"tenants":{"acme":null}}`, `{"proxy_enabled":true,"typo":false}`, `{"proxy_enabled":true} {}`, `{"proxy_enabled":true,"tenants":{"":true}}`} {
		write(body)
		if err := f.Reload(path); err == nil {
			t.Fatalf("accepted invalid config %s", body)
		}
		if f.ProxyEnabled("id-other", "other") || !f.ProxyEnabled("id-acme", "acme") {
			t.Fatal("failed reload changed active flags")
		}
	}
	if err := f.Reload(path + ".missing"); err == nil {
		t.Fatal("accepted missing file")
	}
	write(`{"proxy_enabled":true,"tenants":{"acme":false}}`)
	if err := f.Reload(path); err != nil {
		t.Fatal(err)
	}
	if f.ProxyEnabled("id-acme", "acme") || !f.ProxyEnabled("id-other", "other") {
		t.Fatal("reload did not replace flags")
	}
}

func TestConcurrentReloadAndEvaluate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flags.json")
	if err := os.WriteFile(path, []byte(`{"proxy_enabled":false,"tenants":{"acme":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	var f Flags
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				f.ProxyEnabled("id-acme", "acme")
			}
		}()
	}
	for i := 0; i < 100; i++ {
		if err := f.Reload(path); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestPercentageRollout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flags.json")
	var f Flags
	reload := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := f.Reload(path); err != nil {
			t.Fatal(err)
		}
	}
	reload(`{"proxy_enabled":true,"rollout_percent":10}`)
	var other Flags
	if err := other.Reload(path); err != nil {
		t.Fatal(err)
	}
	selected := make(map[string]bool)
	for i := 0; i < 10000; i++ {
		id := fmt.Sprintf("tenant-%d", i)
		enabled := f.ProxyEnabled(id, "old-name")
		if enabled != other.ProxyEnabled(id, "old-name") {
			t.Fatal("instances disagree")
		}
		if enabled != f.ProxyEnabled(id, "new-name") {
			t.Fatal("rename changed cohort")
		}
		if enabled {
			selected[id] = true
		}
	}
	if len(selected) < 800 || len(selected) > 1200 {
		t.Fatalf("unexpected 10%% cohort size: %d", len(selected))
	}
	reload(`{"proxy_enabled":true,"rollout_percent":50}`)
	for id := range selected {
		if !f.ProxyEnabled(id, "slug") {
			t.Fatal("increasing percentage removed tenant")
		}
	}
	reload(`{"proxy_enabled":true,"rollout_percent":0,"tenants":{"pilot":true}}`)
	if f.ProxyEnabled("id", "normal") || !f.ProxyEnabled("id", "pilot") {
		t.Fatal("zero percent or enable override incorrect")
	}
	for _, body := range []string{
		`{"proxy_enabled":true,"rollout_percent":-1}`,
		`{"proxy_enabled":true,"rollout_percent":101}`,
		`{"proxy_enabled":true,"rollout_percent":10.5}`,
		`{"proxy_enabled":true,"rollout_percent":"10"}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := f.Reload(path); err == nil {
			t.Fatalf("accepted %s", body)
		}
		if f.ProxyEnabled("id", "normal") || !f.ProxyEnabled("id", "pilot") {
			t.Fatal("invalid reload changed snapshot")
		}
	}
	reload(`{"proxy_enabled":true,"rollout_percent":100,"tenants":{"blocked":false}}`)
	for i := 0; i < 10000; i++ {
		if !f.ProxyEnabled(fmt.Sprint(i), "normal") {
			t.Fatal("100 percent excluded tenant")
		}
	}
	if f.ProxyEnabled("id", "blocked") {
		t.Fatal("disable override ignored")
	}
	reload(`{"proxy_enabled":false,"rollout_percent":100}`)
	if f.ProxyEnabled("id", "normal") {
		t.Fatal("percentage bypassed disabled default")
	}
}

func TestRolloutStableHashAndFlagNames(t *testing.T) {
	different := false
	for i := 0; i < 1000; i++ {
		id := fmt.Sprint(i)
		if rolloutEnabled(id, "proxy_enabled", 10) != rolloutEnabled(id, "another_flag", 10) {
			different = true
		}
	}
	if !different {
		t.Fatal("flag name does not affect cohort")
	}
	// Fixed vectors lock the hash algorithm and encoding across future versions.
	if !rolloutEnabled("tenant-0", "proxy_enabled", 70) || rolloutEnabled("tenant-0", "proxy_enabled", 69) {
		t.Fatal("stable bucket changed")
	}
}

func TestConfigurationSizeLimit(t *testing.T) {
	for _, body := range []string{
		`{"proxy_enabled":true}` + strings.Repeat(" ", MaxConfigBytes),
		`{"proxy_enabled":true,"tenants":{"` + strings.Repeat("<", MaxConfigBytes/2) + `":true}}`,
	} {
		if _, err := parse([]byte(body)); err == nil {
			t.Fatal("accepted oversized wire or persisted configuration")
		}
	}
}
