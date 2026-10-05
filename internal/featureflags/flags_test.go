package featureflags

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReload(t *testing.T) {
	var f Flags
	if !f.ProxyEnabled("acme") {
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
	if !f.ProxyEnabled("acme") || f.ProxyEnabled("other") {
		t.Fatal("tenant override or global default incorrect")
	}
	for _, body := range []string{`{`, `{}`, `null`, `{"proxy_enabled":null}`, `{"proxy_enabled":true,"tenants":{"acme":null}}`, `{"proxy_enabled":true,"typo":false}`, `{"proxy_enabled":true} {}`, `{"proxy_enabled":true,"tenants":{"":true}}`} {
		write(body)
		if err := f.Reload(path); err == nil {
			t.Fatalf("accepted invalid config %s", body)
		}
		if f.ProxyEnabled("other") || !f.ProxyEnabled("acme") {
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
	if f.ProxyEnabled("acme") || !f.ProxyEnabled("other") {
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
				f.ProxyEnabled("acme")
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
