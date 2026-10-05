// Package featureflags provides atomically reloadable proxy rollout controls.
package featureflags

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync/atomic"
)

type snapshot struct {
	ProxyEnabled *bool            `json:"proxy_enabled"`
	Tenants      map[string]*bool `json:"tenants"`
}

// Flags holds an immutable snapshot. The zero value preserves existing behavior.
// Tenant overrides use the authenticated tenant's slug, never a client parameter.
type Flags struct{ current atomic.Pointer[snapshot] }

func (f *Flags) ProxyEnabled(tenant string) bool {
	s := f.current.Load()
	if s == nil {
		return true
	}
	if enabled, ok := s.Tenants[tenant]; ok {
		return *enabled
	}
	return *s.ProxyEnabled
}

// Reload publishes only a completely decoded and validated configuration.
// Failed reads or validation leave the previous snapshot in place.
func (f *Flags) Reload(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	dec := json.NewDecoder(io.LimitReader(file, 1<<20+1))
	dec.DisallowUnknownFields()
	var next snapshot
	if err := dec.Decode(&next); err != nil {
		return fmt.Errorf("decode feature flags: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("feature flags must contain one JSON object")
	}
	if next.ProxyEnabled == nil {
		return fmt.Errorf("proxy_enabled must be a boolean")
	}
	for slug, enabled := range next.Tenants {
		if enabled == nil {
			return fmt.Errorf("tenant override must be a boolean")
		}
		if slug == "" {
			return fmt.Errorf("tenant slug must not be empty")
		}
	}
	f.current.Store(&next)
	return nil
}
