// Package featureflags provides atomically reloadable proxy rollout controls.
package featureflags

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync/atomic"
)

type snapshot struct {
	ProxyEnabled   *bool            `json:"proxy_enabled"`
	Tenants        map[string]*bool `json:"tenants"`
	RolloutPercent *int             `json:"rollout_percent,omitempty"`
}

// Flags holds an immutable snapshot. The zero value preserves existing behavior.
// Tenant overrides use the authenticated tenant's slug, never a client parameter.
type Flags struct{ current atomic.Pointer[snapshot] }

func (f *Flags) ProxyEnabled(tenantID, tenantSlug string) bool {
	s := f.current.Load()
	if s == nil {
		return true
	}
	if enabled, ok := s.Tenants[tenantSlug]; ok {
		return *enabled
	}
	if !*s.ProxyEnabled {
		return false
	}
	return s.RolloutPercent == nil || rolloutEnabled(tenantID, "proxy_enabled", *s.RolloutPercent)
}

// rolloutEnabled assigns a stable bucket per tenant and flag. Raising the
// percentage only adds tenants; evaluations require no shared mutable state.
func rolloutEnabled(tenantID, flagName string, percent int) bool {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + flagName))
	return int(binary.BigEndian.Uint64(sum[:8])%100) < percent
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
	if next.RolloutPercent != nil && (*next.RolloutPercent < 0 || *next.RolloutPercent > 100) {
		return fmt.Errorf("rollout_percent must be an integer from 0 to 100")
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
