// Package featureflags provides atomically reloadable proxy rollout controls.
package featureflags

import (
	"bytes"
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
	body, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil {
		return err
	}
	next, err := parse(body)
	if err != nil {
		return err
	}
	f.current.Store(next)
	return nil
}

// MaxConfigBytes bounds file, API, and shared configurations to one MiB.
const MaxConfigBytes = 1 << 20

func parse(body []byte) (*snapshot, error) {
	if len(body) > MaxConfigBytes {
		return nil, fmt.Errorf("feature flags exceed one MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var next snapshot
	if err := dec.Decode(&next); err != nil {
		return nil, fmt.Errorf("decode feature flags: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("feature flags must contain one JSON object")
	}
	if next.ProxyEnabled == nil {
		return nil, fmt.Errorf("proxy_enabled must be a boolean")
	}
	if next.RolloutPercent != nil && (*next.RolloutPercent < 0 || *next.RolloutPercent > 100) {
		return nil, fmt.Errorf("rollout_percent must be an integer from 0 to 100")
	}
	for slug, enabled := range next.Tenants {
		if enabled == nil {
			return nil, fmt.Errorf("tenant override must be a boolean")
		}
		if slug == "" {
			return nil, fmt.Errorf("tenant slug must not be empty")
		}
	}
	// JSON encoding can expand tenant names (for example, HTML escaping).
	// Reject configurations whose persisted representation would exceed the
	// reader's bound, so an accepted write can always be read by other replicas.
	canonical, err := json.Marshal(&next)
	if err != nil {
		return nil, err
	}
	if len(canonical) > MaxConfigBytes {
		return nil, fmt.Errorf("encoded feature flags exceed one MiB")
	}
	return &next, nil
}

// configuration returns an owned copy suitable for seeding shared storage.
func (f *Flags) configuration() []byte {
	s := f.current.Load()
	if s == nil {
		return []byte(`{"proxy_enabled":true}`)
	}
	body, _ := json.Marshal(s)
	return body
}
