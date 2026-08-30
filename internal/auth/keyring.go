package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
)

// Keyring holds the signing keys in memory and keeps them in step with the
// database.
//
// Signing uses one active key; verification accepts every key that has not yet
// expired. That overlap is the whole trick to rotating without downtime: when a
// key is retired, tokens it already signed stay valid until they expire
// naturally, so no client is logged out by a rotation.
//
// Ed25519 rather than RSA or HMAC: HMAC would require every verifier to hold the
// signing secret, which rules out handing verification to anything we do not
// fully trust. Ed25519 signatures are 64 bytes and verify in microseconds, which
// matters when every single request re-verifies.
type Keyring struct {
	mu       sync.RWMutex
	keys     map[string]*postgres.SigningKey // by kid
	active   *postgres.SigningKey
	repo     *postgres.KeyRepo
	maxAge   time.Duration
	log      *slog.Logger
	onReload func(count int)
}

func NewKeyring(repo *postgres.KeyRepo, maxAge time.Duration, log *slog.Logger) *Keyring {
	return &Keyring{
		keys:   map[string]*postgres.SigningKey{},
		repo:   repo,
		maxAge: maxAge,
		log:    log,
	}
}

// OnReload registers a callback fired after each successful reload, used to
// publish the trusted-key gauge.
func (k *Keyring) OnReload(fn func(count int)) { k.onReload = fn }

// Load pulls the keyring from the database, generating the first key if the
// table is empty. Every replica calls this at startup and then periodically, so
// a rotation performed by one replica propagates to the others.
func (k *Keyring) Load(ctx context.Context) error {
	keys, err := k.repo.LoadAll(ctx)
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}
	if len(keys) == 0 {
		k.log.Info("keyring is empty, generating initial signing key")
		// Keys must outlive the tokens they sign. Twice the signing window plus
		// a margin guarantees a retired key is still around to verify the last
		// token minted just before it was retired.
		if _, err := k.repo.Rotate(ctx, 2*k.maxAge+time.Hour); err != nil {
			return fmt.Errorf("bootstrap key: %w", err)
		}
		if keys, err = k.repo.LoadAll(ctx); err != nil {
			return fmt.Errorf("reload after bootstrap: %w", err)
		}
	}

	next := make(map[string]*postgres.SigningKey, len(keys))
	var active *postgres.SigningKey
	for _, key := range keys {
		next[key.KID] = key
		if key.IsActive {
			active = key
		}
	}
	if active == nil {
		return errors.New("keyring: no active signing key; run a rotation")
	}

	k.mu.Lock()
	k.keys, k.active = next, active
	k.mu.Unlock()

	if k.onReload != nil {
		k.onReload(len(next))
	}
	return nil
}

// Active returns the key new tokens are signed with.
func (k *Keyring) Active() (*postgres.SigningKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.active == nil {
		return nil, errors.New("keyring: not loaded")
	}
	return k.active, nil
}

// PublicKey resolves a kid to its verification key. An unknown kid means the
// token was signed by something that is not us, or by a key retired long enough
// ago to have been pruned.
func (k *Keyring) PublicKey(kid string) (ed25519.PublicKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	key, ok := k.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown key id %q: %w", kid, domain.ErrNotFound)
	}
	if time.Now().After(key.ExpiresAt) {
		return nil, fmt.Errorf("key %q has expired: %w", kid, domain.ErrTokenRevoked)
	}
	return key.Public, nil
}

// Rotate mints a new active key and reloads. Safe to call from any replica: the
// database's single-active-key index serialises concurrent attempts.
func (k *Keyring) Rotate(ctx context.Context) (string, error) {
	key, err := k.repo.Rotate(ctx, 2*k.maxAge+time.Hour)
	if err != nil {
		return "", err
	}
	if err := k.Load(ctx); err != nil {
		return "", err
	}
	k.log.Info("signing key rotated", "kid", key.KID, "expires_at", key.ExpiresAt)
	return key.KID, nil
}

// RunRotation keeps the keyring fresh in the background: it reloads often so
// another replica's rotation is picked up quickly, and rotates when the active
// key has been signing for longer than maxAge.
func (k *Keyring) RunRotation(ctx context.Context, reloadEvery time.Duration) {
	ticker := time.NewTicker(reloadEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := k.Load(ctx); err != nil {
				k.log.Error("keyring reload failed", "error", err)
				continue
			}
			active, err := k.Active()
			if err != nil {
				continue
			}
			if time.Since(active.CreatedAt) > k.maxAge {
				if _, err := k.Rotate(ctx); err != nil {
					k.log.Error("scheduled key rotation failed", "error", err)
				}
			}
			if _, err := k.repo.PruneExpired(ctx); err != nil {
				k.log.Warn("pruning expired keys failed", "error", err)
			}
		}
	}
}

// JWK is one entry in the public JWKS document.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS publishes the public half of every trusted key, so downstream services
// can verify gateway-issued tokens themselves without calling back to us and
// without ever holding a signing secret.
func (k *Keyring) JWKS() JWKS {
	k.mu.RLock()
	defer k.mu.RUnlock()

	out := JWKS{Keys: make([]JWK, 0, len(k.keys))}
	for _, key := range k.keys {
		out.Keys = append(out.Keys, JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			Kid: key.KID,
			X:   base64.RawURLEncoding.EncodeToString(key.Public),
			Alg: "EdDSA",
			Use: "sig",
		})
	}
	return out
}
