package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sujendra/identity-gateway/internal/domain"
)

// SigningKey is one entry in the JWT keyring.
type SigningKey struct {
	KID       string
	Algorithm string
	Private   ed25519.PrivateKey
	Public    ed25519.PublicKey
	IsActive  bool
	CreatedAt time.Time
	RetiredAt *time.Time
	ExpiresAt time.Time
}

type KeyRepo struct{ db *DB }

func NewKeyRepo(db *DB) *KeyRepo { return &KeyRepo{db: db} }

// Keys are global rather than tenant-scoped, so every operation runs in system
// scope. They are the one piece of state shared across the whole gateway.

// Rotate generates a new Ed25519 key, makes it the sole active signer and
// retires the previous one. The retired key stays in the table (and in the
// JWKS) until it expires, so tokens already in flight keep verifying. That
// overlap is what makes rotation a non-event for clients.
func (r *KeyRepo) Rotate(ctx context.Context, validFor time.Duration) (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(pub[:12])

	key := &SigningKey{
		KID: kid, Algorithm: "EdDSA", Private: priv, Public: pub,
		IsActive: true, ExpiresAt: time.Now().Add(validFor),
	}
	err = r.db.InSystem(ctx, func(ctx context.Context, q Querier) error {
		if _, err := q.Exec(ctx,
			`UPDATE signing_keys SET is_active=false, retired_at=now() WHERE is_active`); err != nil {
			return err
		}
		return q.QueryRow(ctx,
			`INSERT INTO signing_keys (kid, algorithm, private_key, public_key, is_active, expires_at)
			 VALUES ($1,$2,$3,$4,true,$5) RETURNING created_at`,
			key.KID, key.Algorithm, []byte(priv), []byte(pub), key.ExpiresAt).Scan(&key.CreatedAt)
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

// LoadAll returns every key that is still trusted for verification, expired
// ones excluded. The caller uses the active key to sign and the whole set to
// verify.
func (r *KeyRepo) LoadAll(ctx context.Context) ([]*SigningKey, error) {
	var out []*SigningKey
	err := r.db.InSystem(ctx, func(ctx context.Context, q Querier) error {
		rows, err := q.Query(ctx,
			`SELECT kid, algorithm, private_key, public_key, is_active, created_at, retired_at, expires_at
			   FROM signing_keys WHERE expires_at > now() ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k SigningKey
			var priv, pub []byte
			if err := rows.Scan(&k.KID, &k.Algorithm, &priv, &pub, &k.IsActive,
				&k.CreatedAt, &k.RetiredAt, &k.ExpiresAt); err != nil {
				return err
			}
			k.Private = ed25519.PrivateKey(priv)
			k.Public = ed25519.PublicKey(pub)
			out = append(out, &k)
		}
		return rows.Err()
	})
	return out, err
}

// Active returns the current signing key, or ErrNotFound if the keyring is
// empty and a rotation is needed.
func (r *KeyRepo) Active(ctx context.Context) (*SigningKey, error) {
	var key *SigningKey
	err := r.db.InSystem(ctx, func(ctx context.Context, q Querier) error {
		var k SigningKey
		var priv, pub []byte
		err := q.QueryRow(ctx,
			`SELECT kid, algorithm, private_key, public_key, is_active, created_at, retired_at, expires_at
			   FROM signing_keys WHERE is_active AND expires_at > now()`).
			Scan(&k.KID, &k.Algorithm, &priv, &pub, &k.IsActive, &k.CreatedAt, &k.RetiredAt, &k.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		if err != nil {
			return err
		}
		k.Private = ed25519.PrivateKey(priv)
		k.Public = ed25519.PublicKey(pub)
		key = &k
		return nil
	})
	return key, err
}

// PruneExpired removes keys no live token could have been signed with.
func (r *KeyRepo) PruneExpired(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.InSystem(ctx, func(ctx context.Context, q Querier) error {
		tag, err := q.Exec(ctx, `DELETE FROM signing_keys WHERE expires_at <= now()`)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return nil
	})
	return n, err
}
