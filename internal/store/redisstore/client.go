// Package redisstore holds the low-latency state the verification chain reads on
// every request: live sessions, the revocation list, rate-limit buckets and the
// permission cache. Postgres remains the source of truth; Redis is what keeps a
// per-request re-verification affordable.
package redisstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Client struct {
	rdb *redis.Client
}

func Connect(ctx context.Context, addr, password string, db int) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		PoolSize:     50,
		MinIdleConns: 5,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Client{rdb: rdb}, nil
}

func (c *Client) Close() error { return c.rdb.Close() }

func (c *Client) Ping(ctx context.Context) error { return c.rdb.Ping(ctx).Err() }

func (c *Client) Raw() *redis.Client { return c.rdb }

// HashToken hashes a bearer secret before it is used as a key or stored.
//
// Refresh tokens are high-value credentials. Storing only the digest means a
// dump of Redis yields nothing an attacker can present: they would have to
// invert SHA-256. The token itself is 256 bits of CSPRNG output, so unlike a
// password there is no dictionary to attack and no need for a slow KDF here.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
