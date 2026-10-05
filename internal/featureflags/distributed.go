package featureflags

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var (
	ErrConflict = errors.New("feature flags revision conflict")
	ErrMissing  = errors.New("shared feature flags are missing")
	ErrInvalid  = errors.New("invalid feature flags")
)

// Document is the complete shared configuration. Revision is an opaque ETag.
type Document struct {
	Revision string          `json:"revision"`
	Flags    json.RawMessage `json:"flags"`
}

// Distributed propagates snapshots, not individual flag mutations. Pub/sub is
// only a wakeup hint: every reconciliation reads the authoritative Redis key.
// The mutex serializes reads/writes on this replica so a delayed read cannot
// overwrite a newer locally applied update. Request evaluation remains lock-free.
type Distributed struct {
	redis        *redis.Client
	flags        *Flags
	key, channel string
	interval     time.Duration
	log          *slog.Logger
	mu           sync.Mutex
	revision     string
}

func NewDistributed(client *redis.Client, flags *Flags, key string, interval time.Duration, log *slog.Logger) *Distributed {
	return &Distributed{redis: client, flags: flags, key: key,
		channel: fmt.Sprintf("%s:updates:db%d", key, client.Options().DB), interval: interval, log: log}
}

// Initialize seeds an absent key exactly once, then loads the winning snapshot.
// A seed file is never allowed to overwrite an existing shared configuration.
func (d *Distributed) Initialize(ctx context.Context) error {
	seed := Document{Revision: uuid.NewString(), Flags: d.flags.configuration()}
	body, err := json.Marshal(seed)
	if err != nil {
		return err
	}
	if err := d.redis.SetNX(ctx, d.key, body, 0).Err(); err != nil {
		return err
	}
	_, err = d.Read(ctx)
	return err
}

// Read refreshes this replica and returns the shared state, not a stale cache.
func (d *Distributed) Read(ctx context.Context) (Document, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	body, err := d.redis.Get(ctx, d.key).Bytes()
	if errors.Is(err, redis.Nil) {
		return Document{}, ErrMissing
	}
	if err != nil {
		return Document{}, err
	}
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return Document{}, err
	}
	if _, err := uuid.Parse(doc.Revision); err != nil {
		return Document{}, fmt.Errorf("invalid shared revision: %w", err)
	}
	next, err := parse(doc.Flags)
	if err != nil {
		return Document{}, err
	}
	d.apply(doc, next)
	return doc, nil
}

// One Redis operation checks the revision, persists the replacement, and
// publishes its revision. No notification can precede the corresponding write.
var replaceFlags = redis.NewScript(`
local current = redis.call('GET', KEYS[1])
if not current then return -1 end
if cjson.decode(current).revision ~= ARGV[1] then return 0 end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('PUBLISH', ARGV[3], ARGV[4])
return 1
`)

func (d *Distributed) Update(ctx context.Context, expected string, body []byte) (Document, error) {
	next, err := parse(body)
	if err != nil {
		return Document{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// Canonicalize before storing; never retain the caller's mutable buffer.
	canonical, err := json.Marshal(next)
	if err != nil {
		return Document{}, err
	}
	doc := Document{Revision: uuid.NewString(), Flags: canonical}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return Document{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	result, err := replaceFlags.Run(ctx, d.redis, []string{d.key}, expected, encoded, d.channel, doc.Revision).Int()
	if err != nil {
		return Document{}, err
	}
	switch result {
	case -1:
		return Document{}, ErrMissing
	case 0:
		return Document{}, ErrConflict
	}
	d.apply(doc, next)
	return doc, nil
}

func (d *Distributed) apply(doc Document, next *snapshot) {
	if d.revision == doc.Revision {
		return
	}
	d.flags.current.Store(next)
	d.revision = doc.Revision
	d.log.Info("shared feature flags applied", "revision", doc.Revision)
}

// Run reconciles immediately, on pub/sub notifications, and periodically. The
// go-redis subscriber reconnects automatically; polling also covers messages
// lost during reconnect. Failure keeps the last valid local snapshot intact.
func (d *Distributed) Run(ctx context.Context) {
	sub := d.redis.Subscribe(ctx, d.channel)
	defer sub.Close()
	updates := sub.Channel()
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	reconcile := func() {
		readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if _, err := d.Read(readCtx); err != nil && ctx.Err() == nil {
			d.log.Error("feature flag reconciliation failed; retaining last snapshot", "error", err)
		}
	}
	reconcile()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-updates:
			if !ok {
				updates = nil
				continue
			}
			reconcile()
		case <-ticker.C:
			reconcile()
		}
	}
}
