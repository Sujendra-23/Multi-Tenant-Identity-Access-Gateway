package featureflags

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func sharedTestClient(t *testing.T) (*redis.Client, string) {
	t.Helper()
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("REDIS_TEST_ADDR not set; skipping Redis integration test")
	}
	c := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("REDIS_TEST_PASSWORD"), MaxRetries: -1})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	key := "test:feature-flags:" + uuid.NewString()
	t.Cleanup(func() { c.Del(context.Background(), key); c.Close() })
	return c, key
}

func manager(t *testing.T, c *redis.Client, key string, interval time.Duration) (*Distributed, *Flags) {
	t.Helper()
	f := &Flags{}
	d := NewDistributed(c, f, key, interval, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := d.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	return d, f
}

func startWatcher(t *testing.T, d *Distributed) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("watcher did not stop")
		}
	})
	eventually(t, func() bool {
		counts, err := d.redis.PubSubNumSub(context.Background(), d.channel).Result()
		return err == nil && counts[d.channel] > 0
	})
}

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("replica did not converge")
}

func revision(d *Distributed) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.revision
}

func TestDistributedPubSubAndRestart(t *testing.T) {
	c, key := sharedTestClient(t)
	// Separate clients and Flags simulate independent gateway processes.
	c2 := redis.NewClient(c.Options())
	t.Cleanup(func() { c2.Close() })
	writer, f1 := manager(t, c, key, time.Hour)
	reader, f2 := manager(t, c2, key, time.Hour)
	startWatcher(t, reader)
	doc, err := writer.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"proxy_enabled":true,"rollout_percent":10,"tenants":{"pilot":true}}`,
		`{"proxy_enabled":true,"rollout_percent":100,"tenants":{"blocked":false}}`,
		`{"proxy_enabled":false}`,
	} {
		doc, err = writer.Update(context.Background(), doc.Revision, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		eventually(t, func() bool { return revision(reader) == doc.Revision })
		for i := 0; i < 100; i++ {
			id := uuid.NewString()
			for _, slug := range []string{"normal", "pilot", "blocked"} {
				if f1.ProxyEnabled(id, slug) != f2.ProxyEnabled(id, slug) {
					t.Fatal("replicas disagree")
				}
			}
		}
	}
	restarted, f3 := manager(t, c2, key, time.Hour)
	if revision(restarted) != doc.Revision || f3.ProxyEnabled("id", "normal") {
		t.Fatal("restart overwrote persisted flags with defaults")
	}
}

func TestDistributedMissedNotificationAndReconnect(t *testing.T) {
	c, key := sharedTestClient(t)
	d, f := manager(t, c, key, 20*time.Millisecond)
	startWatcher(t, d)
	// A persisted update with no PUBLISH simulates losing the notification.
	doc := Document{Revision: uuid.NewString(), Flags: json.RawMessage(`{"proxy_enabled":false}`)}
	body, _ := json.Marshal(doc)
	if err := c.Set(context.Background(), key, body, 0).Err(); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return !f.ProxyEnabled("id", "normal") && revision(d) == doc.Revision })
	// Force the pub/sub connection to reconnect. Reconciliation must keep working.
	if err := c.ClientKillByFilter(context.Background(), "TYPE", "pubsub").Err(); err != nil {
		t.Fatal(err)
	}
	doc.Revision = uuid.NewString()
	doc.Flags = json.RawMessage(`{"proxy_enabled":true}`)
	body, _ = json.Marshal(doc)
	if err := c.Set(context.Background(), key, body, 0).Err(); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return f.ProxyEnabled("id", "normal") && revision(d) == doc.Revision })
}

func TestDistributedConcurrentUpdates(t *testing.T) {
	c, key := sharedTestClient(t)
	first, _ := manager(t, c, key, time.Second)
	second, _ := manager(t, c, key, time.Second)
	doc, err := first.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, d := range []*Distributed{first, second} {
		wg.Add(1)
		go func(d *Distributed) {
			defer wg.Done()
			_, err := d.Update(context.Background(), doc.Revision, []byte(`{"proxy_enabled":false}`))
			results <- err
		}(d)
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("got %d writes and %d conflicts", successes, conflicts)
	}
}

func TestDistributedFailureRetainsSnapshot(t *testing.T) {
	c, key := sharedTestClient(t)
	d, f := manager(t, c, key, time.Second)
	doc, err := d.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	doc, err = d.Update(context.Background(), doc.Revision, []byte(`{"proxy_enabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Update(context.Background(), doc.Revision, []byte(`{"proxy_enabled":true,"rollout_percent":101}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	stored, err := d.Read(context.Background())
	if err != nil || stored.Revision != doc.Revision {
		t.Fatal("invalid write altered shared state")
	}
	if err := c.Set(context.Background(), key, `{"revision":"bad","flags":{"proxy_enabled":true}}`, 0).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Read(context.Background()); err == nil {
		t.Fatal("accepted invalid shared data")
	}
	if err := c.Del(context.Background(), key).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Read(context.Background()); !errors.Is(err, ErrMissing) {
		t.Fatalf("got %v", err)
	}
	if _, err := d.Update(context.Background(), doc.Revision, []byte(`{"proxy_enabled":true}`)); !errors.Is(err, ErrMissing) {
		t.Fatalf("got %v", err)
	}
	if f.ProxyEnabled("id", "normal") || revision(d) != doc.Revision {
		t.Fatal("failed synchronization changed local snapshot")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Update(context.Background(), doc.Revision, []byte(`{"proxy_enabled":true}`)); err == nil {
		t.Fatal("write succeeded while disconnected")
	}
	if f.ProxyEnabled("id", "normal") {
		t.Fatal("failed write enabled local flags")
	}
}
