// Package audit buffers security events and writes them to the hash-chained
// store without putting a database round trip on the request path.
package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sujendra/identity-gateway/internal/domain"
	"github.com/sujendra/identity-gateway/internal/observability"
	"github.com/sujendra/identity-gateway/internal/store/postgres"
)

// Logger accepts events from request handlers and flushes them in batches.
//
// The chain append needs a per-tenant lock and a round trip, which is far too
// much to do inline on every request. Buffering moves that cost off the hot path
// and lets one transaction carry many events.
//
// The trade-off is explicit: a hard crash can lose whatever is still buffered.
// That is acceptable for access decisions but would not be for, say, financial
// records — and the choice is made visible by counting every dropped event in a
// metric rather than swallowing it.
type Logger struct {
	repo    *postgres.AuditRepo
	log     *slog.Logger
	metrics *observability.Metrics

	events     chan *domain.AuditEvent
	batchSize  int
	flushEvery time.Duration

	wg   sync.WaitGroup
	once sync.Once
	done chan struct{}
}

func NewLogger(repo *postgres.AuditRepo, log *slog.Logger, m *observability.Metrics, bufferSize, batchSize int, flushEvery time.Duration) *Logger {
	return &Logger{
		repo:       repo,
		log:        log,
		metrics:    m,
		events:     make(chan *domain.AuditEvent, bufferSize),
		batchSize:  batchSize,
		flushEvery: flushEvery,
		done:       make(chan struct{}),
	}
}

// Record enqueues an event. It never blocks.
//
// If the buffer is full the event is dropped and counted. Blocking here would
// let a slow database turn into gateway-wide latency, which trades an
// availability incident for an observability gap — the wrong way round. The
// dropped counter should alert; a non-zero value means the buffer needs to grow
// or the writer needs to keep up.
func (l *Logger) Record(e *domain.AuditEvent) {
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	select {
	case l.events <- e:
		l.metrics.AuditBuffered.Set(float64(len(l.events)))
	default:
		l.metrics.AuditDropped.Inc()
		l.log.Error("audit buffer full, event dropped",
			"action", e.Action, "tenant_id", e.TenantID, "decision", e.Decision)
	}
}

// Run drains the buffer until ctx is cancelled, then flushes what is left.
func (l *Logger) Run(ctx context.Context) {
	l.wg.Add(1)
	defer l.wg.Done()
	defer close(l.done)

	ticker := time.NewTicker(l.flushEvery)
	defer ticker.Stop()

	batch := make([]*domain.AuditEvent, 0, l.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Detached from ctx so that a shutdown still gets its final batch
		// written rather than cancelled halfway.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		l.flush(writeCtx, batch)
		cancel()
		batch = batch[:0]
		l.metrics.AuditBuffered.Set(float64(len(l.events)))
	}

	for {
		select {
		case <-ctx.Done():
			// Drain whatever is still queued before returning.
			for {
				select {
				case e := <-l.events:
					batch = append(batch, e)
					if len(batch) >= l.batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case e := <-l.events:
			batch = append(batch, e)
			if len(batch) >= l.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// flush groups the batch by tenant, because the chain is per tenant and each
// group is one locked transaction. Grouping means a busy tenant's events share
// a single lock acquisition instead of contending one at a time.
func (l *Logger) flush(ctx context.Context, batch []*domain.AuditEvent) {
	byTenant := make(map[uuid.UUID][]*domain.AuditEvent)
	for _, e := range batch {
		byTenant[e.TenantID] = append(byTenant[e.TenantID], e)
	}

	for tenantID, events := range byTenant {
		if tenantID == uuid.Nil {
			// Pre-authentication failures have no tenant to attribute to, so
			// there is no chain to extend. They still matter, so they go to the
			// structured log where the SIEM will pick them up.
			for _, e := range events {
				l.log.Warn("unattributed security event",
					"action", e.Action, "decision", e.Decision, "reason", e.Reason,
					"ip", e.IP, "request_id", e.RequestID)
			}
			continue
		}
		if err := l.repo.AppendBatch(ctx, tenantID, events); err != nil {
			l.metrics.AuditDropped.Add(float64(len(events)))
			l.log.Error("audit batch write failed",
				"tenant_id", tenantID, "events", len(events), "error", err)
			continue
		}
		l.metrics.AuditWritten.Add(float64(len(events)))
	}
}

// Wait blocks until the writer has finished its final flush.
func (l *Logger) Wait(timeout time.Duration) {
	l.once.Do(func() {
		select {
		case <-l.done:
		case <-time.After(timeout):
			l.log.Warn("audit writer did not finish within the shutdown budget")
		}
	})
}

// Builder assembles an event fluently at a call site.
type Builder struct{ e domain.AuditEvent }

func Event(action string) *Builder {
	return &Builder{e: domain.AuditEvent{
		Action:     action,
		Metadata:   map[string]string{},
		OccurredAt: time.Now().UTC(),
	}}
}

func (b *Builder) Tenant(id uuid.UUID) *Builder { b.e.TenantID = id; return b }
func (b *Builder) Actor(id *uuid.UUID, email string) *Builder {
	b.e.ActorID, b.e.ActorEmail = id, email
	return b
}
func (b *Builder) Resource(r string) *Builder { b.e.Resource = r; return b }
func (b *Builder) Allow() *Builder            { b.e.Decision = domain.DecisionAllow; return b }
func (b *Builder) Deny(reason string) *Builder {
	b.e.Decision, b.e.Reason = domain.DecisionDeny, reason
	return b
}
func (b *Builder) Error(reason string) *Builder {
	b.e.Decision, b.e.Reason = domain.DecisionError, reason
	return b
}
func (b *Builder) Risk(score int) *Builder { b.e.RiskScore = score; return b }
func (b *Builder) Request(id, ip, ua string) *Builder {
	b.e.RequestID, b.e.IP, b.e.UserAgent = id, ip, ua
	return b
}
func (b *Builder) Meta(k, v string) *Builder { b.e.Metadata[k] = v; return b }
func (b *Builder) Build() *domain.AuditEvent { return &b.e }
