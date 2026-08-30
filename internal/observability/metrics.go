// Package observability wires Prometheus metrics and structured logging.
//
// Tenant identity is genuinely useful on these series, but an unbounded tenant
// label is the classic way to melt a Prometheus server. TenantLabeller caps the
// number of distinct tenant label values and buckets the rest as "other".
package observability

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Metrics struct {
	Registry *prometheus.Registry

	HTTPRequests *prometheus.CounterVec
	HTTPDuration *prometheus.HistogramVec
	HTTPInFlight prometheus.Gauge

	AuthAttempts   *prometheus.CounterVec
	TokensIssued   *prometheus.CounterVec
	TokenRefresh   *prometheus.CounterVec
	VerifyFailures *prometheus.CounterVec

	AuthzDecisions *prometheus.CounterVec
	AuthzLatency   prometheus.Histogram
	PolicyCacheOps *prometheus.CounterVec

	RiskScore     *prometheus.HistogramVec
	RateLimitHits *prometheus.CounterVec

	AuditBuffered prometheus.Gauge
	AuditWritten  prometheus.Counter
	AuditDropped  prometheus.Counter

	ActiveSessions *prometheus.GaugeVec
	SigningKeys    prometheus.Gauge

	tenants *TenantLabeller
}

func NewMetrics(maxTenantLabels int) *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	m := &Metrics{
		Registry: reg,
		tenants:  NewTenantLabeller(maxTenantLabels),

		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_http_requests_total",
			Help: "Total HTTP requests handled by the gateway.",
		}, []string{"method", "route", "status", "tenant"}),

		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "gateway_http_request_duration_seconds",
			Help:    "End-to-end request latency including the full verification chain.",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}, []string{"method", "route"}),

		HTTPInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_http_in_flight_requests",
			Help: "Requests currently being served.",
		}),

		AuthAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_auth_attempts_total",
			Help: "Authentication attempts by outcome.",
		}, []string{"outcome", "tenant"}),

		TokensIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_tokens_issued_total",
			Help: "Access and refresh tokens issued.",
		}, []string{"type", "tenant"}),

		TokenRefresh: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_token_refresh_total",
			Help: "Refresh-token exchanges by outcome; reuse_detected indicates a replayed token.",
		}, []string{"outcome"}),

		VerifyFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_token_verify_failures_total",
			Help: "Per-request verification failures, labelled by which check rejected the request.",
		}, []string{"stage"}),

		AuthzDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_authz_decisions_total",
			Help: "Authorization decisions by effect and reason.",
		}, []string{"decision", "reason", "tenant"}),

		AuthzLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "gateway_authz_evaluation_seconds",
			Help:    "Time to evaluate the effective permission set for a principal.",
			Buckets: []float64{.0001, .0005, .001, .005, .01, .05, .1},
		}),

		PolicyCacheOps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_policy_cache_ops_total",
			Help: "Permission cache hits and misses.",
		}, []string{"result"}),

		RiskScore: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "gateway_request_risk_score",
			Help:    "Continuous-evaluation risk score assigned per request.",
			Buckets: []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		}, []string{"outcome"}),

		RateLimitHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gateway_rate_limit_rejections_total",
			Help: "Requests rejected by the rate limiter, labelled by which dimension tripped.",
		}, []string{"dimension", "tenant"}),

		AuditBuffered: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_audit_buffer_depth",
			Help: "Audit events waiting to be flushed.",
		}),

		AuditWritten: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gateway_audit_events_written_total",
			Help: "Audit events durably written.",
		}),

		AuditDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gateway_audit_events_dropped_total",
			Help: "Audit events dropped because the buffer was full. Should always be zero.",
		}),

		ActiveSessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "gateway_active_sessions",
			Help: "Live sessions per tenant.",
		}, []string{"tenant"}),

		SigningKeys: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_signing_keys",
			Help: "Signing keys currently trusted for verification.",
		}),
	}

	reg.MustRegister(
		m.HTTPRequests, m.HTTPDuration, m.HTTPInFlight,
		m.AuthAttempts, m.TokensIssued, m.TokenRefresh, m.VerifyFailures,
		m.AuthzDecisions, m.AuthzLatency, m.PolicyCacheOps,
		m.RiskScore, m.RateLimitHits,
		m.AuditBuffered, m.AuditWritten, m.AuditDropped,
		m.ActiveSessions, m.SigningKeys,
	)
	return m
}

// Tenant returns a cardinality-safe label value for a tenant slug.
func (m *Metrics) Tenant(slug string) string { return m.tenants.Label(slug) }

// TenantLabeller keeps the tenant label bounded. The first maxLabels tenants
// observed keep their own slug; every later tenant collapses into "other", so a
// burst of new tenants cannot create unbounded time series.
type TenantLabeller struct {
	mu        sync.RWMutex
	known     map[string]struct{}
	maxLabels int
}

func NewTenantLabeller(maxLabels int) *TenantLabeller {
	if maxLabels <= 0 {
		maxLabels = 50
	}
	return &TenantLabeller{known: make(map[string]struct{}, maxLabels), maxLabels: maxLabels}
}

func (t *TenantLabeller) Label(slug string) string {
	if slug == "" {
		return "none"
	}
	t.mu.RLock()
	_, ok := t.known[slug]
	full := len(t.known) >= t.maxLabels
	t.mu.RUnlock()
	if ok {
		return slug
	}
	if full {
		return "other"
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.known[slug]; ok {
		return slug
	}
	if len(t.known) >= t.maxLabels {
		return "other"
	}
	t.known[slug] = struct{}{}
	return slug
}
