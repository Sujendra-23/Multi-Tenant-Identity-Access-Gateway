package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewMetricsServer builds the internal-only HTTP server that exposes
// /metrics. It is intentionally separate from the tenant-facing API server: an
// operator scrapes this from inside the cluster network (see
// deploy/k8s/networkpolicy.yaml, which allows it only from the Prometheus
// namespace), and it carries none of the tenant auth, rate limiting or CORS
// concerns the public port needs, because it was never meant to be reachable
// from outside it.
func NewMetricsServer(addr string, m *Metrics) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
	return &http.Server{Addr: addr, Handler: mux}
}
