package hooks

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Hook = (*PrometheusHook)(nil)

// PrometheusHook exposes scan metrics for Prometheus scraping.
// It starts an HTTP server that serves metrics at the configured path.
// Metrics include counters for tests/bypasses/blocked/errors, gauges for
// effectiveness and duration, and histograms for response time distribution.
type PrometheusHook struct {
	server   *http.Server
	registry *prometheus.Registry
	opts     PrometheusOptions

	// Counters
	testsTotal    *prometheus.CounterVec
	bypassesTotal *prometheus.CounterVec
	blockedTotal  *prometheus.CounterVec
	errorsTotal   *prometheus.CounterVec

	// Gauges
	effectivenessPercent *prometheus.GaugeVec
	scanDurationSeconds  *prometheus.GaugeVec

	// Histograms
	responseTimeSeconds *prometheus.HistogramVec

	// Internal tracking
	startTime time.Time
	mu        sync.Mutex
	closed    bool
}

// PrometheusOptions configures the Prometheus hook behavior.
type PrometheusOptions struct {
	// Port for the metrics server (default: 9090).
	Port int

	// Path for the metrics endpoint (default: "/metrics").
	Path string

	// ReadTimeout for the HTTP server (default: 5s).
	ReadTimeout time.Duration

	// WriteTimeout for the HTTP server (default: 10s).
	WriteTimeout time.Duration
}

// NewPrometheusHook creates a new Prometheus hook that exposes metrics at the configured endpoint.
// The metrics server starts immediately and runs until Close() is called.
func NewPrometheusHook(opts PrometheusOptions) (*PrometheusHook, error) {
	// Apply defaults
	if opts.Port == 0 {
		opts.Port = 9090
	}
	if opts.Path == "" {
		opts.Path = "/metrics"
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = duration.WebhookShutdown
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = duration.WebhookTimeout
	}

	// Create custom registry (don't pollute default)
	registry := prometheus.NewRegistry()

	hook := &PrometheusHook{
		registry:  registry,
		opts:      opts,
		startTime: time.Now(),
	}

	// Initialize metrics
	if err := hook.initMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	// Start HTTP server
	if err := hook.startServer(); err != nil {
		return nil, fmt.Errorf("failed to start metrics server: %w", err)
	}

	return hook, nil
}

// initMetrics creates and registers all Prometheus metrics.
func (h *PrometheusHook) initMetrics() error {
	// Counters
	h.testsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waftester_tests_total",
			Help: "Total number of WAF tests executed",
		},
		[]string{"target", "category"},
	)

	h.bypassesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waftester_bypasses_total",
			Help: "Total number of WAF bypasses detected",
		},
		[]string{"target", "category", "severity"},
	)

	h.blockedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waftester_blocked_total",
			Help: "Total number of requests blocked by WAF",
		},
		[]string{"target", "category"},
	)

	h.errorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waftester_errors_total",
			Help: "Total number of errors during testing",
		},
		[]string{"target", "type"},
	)

	// Gauges
	h.effectivenessPercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "waftester_effectiveness_percent",
			Help: "WAF effectiveness percentage (blocked / total * 100)",
		},
		[]string{"target"},
	)

	h.scanDurationSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "waftester_scan_duration_seconds",
			Help: "Total scan duration in seconds",
		},
		[]string{"target"},
	)

	// Histograms
	h.responseTimeSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "waftester_response_time_seconds",
			Help:    "Response time distribution in seconds",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"target", "outcome"},
	)

	// Register all metrics
	collectors := []prometheus.Collector{
		h.testsTotal,
		h.bypassesTotal,
		h.blockedTotal,
		h.errorsTotal,
		h.effectivenessPercent,
		h.scanDurationSeconds,
		h.responseTimeSeconds,
	}

	for _, c := range collectors {
		if err := h.registry.Register(c); err != nil {
			return err
		}
	}

	return nil
}

// startServer starts the HTTP server for metrics.
func (h *PrometheusHook) startServer() error {
	mux := http.NewServeMux()
	mux.Handle(h.opts.Path, promhttp.HandlerFor(h.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	h.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", h.opts.Port),
		Handler:      mux,
		ReadTimeout:  h.opts.ReadTimeout,
		WriteTimeout: h.opts.WriteTimeout,
	}

	// Start server in goroutine
	go func() {
		if err := h.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("prometheus: metrics server error: %v", err)
		}
	}()

	return nil
}

// OnEvent processes events and updates Prometheus metrics.
func (h *PrometheusHook) OnEvent(ctx context.Context, event events.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}

	switch e := event.(type) {
	case *events.ResultEvent:
		return h.handleResult(e)
	case *events.BypassEvent:
		return h.handleBypass(e)
	case *events.SummaryEvent:
		return h.handleSummary(e)
	case *events.ProgressEvent:
		return h.handleProgress(e)
	default:
		return nil
	}
}

// handleResult processes result events and updates metrics.
func (h *PrometheusHook) handleResult(result *events.ResultEvent) error {
	target := extractHost(result.Target.URL)
	category := result.Test.Category

	// Always increment tests counter
	h.testsTotal.WithLabelValues(target, category).Inc()

	// Update outcome-specific counters
	switch result.Result.Outcome {
	case events.OutcomeBlocked:
		h.blockedTotal.WithLabelValues(target, category).Inc()
	case events.OutcomeBypass:
		h.bypassesTotal.WithLabelValues(target, category, string(result.Test.Severity)).Inc()
	case events.OutcomeError, events.OutcomeTimeout:
		h.errorsTotal.WithLabelValues(target, string(result.Result.Outcome)).Inc()
	}

	// Record response time histogram (convert ms to seconds)
	if result.Result.LatencyMs > 0 {
		h.responseTimeSeconds.WithLabelValues(target, string(result.Result.Outcome)).Observe(result.Result.LatencyMs / 1000.0)
	}

	return nil
}

// handleBypass processes bypass events and updates metrics.
func (h *PrometheusHook) handleBypass(bypass *events.BypassEvent) error {
	target := extractHost(bypass.Details.Endpoint)
	category := bypass.Details.Category
	severity := string(bypass.Details.Severity)

	h.bypassesTotal.WithLabelValues(target, category, severity).Inc()

	return nil
}

// handleSummary processes summary events and updates final metrics.
func (h *PrometheusHook) handleSummary(summary *events.SummaryEvent) error {
	target := extractHost(summary.Target.URL)

	// Update effectiveness gauge
	h.effectivenessPercent.WithLabelValues(target).Set(summary.Effectiveness.BlockRatePct)

	// Update duration gauge
	h.scanDurationSeconds.WithLabelValues(target).Set(summary.Timing.DurationSec)

	return nil
}

// handleProgress processes progress events for real-time metrics.
func (h *PrometheusHook) handleProgress(progress *events.ProgressEvent) error {
	// We don't derive target from progress events as they don't contain target info
	// Progress metrics are primarily for real-time monitoring during scans
	// The final summary event will set the definitive values
	return nil
}

// EventTypes returns the event types this hook handles.
func (h *PrometheusHook) EventTypes() []events.EventType {
	return []events.EventType{
		events.EventTypeResult,
		events.EventTypeBypass,
		events.EventTypeSummary,
		events.EventTypeProgress,
	}
}

// Close shuts down the metrics server and releases resources.
func (h *PrometheusHook) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}
	h.closed = true

	if h.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), duration.WebhookShutdown)
		defer cancel()
		return h.server.Shutdown(ctx)
	}

	return nil
}

// MetricsAddr returns the address where metrics are served.
// Useful for testing and logging.
func (h *PrometheusHook) MetricsAddr() string {
	return fmt.Sprintf("http://localhost:%d%s", h.opts.Port, h.opts.Path)
}

// extractHost extracts the host from a URL for use as a metric label.
// Returns "unknown" if the URL is empty or malformed.
func extractHost(rawURL string) string {
	if rawURL == "" {
		return "unknown"
	}

	// Simple extraction - find the host portion
	// For full URLs like "https://example.com/path"
	start := 0
	if idx := findIndex(rawURL, "://"); idx >= 0 {
		start = idx + 3
	}

	// Find end of host (first / or end of string)
	end := len(rawURL)
	for i := start; i < len(rawURL); i++ {
		if rawURL[i] == '/' || rawURL[i] == '?' || rawURL[i] == '#' {
			end = i
			break
		}
	}

	host := rawURL[start:end]
	if host == "" {
		return "unknown"
	}
	return host
}

// findIndex returns the index of the first occurrence of substr in s,
// or -1 if not found.
func findIndex(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
