package hooks

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Compile-time interface check.
var _ dispatcher.Hook = (*OTelHook)(nil)

// OTelHook exports scan telemetry to an OpenTelemetry collector.
// It creates spans for scans and records events as span events with attributes.
// The hook supports traces and can be extended for metrics.
type OTelHook struct {
	opts           OTelOptions
	tracerProvider *sdktrace.TracerProvider
	tracer         trace.Tracer

	// Active span tracking
	mu       sync.Mutex
	rootSpan trace.Span
	rootCtx  context.Context
	closed   bool

	// Scan metadata for attributes
	scanID    string
	target    string
	startTime time.Time
}

// OTelOptions configures the OpenTelemetry hook behavior.
type OTelOptions struct {
	// Endpoint is the OTLP endpoint (e.g., "localhost:4317").
	Endpoint string

	// ServiceName is the service name for traces (default: "waftester").
	ServiceName string

	// Insecure uses insecure connection (no TLS).
	Insecure bool

	// Headers contains additional headers for the OTLP exporter.
	Headers map[string]string

	// ShutdownTimeout is the timeout for graceful shutdown (default: 5s).
	ShutdownTimeout time.Duration

	// ConnectionTimeout is the timeout for establishing connection (default: 10s).
	ConnectionTimeout time.Duration
}

// NewOTelHook creates a new OpenTelemetry hook that exports telemetry to the configured endpoint.
// The exporter connects immediately but handles connection failures gracefully without blocking scans.
func NewOTelHook(opts OTelOptions) (*OTelHook, error) {
	// Apply defaults
	if opts.ServiceName == "" {
		opts.ServiceName = defaults.ToolName
	}
	if opts.Endpoint == "" {
		opts.Endpoint = "localhost:4317"
	}
	if opts.ShutdownTimeout == 0 {
		opts.ShutdownTimeout = duration.WebhookShutdown
	}
	if opts.ConnectionTimeout == 0 {
		opts.ConnectionTimeout = duration.WebhookTimeout
	}

	// Build gRPC options
	grpcOpts := []grpc.DialOption{}
	if opts.Insecure {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Build exporter options
	exporterOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(opts.Endpoint),
		otlptracegrpc.WithDialOption(grpcOpts...),
	}

	if opts.Insecure {
		exporterOpts = append(exporterOpts, otlptracegrpc.WithInsecure())
	}

	if len(opts.Headers) > 0 {
		exporterOpts = append(exporterOpts, otlptracegrpc.WithHeaders(opts.Headers))
	}

	// Create exporter with context timeout for connection
	ctx, cancel := context.WithTimeout(context.Background(), opts.ConnectionTimeout)
	defer cancel()

	exporter, err := otlptracegrpc.New(ctx, exporterOpts...)
	if err != nil {
		return nil, err
	}

	// Create resource with service info (avoid merging with Default to prevent schema conflicts)
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(opts.ServiceName),
		semconv.ServiceVersion(defaults.Version),
		attribute.String("service.component", "scanner"),
	)

	// Create tracer provider with batch processor for efficiency
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Set as global provider
	otel.SetTracerProvider(tracerProvider)

	hook := &OTelHook{
		opts:           opts,
		tracerProvider: tracerProvider,
		tracer:         tracerProvider.Tracer("waftester/scanner"),
		startTime:      time.Now(),
	}

	return hook, nil
}

// OnEvent processes events and exports telemetry to the OpenTelemetry collector.
func (h *OTelHook) OnEvent(ctx context.Context, event events.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}

	switch e := event.(type) {
	case *events.StartEvent:
		return h.handleStart(ctx, e)
	case *events.ProgressEvent:
		return h.handleProgress(e)
	case *events.ResultEvent:
		return h.handleResult(e)
	case *events.BypassEvent:
		return h.handleBypass(e)
	case *events.SummaryEvent:
		return h.handleSummary(e)
	case *events.CompleteEvent:
		return h.handleComplete(e)
	default:
		return nil
	}
}

// handleStart creates the root span for the scan.
func (h *OTelHook) handleStart(ctx context.Context, start *events.StartEvent) error {
	h.scanID = start.ScanID()
	h.target = start.Target
	h.startTime = start.Timestamp()

	// Create root span for the entire scan
	spanCtx, span := h.tracer.Start(ctx, "waftester.scan",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("scan_id", h.scanID),
			attribute.String("target", h.target),
			attribute.String("waf_vendor", start.WAFVendor),
			attribute.Int("total_tests", start.TotalTests),
			attribute.Int("concurrency", start.Config.Concurrency),
			attribute.Int("timeout_sec", start.Config.Timeout),
			attribute.StringSlice("categories", start.Categories),
		),
	)

	h.rootSpan = span
	h.rootCtx = spanCtx

	// Add span event for scan start
	span.AddEvent("scan_started", trace.WithAttributes(
		attribute.String("target", h.target),
		attribute.Int("total_tests", start.TotalTests),
	))

	return nil
}

// handleProgress adds span events for progress updates.
func (h *OTelHook) handleProgress(progress *events.ProgressEvent) error {
	if h.rootSpan == nil {
		return nil
	}

	h.rootSpan.AddEvent("progress_update", trace.WithAttributes(
		attribute.String("phase", progress.Progress.Phase),
		attribute.Int("current", progress.Progress.Current),
		attribute.Int("total", progress.Progress.Total),
		attribute.Float64("percentage", progress.Progress.Percentage),
		attribute.Float64("requests_per_sec", progress.Rate.RequestsPerSec),
		attribute.Float64("avg_latency_ms", progress.Rate.AvgLatencyMs),
		attribute.Int("bypasses", progress.Stats.Bypasses),
		attribute.Int("blocked", progress.Stats.Blocked),
		attribute.Int("errors", progress.Stats.Errors),
		attribute.Float64("effectiveness_pct", progress.Stats.EffectivenessPct),
	))

	return nil
}

// handleResult records test results as span events with detailed attributes.
func (h *OTelHook) handleResult(result *events.ResultEvent) error {
	if h.rootSpan == nil {
		return nil
	}

	eventName := "test_result"
	if result.Result.Outcome == events.OutcomeBypass {
		eventName = "bypass_detected"
	}

	h.rootSpan.AddEvent(eventName, trace.WithAttributes(
		attribute.String("scan_id", h.scanID),
		attribute.String("target", result.Target.URL),
		attribute.String("test_id", result.Test.ID),
		attribute.String("category", result.Test.Category),
		attribute.String("severity", string(result.Test.Severity)),
		attribute.String("outcome", string(result.Result.Outcome)),
		attribute.Int("status_code", result.Result.StatusCode),
		attribute.Float64("latency_ms", result.Result.LatencyMs),
		attribute.String("method", result.Target.Method),
		attribute.String("endpoint", result.Target.Endpoint),
	))

	// Set span status to error if bypass detected
	if result.Result.Outcome == events.OutcomeBypass {
		h.rootSpan.SetStatus(codes.Error, "WAF bypass detected")
	}

	return nil
}

// handleBypass records bypass events with critical priority attributes.
func (h *OTelHook) handleBypass(bypass *events.BypassEvent) error {
	if h.rootSpan == nil {
		return nil
	}

	h.rootSpan.AddEvent("bypass_alert", trace.WithAttributes(
		attribute.String("scan_id", h.scanID),
		attribute.String("priority", bypass.Priority),
		attribute.String("test_id", bypass.Details.TestID),
		attribute.String("category", bypass.Details.Category),
		attribute.String("severity", string(bypass.Details.Severity)),
		attribute.Int("status_code", bypass.Details.StatusCode),
		attribute.String("endpoint", bypass.Details.Endpoint),
		attribute.String("method", bypass.Details.Method),
		attribute.String("encoding", bypass.Details.Encoding),
		attribute.String("tamper", bypass.Details.Tamper),
		attribute.String("waf_detected", bypass.Context.WAFDetected),
		attribute.Int("bypasses_so_far", bypass.Context.BypassesSoFar),
	))

	// Mark span with error status for bypasses
	h.rootSpan.SetStatus(codes.Error, bypass.Alert.Title)

	return nil
}

// handleSummary adds summary attributes to the root span.
func (h *OTelHook) handleSummary(summary *events.SummaryEvent) error {
	if h.rootSpan == nil {
		return nil
	}

	// Add comprehensive summary attributes to root span
	h.rootSpan.SetAttributes(
		attribute.String("target.url", summary.Target.URL),
		attribute.String("target.waf_detected", summary.Target.WAFDetected),
		attribute.Float64("target.waf_confidence", summary.Target.WAFConfidence),
		attribute.Int("totals.tests", summary.Totals.Tests),
		attribute.Int("totals.bypasses", summary.Totals.Bypasses),
		attribute.Int("totals.blocked", summary.Totals.Blocked),
		attribute.Int("totals.errors", summary.Totals.Errors),
		attribute.Int("totals.timeouts", summary.Totals.Timeouts),
		attribute.Float64("effectiveness.block_rate_pct", summary.Effectiveness.BlockRatePct),
		attribute.String("effectiveness.grade", summary.Effectiveness.Grade),
		attribute.Float64("timing.duration_sec", summary.Timing.DurationSec),
		attribute.Float64("timing.requests_per_sec", summary.Timing.RequestsPerSec),
		attribute.Int("exit_code", summary.ExitCode),
		attribute.String("exit_reason", summary.ExitReason),
	)

	// Add summary event
	h.rootSpan.AddEvent("scan_summary", trace.WithAttributes(
		attribute.Int("tests", summary.Totals.Tests),
		attribute.Int("bypasses", summary.Totals.Bypasses),
		attribute.Int("blocked", summary.Totals.Blocked),
		attribute.Float64("block_rate_pct", summary.Effectiveness.BlockRatePct),
		attribute.String("grade", summary.Effectiveness.Grade),
		attribute.Float64("duration_sec", summary.Timing.DurationSec),
	))

	// Set final span status based on results
	if summary.Totals.Bypasses > 0 {
		h.rootSpan.SetStatus(codes.Error, "Scan completed with bypasses detected")
	} else {
		h.rootSpan.SetStatus(codes.Ok, "Scan completed successfully")
	}

	return nil
}

// handleComplete finalizes the scan span and flushes telemetry.
func (h *OTelHook) handleComplete(complete *events.CompleteEvent) error {
	if h.rootSpan == nil {
		return nil
	}

	// Add completion event
	h.rootSpan.AddEvent("scan_completed", trace.WithAttributes(
		attribute.Bool("success", complete.Success),
		attribute.Int("exit_code", complete.ExitCode),
		attribute.String("exit_reason", complete.ExitReason),
	))

	// Set final status based on success
	if complete.Success {
		if complete.Summary != nil && complete.Summary.Totals.Bypasses > 0 {
			h.rootSpan.SetStatus(codes.Error, "Completed with bypasses")
		} else {
			h.rootSpan.SetStatus(codes.Ok, "Completed successfully")
		}
	} else {
		h.rootSpan.SetStatus(codes.Error, complete.ExitReason)
	}

	// End the root span
	h.rootSpan.End()
	h.rootSpan = nil

	return nil
}

// EventTypes returns the event types this hook handles.
func (h *OTelHook) EventTypes() []events.EventType {
	return []events.EventType{
		events.EventTypeStart,
		events.EventTypeProgress,
		events.EventTypeResult,
		events.EventTypeBypass,
		events.EventTypeSummary,
		events.EventTypeComplete,
	}
}

// Close shuts down the tracer provider and flushes any pending telemetry.
func (h *OTelHook) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}
	h.closed = true

	// End any active span
	if h.rootSpan != nil {
		h.rootSpan.End()
		h.rootSpan = nil
	}

	// Shutdown tracer provider with timeout
	if h.tracerProvider != nil {
		ctx, cancel := context.WithTimeout(context.Background(), h.opts.ShutdownTimeout)
		defer cancel()

		if err := h.tracerProvider.Shutdown(ctx); err != nil {
			return fmt.Errorf("otel: shutdown tracer provider: %w", err)
		}
	}

	return nil
}

// Endpoint returns the OTLP endpoint being used.
// Useful for testing and logging.
func (h *OTelHook) Endpoint() string {
	return h.opts.Endpoint
}

// ServiceName returns the service name being used.
func (h *OTelHook) ServiceName() string {
	return h.opts.ServiceName
}
