// Package hooks provides event hooks for real-time integrations.
// Hooks are called during scan execution to send events to external systems
// such as webhooks, Slack, GitHub Actions, and other CI/CD platforms.
package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
	"github.com/waftester/waftester/pkg/retry"
)

// Compile-time interface check.
var _ dispatcher.Hook = (*WebhookHook)(nil)

// WebhookHook sends events to an HTTP endpoint.
// It supports retries with exponential backoff, custom headers,
// and filtering by event type or severity.
type WebhookHook struct {
	endpoint string
	client   *http.Client
	opts     WebhookOptions
	logger   *slog.Logger
}

// WebhookOptions configures the webhook hook behavior.
type WebhookOptions struct {
	// Headers to include in requests.
	Headers map[string]string

	// Timeout for HTTP requests (default: 10s).
	Timeout time.Duration

	// RetryCount for failed requests (default: 3).
	RetryCount int

	// OnlyBypasses only sends bypass events.
	OnlyBypasses bool

	// MinSeverity filters events below this severity.
	// Events with severity less severe than this will be skipped.
	MinSeverity events.Severity

	// Logger for structured logging (default: slog.Default()).
	Logger *slog.Logger
}

// severityOrder maps severity to numeric order for comparison.
// Higher number = more severe.
var severityOrder = map[events.Severity]int{
	events.SeverityInfo:     1,
	events.SeverityLow:      2,
	events.SeverityMedium:   3,
	events.SeverityHigh:     4,
	events.SeverityCritical: 5,
}

// NewWebhookHook creates a new webhook hook that sends events to the given endpoint.
// The hook is safe for concurrent use.
func NewWebhookHook(endpoint string, opts WebhookOptions) *WebhookHook {
	// Apply defaults
	if opts.Timeout == 0 {
		opts.Timeout = duration.WebhookTimeout
	}
	if opts.RetryCount == 0 {
		opts.RetryCount = defaults.RetryMedium
	}

	return &WebhookHook{
		endpoint: endpoint,
		client:   httpclient.New(httpclient.Config{Timeout: opts.Timeout}),
		opts:     opts,
		logger:   orDefault(opts.Logger),
	}
}

// OnEvent sends the event to the configured webhook endpoint.
// It returns nil on success or if the event should be skipped.
// Errors are logged but do not block the scan.
func (h *WebhookHook) OnEvent(ctx context.Context, event events.Event) error {
	// Apply OnlyBypasses filter
	if h.opts.OnlyBypasses && event.EventType() != events.EventTypeBypass {
		return nil
	}

	// Apply MinSeverity filter
	if h.opts.MinSeverity != "" && !h.meetsMinSeverity(event) {
		return nil
	}

	// Serialize event to JSON
	body, err := json.Marshal(event)
	if err != nil {
		h.logger.Warn("failed to marshal event", slog.String("error", err.Error()))
		return nil // Don't block scan on serialization errors
	}

	// Send with retries
	if err := h.sendWithRetry(ctx, event.EventType(), body); err != nil {
		h.logger.Warn("failed to send event after retries", slog.String("error", err.Error()))
		return nil // Don't block scan on webhook failures
	}

	return nil
}

// EventTypes returns nil to receive all event types.
// Filtering is done in OnEvent based on options.
func (h *WebhookHook) EventTypes() []events.EventType {
	return nil
}

// meetsMinSeverity checks if the event meets the minimum severity threshold.
func (h *WebhookHook) meetsMinSeverity(event events.Event) bool {
	minOrder, ok := severityOrder[h.opts.MinSeverity]
	if !ok {
		return true // Unknown severity, allow through
	}

	// Extract severity from the event
	var eventSeverity events.Severity
	switch e := event.(type) {
	case *events.ResultEvent:
		eventSeverity = e.Test.Severity
	case *events.BypassEvent:
		eventSeverity = e.Details.Severity
	default:
		return true // Non-severity events pass through
	}

	eventOrder, ok := severityOrder[eventSeverity]
	if !ok {
		return true // Unknown severity, allow through
	}

	return eventOrder >= minOrder
}

// sendWithRetry sends the request with exponential backoff retries.
func (h *WebhookHook) sendWithRetry(ctx context.Context, eventType events.EventType, body []byte) error {
	cfg := retry.Config{
		MaxAttempts: h.opts.RetryCount,
		InitDelay:   1 * time.Second,
		MaxDelay:    30 * time.Second,
		Strategy:    retry.Exponential,
	}

	return retry.Do(ctx, cfg, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(body))
		if err != nil {
			return retry.Stop(fmt.Errorf("failed to create request: %w", err))
		}

		// Set headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", defaults.ToolName+"/"+defaults.Version)
		req.Header.Set("X-WAFtester-Event-Type", string(eventType))

		for key, value := range h.opts.Headers {
			req.Header.Set(key, value)
		}

		resp, err := h.client.Do(req)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()

		// Success
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		// Retry on 5xx errors
		if resp.StatusCode >= 500 {
			return fmt.Errorf("server error: %d", resp.StatusCode)
		}

		// Don't retry on 4xx errors
		return retry.Stop(fmt.Errorf("client error: %d", resp.StatusCode))
	})
}
