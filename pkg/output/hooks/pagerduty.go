package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Hook = (*PagerDutyHook)(nil)

// PagerDutyHook creates incidents in PagerDuty via the Events API v2.
// It sends alerts for WAF bypasses that meet the severity threshold.
type PagerDutyHook struct {
	routingKey string
	client     *http.Client
	opts       PagerDutyOptions
}

// PagerDutyOptions configures the PagerDuty hook behavior.
type PagerDutyOptions struct {
	// MinSeverity to trigger incident (default: high).
	MinSeverity events.Severity

	// Source identifier (default: "waftester").
	Source string

	// Component for the incident.
	Component string

	// Timeout for HTTP requests (default: 10s).
	Timeout time.Duration
}

// pagerDutyEvent represents the PagerDuty Events API v2 payload.
type pagerDutyEvent struct {
	RoutingKey  string           `json:"routing_key"`
	EventAction string           `json:"event_action"`
	DedupKey    string           `json:"dedup_key"`
	Payload     pagerDutyPayload `json:"payload"`
	Links       []pagerDutyLink  `json:"links,omitempty"`
	Images      []pagerDutyImage `json:"images,omitempty"`
}

// pagerDutyPayload contains the incident details.
type pagerDutyPayload struct {
	Summary       string                 `json:"summary"`
	Source        string                 `json:"source"`
	Severity      string                 `json:"severity"`
	Timestamp     string                 `json:"timestamp"`
	Component     string                 `json:"component,omitempty"`
	Group         string                 `json:"group,omitempty"`
	Class         string                 `json:"class,omitempty"`
	CustomDetails map[string]interface{} `json:"custom_details,omitempty"`
}

// pagerDutyLink represents a link in the PagerDuty event.
type pagerDutyLink struct {
	Href string `json:"href"`
	Text string `json:"text"`
}

// pagerDutyImage represents an image in the PagerDuty event.
type pagerDutyImage struct {
	Src  string `json:"src"`
	Href string `json:"href,omitempty"`
	Alt  string `json:"alt,omitempty"`
}

// pagerDutySeverityMap maps WAFtester severity to PagerDuty severity.
var pagerDutySeverityMap = map[events.Severity]string{
	events.SeverityCritical: "critical",
	events.SeverityHigh:     "error",
	events.SeverityMedium:   "warning",
	events.SeverityLow:      "info",
	events.SeverityInfo:     "info",
}

// NewPagerDutyHook creates a new PagerDuty hook that sends events to PagerDuty.
func NewPagerDutyHook(routingKey string, opts PagerDutyOptions) *PagerDutyHook {
	// Apply defaults
	if opts.MinSeverity == "" {
		opts.MinSeverity = events.SeverityHigh
	}
	if opts.Source == "" {
		opts.Source = defaults.ToolName
	}
	if opts.Component == "" {
		opts.Component = "web-application-firewall"
	}
	if opts.Timeout == 0 {
		opts.Timeout = duration.WebhookTimeout
	}

	return &PagerDutyHook{
		routingKey: routingKey,
		client: &http.Client{
			Timeout: opts.Timeout,
		},
		opts: opts,
	}
}

// OnEvent processes events and sends them to PagerDuty.
// Only bypass events that meet the MinSeverity threshold are sent.
func (h *PagerDutyHook) OnEvent(ctx context.Context, event events.Event) error {
	bypass, ok := event.(*events.BypassEvent)
	if !ok {
		return nil
	}

	// Apply MinSeverity filter
	if !h.meetsMinSeverity(bypass.Details.Severity) {
		return nil
	}

	return h.sendEvent(ctx, bypass)
}

// EventTypes returns the event types this hook handles.
func (h *PagerDutyHook) EventTypes() []events.EventType {
	return []events.EventType{
		events.EventTypeBypass,
	}
}

// meetsMinSeverity checks if the severity meets the minimum threshold.
func (h *PagerDutyHook) meetsMinSeverity(severity events.Severity) bool {
	minOrder, ok := severityOrder[h.opts.MinSeverity]
	if !ok {
		return true
	}

	eventOrder, ok := severityOrder[severity]
	if !ok {
		return true
	}

	return eventOrder >= minOrder
}

// sendEvent sends a bypass event to PagerDuty.
func (h *PagerDutyHook) sendEvent(ctx context.Context, bypass *events.BypassEvent) error {
	pdEvent := h.buildEvent(bypass)

	body, err := json.Marshal(pdEvent)
	if err != nil {
		log.Printf("pagerduty: failed to marshal event: %v", err)
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://events.pagerduty.com/v2/enqueue", bytes.NewReader(body))
	if err != nil {
		log.Printf("pagerduty: failed to create request: %v", err)
		return nil
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		log.Printf("pagerduty: failed to send event: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("pagerduty: received error status %d", resp.StatusCode)
		return nil
	}

	return nil
}

// buildEvent constructs the PagerDuty event payload from a bypass event.
func (h *PagerDutyHook) buildEvent(bypass *events.BypassEvent) pagerDutyEvent {
	pdSeverity := pagerDutySeverityMap[bypass.Details.Severity]
	if pdSeverity == "" {
		pdSeverity = "error"
	}

	dedupKey := h.generateDedupKey(bypass)
	summary := fmt.Sprintf("WAF Bypass Detected: %s (%s)",
		capitalize(bypass.Details.Category),
		bypass.Details.Severity)

	customDetails := map[string]interface{}{
		"test_id":     bypass.Details.TestID,
		"category":    bypass.Details.Category,
		"target":      bypass.Details.Endpoint,
		"status_code": bypass.Details.StatusCode,
	}

	if bypass.Details.Curl != "" {
		customDetails["curl_command"] = bypass.Details.Curl
	}
	if bypass.Details.Payload != "" {
		customDetails["payload"] = bypass.Details.Payload
	}
	if bypass.Details.Method != "" {
		customDetails["method"] = bypass.Details.Method
	}

	return pagerDutyEvent{
		RoutingKey:  h.routingKey,
		EventAction: "trigger",
		DedupKey:    dedupKey,
		Payload: pagerDutyPayload{
			Summary:       summary,
			Source:        h.opts.Source,
			Severity:      pdSeverity,
			Timestamp:     bypass.Timestamp().Format(time.RFC3339),
			Component:     h.opts.Component,
			Group:         bypass.Details.Category,
			Class:         "waf-bypass",
			CustomDetails: customDetails,
		},
	}
}

// generateDedupKey creates a unique key for deduplication.
func (h *PagerDutyHook) generateDedupKey(bypass *events.BypassEvent) string {
	// Extract host from endpoint
	host := ""
	if bypass.Details.Endpoint != "" {
		if u, err := url.Parse(bypass.Details.Endpoint); err == nil {
			host = u.Host
		}
	}

	// Format: waftester-{testid}-{host}
	parts := []string{defaults.ToolName, bypass.Details.TestID}
	if host != "" {
		parts = append(parts, host)
	}

	return strings.Join(parts, "-")
}
