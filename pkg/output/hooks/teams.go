package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Hook = (*TeamsHook)(nil)

// TeamsHook sends formatted messages to Microsoft Teams via incoming webhooks.
// It uses MessageCard format for rich formatting of scan summaries.
type TeamsHook struct {
	webhookURL string
	client     *http.Client
	opts       TeamsOptions
	bypasses   []*events.BypassEvent
	mu         sync.Mutex
	logger     *slog.Logger
}

// TeamsOptions configures the Teams hook behavior.
type TeamsOptions struct {
	// MinSeverity filters events below this severity.
	MinSeverity events.Severity

	// OnlyOnBypasses only sends the summary if bypasses were detected.
	OnlyOnBypasses bool

	// Timeout for HTTP requests (default: 10s).
	Timeout time.Duration

	// Logger for structured logging (default: slog.Default()).
	Logger *slog.Logger
}

// Teams theme colors based on severity.
const (
	teamsColorGreen  = "00FF00" // No bypasses
	teamsColorYellow = "FFFF00" // Low/medium severity bypasses
	teamsColorRed    = "FF0000" // High/critical severity bypasses
	teamsColorBlue   = "0076D7" // Default/neutral
)

// NewTeamsHook creates a new Teams hook that sends messages to the given webhook URL.
func NewTeamsHook(webhookURL string, opts TeamsOptions) *TeamsHook {
	// Apply defaults
	if opts.Timeout == 0 {
		opts.Timeout = duration.WebhookTimeout
	}

	return &TeamsHook{
		webhookURL: webhookURL,
		client:     httpclient.New(httpclient.Config{Timeout: opts.Timeout}),
		opts:       opts,
		bypasses:   make([]*events.BypassEvent, 0),
		logger:     orDefault(opts.Logger),
	}
}

// OnEvent processes events and sends them to Teams.
// Summary events trigger the MessageCard to be sent.
func (h *TeamsHook) OnEvent(ctx context.Context, event events.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch e := event.(type) {
	case *events.BypassEvent:
		return h.handleBypass(e)
	case *events.SummaryEvent:
		return h.handleSummary(ctx, e)
	default:
		return nil
	}
}

// EventTypes returns the event types this hook handles.
func (h *TeamsHook) EventTypes() []events.EventType {
	return []events.EventType{
		events.EventTypeBypass,
		events.EventTypeSummary,
	}
}

// handleBypass collects bypass events for the summary.
func (h *TeamsHook) handleBypass(bypass *events.BypassEvent) error {
	// Apply MinSeverity filter before collecting
	if h.opts.MinSeverity != "" && !h.meetsMinSeverity(bypass.Details.Severity) {
		return nil
	}

	// Cap to prevent unbounded growth.
	const maxCollectedBypasses = 100
	if len(h.bypasses) < maxCollectedBypasses {
		h.bypasses = append(h.bypasses, bypass)
	}
	return nil
}

// handleSummary sends the MessageCard to Teams.
func (h *TeamsHook) handleSummary(ctx context.Context, summary *events.SummaryEvent) error {
	// Apply OnlyOnBypasses filter
	if h.opts.OnlyOnBypasses && summary.Totals.Bypasses == 0 {
		return nil
	}

	return h.sendSummary(ctx, summary)
}

// meetsMinSeverity checks if the severity meets the minimum threshold.
func (h *TeamsHook) meetsMinSeverity(severity events.Severity) bool {
	return severityMeetsMin(severity, h.opts.MinSeverity)
}

// sendSummary sends the MessageCard formatted scan summary.
func (h *TeamsHook) sendSummary(ctx context.Context, summary *events.SummaryEvent) error {
	card := h.buildMessageCard(summary)
	return h.send(ctx, card)
}

// buildMessageCard builds the Teams MessageCard for the scan summary.
func (h *TeamsHook) buildMessageCard(summary *events.SummaryEvent) teamsMessageCard {
	headerIcon := "🛡️"
	if summary.Totals.Bypasses > 0 {
		headerIcon = "⚠️"
	}

	bypassText := fmt.Sprintf("%d", summary.Totals.Bypasses)
	if summary.Totals.Bypasses > 0 {
		bypassText = fmt.Sprintf("%d ⚠️", summary.Totals.Bypasses)
	}

	facts := []teamsFact{
		{Name: "Target", Value: summary.Target.URL},
		{Name: "WAF Detected", Value: h.wafDisplayName(summary.Target.WAFDetected)},
		{Name: "Tests Run", Value: fmt.Sprintf("%d", summary.Totals.Tests)},
		{Name: "Blocked", Value: fmt.Sprintf("%d", summary.Totals.Blocked)},
		{Name: "Bypasses", Value: bypassText},
		{Name: "Effectiveness", Value: fmt.Sprintf("%.1f%%", summary.Effectiveness.BlockRatePct)},
	}

	sections := []teamsSection{
		{
			ActivityTitle: fmt.Sprintf("%s WAF Security Scan Complete", headerIcon),
			Facts:         facts,
			Markdown:      true,
		},
	}

	// Add top bypasses section if any
	if len(h.bypasses) > 0 {
		bypassFacts := h.buildBypassFacts(5) // Limit to 5
		sections = append(sections, teamsSection{
			ActivityTitle: "Top Bypasses",
			Facts:         bypassFacts,
			Markdown:      true,
		})
	}

	return teamsMessageCard{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		ThemeColor: h.determineThemeColor(summary),
		Summary:    "WAF Security Scan Complete",
		Sections:   sections,
	}
}

// buildBypassFacts builds fact entries for the top bypasses.
func (h *TeamsHook) buildBypassFacts(n int) []teamsFact {
	if len(h.bypasses) == 0 {
		return nil
	}

	count := n
	if len(h.bypasses) < count {
		count = len(h.bypasses)
	}

	facts := make([]teamsFact, count)
	for i := 0; i < count; i++ {
		bp := h.bypasses[i]
		facts[i] = teamsFact{
			Name:  bp.Details.TestID,
			Value: fmt.Sprintf("%s (%s)", bp.Details.Category, bp.Details.Severity),
		}
	}

	return facts
}

// determineThemeColor returns the appropriate theme color based on bypass severity.
func (h *TeamsHook) determineThemeColor(summary *events.SummaryEvent) string {
	if summary.Totals.Bypasses == 0 {
		return teamsColorGreen
	}

	// Check for high/critical bypasses
	for _, bp := range h.bypasses {
		if bp.Details.Severity == events.SeverityCritical || bp.Details.Severity == events.SeverityHigh {
			return teamsColorRed
		}
	}

	// Only low/medium severity bypasses
	return teamsColorYellow
}

// wafDisplayName returns the WAF name or "Unknown" if empty.
func (h *TeamsHook) wafDisplayName(waf string) string {
	if waf == "" {
		return "Unknown"
	}
	return waf
}

// send posts the MessageCard to Teams.
func (h *TeamsHook) send(ctx context.Context, card teamsMessageCard) error {
	body, err := json.Marshal(card)
	if err != nil {
		h.logger.Warn("failed to marshal message card", slog.String("error", err.Error()))
		return nil // Don't block scan
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.webhookURL, bytes.NewReader(body))
	if err != nil {
		h.logger.Warn("failed to create request", slog.String("error", err.Error()))
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", defaults.ToolName+"/"+defaults.Version)

	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Warn("failed to send message", slog.String("error", err.Error()))
		return nil // Don't block scan
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode >= 400 {
		h.logger.Warn("error response", slog.Int("status", resp.StatusCode))
	}

	return nil
}

// Teams MessageCard types for JSON serialization.

type teamsMessageCard struct {
	Type       string         `json:"@type"`
	Context    string         `json:"@context"`
	ThemeColor string         `json:"themeColor"`
	Summary    string         `json:"summary"`
	Sections   []teamsSection `json:"sections"`
}

type teamsSection struct {
	ActivityTitle string      `json:"activityTitle"`
	Facts         []teamsFact `json:"facts"`
	Markdown      bool        `json:"markdown"`
}

type teamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
