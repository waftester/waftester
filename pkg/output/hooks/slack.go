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
	"unicode"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Hook = (*SlackHook)(nil)

// SlackHook sends formatted messages to Slack via incoming webhooks.
// It uses Slack's Block Kit for rich formatting of scan summaries
// and sends immediate alerts for critical bypasses.
type SlackHook struct {
	webhookURL string
	client     *http.Client
	opts       SlackOptions
	bypasses   []*events.BypassEvent
	mu         sync.Mutex
	logger     *slog.Logger
}

// SlackOptions configures the Slack hook behavior.
type SlackOptions struct {
	// Channel override (uses webhook default if empty).
	Channel string

	// Username for bot (default: "WAFtester").
	Username string

	// IconEmoji for bot avatar (default: ":shield:").
	IconEmoji string

	// MinSeverity filters events below this severity.
	MinSeverity events.Severity

	// OnlyOnBypasses only sends the summary if bypasses were detected.
	OnlyOnBypasses bool

	// Timeout for HTTP requests (default: 10s).
	Timeout time.Duration

	// Logger for structured logging (default: slog.Default()).
	Logger *slog.Logger
}

// NewSlackHook creates a new Slack hook that sends messages to the given webhook URL.
func NewSlackHook(webhookURL string, opts SlackOptions) *SlackHook {
	// Apply defaults
	if opts.Username == "" {
		opts.Username = defaults.ToolNameDisplay
	}
	if opts.IconEmoji == "" {
		opts.IconEmoji = ":shield:"
	}
	if opts.Timeout == 0 {
		opts.Timeout = duration.WebhookTimeout
	}

	return &SlackHook{
		webhookURL: webhookURL,
		client:     httpclient.New(httpclient.Config{Timeout: opts.Timeout}),
		opts:       opts,
		bypasses:   make([]*events.BypassEvent, 0),
		logger:     orDefault(opts.Logger),
	}
}

// OnEvent processes events and sends them to Slack.
// Critical/high severity bypasses trigger immediate alerts.
// Summary events send a complete Block Kit message.
func (h *SlackHook) OnEvent(ctx context.Context, event events.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch e := event.(type) {
	case *events.BypassEvent:
		return h.handleBypass(ctx, e)
	case *events.SummaryEvent:
		return h.handleSummary(ctx, e)
	default:
		return nil
	}
}

// EventTypes returns the event types this hook handles.
func (h *SlackHook) EventTypes() []events.EventType {
	return []events.EventType{
		events.EventTypeBypass,
		events.EventTypeSummary,
	}
}

// handleBypass collects bypass events and sends immediate alerts for critical/high severity.
func (h *SlackHook) handleBypass(ctx context.Context, bypass *events.BypassEvent) error {
	// Collect for summary, capped to prevent unbounded growth.
	const maxCollectedBypasses = 100
	if len(h.bypasses) < maxCollectedBypasses {
		h.bypasses = append(h.bypasses, bypass)
	}

	// Apply MinSeverity filter
	if h.opts.MinSeverity != "" && !h.meetsMinSeverity(bypass.Details.Severity) {
		return nil
	}

	// Send immediate alert for critical/high severity
	if bypass.Details.Severity == events.SeverityCritical || bypass.Details.Severity == events.SeverityHigh {
		return h.sendBypassAlert(ctx, bypass)
	}

	return nil
}

// handleSummary sends the final scan summary to Slack.
func (h *SlackHook) handleSummary(ctx context.Context, summary *events.SummaryEvent) error {
	// Apply OnlyOnBypasses filter
	if h.opts.OnlyOnBypasses && summary.Totals.Bypasses == 0 {
		return nil
	}

	return h.sendSummary(ctx, summary)
}

// meetsMinSeverity checks if the severity meets the minimum threshold.
func (h *SlackHook) meetsMinSeverity(severity events.Severity) bool {
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

// sendBypassAlert sends an immediate alert for a critical/high bypass.
func (h *SlackHook) sendBypassAlert(ctx context.Context, bypass *events.BypassEvent) error {
	emoji := "🚨"
	color := "danger"
	severityLabel := string(bypass.Details.Severity)

	message := slackMessage{
		Username:  h.opts.Username,
		IconEmoji: h.opts.IconEmoji,
		Channel:   h.opts.Channel,
		Text:      fmt.Sprintf("%s *%s WAF Bypass Detected*", emoji, capitalize(severityLabel)),
		Attachments: []slackAttachment{
			{
				Color: color,
				Fields: []slackField{
					{Title: "Category", Value: bypass.Details.Category, Short: true},
					{Title: "Test ID", Value: bypass.Details.TestID, Short: true},
					{Title: "Severity", Value: capitalize(severityLabel), Short: true},
					{Title: "Status Code", Value: fmt.Sprintf("%d", bypass.Details.StatusCode), Short: true},
					{Title: "Target", Value: bypass.Details.Endpoint, Short: false},
				},
			},
		},
	}

	return h.send(ctx, message)
}

// sendSummary sends the Block Kit formatted scan summary.
func (h *SlackHook) sendSummary(ctx context.Context, summary *events.SummaryEvent) error {
	blocks := h.buildSummaryBlocks(summary)

	message := slackBlockMessage{
		Username:  h.opts.Username,
		IconEmoji: h.opts.IconEmoji,
		Channel:   h.opts.Channel,
		Blocks:    blocks,
	}

	return h.send(ctx, message)
}

// buildSummaryBlocks builds Block Kit blocks for the scan summary.
func (h *SlackHook) buildSummaryBlocks(summary *events.SummaryEvent) []slackBlock {
	blocks := make([]slackBlock, 0, 6)

	// Header
	headerIcon := "🛡️"
	if summary.Totals.Bypasses > 0 {
		headerIcon = "⚠️"
	}
	blocks = append(blocks, slackBlock{
		Type: "header",
		Text: &slackText{
			Type: "plain_text",
			Text: fmt.Sprintf("%s WAF Security Scan Complete", headerIcon),
		},
	})

	// Target and WAF info section
	targetField := slackText{Type: "mrkdwn", Text: fmt.Sprintf("*Target:*\n%s", summary.Target.URL)}
	wafField := slackText{Type: "mrkdwn", Text: fmt.Sprintf("*WAF:*\n%s", h.wafDisplayName(summary.Target.WAFDetected))}
	blocks = append(blocks, slackBlock{
		Type:   "section",
		Fields: []*slackText{&targetField, &wafField},
	})

	// Stats section
	bypassText := fmt.Sprintf("%d", summary.Totals.Bypasses)
	if summary.Totals.Bypasses > 0 {
		bypassText = fmt.Sprintf("%d ⚠️", summary.Totals.Bypasses)
	}

	blockedField := slackText{Type: "mrkdwn", Text: fmt.Sprintf("*Blocked:*\n%d", summary.Totals.Blocked)}
	bypassField := slackText{Type: "mrkdwn", Text: fmt.Sprintf("*Bypasses:*\n%s", bypassText)}
	effectivenessField := slackText{Type: "mrkdwn", Text: fmt.Sprintf("*Effectiveness:*\n%.1f%%", summary.Effectiveness.BlockRatePct)}

	blocks = append(blocks, slackBlock{
		Type:   "section",
		Fields: []*slackText{&blockedField, &bypassField, &effectivenessField},
	})

	// Add top bypasses if any
	if len(h.bypasses) > 0 {
		blocks = append(blocks, slackBlock{Type: "divider"})

		topBypasses := h.formatTopBypasses(5) // Limit to 5
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*Top Bypasses:*\n%s", topBypasses),
			},
		})
	}

	return blocks
}

// formatTopBypasses formats the top N bypasses as a bullet list.
func (h *SlackHook) formatTopBypasses(n int) string {
	if len(h.bypasses) == 0 {
		return "_No bypasses detected_"
	}

	count := n
	if len(h.bypasses) < count {
		count = len(h.bypasses)
	}

	var buf bytes.Buffer
	for i := 0; i < count; i++ {
		bp := h.bypasses[i]
		buf.WriteString(fmt.Sprintf("• `%s` - %s (%s)\n", bp.Details.TestID, bp.Details.Category, bp.Details.Severity))
	}

	return buf.String()
}

// wafDisplayName returns the WAF name or "Unknown" if empty.
func (h *SlackHook) wafDisplayName(waf string) string {
	if waf == "" {
		return "Unknown"
	}
	return waf
}

// send posts the message to Slack.
func (h *SlackHook) send(ctx context.Context, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		h.logger.Warn("failed to marshal message", slog.String("error", err.Error()))
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

// capitalize returns the string with the first letter uppercase.
// Handles empty strings, uppercase letters, numbers, and Unicode safely.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	// Get first rune and uppercase it safely
	for i, r := range s {
		if i == 0 {
			return string(unicode.ToUpper(r)) + s[1:]
		}
	}
	return s
}

// Slack message types for JSON serialization.

type slackMessage struct {
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Fields []slackField `json:"fields"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type slackBlockMessage struct {
	Username  string       `json:"username,omitempty"`
	IconEmoji string       `json:"icon_emoji,omitempty"`
	Channel   string       `json:"channel,omitempty"`
	Blocks    []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type   string       `json:"type"`
	Text   *slackText   `json:"text,omitempty"`
	Fields []*slackText `json:"fields,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
