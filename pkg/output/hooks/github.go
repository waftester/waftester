package hooks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Hook = (*GitHubActionsHook)(nil)

// GitHubActionsHook writes scan results to GitHub Actions environment.
// It sets output variables in $GITHUB_OUTPUT and optionally generates
// a step summary in $GITHUB_STEP_SUMMARY.
type GitHubActionsHook struct {
	outputPath  string // $GITHUB_OUTPUT path
	summaryPath string // $GITHUB_STEP_SUMMARY path
	opts        GitHubActionsOptions
	mu          sync.Mutex
	bypasses    []events.BypassInfo // Collected bypasses for summary
}

// GitHubActionsOptions configures the GitHub Actions hook behavior.
type GitHubActionsOptions struct {
	// AddSummary enables step summary generation.
	AddSummary bool
}

// NewGitHubActionsHook creates a new GitHub Actions hook.
// It reads $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY from the environment.
// Returns an error if not running in GitHub Actions environment.
func NewGitHubActionsHook(opts GitHubActionsOptions) (*GitHubActionsHook, error) {
	outputPath := os.Getenv("GITHUB_OUTPUT")
	summaryPath := os.Getenv("GITHUB_STEP_SUMMARY")

	if outputPath == "" {
		return nil, fmt.Errorf("not running in GitHub Actions environment")
	}

	return &GitHubActionsHook{
		outputPath:  outputPath,
		summaryPath: summaryPath,
		opts:        opts,
		bypasses:    make([]events.BypassInfo, 0),
	}, nil
}

// NewGitHubActionsHookWithPaths creates a hook with explicit paths for testing.
// This is primarily used for unit testing without actual GitHub Actions environment.
func NewGitHubActionsHookWithPaths(outputPath, summaryPath string, opts GitHubActionsOptions) *GitHubActionsHook {
	return &GitHubActionsHook{
		outputPath:  outputPath,
		summaryPath: summaryPath,
		opts:        opts,
		bypasses:    make([]events.BypassInfo, 0),
	}
}

// OnEvent processes events and writes to GitHub Actions outputs.
// It collects bypass events and writes summary on SummaryEvent.
func (h *GitHubActionsHook) OnEvent(ctx context.Context, event events.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch e := event.(type) {
	case *events.BypassEvent:
		// Collect bypasses for the summary table
		h.bypasses = append(h.bypasses, events.BypassInfo{
			ID:       e.Details.TestID,
			Severity: string(e.Details.Severity),
			Category: e.Details.Category,
			Encoding: e.Details.Encoding,
			Curl:     e.Details.Curl,
		})
		return nil

	case *events.SummaryEvent:
		return h.writeSummary(e)

	default:
		return nil
	}
}

// EventTypes returns the event types this hook handles.
// It processes bypass events (to collect them) and summary events (to output).
func (h *GitHubActionsHook) EventTypes() []events.EventType {
	return []events.EventType{
		events.EventTypeBypass,
		events.EventTypeSummary,
	}
}

// writeSummary writes outputs and optional step summary on scan completion.
func (h *GitHubActionsHook) writeSummary(summary *events.SummaryEvent) error {
	// Determine result
	result := "pass"
	if summary.Totals.Bypasses > 0 {
		result = "fail"
	}

	// Write to $GITHUB_OUTPUT
	if err := h.writeOutput(summary, result); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Write to $GITHUB_STEP_SUMMARY if enabled and path is set
	if h.opts.AddSummary && h.summaryPath != "" {
		if err := h.writeStepSummary(summary); err != nil {
			return fmt.Errorf("failed to write step summary: %w", err)
		}
	}

	return nil
}

// writeOutput writes key=value pairs to $GITHUB_OUTPUT file.
func (h *GitHubActionsHook) writeOutput(summary *events.SummaryEvent, result string) error {
	f, err := os.OpenFile(h.outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}
	defer f.Close()

	lines := []string{
		fmt.Sprintf("bypasses=%d", summary.Totals.Bypasses),
		fmt.Sprintf("blocked=%d", summary.Totals.Blocked),
		fmt.Sprintf("tests=%d", summary.Totals.Tests),
		fmt.Sprintf("effectiveness=%.1f", summary.Effectiveness.BlockRatePct),
		fmt.Sprintf("result=%s", result),
	}

	for _, line := range lines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			return err
		}
	}

	return nil
}

// writeStepSummary writes a markdown summary to $GITHUB_STEP_SUMMARY.
func (h *GitHubActionsHook) writeStepSummary(summary *events.SummaryEvent) error {
	f, err := os.OpenFile(h.summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open summary file: %w", err)
	}
	defer f.Close()

	var sb strings.Builder

	// Header with icon based on result
	icon := "✅"
	if summary.Totals.Bypasses > 0 {
		icon = "⚠️"
	}
	sb.WriteString(fmt.Sprintf("## 🛡️ WAF Security Scan Results %s\n\n", icon))

	// Results table
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Tests | %d |\n", summary.Totals.Tests))
	sb.WriteString(fmt.Sprintf("| Blocked | %d |\n", summary.Totals.Blocked))

	// Highlight bypasses if any
	if summary.Totals.Bypasses > 0 {
		sb.WriteString(fmt.Sprintf("| **Bypasses** | **%d** ⚠️ |\n", summary.Totals.Bypasses))
	} else {
		sb.WriteString(fmt.Sprintf("| Bypasses | %d |\n", summary.Totals.Bypasses))
	}

	sb.WriteString(fmt.Sprintf("| Effectiveness | %.1f%% |\n", summary.Effectiveness.BlockRatePct))

	// Add grade if available
	if summary.Effectiveness.Grade != "" {
		sb.WriteString(fmt.Sprintf("| Grade | %s |\n", summary.Effectiveness.Grade))
	}

	// Bypasses table if any
	if len(h.bypasses) > 0 {
		sb.WriteString("\n### Bypasses Found\n\n")
		sb.WriteString("| Category | Severity | Test ID |\n")
		sb.WriteString("|----------|----------|--------|\n")
		for _, bypass := range h.bypasses {
			severityEmoji := h.severityEmoji(bypass.Severity)
			sb.WriteString(fmt.Sprintf("| %s | %s %s | %s |\n",
				bypass.Category, severityEmoji, bypass.Severity, bypass.ID))
		}
	}

	// WAF info if detected
	if summary.Target.WAFDetected != "" {
		sb.WriteString(fmt.Sprintf("\n**WAF Detected:** %s", summary.Target.WAFDetected))
		if summary.Target.WAFConfidence > 0 {
			sb.WriteString(fmt.Sprintf(" (%.0f%% confidence)", summary.Target.WAFConfidence*100))
		}
		sb.WriteString("\n")
	}

	// Recommendation if available
	if summary.Effectiveness.Recommendation != "" {
		sb.WriteString(fmt.Sprintf("\n> 💡 %s\n", summary.Effectiveness.Recommendation))
	}

	_, err = f.WriteString(sb.String())
	return err
}

// severityEmoji returns an emoji for the severity level.
func (h *GitHubActionsHook) severityEmoji(severity string) string {
	switch events.Severity(severity) {
	case events.SeverityCritical:
		return "🔴"
	case events.SeverityHigh:
		return "🟠"
	case events.SeverityMedium:
		return "🟡"
	case events.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}
