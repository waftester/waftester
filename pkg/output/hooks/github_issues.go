package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Hook = (*GitHubIssuesHook)(nil)

// validGitHubName matches valid GitHub owner and repo names (alphanumeric, hyphen, underscore, dot).
var validGitHubName = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// GitHubIssuesHook creates issues in GitHub via the REST API v3.
// It creates issues for WAF bypasses that meet the severity threshold.
type GitHubIssuesHook struct {
	baseURL string
	client  *http.Client
	opts    GitHubIssuesOptions
	logger  *slog.Logger
}

// GitHubIssuesOptions configures the GitHub Issues hook behavior.
type GitHubIssuesOptions struct {
	// Token is the GitHub personal access token or GitHub App token.
	// Required scopes: repo (for private repos) or public_repo (for public repos).
	Token string

	// Owner is the repository owner (user or organization).
	Owner string

	// Repo is the repository name.
	Repo string

	// BaseURL is the API base URL for GitHub Enterprise (default: https://api.github.com).
	// For GitHub Enterprise, use: https://github.example.com/api/v3
	BaseURL string

	// Labels to add to issues (e.g., "security", "waf-bypass").
	Labels []string

	// Assignees are GitHub usernames to assign to issues.
	Assignees []string

	// MinSeverity to create issue (default: high).
	MinSeverity events.Severity

	// Timeout for HTTP requests (default: 30s).
	Timeout time.Duration

	// Logger for structured logging (default: slog.Default()).
	Logger *slog.Logger
}

// githubIssueRequest is the GitHub API issue create request.
type githubIssueRequest struct {
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Labels    []string `json:"labels,omitempty"`
	Assignees []string `json:"assignees,omitempty"`
}

// githubIssueResponse is the GitHub API create issue response.
type githubIssueResponse struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

// githubErrorResponse represents a GitHub API error.
type githubErrorResponse struct {
	Message          string `json:"message"`
	DocumentationURL string `json:"documentation_url"`
}

// NewGitHubIssuesHook creates a new GitHub Issues hook.
// Returns an error if Owner or Repo contain invalid characters.
func NewGitHubIssuesHook(opts GitHubIssuesOptions) (*GitHubIssuesHook, error) {
	if !validGitHubName.MatchString(opts.Owner) {
		return nil, fmt.Errorf("invalid GitHub owner: %q", opts.Owner)
	}
	if !validGitHubName.MatchString(opts.Repo) {
		return nil, fmt.Errorf("invalid GitHub repo: %q", opts.Repo)
	}

	if opts.Timeout == 0 {
		opts.Timeout = duration.WebhookTimeout
	}
	if opts.MinSeverity == "" {
		opts.MinSeverity = events.SeverityHigh
	}

	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}

	return &GitHubIssuesHook{
		baseURL: baseURL,
		opts:    opts,
		client: httpclient.New(httpclient.Config{
			Timeout:            opts.Timeout,
			InsecureSkipVerify: false, // GitHub uses valid certs
		}),
		logger: orDefault(opts.Logger),
	}, nil
}

// OnEvent processes events and creates issues in GitHub.
// Only bypass events that meet the MinSeverity threshold create issues.
func (h *GitHubIssuesHook) OnEvent(ctx context.Context, event events.Event) error {
	bypass, ok := event.(*events.BypassEvent)
	if !ok {
		return nil
	}

	// Apply MinSeverity filter
	if !h.meetsMinSeverity(bypass.Details.Severity) {
		return nil
	}

	return h.createIssue(ctx, bypass)
}

// EventTypes returns the event types this hook handles.
func (h *GitHubIssuesHook) EventTypes() []events.EventType {
	return []events.EventType{
		events.EventTypeBypass,
	}
}

// meetsMinSeverity checks if the severity meets the minimum threshold.
func (h *GitHubIssuesHook) meetsMinSeverity(severity events.Severity) bool {
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

// createIssue creates a GitHub issue for the bypass event.
func (h *GitHubIssuesHook) createIssue(ctx context.Context, bypass *events.BypassEvent) error {
	issue := h.buildIssue(bypass)

	body, err := json.Marshal(issue)
	if err != nil {
		h.logger.Warn("failed to marshal issue", slog.String("error", err.Error()))
		return nil
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/issues", h.baseURL, h.opts.Owner, h.opts.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		h.logger.Warn("failed to create request", slog.String("error", err.Error()))
		return nil
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "Bearer "+h.opts.Token)
	req.Header.Set("User-Agent", defaults.ToolName+"/"+defaults.Version)

	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Warn("request failed", slog.String("error", err.Error()))
		return nil
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp githubErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			h.logger.Warn("API error", slog.Int("status", resp.StatusCode), slog.String("error", errResp.Message))
		} else {
			h.logger.Warn("API error", slog.Int("status", resp.StatusCode))
		}
		return nil
	}

	var issueResp githubIssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&issueResp); err != nil {
		h.logger.Warn("failed to decode response", slog.String("error", err.Error()))
		return nil
	}

	h.logger.Info("created issue", slog.Int("number", issueResp.Number), slog.String("url", issueResp.HTMLURL))
	return nil
}

// buildIssue constructs the GitHub issue request from a bypass event.
func (h *GitHubIssuesHook) buildIssue(bypass *events.BypassEvent) githubIssueRequest {
	d := bypass.Details

	// Build labels
	labels := append([]string{}, h.opts.Labels...)
	labels = append(labels, severityToGitHubLabel(d.Severity))

	// Build title
	title := fmt.Sprintf("[WAF Bypass] %s - %s", d.Category, d.TestID)

	// Build markdown body
	var sb strings.Builder

	sb.WriteString("## WAF Bypass Finding\n\n")

	sb.WriteString("| Field | Value |\n")
	sb.WriteString("|-------|-------|\n")
	sb.WriteString(fmt.Sprintf("| **Test ID** | `%s` |\n", d.TestID))
	sb.WriteString(fmt.Sprintf("| **Category** | %s |\n", d.Category))
	sb.WriteString(fmt.Sprintf("| **Severity** | %s |\n", severityEmoji(d.Severity)))
	sb.WriteString(fmt.Sprintf("| **Target** | `%s` |\n", d.Endpoint))
	sb.WriteString(fmt.Sprintf("| **HTTP Status** | %d |\n", d.StatusCode))
	if d.Method != "" {
		sb.WriteString(fmt.Sprintf("| **Method** | %s |\n", d.Method))
	}

	if len(d.CWE) > 0 {
		cweStr := fmt.Sprintf("CWE-%d", d.CWE[0])
		sb.WriteString(fmt.Sprintf("| **CWE** | [%s](https://cwe.mitre.org/data/definitions/%d.html) |\n", cweStr, d.CWE[0]))
	}

	sb.WriteString("\n### Description\n\n")
	sb.WriteString(fmt.Sprintf("A WAF bypass was detected for attack type **%s**. ", d.Category))
	sb.WriteString("The payload was not blocked by the WAF, indicating a potential security gap.\n")

	if d.Payload != "" {
		sb.WriteString("\n### Payload\n\n")
		sb.WriteString("```\n")
		if len(d.Payload) > 500 {
			sb.WriteString(d.Payload[:500])
			sb.WriteString("\n... (truncated)")
		} else {
			sb.WriteString(d.Payload)
		}
		sb.WriteString("\n```\n")
	}

	sb.WriteString("\n### Recommendation\n\n")
	sb.WriteString("1. Verify this bypass in a controlled environment\n")
	sb.WriteString("2. Update WAF rules to detect this attack pattern\n")
	sb.WriteString("3. Consider implementing additional security controls\n")

	sb.WriteString("\n---\n")
	sb.WriteString(fmt.Sprintf("*Created by %s v%s*\n", defaults.ToolName, defaults.Version))

	return githubIssueRequest{
		Title:     title,
		Body:      sb.String(),
		Labels:    labels,
		Assignees: h.opts.Assignees,
	}
}

// severityEmoji returns a severity indicator with emoji.
func severityEmoji(sev events.Severity) string {
	switch sev {
	case events.SeverityCritical:
		return "🔴 Critical"
	case events.SeverityHigh:
		return "🟠 High"
	case events.SeverityMedium:
		return "🟡 Medium"
	case events.SeverityLow:
		return "🟢 Low"
	default:
		return "ℹ️ Info"
	}
}

// severityToGitHubLabel converts severity to a GitHub-friendly label.
func severityToGitHubLabel(sev events.Severity) string {
	switch sev {
	case events.SeverityCritical:
		return "severity:critical"
	case events.SeverityHigh:
		return "severity:high"
	case events.SeverityMedium:
		return "severity:medium"
	case events.SeverityLow:
		return "severity:low"
	default:
		return "severity:info"
	}
}
