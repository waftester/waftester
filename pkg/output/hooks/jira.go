package hooks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Hook = (*JiraHook)(nil)

// validJiraProjectKey matches valid Jira project keys (uppercase alphanumeric, 2-10 chars).
var validJiraProjectKey = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}$`)

// JiraHook creates issues in Jira via the REST API v3.
// It creates issues for WAF bypasses that meet the severity threshold.
type JiraHook struct {
	baseURL string
	client  *http.Client
	opts    JiraOptions
	logger  *slog.Logger
}

// JiraOptions configures the Jira hook behavior.
type JiraOptions struct {
	// ProjectKey for issue creation (required).
	ProjectKey string

	// IssueType (default: "Bug").
	IssueType string

	// Username for basic auth.
	Username string

	// APIToken for authentication.
	APIToken string

	// MinSeverity to create issue (default: high).
	MinSeverity events.Severity

	// Labels to add to issues.
	Labels []string

	// AssigneeID to assign issues to.
	AssigneeID string

	// Timeout for HTTP requests (default: 10s).
	Timeout time.Duration

	// Logger for structured logging (default: slog.Default()).
	Logger *slog.Logger
}

// jiraIssue represents the Jira REST API v3 issue creation payload.
type jiraIssue struct {
	Fields jiraFields `json:"fields"`
}

// jiraFields contains the issue fields.
type jiraFields struct {
	Project     jiraProject     `json:"project"`
	Summary     string          `json:"summary"`
	Description jiraADFDocument `json:"description"`
	IssueType   jiraIssueType   `json:"issuetype"`
	Priority    *jiraPriority   `json:"priority,omitempty"`
	Labels      []string        `json:"labels,omitempty"`
	Assignee    *jiraAssignee   `json:"assignee,omitempty"`
}

// jiraProject identifies the Jira project.
type jiraProject struct {
	Key string `json:"key"`
}

// jiraIssueType identifies the issue type.
type jiraIssueType struct {
	Name string `json:"name"`
}

// jiraPriority identifies the priority.
type jiraPriority struct {
	Name string `json:"name"`
}

// jiraAssignee identifies the assignee.
type jiraAssignee struct {
	ID string `json:"id"`
}

// jiraADFDocument represents an Atlassian Document Format document.
type jiraADFDocument struct {
	Type    string        `json:"type"`
	Version int           `json:"version"`
	Content []jiraADFNode `json:"content"`
}

// jiraADFNode represents a node in an ADF document.
type jiraADFNode struct {
	Type    string                 `json:"type"`
	Content []jiraADFNode          `json:"content,omitempty"`
	Attrs   map[string]interface{} `json:"attrs,omitempty"`
	Text    string                 `json:"text,omitempty"`
}

// jiraPriorityMap maps WAFtester severity to Jira priority names.
var jiraPriorityMap = map[events.Severity]string{
	events.SeverityCritical: "Highest",
	events.SeverityHigh:     "High",
	events.SeverityMedium:   "Medium",
	events.SeverityLow:      "Low",
	events.SeverityInfo:     "Lowest",
}

// NewJiraHook creates a new Jira hook that creates issues in Jira.
// Returns an error if baseURL is invalid, credentials are missing, or ProjectKey is malformed.
func NewJiraHook(baseURL string, opts JiraOptions) (*JiraHook, error) {
	// Validate base URL
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid Jira base URL: %q", baseURL)
	}

	// Require authentication credentials
	if opts.Username == "" || opts.APIToken == "" {
		return nil, fmt.Errorf("jira requires Username and APIToken for authentication")
	}

	// Validate project key (Jira keys are uppercase alpha + digits, e.g. SEC, PROJ10)
	if !validJiraProjectKey.MatchString(opts.ProjectKey) {
		return nil, fmt.Errorf("invalid Jira project key: %q (must be 2-10 uppercase alphanumeric chars starting with a letter)", opts.ProjectKey)
	}

	// Apply defaults
	if opts.IssueType == "" {
		opts.IssueType = "Bug"
	}
	if opts.MinSeverity == "" {
		opts.MinSeverity = events.SeverityHigh
	}
	if opts.Labels == nil {
		opts.Labels = []string{defaults.ToolName, "waf-bypass", "security"}
	}
	if opts.Timeout == 0 {
		opts.Timeout = duration.WebhookTimeout
	}

	return &JiraHook{
		baseURL: baseURL,
		client:  httpclient.New(httpclient.Config{Timeout: opts.Timeout}),
		opts:    opts,
		logger:  orDefault(opts.Logger),
	}, nil
}

// OnEvent processes events and creates issues in Jira.
// Only bypass events that meet the MinSeverity threshold create issues.
func (h *JiraHook) OnEvent(ctx context.Context, event events.Event) error {
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
func (h *JiraHook) EventTypes() []events.EventType {
	return []events.EventType{
		events.EventTypeBypass,
	}
}

// meetsMinSeverity checks if the severity meets the minimum threshold.
func (h *JiraHook) meetsMinSeverity(severity events.Severity) bool {
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

// createIssue creates a Jira issue for the bypass event.
func (h *JiraHook) createIssue(ctx context.Context, bypass *events.BypassEvent) error {
	issue := h.buildIssue(bypass)

	body, err := json.Marshal(issue)
	if err != nil {
		h.logger.Warn("failed to marshal issue", slog.String("error", err.Error()))
		return nil
	}

	endpoint := fmt.Sprintf("%s/rest/api/3/issue", h.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		h.logger.Warn("failed to create request", slog.String("error", err.Error()))
		return nil
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", defaults.ToolName+"/"+defaults.Version)

	// Add basic auth if credentials provided
	if h.opts.Username != "" && h.opts.APIToken != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(h.opts.Username + ":" + h.opts.APIToken))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Warn("failed to create issue", slog.String("error", err.Error()))
		return nil
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode >= 400 {
		// Decode error response for better troubleshooting
		var errResp struct {
			ErrorMessages []string          `json:"errorMessages"`
			Errors        map[string]string `json:"errors"`
		}
		if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr == nil {
			if len(errResp.ErrorMessages) > 0 {
				h.logger.Warn("API error", slog.Int("status", resp.StatusCode), slog.Any("errors", errResp.ErrorMessages))
			} else if len(errResp.Errors) > 0 {
				h.logger.Warn("API error", slog.Int("status", resp.StatusCode), slog.Any("errors", errResp.Errors))
			} else {
				h.logger.Warn("error response", slog.Int("status", resp.StatusCode))
			}
		} else {
			h.logger.Warn("error response", slog.Int("status", resp.StatusCode))
		}
		return nil
	}

	// Parse response to log created issue key
	var result struct {
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Key != "" {
		h.logger.Info("created issue", slog.String("key", result.Key), slog.String("url", result.Self))
	}

	return nil
}

// buildIssue constructs the Jira issue payload from a bypass event.
func (h *JiraHook) buildIssue(bypass *events.BypassEvent) jiraIssue {
	summary := fmt.Sprintf("[WAFtester] %s WAF Bypass - %s",
		capitalize(bypass.Details.Category),
		bypass.Details.TestID)

	description := h.buildADFDescription(bypass)

	priority := jiraPriorityMap[bypass.Details.Severity]
	if priority == "" {
		priority = "High"
	}

	issue := jiraIssue{
		Fields: jiraFields{
			Project:     jiraProject{Key: h.opts.ProjectKey},
			Summary:     summary,
			Description: description,
			IssueType:   jiraIssueType{Name: h.opts.IssueType},
			Priority:    &jiraPriority{Name: priority},
			Labels:      h.opts.Labels,
		},
	}

	if h.opts.AssigneeID != "" {
		issue.Fields.Assignee = &jiraAssignee{ID: h.opts.AssigneeID}
	}

	return issue
}

// buildADFDescription creates an Atlassian Document Format description.
func (h *JiraHook) buildADFDescription(bypass *events.BypassEvent) jiraADFDocument {
	content := []jiraADFNode{
		// Introduction paragraph
		{
			Type: "paragraph",
			Content: []jiraADFNode{
				{Type: "text", Text: "A WAF bypass was detected during security testing."},
			},
		},
		// Details heading
		{
			Type:  "heading",
			Attrs: map[string]interface{}{"level": 2},
			Content: []jiraADFNode{
				{Type: "text", Text: "Details"},
			},
		},
		// Bullet list with details
		h.buildDetailsList(bypass),
	}

	// Add curl command if available
	if bypass.Details.Curl != "" {
		content = append(content,
			jiraADFNode{
				Type:  "heading",
				Attrs: map[string]interface{}{"level": 2},
				Content: []jiraADFNode{
					{Type: "text", Text: "Reproduction"},
				},
			},
			jiraADFNode{
				Type: "codeBlock",
				Attrs: map[string]interface{}{
					"language": "bash",
				},
				Content: []jiraADFNode{
					{Type: "text", Text: bypass.Details.Curl},
				},
			},
		)
	}

	return jiraADFDocument{
		Type:    "doc",
		Version: 1,
		Content: content,
	}
}

// buildDetailsList creates a bullet list of bypass details.
func (h *JiraHook) buildDetailsList(bypass *events.BypassEvent) jiraADFNode {
	items := []jiraADFNode{
		h.buildListItem(fmt.Sprintf("Category: %s", capitalize(bypass.Details.Category))),
		h.buildListItem(fmt.Sprintf("Severity: %s", capitalize(string(bypass.Details.Severity)))),
		h.buildListItem(fmt.Sprintf("Test ID: %s", bypass.Details.TestID)),
		h.buildListItem(fmt.Sprintf("Target: %s", bypass.Details.Endpoint)),
		h.buildListItem(fmt.Sprintf("Status Code: %d", bypass.Details.StatusCode)),
	}

	if bypass.Details.Method != "" {
		items = append(items, h.buildListItem(fmt.Sprintf("Method: %s", bypass.Details.Method)))
	}

	if bypass.Details.Payload != "" {
		items = append(items, h.buildListItem(fmt.Sprintf("Payload: %s", bypass.Details.Payload)))
	}

	return jiraADFNode{
		Type:    "bulletList",
		Content: items,
	}
}

// buildListItem creates a list item node for the ADF document.
func (h *JiraHook) buildListItem(text string) jiraADFNode {
	return jiraADFNode{
		Type: "listItem",
		Content: []jiraADFNode{
			{
				Type: "paragraph",
				Content: []jiraADFNode{
					{Type: "text", Text: text},
				},
			},
		},
	}
}
