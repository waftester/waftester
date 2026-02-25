package hooks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
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
var _ dispatcher.Hook = (*AzureDevOpsHook)(nil)

// validADOName matches valid Azure DevOps organization, project, and work item type names.
var validADOName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,63}$`)

// AzureDevOpsHook creates work items in Azure DevOps via the REST API.
// It creates work items for WAF bypasses that meet the severity threshold.
type AzureDevOpsHook struct {
	client *http.Client
	opts   AzureDevOpsOptions
	logger *slog.Logger
}

// AzureDevOpsOptions configures the Azure DevOps hook behavior.
type AzureDevOpsOptions struct {
	// Organization is the Azure DevOps organization name (required).
	Organization string

	// Project is the Azure DevOps project name (required).
	Project string

	// PAT is the Personal Access Token for authentication (required).
	// Required scopes: vso.work_write (Work Items - Read & Write).
	PAT string

	// WorkItemType is the type of work item to create (default: "Bug").
	// Common types: Bug, Task, Issue, User Story, Feature.
	WorkItemType string

	// AreaPath is the optional area path for the work item.
	AreaPath string

	// IterationPath is the optional iteration/sprint path.
	IterationPath string

	// Tags to add to work items (semicolon-separated in ADO).
	Tags []string

	// AssignedTo is the user email or display name to assign work items to.
	AssignedTo string

	// MinSeverity to create work item (default: high).
	MinSeverity events.Severity

	// Timeout for HTTP requests (default: 30s).
	Timeout time.Duration

	// Logger for structured logging (default: slog.Default()).
	Logger *slog.Logger
}

// adoWorkItemOp represents a JSON Patch operation for work item creation.
type adoWorkItemOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// adoWorkItemResponse represents the Azure DevOps work item creation response.
type adoWorkItemResponse struct {
	ID    int    `json:"id"`
	URL   string `json:"url"`
	Links struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"_links"`
}

// adoErrorResponse represents an Azure DevOps API error.
type adoErrorResponse struct {
	Message string `json:"message"`
}

// adoSeverityMap maps WAFtester severity to Azure DevOps severity values.
// ADO Bug severity: 1 - Critical, 2 - High, 3 - Medium, 4 - Low.
var adoSeverityMap = map[events.Severity]string{
	events.SeverityCritical: "1 - Critical",
	events.SeverityHigh:     "2 - High",
	events.SeverityMedium:   "3 - Medium",
	events.SeverityLow:      "4 - Low",
	events.SeverityInfo:     "4 - Low",
}

// adoPriorityMap maps WAFtester severity to Azure DevOps priority values.
// Priority: 1 (highest) to 4 (lowest).
var adoPriorityMap = map[events.Severity]int{
	events.SeverityCritical: 1,
	events.SeverityHigh:     2,
	events.SeverityMedium:   3,
	events.SeverityLow:      4,
	events.SeverityInfo:     4,
}

// NewAzureDevOpsHook creates a new Azure DevOps hook.
// Returns an error if Organization, Project, or WorkItemType contain invalid characters.
func NewAzureDevOpsHook(opts AzureDevOpsOptions) (*AzureDevOpsHook, error) {
	if !validADOName.MatchString(opts.Organization) {
		return nil, fmt.Errorf("invalid Azure DevOps organization: %q", opts.Organization)
	}
	if !validADOName.MatchString(opts.Project) {
		return nil, fmt.Errorf("invalid Azure DevOps project: %q", opts.Project)
	}
	if opts.WorkItemType == "" {
		opts.WorkItemType = "Bug"
	}
	if !validADOName.MatchString(opts.WorkItemType) {
		return nil, fmt.Errorf("invalid Azure DevOps work item type: %q", opts.WorkItemType)
	}

	// Apply defaults
	if opts.MinSeverity == "" {
		opts.MinSeverity = events.SeverityHigh
	}
	if opts.Tags == nil {
		opts.Tags = []string{defaults.ToolName, "waf-bypass", "security"}
	}
	if opts.Timeout == 0 {
		opts.Timeout = duration.WebhookTimeout
	}

	return &AzureDevOpsHook{
		client: httpclient.New(httpclient.Config{
			Timeout:            opts.Timeout,
			InsecureSkipVerify: false, // Use valid certs
		}),
		opts:   opts,
		logger: orDefault(opts.Logger),
	}, nil
}

// OnEvent processes events and creates work items in Azure DevOps.
// Only bypass events that meet the MinSeverity threshold create work items.
func (h *AzureDevOpsHook) OnEvent(ctx context.Context, event events.Event) error {
	bypass, ok := event.(*events.BypassEvent)
	if !ok {
		return nil
	}

	// Apply MinSeverity filter
	if !h.meetsMinSeverity(bypass.Details.Severity) {
		return nil
	}

	return h.createWorkItem(ctx, bypass)
}

// EventTypes returns the event types this hook handles.
func (h *AzureDevOpsHook) EventTypes() []events.EventType {
	return []events.EventType{
		events.EventTypeBypass,
	}
}

// meetsMinSeverity checks if the severity meets the minimum threshold.
func (h *AzureDevOpsHook) meetsMinSeverity(severity events.Severity) bool {
	return severityMeetsMin(severity, h.opts.MinSeverity)
}

// createWorkItem creates an Azure DevOps work item for the bypass event.
func (h *AzureDevOpsHook) createWorkItem(ctx context.Context, bypass *events.BypassEvent) error {
	ops := h.buildWorkItemOps(bypass)

	body, err := json.Marshal(ops)
	if err != nil {
		h.logger.Warn("failed to marshal work item", slog.String("error", err.Error()))
		return nil
	}

	// Build endpoint URL
	// https://dev.azure.com/{organization}/{project}/_apis/wit/workitems/${type}?api-version=7.1
	endpoint := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/wit/workitems/$%s?api-version=7.1",
		h.opts.Organization,
		h.opts.Project,
		h.opts.WorkItemType,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		h.logger.Warn("failed to create request", slog.String("error", err.Error()))
		return nil
	}

	// Azure DevOps uses Basic auth with PAT (empty username, PAT as password)
	auth := base64.StdEncoding.EncodeToString([]byte(":" + h.opts.PAT))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/json-patch+json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", defaults.ToolName+"/"+defaults.Version)

	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Warn("request failed", slog.String("error", err.Error()))
		return nil
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp adoErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Message != "" {
			h.logger.Warn("API error", slog.Int("status", resp.StatusCode), slog.String("error", errResp.Message))
		} else {
			h.logger.Warn("API error", slog.Int("status", resp.StatusCode))
		}
		return nil
	}

	var workItemResp adoWorkItemResponse
	if err := json.NewDecoder(resp.Body).Decode(&workItemResp); err != nil {
		h.logger.Warn("failed to decode response", slog.String("error", err.Error()))
		return nil
	}

	htmlURL := workItemResp.Links.HTML.Href
	if htmlURL == "" {
		htmlURL = workItemResp.URL
	}
	h.logger.Info("created work item", slog.Int("id", workItemResp.ID), slog.String("url", htmlURL))
	return nil
}

// buildWorkItemOps constructs the JSON Patch operations for work item creation.
func (h *AzureDevOpsHook) buildWorkItemOps(bypass *events.BypassEvent) []adoWorkItemOp {
	d := bypass.Details

	// Build title
	title := fmt.Sprintf("[WAFtester] %s WAF Bypass - %s",
		capitalize(d.Category),
		d.TestID,
	)

	// Build description in HTML format (ADO uses HTML)
	description := h.buildDescription(bypass)

	// Build tags (semicolon-separated in ADO)
	tags := strings.Join(h.opts.Tags, "; ")

	ops := []adoWorkItemOp{
		{Op: "add", Path: "/fields/System.Title", Value: title},
		{Op: "add", Path: "/fields/System.Description", Value: description},
		{Op: "add", Path: "/fields/System.Tags", Value: tags},
	}

	// Add severity and priority for Bug type
	if severity, ok := adoSeverityMap[d.Severity]; ok {
		ops = append(ops, adoWorkItemOp{
			Op:    "add",
			Path:  "/fields/Microsoft.VSTS.Common.Severity",
			Value: severity,
		})
	}
	if priority, ok := adoPriorityMap[d.Severity]; ok {
		ops = append(ops, adoWorkItemOp{
			Op:    "add",
			Path:  "/fields/Microsoft.VSTS.Common.Priority",
			Value: priority,
		})
	}

	// Add optional fields
	if h.opts.AreaPath != "" {
		ops = append(ops, adoWorkItemOp{
			Op:    "add",
			Path:  "/fields/System.AreaPath",
			Value: h.opts.AreaPath,
		})
	}

	if h.opts.IterationPath != "" {
		ops = append(ops, adoWorkItemOp{
			Op:    "add",
			Path:  "/fields/System.IterationPath",
			Value: h.opts.IterationPath,
		})
	}

	if h.opts.AssignedTo != "" {
		ops = append(ops, adoWorkItemOp{
			Op:    "add",
			Path:  "/fields/System.AssignedTo",
			Value: h.opts.AssignedTo,
		})
	}

	// Add repro steps if curl is available
	if d.Curl != "" {
		reproSteps := fmt.Sprintf(`<div>
<h3>Reproduction Steps</h3>
<ol>
<li>Run the following command:</li>
</ol>
<pre><code>%s</code></pre>
<ol start="2">
<li>Observe the request bypasses the WAF</li>
</ol>
</div>`, html.EscapeString(d.Curl))
		ops = append(ops, adoWorkItemOp{
			Op:    "add",
			Path:  "/fields/Microsoft.VSTS.TCM.ReproSteps",
			Value: reproSteps,
		})
	}

	return ops
}

// buildDescription creates an HTML description for the work item.
func (h *AzureDevOpsHook) buildDescription(bypass *events.BypassEvent) string {
	d := bypass.Details

	var sb strings.Builder

	sb.WriteString("<div>\n")
	sb.WriteString("<h2>WAF Bypass Finding</h2>\n")
	sb.WriteString("<p>A WAF bypass was detected during security testing.</p>\n\n")

	// Details table
	sb.WriteString("<table>\n")
	sb.WriteString("<tr><th>Field</th><th>Value</th></tr>\n")
	sb.WriteString(fmt.Sprintf("<tr><td><strong>Test ID</strong></td><td><code>%s</code></td></tr>\n", html.EscapeString(d.TestID)))
	sb.WriteString(fmt.Sprintf("<tr><td><strong>Category</strong></td><td>%s</td></tr>\n", html.EscapeString(d.Category)))
	sb.WriteString(fmt.Sprintf("<tr><td><strong>Severity</strong></td><td>%s</td></tr>\n", severityLabel(d.Severity)))
	sb.WriteString(fmt.Sprintf("<tr><td><strong>Target</strong></td><td><code>%s</code></td></tr>\n", html.EscapeString(d.Endpoint)))
	sb.WriteString(fmt.Sprintf("<tr><td><strong>HTTP Status</strong></td><td>%d</td></tr>\n", d.StatusCode))
	if d.Method != "" {
		sb.WriteString(fmt.Sprintf("<tr><td><strong>Method</strong></td><td>%s</td></tr>\n", html.EscapeString(d.Method)))
	}
	if len(d.CWE) > 0 {
		cweLink := fmt.Sprintf("<a href=\"https://cwe.mitre.org/data/definitions/%d.html\">CWE-%d</a>", d.CWE[0], d.CWE[0])
		sb.WriteString(fmt.Sprintf("<tr><td><strong>CWE</strong></td><td>%s</td></tr>\n", cweLink))
	}
	sb.WriteString("</table>\n\n")

	// Payload section
	if d.Payload != "" {
		sb.WriteString("<h3>Payload</h3>\n")
		payload := d.Payload
		if len(payload) > 500 {
			payload = payload[:500] + "... (truncated)"
		}
		sb.WriteString(fmt.Sprintf("<pre><code>%s</code></pre>\n", html.EscapeString(payload)))
	}

	// Recommendation
	sb.WriteString("<h3>Recommendation</h3>\n")
	sb.WriteString("<ol>\n")
	sb.WriteString("<li>Verify this bypass in a controlled environment</li>\n")
	sb.WriteString("<li>Update WAF rules to detect this attack pattern</li>\n")
	sb.WriteString("<li>Consider implementing additional security controls</li>\n")
	sb.WriteString("</ol>\n")

	sb.WriteString("<hr/>\n")
	sb.WriteString(fmt.Sprintf("<p><em>Created by %s v%s</em></p>\n", defaults.ToolName, defaults.Version))
	sb.WriteString("</div>")

	return sb.String()
}

// severityLabel returns a severity label string.
func severityLabel(sev events.Severity) string {
	switch sev {
	case events.SeverityCritical:
		return "\U0001f534 Critical"
	case events.SeverityHigh:
		return "\U0001f7e0 High"
	case events.SeverityMedium:
		return "\U0001f7e1 Medium"
	case events.SeverityLow:
		return "\U0001f7e2 Low"
	default:
		return "\u2139\ufe0f Info"
	}
}
