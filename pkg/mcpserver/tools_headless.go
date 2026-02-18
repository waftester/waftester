package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ═══════════════════════════════════════════════════════════════════════════
// event_crawl — DOM Event Crawling via Headless Browser
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addEventCrawlTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "event_crawl",
			Title: "DOM Event Crawling",
			Description: `Click every interactive element on a page using a headless browser to discover hidden endpoints, XHR/API calls, and dynamic routes that static crawling misses.

Many modern web apps use JavaScript frameworks (React, Vue, Angular) where endpoints are only revealed when buttons, dropdowns, tabs, and other interactive elements are clicked. This tool uses headless Chromium to systematically interact with the page and capture all resulting network requests, navigation events, and DOM mutations.

USE THIS TOOL WHEN:
• The user says "find hidden endpoints", "crawl JavaScript", or "discover API calls"
• Static crawling ('discover') missed endpoints in a SPA or JavaScript-heavy app
• You need to find XHR/fetch API calls triggered by user interactions
• Testing a React/Vue/Angular app where routes are client-side
• The user says "click around and see what happens" or "explore the UI"

DO NOT USE THIS TOOL WHEN:
• Static endpoint discovery is sufficient — use 'discover' instead (faster, no browser needed)
• You want to scan for vulnerabilities — use 'scan' after discovering endpoints
• You want to test WAF rules — use 'scan', 'bypass', or 'discover_bypasses'
• The target is a simple API without a web UI

'event_crawl' vs 'discover': 'discover' uses 9 static sources (robots.txt, sitemap, HTML parsing, etc.). 'event_crawl' loads the page in a real browser and clicks interactive elements. Use 'discover' first for static endpoints, then 'event_crawl' for JavaScript-rendered content.

ELEMENT TYPES DETECTED: links, buttons, onclick handlers, ARIA role=button, framework bindings (@click, ng-click, onClick), elements with cursor:pointer CSS.

EXAMPLE INPUTS:
• Basic crawl: {"target": "https://example.com"}
• Deep crawl: {"target": "https://app.example.com/dashboard", "max_clicks": 100}
• Quick scan: {"target": "https://example.com", "max_clicks": 20, "click_timeout": 3}

Returns: interactive elements found, discovered URLs, XHR/API requests captured, DOM changes detected, total unique endpoints.

ASYNC TOOL: Returns a task_id immediately. Duration depends on page complexity and max_clicks (typically 15-60s). Poll with get_task_status.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to event-crawl. Should be a page with interactive elements (buttons, forms, tabs).",
						"format":      "uri",
					},
					"max_clicks": map[string]any{
						"type":        "integer",
						"description": "Maximum number of elements to click. Higher = more thorough but slower.",
						"default":     50,
						"minimum":     1,
						"maximum":     200,
					},
					"click_timeout": map[string]any{
						"type":        "integer",
						"description": "Timeout per click interaction in seconds.",
						"default":     5,
						"minimum":     1,
						"maximum":     30,
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:    false,
				IdempotentHint:  false,
				OpenWorldHint:   boolPtr(true),
				DestructiveHint: boolPtr(false),
				Title:           "DOM Event Crawling",
			},
		},
		loggedTool("event_crawl", s.handleEventCrawl),
	)
}

type eventCrawlArgs struct {
	Target       string `json:"target"`
	MaxClicks    int    `json:"max_clicks"`
	ClickTimeout int    `json:"click_timeout"`
}

func (s *Server) handleEventCrawl(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.config.EventCrawlFn == nil {
		return enrichedError(
			"event crawling is not available — headless browser support is not configured",
			[]string{
				"The MCP server was started without headless browser support.",
				"Use 'discover' for static endpoint discovery instead.",
				"To enable event crawling, ensure Chromium/Chrome is installed and the server is configured with headless support.",
			}), nil
	}

	var args eventCrawlArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\"}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	if args.MaxClicks <= 0 {
		args.MaxClicks = 50
	}
	if args.MaxClicks > 200 {
		args.MaxClicks = 200
	}
	if args.ClickTimeout <= 0 {
		args.ClickTimeout = 5
	}
	if args.ClickTimeout > 30 {
		args.ClickTimeout = 30
	}

	estimatedDuration := fmt.Sprintf("%d-%ds depending on page complexity", args.MaxClicks/5, args.MaxClicks*args.ClickTimeout)

	return s.launchAsync(ctx, "event_crawl", estimatedDuration, func(taskCtx context.Context, task *Task) {
		task.SetProgress(0, 100, fmt.Sprintf("Starting headless browser for %s (max %d clicks)…", args.Target, args.MaxClicks))

		results, discoveredURLs, err := s.config.EventCrawlFn(taskCtx, args.Target, args.MaxClicks, args.ClickTimeout)
		if err != nil {
			task.Fail(fmt.Sprintf("event crawl failed: %v", err))
			return
		}

		cancelled := taskCtx.Err() != nil

		wrapped := buildEventCrawlResponse(results, discoveredURLs, args)
		if cancelled {
			wrapped.Summary = "PARTIAL RESULTS (crawl was cancelled): " + wrapped.Summary
		}

		data, err := json.Marshal(wrapped)
		if err != nil {
			task.Fail(fmt.Sprintf("marshaling result: %v", err))
			return
		}
		task.Complete(data)
	})
}

// eventCrawlResponse wraps event crawl results with narrative context.
type eventCrawlResponse struct {
	Summary        string             `json:"summary"`
	Interpretation string             `json:"interpretation"`
	ElementsFound  int                `json:"elements_found"`
	DiscoveredURLs []string           `json:"discovered_urls"`
	XHRRequests    []string           `json:"xhr_requests"`
	Results        []EventCrawlResult `json:"results"`
	NextSteps      []string           `json:"next_steps"`
}

func buildEventCrawlResponse(results []EventCrawlResult, discoveredURLs []string, args eventCrawlArgs) *eventCrawlResponse {
	resp := &eventCrawlResponse{
		ElementsFound:  len(results),
		DiscoveredURLs: discoveredURLs,
		Results:        results,
	}

	// Collect unique XHR requests across all results
	xhrSeen := make(map[string]bool)
	for _, r := range results {
		for _, xhr := range r.XHRRequests {
			if !xhrSeen[xhr] {
				xhrSeen[xhr] = true
				resp.XHRRequests = append(resp.XHRRequests, xhr)
			}
		}
	}

	// Count DOM changes
	domChanges := 0
	for _, r := range results {
		if r.DOMChanged {
			domChanges++
		}
	}

	// Build summary
	var sb strings.Builder
	fmt.Fprintf(&sb, "Event-crawled %s: clicked %d interactive elements. ", args.Target, len(results))
	fmt.Fprintf(&sb, "Discovered %d unique URLs and %d XHR/API requests. ", len(discoveredURLs), len(resp.XHRRequests))
	if domChanges > 0 {
		fmt.Fprintf(&sb, "%d clicks caused DOM mutations. ", domChanges)
	}
	resp.Summary = sb.String()

	// Build interpretation
	var interp strings.Builder
	if len(discoveredURLs) > 0 || len(resp.XHRRequests) > 0 {
		totalEndpoints := len(discoveredURLs) + len(resp.XHRRequests)
		fmt.Fprintf(&interp, "Found %d endpoints that are only discoverable through browser interaction. ", totalEndpoints)
		if len(resp.XHRRequests) > 0 {
			fmt.Fprintf(&interp, "The %d XHR/API calls represent backend endpoints that the JavaScript app communicates with — these are high-value scan targets. ", len(resp.XHRRequests))
		}
		if len(discoveredURLs) > 0 {
			fmt.Fprintf(&interp, "The %d discovered URLs include client-side routes and navigation targets revealed by clicking UI elements. ", len(discoveredURLs))
		}
	} else {
		interp.WriteString("No hidden endpoints discovered. The page may be static, or interactive elements did not trigger network requests. ")
		interp.WriteString("Consider running 'discover' for static endpoint discovery methods.")
	}
	resp.Interpretation = interp.String()

	// Build next steps
	steps := make([]string, 0, 5)
	if len(discoveredURLs) > 0 || len(resp.XHRRequests) > 0 {
		// Copy to avoid aliasing the discoveredURLs backing array
		allEndpoints := make([]string, 0, len(discoveredURLs)+len(resp.XHRRequests))
		allEndpoints = append(allEndpoints, discoveredURLs...)
		allEndpoints = append(allEndpoints, resp.XHRRequests...)
		if len(allEndpoints) > 3 {
			allEndpoints = allEndpoints[:3]
		}
		steps = append(steps,
			fmt.Sprintf("Use 'scan' to test the discovered endpoints for WAF bypasses. Start with: %s", strings.Join(allEndpoints, ", ")))
		steps = append(steps,
			"XHR/API endpoints are often less protected by WAF rules — prioritize scanning those.")
		steps = append(steps,
			"Use 'detect_waf' on the API endpoints to check if they have the same WAF protection as the main app.")
	}
	if len(results) == args.MaxClicks && args.MaxClicks < 200 {
		steps = append(steps,
			fmt.Sprintf("Hit the max_clicks limit (%d). Re-run with a higher limit to discover more: {\"max_clicks\": %d}.",
				args.MaxClicks, min(args.MaxClicks*2, 200)))
	} else if len(results) == args.MaxClicks {
		steps = append(steps,
			fmt.Sprintf("Hit the max_clicks limit (%d). All interactive elements may not have been explored — consider narrowing the target to a specific page.", args.MaxClicks))
	}
	steps = append(steps,
		fmt.Sprintf("Use 'discover' on %s for complementary static endpoint discovery (robots.txt, sitemap, HTML parsing).", args.Target))
	resp.NextSteps = steps

	return resp
}
