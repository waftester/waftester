package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/learning"
)

// ═══════════════════════════════════════════════════════════════════════════
// discover — Endpoint & Attack Surface Discovery
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addDiscoverTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "discover",
			Title: "Discover Attack Surface",
			Description: `Map the full attack surface of a target — endpoints, parameters, technologies, secrets. This is the deep recon tool.

USE THIS TOOL WHEN:
• Starting a comprehensive assessment — run after 'detect_waf', before 'learn'
• The user says "find all endpoints" or "map the attack surface" or "discover what's there"
• You need to feed endpoint data into 'learn' to generate a targeted test plan
• Testing a complex app with APIs, forms, JS files, and multiple paths

DO NOT USE THIS TOOL WHEN:
• The user already has a specific URL endpoint to test — use 'scan' directly
• You only need quick infra info (TLS, headers) — use 'probe' instead
• You only need to identify the WAF vendor — use 'detect_waf' instead

Crawls the target using 9 discovery sources: robots.txt, sitemap.xml, JavaScript analysis, Wayback Machine, HTML forms, active path brute-forcing, service presets, API spec parsing, and link following. Takes 1-5 minutes.

EXAMPLE INPUTS:
• Basic discovery: {"target": "https://app.example.com"}
• Known service: {"target": "https://auth.example.com", "service": "authentik"}
• Deep crawl: {"target": "https://big-app.com", "max_depth": 5, "concurrency": 20}
• Self-signed cert: {"target": "https://internal.local", "skip_verify": true}
• Passive only: {"target": "https://prod.com", "disable_active": true}

SERVICE PRESETS: authentik, n8n, immich, webapp, intranet — adds known endpoint patterns.

Returns: endpoint list with methods/params, technologies, secrets found, WAF status, attack surface analysis.

ASYNC TOOL: This tool returns a task_id immediately and runs in the background (15-120s). Poll with get_task_status to retrieve results.

TYPICAL WORKFLOW: detect_waf → discover → learn → scan`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to discover (e.g. https://app.example.com).",
						"format":      "uri",
					},
					"max_depth": map[string]any{
						"type":        "integer",
						"description": "Maximum crawl depth for link following.",
						"default":     3,
						"minimum":     1,
						"maximum":     10,
					},
					"concurrency": map[string]any{
						"type":        "integer",
						"description": "Number of parallel discovery workers.",
						"default":     10,
						"minimum":     1,
						"maximum":     50,
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "HTTP request timeout in seconds.",
						"default":     10,
						"minimum":     1,
						"maximum":     60,
					},
					"service": map[string]any{
						"type":        "string",
						"description": "Application preset — adds known endpoint patterns.",
						"enum":        []string{"authentik", "n8n", "immich", "webapp", "intranet"},
					},
					"skip_verify": map[string]any{
						"type":        "boolean",
						"description": "Skip TLS certificate verification (for self-signed certs).",
						"default":     false,
					},
					"disable_active": map[string]any{
						"type":        "boolean",
						"description": "Skip active path brute-forcing (passive discovery only).",
						"default":     false,
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   false, // Sends HTTP probes and brute-forces paths
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(true),
				Title:          "Discover Attack Surface",
			},
		},
		loggedTool("discover", s.handleDiscover),
	)
}

type discoverArgs struct {
	Target        string `json:"target"`
	MaxDepth      int    `json:"max_depth"`
	Concurrency   int    `json:"concurrency"`
	Timeout       int    `json:"timeout"`
	Service       string `json:"service"`
	SkipVerify    bool   `json:"skip_verify"`
	DisableActive bool   `json:"disable_active"`
}

func (s *Server) handleDiscover(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args discoverArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://app.example.com\"}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	if args.MaxDepth <= 0 {
		args.MaxDepth = defaults.DepthMedium
	} else if args.MaxDepth > 10 {
		args.MaxDepth = 10
	}
	if args.Concurrency <= 0 {
		args.Concurrency = defaults.ConcurrencyMedium
	} else if args.Concurrency > 50 {
		args.Concurrency = 50
	}

	return s.launchAsync(ctx, "discover", "15-120s depending on site size", func(taskCtx context.Context, task *Task) {
		hosterrors.Clear(args.Target)

		task.SetProgress(0, 100, "Starting discovery on "+args.Target)

		cfg := discovery.DiscoveryConfig{
			Target:        args.Target,
			Timeout:       timeout,
			MaxDepth:      args.MaxDepth,
			Concurrency:   args.Concurrency,
			SkipVerify:    args.SkipVerify,
			Service:       args.Service,
			DisableActive: args.DisableActive,
		}

		discoverer := discovery.NewDiscoverer(cfg)
		task.SetProgress(10, 100, "Probing target and checking WAF…")

		result, err := discoverer.Discover(taskCtx)
		if err != nil {
			task.Fail(fmt.Sprintf("discovery failed: %v", err))
			return
		}

		cancelled := taskCtx.Err() != nil

		task.SetProgress(90, 100, fmt.Sprintf("Discovered %d endpoints, building summary…", len(result.Endpoints)))

		summary := buildDiscoverySummary(result)
		if cancelled {
			summary.Summary = "PARTIAL RESULTS (discovery was cancelled): " + summary.Summary
		}
		data, err := json.Marshal(summary)
		if err != nil {
			task.Fail(fmt.Sprintf("marshaling result: %v", err))
			return
		}

		task.Complete(data)
	})
}

type discoverySummary struct {
	Summary        string                         `json:"summary"`
	Target         string                         `json:"target"`
	EndpointCount  int                            `json:"endpoint_count"`
	WAFDetected    bool                           `json:"waf_detected"`
	WAFFingerprint string                         `json:"waf_fingerprint,omitempty"`
	Technologies   []string                       `json:"technologies,omitempty"`
	AttackSurface  *discovery.AttackSurface       `json:"attack_surface,omitempty"`
	Statistics     *discovery.DiscoveryStatistics `json:"statistics,omitempty"`
	TopEndpoints   []endpointPreview              `json:"top_endpoints,omitempty"`
	SecretsFound   int                            `json:"secrets_found"`
	NextSteps      []string                       `json:"next_steps"`
}

type endpointPreview struct {
	Path       string `json:"path"`
	Method     string `json:"method"`
	Category   string `json:"category,omitempty"`
	Parameters int    `json:"parameters,omitempty"`
}

func buildDiscoverySummary(r *discovery.DiscoveryResult) *discoverySummary {
	s := &discoverySummary{
		Target:         r.Target,
		EndpointCount:  len(r.Endpoints),
		WAFDetected:    r.WAFDetected,
		WAFFingerprint: r.WAFFingerprint,
		Technologies:   r.Technologies,
		AttackSurface:  &r.AttackSurface,
		Statistics:     &r.Statistics,
	}

	// Count total secrets across all categories
	for _, secrets := range r.Secrets {
		s.SecretsFound += len(secrets)
	}

	limit := 20
	if len(r.Endpoints) < limit {
		limit = len(r.Endpoints)
	}
	for _, ep := range r.Endpoints[:limit] {
		s.TopEndpoints = append(s.TopEndpoints, endpointPreview{
			Path:       ep.Path,
			Method:     ep.Method,
			Category:   ep.Category,
			Parameters: len(ep.Parameters),
		})
	}

	// Build narrative summary
	var sb strings.Builder
	fmt.Fprintf(&sb, "Discovered %d endpoints on %s. ", len(r.Endpoints), r.Target)
	if r.WAFDetected {
		fmt.Fprintf(&sb, "WAF detected: %s. ", r.WAFFingerprint)
	} else {
		sb.WriteString("No WAF detected. ")
	}
	if len(r.Technologies) > 0 {
		fmt.Fprintf(&sb, "Technologies: %s. ", strings.Join(r.Technologies, ", "))
	}
	if s.SecretsFound > 0 {
		fmt.Fprintf(&sb, "WARNING: %d exposed secrets found! ", s.SecretsFound)
	}
	paramCount := 0
	for _, ep := range r.Endpoints {
		paramCount += len(ep.Parameters)
	}
	if paramCount > 0 {
		fmt.Fprintf(&sb, "Total injectable parameters: %d. ", paramCount)
	}
	fmt.Fprintf(&sb, "Showing top %d endpoints.", limit)
	s.Summary = sb.String()

	// Build next steps
	steps := make([]string, 0, 4)
	steps = append(steps,
		"Use 'learn' with this discovery output to generate a prioritized, endpoint-aware test plan.")
	steps = append(steps,
		fmt.Sprintf("Use 'scan' on %s with specific categories to test WAF blocking.", r.Target))
	if !r.WAFDetected {
		steps = append(steps,
			fmt.Sprintf("Use 'detect_waf' on %s for deeper WAF fingerprinting — discovery WAF check is basic.", r.Target))
	}
	if s.SecretsFound > 0 {
		steps = append(steps,
			fmt.Sprintf("URGENT: %d secrets exposed — investigate and rotate immediately.", s.SecretsFound))
	}
	steps = append(steps,
		"Use 'probe' for detailed TLS and security header analysis.")
	s.NextSteps = steps

	return s
}

// ═══════════════════════════════════════════════════════════════════════════
// learn — Intelligent Test Plan Generation
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addLearnTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "learn",
			Title: "Generate Test Plan",
			Description: `Turn discovery results into a prioritized test plan. This is the brain between 'discover' and 'scan'.

USE THIS TOOL WHEN:
• You just ran 'discover' and need to generate a smart test plan
• The user wants an intelligent, endpoint-aware scan (not just blind payload spraying)
• You want to prioritize which endpoints to test first based on risk

DO NOT USE THIS TOOL WHEN:
• You want to scan a single known URL — use 'scan' directly with a category
• You haven't run 'discover' yet — run that first to get the input JSON
• You want WAF metrics/grades — use 'assess' instead

Takes raw discovery JSON and produces: endpoint-to-attack mappings, priority rankings (P1 auth/injection through P5 fuzzing), injection point identification (query, body, headers, cookies), custom payload selection per endpoint, and optimal concurrency settings.

EXAMPLE INPUTS:
• From discovery output: {"discovery_json": "<paste raw JSON from discover tool>"}

The input MUST be the raw JSON string output from the 'discover' tool. Pass it as a string, not an object.

Returns: test groups, endpoint tests, priorities, category mappings, recommendations.

TYPICAL WORKFLOW: detect_waf → discover → learn → scan`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"discovery_json": map[string]any{
						"type":        "string",
						"description": "JSON string containing discovery results from the 'discover' tool. Pass the raw JSON output.",
					},
				},
				"required": []string{"discovery_json"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "Generate Test Plan",
			},
		},
		loggedTool("learn", s.handleLearn),
	)
}

type learnArgs struct {
	DiscoveryJSON string `json:"discovery_json"`
}

func (s *Server) handleLearn(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args learnArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.DiscoveryJSON == "" {
		return errorResult("discovery_json is required. Run the 'discover' tool first and pass its JSON output here."), nil
	}

	var disc discovery.DiscoveryResult
	if err := json.Unmarshal([]byte(args.DiscoveryJSON), &disc); err != nil {
		return errorResult(fmt.Sprintf("invalid discovery JSON: %v. Pass the raw JSON output from the 'discover' tool.", err)), nil
	}

	notifyProgress(ctx, req, 0, 100, "Analyzing discovery results…")
	logToSession(ctx, req, logInfo, fmt.Sprintf("Generating test plan for %s (%d endpoints)", disc.Target, len(disc.Endpoints)))

	learner := learning.NewLearner(&disc, s.config.PayloadDir)

	notifyProgress(ctx, req, 30, 100, "Mapping endpoints to attack categories…")

	plan := learner.GenerateTestPlan()

	notifyProgress(ctx, req, 100, 100, "Test plan generated")
	logToSession(ctx, req, logInfo, fmt.Sprintf("Test plan ready: %d groups, %d endpoint tests", len(plan.TestGroups), len(plan.EndpointTests)))

	wrapped := buildLearnResponse(plan)
	return jsonResult(wrapped)
}

// learnResponse wraps TestPlan with narrative context for AI agents.
type learnResponse struct {
	Summary   string             `json:"summary"`
	Plan      *learning.TestPlan `json:"plan"`
	NextSteps []string           `json:"next_steps"`
}

func buildLearnResponse(plan *learning.TestPlan) *learnResponse {
	resp := &learnResponse{Plan: plan}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Generated test plan for %s: %d test groups, %d endpoint-specific tests, ~%d total payloads. ",
		plan.Target, len(plan.TestGroups), len(plan.EndpointTests), plan.TotalTests)
	fmt.Fprintf(&sb, "Estimated time: %s. ", plan.EstimatedTime)

	// Highlight high-priority groups
	var p1Groups []string
	for _, g := range plan.TestGroups {
		if g.Priority <= 2 {
			p1Groups = append(p1Groups, g.Category)
		}
	}
	if len(p1Groups) > 0 {
		fmt.Fprintf(&sb, "High-priority categories: %s. ", strings.Join(p1Groups, ", "))
	}

	resp.Summary = sb.String()

	// Build next steps
	steps := make([]string, 0, 4)
	if len(plan.RecommendedFlags.Categories) > 0 {
		steps = append(steps,
			fmt.Sprintf("Use 'scan' with {\"target\": \"%s\", \"categories\": %v} to execute the test plan.",
				plan.Target, plan.RecommendedFlags.Categories))
	} else {
		steps = append(steps,
			fmt.Sprintf("Use 'scan' on %s to execute the test plan with all recommended categories.", plan.Target))
	}
	steps = append(steps,
		fmt.Sprintf("Set concurrency=%d, rate_limit=%d, timeout=%ds as recommended by the test plan.",
			plan.RecommendedFlags.Concurrency, plan.RecommendedFlags.RateLimit, plan.RecommendedFlags.Timeout))
	steps = append(steps,
		fmt.Sprintf("Use 'assess' on %s for a full enterprise assessment with formal grading after the scan.", plan.Target))
	if len(plan.RecommendedFlags.FocusAreas) > 0 {
		steps = append(steps,
			fmt.Sprintf("Focus areas identified: %s", strings.Join(plan.RecommendedFlags.FocusAreas, ", ")))
	}
	resp.NextSteps = steps

	return resp
}
