package mcpserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/assessment"
	"github.com/waftester/waftester/pkg/core"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/learning"
	"github.com/waftester/waftester/pkg/mutation"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/waf"
)

// registerTools adds all WAF testing tools to the MCP server.
func (s *Server) registerTools() {
	s.addListPayloadsTool()
	s.addDetectWAFTool()
	s.addDiscoverTool()
	s.addLearnTool()
	s.addScanTool()
	s.addAssessTool()
	s.addMutateTool()
	s.addBypassTool()
	s.addProbeTool()
	s.addGenerateCICDTool()
}

// ═══════════════════════════════════════════════════════════════════════════
// list_payloads — Browse the attack payload catalog
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addListPayloadsTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "list_payloads",
			Title: "List Attack Payloads",
			Description: `Inventory tool — browse the local attack payload catalog WITHOUT sending any traffic.

USE THIS TOOL WHEN:
• The user asks "what payloads/categories/attacks do you support?"
• You need to check how many payloads exist for a category before running 'scan'
• You want to show the user sample payloads for a specific attack type
• Planning which categories to include in a scan or assessment

DO NOT USE THIS TOOL WHEN:
• You want to actually TEST a target — use 'scan' instead
• You want WAF bypass testing — use 'bypass' instead
• You want to encode/mutate a specific payload — use 'mutate' instead

This is a READ-ONLY local operation. Zero network requests. Instant results.

EXAMPLE INPUTS:
• See everything: {} (no arguments)
• Browse SQL injection payloads: {"category": "sqli"}
• Only critical XSS payloads: {"category": "xss", "severity": "Critical"}
• High+ severity across all categories: {"severity": "High"}

CATEGORIES: sqli, xss, traversal, auth, ssrf, ssti, cmdi, xxe, nosqli, graphql, cors, crlf, redirect, upload, jwt, oauth, prototype, deserialize
SEVERITY (descending): Critical > High > Medium > Low

Returns: total count, per-category breakdown, severity distribution, 5 sample payloads.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"category": map[string]any{
						"type":        "string",
						"description": "Filter by specific attack category. Leave empty to see all categories.",
						"enum":        []string{"sqli", "xss", "traversal", "auth", "ssrf", "ssti", "cmdi", "xxe", "nosqli", "graphql", "cors", "crlf", "redirect", "upload", "jwt", "oauth", "prototype", "deserialize"},
					},
					"severity": map[string]any{
						"type":        "string",
						"description": "Filter by minimum severity level. Only payloads at this severity or higher are returned.",
						"enum":        []string{"Critical", "High", "Medium", "Low"},
					},
				},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(false),
				Title:          "List Attack Payloads",
			},
		},
		s.handleListPayloads,
	)
}

type listPayloadsArgs struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
}

type payloadSummary struct {
	TotalPayloads  int            `json:"total_payloads"`
	Categories     int            `json:"categories"`
	ByCategory     map[string]int `json:"by_category"`
	BySeverity     map[string]int `json:"by_severity"`
	FilterApplied  string         `json:"filter_applied,omitempty"`
	SamplePayloads []sampleEntry  `json:"sample_payloads,omitempty"`
}

type sampleEntry struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Snippet  string `json:"snippet"`
}

func (s *Server) handleListPayloads(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args listPayloadsArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v. Expected optional 'category' (string) and 'severity' (string).", err)), nil
	}

	loader := payloads.NewLoader(s.config.PayloadDir)
	all, err := loader.LoadAll()
	if err != nil {
		return errorResult(fmt.Sprintf("failed to load payloads from %s: %v. Verify the payload directory exists and contains JSON files.", s.config.PayloadDir, err)), nil
	}

	filtered := payloads.Filter(all, args.Category, args.Severity)
	stats := payloads.GetStats(filtered)

	bySeverity := make(map[string]int)
	for _, p := range filtered {
		if p.SeverityHint != "" {
			bySeverity[p.SeverityHint]++
		}
	}

	summary := payloadSummary{
		TotalPayloads: stats.TotalPayloads,
		Categories:    stats.CategoriesUsed,
		ByCategory:    stats.ByCategory,
		BySeverity:    bySeverity,
	}

	if args.Category != "" || args.Severity != "" {
		parts := make([]string, 0, 2)
		if args.Category != "" {
			parts = append(parts, "category="+args.Category)
		}
		if args.Severity != "" {
			parts = append(parts, "severity≥"+args.Severity)
		}
		summary.FilterApplied = strings.Join(parts, ", ")
	}

	limit := 5
	if len(filtered) < limit {
		limit = len(filtered)
	}
	for _, p := range filtered[:limit] {
		snippet := p.Payload
		if len(snippet) > 80 {
			snippet = snippet[:80] + "…"
		}
		summary.SamplePayloads = append(summary.SamplePayloads, sampleEntry{
			ID:       p.ID,
			Category: p.Category,
			Severity: p.SeverityHint,
			Snippet:  snippet,
		})
	}

	return jsonResult(summary)
}

// ═══════════════════════════════════════════════════════════════════════════
// detect_waf — WAF/CDN Detection & Fingerprinting
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addDetectWAFTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "detect_waf",
			Title: "Detect WAF/CDN",
			Description: `Fingerprint the WAF/CDN vendor protecting a target. This is step 1 of any engagement — run it FIRST.

USE THIS TOOL WHEN:
• Starting any new target — ALWAYS detect the WAF before scanning or bypassing
• The user asks "what WAF is protecting this site?"
• You need vendor-specific bypass hints before running 'bypass' or 'scan'
• Verifying whether a target even has a WAF in front of it

DO NOT USE THIS TOOL WHEN:
• The user already told you the WAF vendor (skip straight to 'scan' or 'bypass')
• You want full attack surface mapping — use 'discover' instead
• You want TLS/header/infra details without WAF focus — use 'probe' instead

Sends ~20 benign probes + ~5 trigger requests. Very low impact. Takes 10-30 seconds.
Covers 25+ WAF vendors with header analysis, behavioral probing, and TLS fingerprinting.

EXAMPLE INPUTS:
• Basic detection: {"target": "https://example.com"}
• With custom timeout: {"target": "https://slow-site.com", "timeout": 30}

Returns: vendor name, confidence %, detection method, CDN info, and bypass tips.
Known vendors: Cloudflare, AWS WAF, Azure WAF, Akamai, Imperva, ModSecurity, Coraza, F5 BIG-IP, Fortinet, Barracuda, Sucuri, Google Cloud Armor, Wallarm, and more.

TYPICAL WORKFLOW: detect_waf → discover → learn → scan → bypass`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to detect WAF on. Must include scheme (https://example.com).",
						"format":      "uri",
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "Detection timeout in seconds.",
						"default":     10,
						"minimum":     1,
						"maximum":     60,
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(true),
				Title:          "Detect WAF/CDN",
			},
		},
		s.handleDetectWAF,
	)
}

type detectWAFArgs struct {
	Target  string `json:"target"`
	Timeout int    `json:"timeout"`
}

func (s *Server) handleDetectWAF(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args detectWAFArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\"}"), nil
	}

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	notifyProgress(ctx, req, 0, 100, "Starting WAF detection on "+args.Target)
	logToSession(ctx, req, logInfo, "Initiating WAF/CDN detection for "+args.Target)

	detector := waf.NewDetector(timeout)

	notifyProgress(ctx, req, 15, 100, "Analyzing response headers…")
	notifyProgress(ctx, req, 30, 100, "Running behavioral probes…")

	result, err := detector.Detect(ctx, args.Target)
	if err != nil {
		return errorResult(fmt.Sprintf("WAF detection failed: %v. Check that the target is reachable and the URL includes the scheme (https://).", err)), nil
	}

	notifyProgress(ctx, req, 100, 100, "Detection complete")
	logToSession(ctx, req, logInfo, fmt.Sprintf("WAF detection complete for %s", args.Target))

	return jsonResult(result)
}

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
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(true),
				Title:          "Discover Attack Surface",
			},
		},
		s.handleDiscover,
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

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	cfg := discovery.DiscoveryConfig{
		Target:        args.Target,
		Timeout:       timeout,
		MaxDepth:      args.MaxDepth,
		Concurrency:   args.Concurrency,
		SkipVerify:    args.SkipVerify,
		Service:       args.Service,
		DisableActive: args.DisableActive,
	}

	notifyProgress(ctx, req, 0, 100, "Starting discovery on "+args.Target)
	logToSession(ctx, req, logInfo, "Initiating attack surface discovery for "+args.Target)

	discoverer := discovery.NewDiscoverer(cfg)

	notifyProgress(ctx, req, 10, 100, "Probing target and checking WAF…")

	result, err := discoverer.Discover(ctx)
	if err != nil {
		return errorResult(fmt.Sprintf("discovery failed: %v. Check that the target is reachable.", err)), nil
	}

	notifyProgress(ctx, req, 100, 100, "Discovery complete")
	logToSession(ctx, req, logInfo, fmt.Sprintf("Discovered %d endpoints for %s", len(result.Endpoints), args.Target))

	summary := buildDiscoverySummary(result)
	return jsonResult(summary)
}

type discoverySummary struct {
	Target         string                         `json:"target"`
	EndpointCount  int                            `json:"endpoint_count"`
	WAFDetected    bool                           `json:"waf_detected"`
	WAFFingerprint string                         `json:"waf_fingerprint,omitempty"`
	Technologies   []string                       `json:"technologies,omitempty"`
	AttackSurface  *discovery.AttackSurface       `json:"attack_surface,omitempty"`
	Statistics     *discovery.DiscoveryStatistics `json:"statistics,omitempty"`
	TopEndpoints   []endpointPreview              `json:"top_endpoints,omitempty"`
	SecretsFound   int                            `json:"secrets_found"`
}

type endpointPreview struct {
	Path       string `json:"path"`
	Method     string `json:"method"`
	Category   string `json:"category,omitempty"`
	Parameters int    `json:"parameters,omitempty"`
}

func buildDiscoverySummary(r *discovery.DiscoveryResult) *discoverySummary {
	as := r.AttackSurface
	st := r.Statistics

	s := &discoverySummary{
		Target:         r.Target,
		EndpointCount:  len(r.Endpoints),
		WAFDetected:    r.WAFDetected,
		WAFFingerprint: r.WAFFingerprint,
		Technologies:   r.Technologies,
		AttackSurface:  &as,
		Statistics:     &st,
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
		s.handleLearn,
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

	return jsonResult(plan)
}

// ═══════════════════════════════════════════════════════════════════════════
// scan — WAF Security Scan
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addScanTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "scan",
			Title: "WAF Security Scan",
			Description: `Fire attack payloads at a target and see what the WAF blocks vs. lets through. This is the core scanning tool.

USE THIS TOOL WHEN:
• The user says "scan this", "test this URL", or "check if the WAF blocks SQLi"
• You want to test specific attack categories against a known URL
• You need a detection rate (% of attacks blocked) for a specific endpoint
• Running targeted tests after 'discover' + 'learn' identified interesting endpoints
• Quick validation: "does the WAF block XSS on /search?q=" — yes, use this

DO NOT USE THIS TOOL WHEN:
• You need formal WAF grades/metrics (F1, MCC, FPR) — use 'assess' instead
• You want to find bypass VARIANTS via encoding/mutation — use 'bypass' instead
• You want to just encode a payload without testing it — use 'mutate' instead
• You want to browse available payloads — use 'list_payloads' instead

'scan' vs 'assess': scan gives you a detection rate and bypass list. assess gives you enterprise metrics (F1 score, false positive rate, MCC, letter grade). Use scan for quick checks, assess for formal reports.
'scan' vs 'bypass': scan tests known payloads as-is. bypass applies the full mutation matrix (encoders x locations x evasions) to find WAF-evading variants.

EXAMPLE INPUTS:
• Quick SQLi scan: {"target": "https://example.com/search?q=test", "categories": ["sqli"]}
• SQLi + XSS: {"target": "https://app.example.com", "categories": ["sqli", "xss"]}
• All categories: {"target": "https://example.com"}
• Critical only: {"target": "https://prod.com", "severity": "Critical", "rate_limit": 20}
• Through Burp proxy: {"target": "https://example.com", "proxy": "http://127.0.0.1:8080"}
• Production-safe: {"target": "https://prod.com", "concurrency": 5, "rate_limit": 10}

RESULT MEANINGS:
• "Blocked" = WAF stopped the attack (good)
• "Fail" = attack reached the app (BAD — this is a bypass)
• "Error" = network issue (investigate connectivity)

Returns: detection rate, total/blocked/failed counts, bypass details with reproduction info, latency stats.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to scan (e.g. https://example.com/search?q=test).",
						"format":      "uri",
					},
					"categories": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Payload categories to test. Empty means all. Examples: [\"sqli\", \"xss\", \"traversal\"].",
					},
					"severity": map[string]any{
						"type":        "string",
						"description": "Minimum severity level to test.",
						"enum":        []string{"Critical", "High", "Medium", "Low"},
					},
					"concurrency": map[string]any{
						"type":        "integer",
						"description": "Number of concurrent workers.",
						"default":     10,
						"minimum":     1,
						"maximum":     100,
					},
					"rate_limit": map[string]any{
						"type":        "integer",
						"description": "Maximum requests per second.",
						"default":     50,
						"minimum":     1,
						"maximum":     1000,
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "HTTP request timeout in seconds.",
						"default":     5,
						"minimum":     1,
						"maximum":     60,
					},
					"skip_verify": map[string]any{
						"type":        "boolean",
						"description": "Skip TLS certificate verification.",
						"default":     false,
					},
					"proxy": map[string]any{
						"type":        "string",
						"description": "Proxy URL for requests (e.g. http://127.0.0.1:8080 for Burp Suite).",
						"format":      "uri",
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:    false,
				IdempotentHint:  false,
				OpenWorldHint:   boolPtr(true),
				DestructiveHint: boolPtr(false),
				Title:           "WAF Security Scan",
			},
		},
		s.handleScan,
	)
}

type scanArgs struct {
	Target      string   `json:"target"`
	Categories  []string `json:"categories"`
	Severity    string   `json:"severity"`
	Concurrency int      `json:"concurrency"`
	RateLimit   int      `json:"rate_limit"`
	Timeout     int      `json:"timeout"`
	SkipVerify  bool     `json:"skip_verify"`
	Proxy       string   `json:"proxy"`
}

type scanResultSummary struct {
	Target        string                  `json:"target"`
	DetectionRate string                  `json:"detection_rate"`
	Results       output.ExecutionResults `json:"results"`
}

func (s *Server) handleScan(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args scanArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\"}"), nil
	}

	if args.Concurrency <= 0 {
		args.Concurrency = 10
	}
	if args.RateLimit <= 0 {
		args.RateLimit = 50
	}
	if args.Timeout <= 0 {
		args.Timeout = 5
	}

	notifyProgress(ctx, req, 0, 100, "Loading payloads…")
	logToSession(ctx, req, logInfo, fmt.Sprintf("Starting scan on %s (concurrency=%d, rate=%d/s)", args.Target, args.Concurrency, args.RateLimit))

	loader := payloads.NewLoader(s.config.PayloadDir)
	all, err := loader.LoadAll()
	if err != nil {
		return errorResult(fmt.Sprintf("failed to load payloads from %s: %v", s.config.PayloadDir, err)), nil
	}

	var filtered []payloads.Payload
	if len(args.Categories) > 0 {
		catSet := make(map[string]bool)
		for _, c := range args.Categories {
			catSet[strings.ToLower(c)] = true
		}
		for _, p := range all {
			if catSet[strings.ToLower(p.Category)] {
				filtered = append(filtered, p)
			}
		}
	} else {
		filtered = all
	}

	if args.Severity != "" {
		filtered = payloads.Filter(filtered, "", args.Severity)
	}

	if len(filtered) == 0 {
		return errorResult("no payloads match the specified filters. Try broadening the category or severity, or check that the payload directory contains files."), nil
	}

	notifyProgress(ctx, req, 10, 100, fmt.Sprintf("Loaded %d payloads, scanning…", len(filtered)))

	total := len(filtered)
	var received atomic.Int64
	var bypasses atomic.Int64

	executor := core.NewExecutor(core.ExecutorConfig{
		TargetURL:   args.Target,
		Concurrency: args.Concurrency,
		RateLimit:   args.RateLimit,
		Timeout:     time.Duration(args.Timeout) * time.Second,
		SkipVerify:  args.SkipVerify,
		Proxy:       args.Proxy,
		OnResult: func(r *output.TestResult) {
			n := received.Add(1)
			if r.Outcome == "Fail" {
				b := bypasses.Add(1)
				logToSession(ctx, req, logWarning,
					fmt.Sprintf("BYPASS: %s [%s] → %d", r.ID, r.Category, r.StatusCode))
				_ = b // used only in the progress message below
			}
			if n%10 == 0 || n == int64(total) {
				pct := float64(n) / float64(total) * 80
				notifyProgress(ctx, req, 10+pct, 100,
					fmt.Sprintf("Tested %d/%d (bypasses: %d)…", n, total, bypasses.Load()))
			}
		},
	})

	execResults := executor.Execute(ctx, filtered, &discardWriter{})

	notifyProgress(ctx, req, 95, 100, "Generating summary…")

	// Calculate detection rate
	detectionRate := ""
	tested := execResults.BlockedTests + execResults.FailedTests
	if tested > 0 {
		rate := float64(execResults.BlockedTests) / float64(tested) * 100
		detectionRate = fmt.Sprintf("%.1f%%", rate)
	}

	summary := &scanResultSummary{
		Target:        args.Target,
		DetectionRate: detectionRate,
		Results:       execResults,
	}

	notifyProgress(ctx, req, 100, 100, fmt.Sprintf("Scan complete — %d bypasses found", execResults.FailedTests))
	logToSession(ctx, req, logInfo, fmt.Sprintf("Scan finished: %d tested, %d blocked, %d bypassed, detection rate: %s",
		execResults.TotalTests, execResults.BlockedTests, execResults.FailedTests, detectionRate))

	return jsonResult(summary)
}

// discardWriter implements output.Writer and discards all results.
// Used when results are collected via the OnResult callback instead.
type discardWriter struct{}

func (w *discardWriter) Write(_ *output.TestResult) error { return nil }
func (w *discardWriter) Close() error                     { return nil }

// ═══════════════════════════════════════════════════════════════════════════
// assess — Enterprise WAF Assessment
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addAssessTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "assess",
			Title: "Enterprise WAF Assessment",
			Description: `Enterprise-grade WAF scoring with letter grades, F1/MCC metrics, and false positive measurement. The formal assessment tool.

USE THIS TOOL WHEN:
• The user asks for a "WAF assessment", "WAF grade", or "WAF score"
• You need quantitative metrics: F1 score, MCC, false positive rate, detection rate
• Producing a formal report or compliance artifact
• Comparing WAF vendors or configurations side-by-side
• The user wants a letter grade (A through F) for their WAF

DO NOT USE THIS TOOL WHEN:
• Quick check on a single category — use 'scan' instead (much faster)
• Looking for bypass variants via encoding — use 'bypass' instead
• Just need to identify the WAF vendor — use 'detect_waf' instead

'assess' vs 'scan': assess runs a full rubric across all categories, measures false positives using a benign corpus, computes F1/MCC/FPR, and assigns a letter grade. scan just fires payloads and reports pass/fail. Use assess for formal evaluations, scan for targeted checks.

EXAMPLE INPUTS:
• Standard assessment: {"target": "https://example.com"}
• Specific categories: {"target": "https://example.com", "categories": ["sqli", "xss", "cmdi"]}
• Skip false-positive testing (faster): {"target": "https://example.com", "enable_fp_testing": false}
• Conservative (production): {"target": "https://prod.com", "rate_limit": 10, "concurrency": 3}

GRADING RUBRIC: A+ (>97%) → A (>93%) → B (>85%) → C (>70%) → D (>50%) → F (<50%)
METRICS: Detection Rate, F1 Score (precision×recall balance), MCC (Matthews Correlation), FPR (false positive rate)

Returns: letter grade, category scores, F1/MCC/FPR metrics, bypass list, per-category breakdown, improvement recommendations.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to assess.",
						"format":      "uri",
					},
					"concurrency": map[string]any{
						"type":        "integer",
						"description": "Concurrent workers.",
						"default":     25,
						"minimum":     1,
						"maximum":     100,
					},
					"rate_limit": map[string]any{
						"type":        "integer",
						"description": "Maximum requests per second.",
						"default":     100,
						"minimum":     1,
						"maximum":     500,
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "Request timeout in seconds.",
						"default":     10,
						"minimum":     1,
						"maximum":     60,
					},
					"categories": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Attack categories to test. Empty means all.",
					},
					"enable_fp_testing": map[string]any{
						"type":        "boolean",
						"description": "Enable false positive testing with benign corpus.",
						"default":     true,
					},
					"detect_waf": map[string]any{
						"type":        "boolean",
						"description": "Auto-detect WAF vendor before testing.",
						"default":     true,
					},
					"skip_verify": map[string]any{
						"type":        "boolean",
						"description": "Skip TLS certificate verification.",
						"default":     false,
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				OpenWorldHint:   boolPtr(true),
				DestructiveHint: boolPtr(false),
				Title:           "Enterprise WAF Assessment",
			},
		},
		s.handleAssess,
	)
}

type assessArgs struct {
	Target          string   `json:"target"`
	Concurrency     int      `json:"concurrency"`
	RateLimit       int      `json:"rate_limit"`
	Timeout         int      `json:"timeout"`
	Categories      []string `json:"categories"`
	EnableFPTesting *bool    `json:"enable_fp_testing"`
	DetectWAF       *bool    `json:"detect_waf"`
	SkipVerify      bool     `json:"skip_verify"`
}

func (s *Server) handleAssess(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args assessArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\"}"), nil
	}

	cfg := assessment.DefaultConfig()
	cfg.TargetURL = args.Target
	cfg.PayloadDir = s.config.PayloadDir
	cfg.SkipTLSVerify = args.SkipVerify
	cfg.OutputFormat = "json"

	if args.Concurrency > 0 {
		cfg.Concurrency = args.Concurrency
	}
	if args.RateLimit > 0 {
		cfg.RateLimit = float64(args.RateLimit)
	}
	if args.Timeout > 0 {
		cfg.Timeout = time.Duration(args.Timeout) * time.Second
	}
	if len(args.Categories) > 0 {
		cfg.Categories = args.Categories
	}
	if args.EnableFPTesting != nil {
		cfg.EnableFPTesting = *args.EnableFPTesting
	}
	if args.DetectWAF != nil {
		cfg.DetectWAF = *args.DetectWAF
	}

	notifyProgress(ctx, req, 0, 100, "Starting enterprise assessment on "+args.Target)
	logToSession(ctx, req, logInfo, "Enterprise WAF assessment initiated for "+args.Target)

	a := assessment.New(cfg)

	progressFn := func(completed, total int64, phase string) {
		if total > 0 {
			pct := float64(completed) / float64(total) * 90
			notifyProgress(ctx, req, pct, 100, fmt.Sprintf("[%s] %d/%d", phase, completed, total))
		}
	}

	metrics, err := a.Run(ctx, progressFn)
	if err != nil {
		return errorResult(fmt.Sprintf("assessment failed: %v", err)), nil
	}

	notifyProgress(ctx, req, 100, 100, fmt.Sprintf("Assessment complete — Grade: %s", metrics.Grade))
	logToSession(ctx, req, logInfo, fmt.Sprintf("Assessment complete: Grade=%s, F1=%.3f, FPR=%.3f",
		metrics.Grade, metrics.F1Score, metrics.FalsePositiveRate))

	return jsonResult(metrics)
}

// ═══════════════════════════════════════════════════════════════════════════
// mutate — Payload Mutation & Encoding
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addMutateTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "mutate",
			Title: "Mutate Payloads",
			Description: `Encode a payload string into WAF-evasion variants — URL, double-URL, Unicode, HTML hex. Offline encoding, no network traffic.

USE THIS TOOL WHEN:
• A payload was blocked and the user wants to see how it looks in different encodings
• The user says "encode this", "mutate this payload", or "show me evasion variants"
• Inspecting what the mutation matrix would produce before testing live with 'bypass'
• Preparing payloads for manual testing in Burp Suite or curl

DO NOT USE THIS TOOL WHEN:
• You want to also TEST the mutations against a WAF — use 'bypass' instead (it mutates AND tests)
• You want to scan a target — use 'scan' instead
• You want to browse the payload catalog — use 'list_payloads' instead

'mutate' vs 'bypass': mutate is offline — it shows you what the encodings look like. bypass is online — it encodes AND fires them at a target to find what passes. mutate = preview, bypass = execute.

EXAMPLE INPUTS:
• URL-encode a SQLi payload: {"payload": "' OR 1=1--", "encoders": ["url"]}
• Try multiple encodings: {"payload": "<script>alert(1)</script>", "encoders": ["url", "double_url", "unicode", "html_hex"]}
• All available encoders: {"payload": "{{7*7}}"}
• HTML hex encoding: {"payload": "<img src=x onerror=alert(1)>", "encoders": ["html_hex"]}

AVAILABLE ENCODERS: url, double_url, unicode, html_hex
If encoders is omitted, ALL are applied.

Returns: list of {encoder, encoded_payload} pairs ready for copy-paste testing.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"payload": map[string]any{
						"type":        "string",
						"description": "The attack payload string to mutate (e.g. \"' OR 1=1--\").",
					},
					"encoders": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "string",
							"enum": []string{"url", "double_url", "unicode", "html_hex"},
						},
						"description": "Encoders to apply. Default: all available encoders.",
					},
				},
				"required": []string{"payload"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "Mutate Payloads",
			},
		},
		s.handleMutate,
	)
}

type mutateArgs struct {
	Payload  string   `json:"payload"`
	Encoders []string `json:"encoders"`
}

type mutateResult struct {
	Original string          `json:"original"`
	Variants []mutateVariant `json:"variants"`
	Count    int             `json:"count"`
	Tip      string          `json:"tip"`
}

type mutateVariant struct {
	Encoder string `json:"encoder"`
	Encoded string `json:"encoded"`
}

func (s *Server) handleMutate(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args mutateArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Payload == "" {
		return errorResult("payload is required. Example: {\"payload\": \"' OR 1=1--\"}"), nil
	}

	variants := applyBasicEncodings(args.Payload, args.Encoders)

	result := mutateResult{
		Original: args.Payload,
		Variants: variants,
		Count:    len(variants),
		Tip:      "Try each variant against the target. If double_url bypasses, the WAF likely decodes only once. Use the 'bypass' tool for automated testing of all mutations.",
	}

	return jsonResult(result)
}

// applyBasicEncodings applies common encoding transformations to a payload.
func applyBasicEncodings(payload string, encoders []string) []mutateVariant {
	if len(encoders) == 0 {
		encoders = []string{"url", "double_url", "unicode", "html_hex"}
	}

	encSet := make(map[string]bool)
	for _, e := range encoders {
		encSet[strings.ToLower(e)] = true
	}

	var variants []mutateVariant

	if encSet["url"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				fmt.Fprintf(&sb, "%%%02X", r)
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "url", Encoded: sb.String()})
	}

	if encSet["double_url"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				hex := fmt.Sprintf("%%%02X", r)
				for _, c := range hex {
					if c == '%' {
						sb.WriteString("%25")
					} else {
						sb.WriteRune(c)
					}
				}
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "double_url", Encoded: sb.String()})
	}

	if encSet["unicode"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				fmt.Fprintf(&sb, "\\u%04X", r)
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "unicode", Encoded: sb.String()})
	}

	if encSet["html_hex"] {
		var sb strings.Builder
		for _, r := range payload {
			if shouldURLEncode(r) {
				fmt.Fprintf(&sb, "&#x%X;", r)
			} else {
				sb.WriteRune(r)
			}
		}
		variants = append(variants, mutateVariant{Encoder: "html_hex", Encoded: sb.String()})
	}

	return variants
}

func shouldURLEncode(r rune) bool {
	switch r {
	case '<', '>', '\'', '"', '(', ')', '{', '}', '[', ']', ';', '|', '&', '=', ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// bypass — WAF Bypass Discovery
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addBypassTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "bypass",
			Title: "WAF Bypass Finder",
			Description: `Hunt for WAF bypasses by testing payload mutations against a live target. The mutation matrix engine.

USE THIS TOOL WHEN:
• A 'scan' found blocks and now you want encoding/mutation variants that evade the WAF
• The user says "find bypasses", "evade the WAF", or "can we get past the rules?"
• Red team engagement — you need to prove exploitability, not just detect coverage
• Testing a specific rule: "bypass the SQLi detection"

DO NOT USE THIS TOOL WHEN:
• You haven't scanned yet — use 'scan' first to establish a baseline
• You just want to SEE encoded variants without testing — use 'mutate' instead
• You want a WAF grade — use 'assess' instead

'bypass' vs 'scan': scan fires known payloads as-is. bypass takes payloads, generates mutations (encoder x location x evasion), and tests each one to find what the WAF misses. bypass is heavier, slower, and more thorough.
'bypass' vs 'mutate': mutate shows you the encodings offline. bypass encodes AND fires them at the target to find actual bypasses.

Mutation Matrix: For each payload, bypass tries multiple encoders (url, double_url, html_hex, unicode, hex) x injection locations (query_param, post_form, post_json, header, cookie, path) x evasion techniques (case_swap, sql_comment, null_byte, whitespace, concat). This exponential combination is what finds bypasses.

EXAMPLE INPUTS:
• Hunt SQLi bypasses: {"target": "https://example.com/search?q=test", "payloads": ["' OR 1=1--", "1 UNION SELECT null--"]}
• XSS bypass: {"target": "https://example.com", "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]}
• Stealth mode: {"target": "https://example.com", "payloads": ["' OR 1=1--"], "rate_limit": 5, "concurrency": 2}
• Self-signed cert: {"target": "https://internal.app", "payloads": ["{{7*7}}"], "skip_verify": true}

Returns: successful bypasses with exact payload + encoding + location, total mutations tested, bypass rate, reproduction details.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to test bypasses against.",
						"format":      "uri",
					},
					"payloads": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Attack payload strings to mutate and test. Example: [\"' OR 1=1--\", \"<script>alert(1)</script>\"].",
					},
					"concurrency": map[string]any{
						"type":        "integer",
						"description": "Concurrent workers.",
						"default":     5,
						"minimum":     1,
						"maximum":     50,
					},
					"rate_limit": map[string]any{
						"type":        "integer",
						"description": "Maximum requests per second (keep low for stealth).",
						"default":     10,
						"minimum":     1,
						"maximum":     100,
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "Request timeout in seconds.",
						"default":     10,
						"minimum":     1,
						"maximum":     60,
					},
					"skip_verify": map[string]any{
						"type":        "boolean",
						"description": "Skip TLS certificate verification.",
						"default":     false,
					},
				},
				"required": []string{"target", "payloads"},
			},
			Annotations: &mcp.ToolAnnotations{
				OpenWorldHint:   boolPtr(true),
				DestructiveHint: boolPtr(false),
				Title:           "WAF Bypass Finder",
			},
		},
		s.handleBypass,
	)
}

type bypassArgs struct {
	Target      string   `json:"target"`
	Payloads    []string `json:"payloads"`
	Concurrency int      `json:"concurrency"`
	RateLimit   int      `json:"rate_limit"`
	Timeout     int      `json:"timeout"`
	SkipVerify  bool     `json:"skip_verify"`
}

func (s *Server) handleBypass(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args bypassArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required."), nil
	}
	if len(args.Payloads) == 0 {
		return errorResult("at least one payload is required. Example: {\"payloads\": [\"' OR 1=1--\"]}"), nil
	}

	if args.Concurrency <= 0 {
		args.Concurrency = 5
	}
	if args.RateLimit <= 0 {
		args.RateLimit = 10
	}
	if args.Timeout <= 0 {
		args.Timeout = 10
	}

	notifyProgress(ctx, req, 0, 100, fmt.Sprintf("Preparing bypass matrix for %d payloads…", len(args.Payloads)))
	logToSession(ctx, req, logInfo, fmt.Sprintf("Bypass testing %d payloads against %s", len(args.Payloads), args.Target))

	executor := mutation.NewExecutor(&mutation.ExecutorConfig{
		TargetURL:   args.Target,
		Concurrency: args.Concurrency,
		RateLimit:   float64(args.RateLimit),
		Timeout:     time.Duration(args.Timeout) * time.Second,
		SkipVerify:  args.SkipVerify,
	})

	notifyProgress(ctx, req, 10, 100, "Running mutation matrix…")

	result := executor.FindBypasses(ctx, args.Payloads)

	notifyProgress(ctx, req, 100, 100, fmt.Sprintf("Bypass testing complete — %d bypasses found", len(result.BypassPayloads)))
	logToSession(ctx, req, logInfo, fmt.Sprintf("Bypass results: %d/%d found bypasses", len(result.BypassPayloads), result.TotalTested))

	return jsonResult(result)
}

// ═══════════════════════════════════════════════════════════════════════════
// probe — Infrastructure Probing
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addProbeTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "probe",
			Title: "Probe Infrastructure",
			Description: `Quick infra check — TLS config, security headers, server fingerprinting. No attack traffic. Read-only recon.

USE THIS TOOL WHEN:
• The user asks "is this site up?" or "what TLS version?" or "check security headers"
• You need to verify a target is reachable before scanning
• Fingerprinting the server (Apache, Nginx, IIS, etc.) or technology stack
• Checking HSTS, CSP, X-Frame-Options, or other security headers
• Quick tech recon without any invasive testing

DO NOT USE THIS TOOL WHEN:
• You need full attack surface mapping — use 'discover' instead (probe just reads headers)
• You need to identify the WAF vendor — use 'detect_waf' instead (probe doesn't do WAF fingerprinting)
• You want to test for vulnerabilities — use 'scan' or 'assess' instead

'probe' vs 'detect_waf': probe gives you TLS, headers, server info. detect_waf sends trigger requests to identify the WAF product. They are complementary but distinct.
'probe' vs 'discover': probe makes 1-2 requests and reads headers. discover crawls the entire site with 9 discovery sources. Scope difference: single page vs entire app.

EXAMPLE INPUTS:
• Basic probe: {"target": "https://example.com"}
• Self-signed cert: {"target": "https://internal.dev", "skip_verify": true}
• Slow target: {"target": "https://slow-site.com", "timeout": 30}

Returns: HTTP status, server header, TLS version + cipher suite, security headers (HSTS, CSP, etc.), response time, redirect chain, technology hints.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL to probe (e.g. https://example.com).",
						"format":      "uri",
					},
					"timeout": map[string]any{
						"type":        "integer",
						"description": "Probe timeout in seconds.",
						"default":     10,
						"minimum":     1,
						"maximum":     30,
					},
					"skip_verify": map[string]any{
						"type":        "boolean",
						"description": "Skip TLS certificate verification.",
						"default":     false,
					},
				},
				"required": []string{"target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(true),
				Title:          "Probe Infrastructure",
			},
		},
		s.handleProbe,
	)
}

type probeArgs struct {
	Target     string `json:"target"`
	Timeout    int    `json:"timeout"`
	SkipVerify bool   `json:"skip_verify"`
}

type probeReport struct {
	Target          string            `json:"target"`
	Reachable       bool              `json:"reachable"`
	StatusCode      int               `json:"status_code,omitempty"`
	Server          string            `json:"server,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	TLS             *probeTLSInfo     `json:"tls,omitempty"`
	SecurityHeaders []headerCheck     `json:"security_headers,omitempty"`
	RedirectChain   []string          `json:"redirect_chain,omitempty"`
	Error           string            `json:"error,omitempty"`
}

type probeTLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	Certificate string `json:"certificate,omitempty"`
	Expiry      string `json:"expiry,omitempty"`
}

type headerCheck struct {
	Header  string `json:"header"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
	Status  string `json:"status"` // "good" or "missing"
}

func (s *Server) handleProbe(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args probeArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\"}"), nil
	}

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	notifyProgress(ctx, req, 0, 100, "Probing "+args.Target+"…")
	report := probeTarget(ctx, args.Target, timeout, args.SkipVerify)
	notifyProgress(ctx, req, 100, 100, "Probe complete")

	return jsonResult(report)
}

func probeTarget(ctx context.Context, target string, timeout time.Duration, skipVerify bool) *probeReport {
	report := &probeReport{
		Target:  target,
		Headers: make(map[string]string),
	}

	transport := &http.Transport{
		TLSHandshakeTimeout: timeout,
	}
	if skipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-controlled flag
	}

	var redirectChain []string
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(r *http.Request, _ []*http.Request) error {
			redirectChain = append(redirectChain, r.URL.String())
			if len(redirectChain) > 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		report.Error = fmt.Sprintf("invalid URL: %v", err)
		return report
	}
	httpReq.Header.Set("User-Agent", "waf-tester/probe")

	resp, err := client.Do(httpReq)
	if err != nil {
		report.Error = fmt.Sprintf("request failed: %v", err)
		return report
	}
	defer resp.Body.Close()

	report.Reachable = true
	report.StatusCode = resp.StatusCode
	report.Server = resp.Header.Get("Server")
	report.RedirectChain = redirectChain

	// Capture key fingerprinting headers
	for _, h := range []string{"Server", "X-Powered-By", "Via", "X-Cache", "CF-RAY", "X-Request-Id",
		"X-AspNet-Version", "X-Amzn-Trace-Id"} {
		if v := resp.Header.Get(h); v != "" {
			report.Headers[h] = v
		}
	}

	// TLS info
	if resp.TLS != nil {
		info := &probeTLSInfo{
			Version:     tlsVersionString(resp.TLS.Version),
			CipherSuite: tls.CipherSuiteName(resp.TLS.CipherSuite),
		}
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			info.Certificate = cert.Subject.CommonName
			info.Expiry = cert.NotAfter.Format(time.RFC3339)
		}
		report.TLS = info
	}

	// Security headers check
	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	for _, name := range securityHeaders {
		v := resp.Header.Get(name)
		check := headerCheck{
			Header:  name,
			Present: v != "",
			Value:   v,
			Status:  "missing",
		}
		if v != "" {
			check.Status = "good"
		}
		report.SecurityHeaders = append(report.SecurityHeaders, check)
	}

	return report
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// generate_cicd — CI/CD Pipeline Generation
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addGenerateCICDTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "generate_cicd",
			Title: "Generate CI/CD Pipeline",
			Description: `Generate a ready-to-use CI/CD pipeline config for automated WAF testing. Copy-paste output into your repo.

USE THIS TOOL WHEN:
• The user says "set up CI/CD for WAF testing" or "GitHub Actions for WAF" or "automate this"
• Creating recurring WAF regression tests that run on push/schedule
• Integrating WAF checks into an existing deployment pipeline

DO NOT USE THIS TOOL WHEN:
• You want to run a scan right now — use 'scan' or 'assess' instead
• You want to detect the WAF — use 'detect_waf' instead
• You need discovery or recon — use 'discover' instead

This is OFFLINE code generation. No network requests to any target. Produces a complete, ready-to-commit YAML/Groovy pipeline file for the chosen platform.

EXAMPLE INPUTS:
• GitHub Actions: {"platform": "github", "target": "https://staging.example.com", "scan_types": ["sqli", "xss"]}
• GitLab CI: {"platform": "gitlab", "target": "https://app.example.com"}
• Jenkins: {"platform": "jenkins", "target": "https://internal.app"}
• Azure DevOps: {"platform": "azure-devops", "target": "https://myapp.azurewebsites.net"}
• CircleCI: {"platform": "circleci", "target": "https://api.example.com", "scan_types": ["sqli"]}
• Bitbucket: {"platform": "bitbucket", "target": "https://example.com"}
• With schedule: {"platform": "github", "target": "https://example.com", "schedule": "0 2 * * 1"}

PLATFORMS: github, gitlab, jenkins, azure-devops, circleci, bitbucket

Returns: complete pipeline YAML/Groovy, ready to paste into your repo and commit.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"platform": map[string]any{
						"type":        "string",
						"description": "CI/CD platform to generate config for.",
						"enum":        []string{"github", "gitlab", "jenkins", "azure-devops", "circleci", "bitbucket"},
					},
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL for WAF testing (can use environment variable like $TARGET_URL).",
					},
					"scan_types": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Vulnerability scan types to include. Example: [\"sqli\", \"xss\"].",
					},
					"schedule": map[string]any{
						"type":        "string",
						"description": "Cron schedule for automated runs (e.g. '0 2 * * 1' for weekly Monday 2am).",
					},
				},
				"required": []string{"platform", "target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "Generate CI/CD Pipeline",
			},
		},
		s.handleGenerateCICD,
	)
}

type cicdArgs struct {
	Platform  string   `json:"platform"`
	Target    string   `json:"target"`
	ScanTypes []string `json:"scan_types"`
	Schedule  string   `json:"schedule"`
}

func (s *Server) handleGenerateCICD(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args cicdArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Platform == "" {
		return errorResult("platform is required. Supported: github, gitlab, jenkins, azure-devops, circleci, bitbucket"), nil
	}
	if args.Target == "" {
		return errorResult("target URL is required."), nil
	}

	pipeline := generateCICDConfig(args)
	return textResult(pipeline), nil
}

func generateCICDConfig(args cicdArgs) string {
	scanTypes := "sqli,xss"
	if len(args.ScanTypes) > 0 {
		scanTypes = strings.Join(args.ScanTypes, ",")
	}

	switch args.Platform {
	case "github":
		return generateGitHubActions(args.Target, scanTypes, args.Schedule)
	case "gitlab":
		return generateGitLabCI(args.Target, scanTypes, args.Schedule)
	case "jenkins":
		return generateJenkinsfile(args.Target, scanTypes)
	case "azure-devops":
		return generateAzureDevOps(args.Target, scanTypes)
	case "circleci":
		return generateCircleCI(args.Target, scanTypes)
	case "bitbucket":
		return generateBitbucket(args.Target, scanTypes)
	default:
		return fmt.Sprintf("# Unsupported platform: %s\n# Supported: github, gitlab, jenkins, azure-devops, circleci, bitbucket", args.Platform)
	}
}

func generateGitHubActions(target, scanTypes, schedule string) string {
	cron := ""
	if schedule != "" {
		cron = fmt.Sprintf("\n  schedule:\n    - cron: '%s'", schedule)
	}
	return fmt.Sprintf(`name: WAF Security Testing
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]%s

jobs:
  waf-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install waf-tester
        run: |
          curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
          chmod +x waf-tester

      - name: Run WAF Security Scan
        run: |
          ./waf-tester scan -u %s -types %s \
            -format sarif -o results.sarif \
            -c 10 -rl 50

      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
`, cron, target, scanTypes)
}

func generateGitLabCI(target, scanTypes, schedule string) string {
	scheduleNote := ""
	if schedule != "" {
		scheduleNote = fmt.Sprintf("\n# Schedule: %s (configure in GitLab CI/CD > Schedules)", schedule)
	}
	return fmt.Sprintf(`%s
waf-security-test:
  stage: test
  image: golang:1.24
  script:
    - curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
    - chmod +x waf-tester
    - ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
  artifacts:
    paths:
      - results.json
    expire_in: 30 days
`, scheduleNote, target, scanTypes)
}

func generateJenkinsfile(target, scanTypes string) string {
	return fmt.Sprintf(`pipeline {
    agent any
    stages {
        stage('WAF Security Test') {
            steps {
                sh '''
                    curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
                    chmod +x waf-tester
                    ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'results.json'
                }
            }
        }
    }
}
`, target, scanTypes)
}

func generateAzureDevOps(target, scanTypes string) string {
	return fmt.Sprintf(`trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: |
      curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
      chmod +x waf-tester
      ./waf-tester scan -u %s -types %s -format json -o $(Build.ArtifactStagingDirectory)/results.json -c 10 -rl 50
    displayName: 'Run WAF Security Scan'

  - publish: $(Build.ArtifactStagingDirectory)/results.json
    artifact: waf-test-results
`, target, scanTypes)
}

func generateCircleCI(target, scanTypes string) string {
	return fmt.Sprintf(`version: 2.1
jobs:
  waf-test:
    docker:
      - image: cimg/go:1.24
    steps:
      - checkout
      - run:
          name: Install waf-tester
          command: |
            curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
            chmod +x waf-tester
      - run:
          name: Run WAF Security Scan
          command: ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
      - store_artifacts:
          path: results.json

workflows:
  security:
    jobs:
      - waf-test
`, target, scanTypes)
}

func generateBitbucket(target, scanTypes string) string {
	return fmt.Sprintf(`pipelines:
  default:
    - step:
        name: WAF Security Test
        image: golang:1.24
        script:
          - curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
          - chmod +x waf-tester
          - ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
        artifacts:
          - results.json
`, target, scanTypes)
}
