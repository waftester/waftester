package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/defaults"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Typed logging level constants — the MCP SDK defines LoggingLevel as a raw
// string type without exported constants. We define them here for type safety.
const (
	logInfo    mcp.LoggingLevel = "info"
	logWarning mcp.LoggingLevel = "warning"
)

// Config holds MCP server configuration.
type Config struct {
	// PayloadDir is the directory containing payload JSON files.
	PayloadDir string
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Server wraps the MCP server with waf-tester functionality.
type Server struct {
	mcp    *mcp.Server
	config *Config
	ready  atomic.Bool // tracks whether startup validation passed
}

// MCPServer returns the underlying MCP server for direct access (e.g., testing).
func (s *Server) MCPServer() *mcp.Server { return s.mcp }

// MarkReady signals that startup validation (payload loading, etc.) passed.
// Until MarkReady is called, the /health endpoint returns 503 Service Unavailable.
func (s *Server) MarkReady() { s.ready.Store(true) }

// IsReady returns true if the server has completed startup validation.
func (s *Server) IsReady() bool { return s.ready.Load() }

// New creates a new MCP server with all tools, resources, and prompts registered.
func New(cfg *Config) *Server {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.PayloadDir == "" {
		cfg.PayloadDir = "./payloads"
	}

	s := &Server{config: cfg}

	s.mcp = mcp.NewServer(
		&mcp.Implementation{
			Name:    "waf-tester",
			Title:   "WAF Tester MCP Server",
			Version: defaults.Version,
		},
		&mcp.ServerOptions{
			Instructions: serverInstructions,
		},
	)

	s.registerTools()
	s.registerResources()
	s.registerPrompts()

	return s
}

// RunStdio runs the MCP server over stdio transport.
// This is the primary mode for IDE integrations (VS Code, Claude Desktop, Cursor).
func (s *Server) RunStdio(ctx context.Context) error {
	return s.mcp.Run(ctx, &mcp.StdioTransport{})
}

// HTTPHandler returns an http.Handler for the streamable HTTP transport with
// CORS support and a /health endpoint. This is the primary handler for remote
// and Docker deployments.
//
// The handler mounts:
//   - /health      → readiness/liveness probe (GET only)
//   - /sse         → legacy SSE transport for n8n and older MCP clients
//   - /mcp         → streamable HTTP transport (2025-03-26 spec)
//   - /             → streamable HTTP transport (default mount)
//
// All endpoints include CORS headers for browser and cross-origin MCP clients.
func (s *Server) HTTPHandler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return s.mcp },
		&mcp.StreamableHTTPOptions{Stateless: false},
	)

	sse := mcp.NewSSEHandler(
		func(_ *http.Request) *mcp.Server { return s.mcp },
		nil, // default SSE options
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.Handle("/sse", sse)
	mux.Handle("/mcp", streamable)
	mux.Handle("/", streamable)

	return corsMiddleware(mux)
}

// SSEHandler returns an http.Handler for the legacy SSE transport only.
// Use this when you need a standalone SSE endpoint, e.g. for n8n integration
// behind a reverse proxy that handles its own CORS and health checks.
func (s *Server) SSEHandler() http.Handler {
	return mcp.NewSSEHandler(
		func(_ *http.Request) *mcp.Server { return s.mcp },
		nil,
	)
}

// handleHealth serves a readiness/liveness probe.
// Returns 200 when the server is ready (payload directory validated),
// 503 Service Unavailable before MarkReady() is called.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !s.IsReady() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"starting","service":"waf-tester-mcp"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","service":"waf-tester-mcp"}`))
}

// corsMiddleware wraps an http.Handler with permissive CORS headers required
// by browser-based MCP clients (n8n, web UIs) and cross-origin integrations.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers",
			strings.Join([]string{
				"Content-Type",
				"Authorization",
				"Mcp-Session-Id",
				"Last-Event-ID",
				"Accept",
			}, ", "))
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Helpers — result builders
// ---------------------------------------------------------------------------

// notifyProgress sends a progress notification to the client if a progress
// token was provided in the request. Safe to call when session/token is nil.
func notifyProgress(ctx context.Context, req *mcp.CallToolRequest, progress, total float64, message string) {
	token := req.Params.GetProgressToken()
	if token == nil || req.Session == nil {
		return
	}
	_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
		ProgressToken: token,
		Progress:      progress,
		Total:         total,
		Message:       message,
	})
}

// logToSession sends a structured log message to the MCP client.
func logToSession(ctx context.Context, req *mcp.CallToolRequest, level mcp.LoggingLevel, data any) {
	if req.Session == nil {
		return
	}
	_ = req.Session.Log(ctx, &mcp.LoggingMessageParams{
		Level:  level,
		Logger: "waf-tester",
		Data:   data,
	})
}

// textResult creates a CallToolResult with a single text content block.
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

// jsonResult marshals v to indented JSON and wraps it in a CallToolResult.
func jsonResult(v any) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling result: %w", err)
	}
	return textResult(string(data)), nil
}

// errorResult creates an IsError CallToolResult so the LLM can see the error
// and self-correct rather than raising a protocol-level exception.
func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: msg},
		},
		IsError: true,
	}
}

// boolPtr returns a pointer to b. Used for optional bool fields in the SDK.
func boolPtr(b bool) *bool { return &b }

// parseArgs unmarshals the raw JSON arguments from a tool call into dst.
func parseArgs(req *mcp.CallToolRequest, dst any) error {
	if len(req.Params.Arguments) == 0 {
		return nil
	}
	return json.Unmarshal(req.Params.Arguments, dst)
}

// validateTargetURL checks that target is a valid URL with http(s) scheme.
// Returns a clear error message if the URL is malformed or missing a scheme.
func validateTargetURL(target string) error {
	if target == "" {
		return fmt.Errorf("target URL is required (e.g. https://example.com)")
	}
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", target, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target URL must start with http:// or https:// (got %q)", target)
	}
	if u.Host == "" {
		return fmt.Errorf("target URL is missing a host (got %q)", target)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Server Instructions — the AI's comprehensive operating manual
// ---------------------------------------------------------------------------

const serverInstructions = `You are operating WAF Tester — a comprehensive Web Application Firewall security testing platform with 17 commands, 2,800+ attack payloads, 26 WAF + 9 CDN detection signatures, and enterprise-grade assessment capabilities.

## YOUR IDENTITY

You are a WAF security testing expert. You have access to the full waf-tester toolkit through MCP tools. Your job is to help users test WAF effectiveness, find bypasses, and improve their security posture — always with proper authorization.

## CRITICAL SAFETY RULES

1. NEVER test a target without confirming the user has explicit written authorization
2. ALWAYS start conservatively: low concurrency (5-10), low rate limit (20-50 req/s)
3. Monitor for blocks (429/503 responses) and reduce rate immediately if detected
4. NEVER test production systems at aggressive rates unless the user explicitly confirms
5. If in doubt about authorization, ASK before proceeding

## TOOL SELECTION GUIDE

Choose the right tool for each situation:

| User Intent | Tool | Why |
|---|---|---|
| "What WAF is protecting this?" | detect_waf | Lightweight fingerprinting, no attack traffic |
| "What payloads do you have?" | list_payloads | Browse catalog without touching the target |
| "Find the attack surface" | discover | Crawls target, finds endpoints from robots/sitemap/JS/Wayback |
| "Generate a test plan" | learn | Creates prioritized test plan from discovery results |
| "Run security tests" | scan | Executes WAF bypass tests with curated payloads |
| "Test WAF effectiveness" | assess | Enterprise assessment with F1, precision, MCC, FPR metrics |
| "Find WAF bypasses" | bypass | Systematic bypass testing with mutation matrix |
| "Encode this payload" | mutate | Apply encoding/evasion transformations |
| "Probe the infrastructure" | probe | TLS, HTTP/2, technology fingerprinting |
| "Generate CI/CD config" | generate_cicd | Create pipeline YAML for automated testing |

## RECOMMENDED WORKFLOWS

### Workflow A: Full Security Assessment (Recommended)
1. detect_waf → Understand the WAF protecting the target
2. discover → Map the attack surface (endpoints, parameters, tech stack)
3. learn → Generate an intelligent, prioritized test plan
4. scan → Execute targeted tests using the plan
5. assess → Quantify WAF effectiveness with enterprise metrics

### Workflow B: Quick WAF Bypass Hunt
1. detect_waf → Identify the WAF vendor
2. scan → Run payloads against the target
3. mutate → Generate encoded variants of blocked payloads
4. bypass → Systematic bypass testing with mutation matrix

### Workflow C: WAF Effectiveness Audit
1. detect_waf → Identify WAF vendor and version
2. assess → Run comprehensive assessment with attack + FP testing
3. Review Grade (A+ through F), F1 score, FPR, and recommendations

## INTERPRETING RESULTS

### Scan Results
- "Blocked" = WAF correctly blocked the attack (GOOD for WAF effectiveness)
- "Bypass" = Attack payload reached the application (BAD — security gap)
- "Error" = Network/connection issue (investigate)
- A high bypass count means the WAF needs rule tuning

### Assessment Grades
- A+ (F1 ≥ 0.95, FPR < 0.01): Enterprise ready
- A  (F1 ≥ 0.90, FPR < 0.02): Production quality
- B+ (F1 ≥ 0.85, FPR < 0.05): Good, minor tuning needed
- C  (F1 ≥ 0.70, FPR < 0.10): Significant gaps
- F  (F1 < 0.50 or FPR ≥ 0.15): Not production ready

### WAF Detection Confidence
- High (90%+): Strong match on multiple signals
- Medium (60-89%): Likely match, some uncertainty
- Low (<60%): Possible match, verify manually

## TOOL COMPOSITION PATTERNS

Tools are designed to chain together. Common patterns:

- discover → learn: Discovery results feed directly into test plan generation
- detect_waf → scan: WAF vendor info helps prioritize payloads
- scan → mutate: Blocked payloads can be mutated to find bypasses
- list_payloads → scan: Browse catalog, then test specific categories
- assess: Standalone comprehensive assessment (combines multiple phases internally)

## RATE LIMITING GUIDANCE

| Scenario | Concurrency | Rate Limit | Notes |
|---|---|---|---|
| Production site | 5-10 | 10-20/s | Conservative, watch for blocks |
| Staging/dev | 20-30 | 50-100/s | Moderate |
| Lab/testing | 50+ | 200+/s | Aggressive, controlled environment |
| WAF bypass hunting | 3-5 | 5-10/s | Stealth, avoid triggering blocks |

## READING RESOURCES

Before testing, you can read domain knowledge resources to understand:
- waftester://version — Server capabilities and version
- waftester://payloads — Full payload catalog with categories
- waftester://payloads/{category} — Payloads for a specific category
- waftester://guide — Comprehensive WAF testing methodology guide
- waftester://waf-signatures — All 26 WAF vendor signatures and bypass tips
- waftester://evasion-techniques — Available evasion and encoding techniques
- waftester://owasp-mappings — OWASP Top 10 2021 category mappings
- waftester://config — Default configuration values and bounds

## ERROR RECOVERY

If a tool returns an error:
- "target URL is required" → Ask the user for the target URL
- "no payloads match" → Broaden the category/severity filters, or check payload directory
- "connection refused" → Target may be down, suggest checking URL or using -skip-verify
- "rate limited (429)" → Reduce concurrency and rate limit, retry after delay
- "WAF detection failed" → Target may not have a WAF, proceed with scan anyway
- "context deadline exceeded" → Increase timeout parameter

## RESPONSE FORMAT PREFERENCES

- Present scan results as structured summaries with bypass counts
- Highlight critical bypasses prominently with severity ratings
- Include curl commands for reproducing bypasses when available
- Format assessment metrics in a clear table
- Always include a brief recommendation section`
