package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/defaults"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Config holds MCP server configuration.
type Config struct {
	// PayloadDir is the directory containing payload JSON files.
	PayloadDir string

	// SessionTimeout is the maximum duration for an MCP session.
	// Zero means no timeout.
	SessionTimeout time.Duration
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Server wraps the MCP server with waf-tester functionality.
type Server struct {
	mcp    *mcp.Server
	config *Config
}

// MCPServer returns the underlying MCP server for direct access (e.g., testing).
func (s *Server) MCPServer() *mcp.Server { return s.mcp }

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

// HTTPHandler returns an http.Handler for the streamable HTTP transport.
// Use this for remote/Docker deployments with session management.
func (s *Server) HTTPHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return s.mcp },
		&mcp.StreamableHTTPOptions{Stateless: false},
	)
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

// ---------------------------------------------------------------------------
// Server Instructions — the AI's comprehensive operating manual
// ---------------------------------------------------------------------------

const serverInstructions = `You are operating WAF Tester — a comprehensive Web Application Firewall security testing platform with 17 commands, 1,172+ attack payloads, 197+ WAF signatures, and enterprise-grade assessment capabilities.

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
- waftester://waf-signatures — All 25+ WAF vendor signatures and bypass tips
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
