package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/apispec"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	"github.com/waftester/waftester/pkg/templateresolver"
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

// EventCrawlResult holds what was discovered by interacting with one DOM element.
// Mirrors headless.EventCrawlResult to avoid importing chromedp into this package.
type EventCrawlResult struct {
	Element        map[string]any `json:"element"`
	DiscoveredURLs []string       `json:"discovered_urls"`
	XHRRequests    []string       `json:"xhr_requests"`
	NavigatedTo    string         `json:"navigated_to,omitempty"`
	DOMChanged     bool           `json:"dom_changed"`
}

// EventCrawlFn runs DOM event crawling on a target URL.
// Injected from cmd/cli where chromedp is imported.
// Parameters: ctx, targetURL, maxClicks, clickTimeoutSec.
// Returns results and discovered same-origin URLs.
type EventCrawlFn func(ctx context.Context, targetURL string, maxClicks, clickTimeoutSec int) (results []EventCrawlResult, discoveredURLs []string, err error)

// Config holds MCP server configuration.
type Config struct {
	// PayloadDir is the directory containing payload JSON files.
	PayloadDir string

	// TemplateDir is the directory containing Nuclei template files.
	TemplateDir string

	// TamperDir is the directory containing .tengo script tampers.
	// When set, script tampers are loaded and registered at startup.
	TamperDir string

	// SpecScanFn is the scanner bridge for spec-driven scanning.
	// When set, the scan_spec MCP tool uses this function to dispatch
	// scan categories (sqli, xss, etc.) against spec endpoints.
	// Injected from cmd/cli where scanner packages are imported.
	SpecScanFn apispec.ScanFunc

	// EventCrawlFn runs DOM event crawling via headless Chromium.
	// When set, the event_crawl MCP tool is available.
	// Injected from cmd/cli where chromedp is imported.
	EventCrawlFn EventCrawlFn
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Server wraps the MCP server with waf-tester functionality.
type Server struct {
	mcp      *mcp.Server
	config   *Config
	tasks    *TaskManager // async task lifecycle manager
	ready    atomic.Bool  // tracks whether startup validation passed
	syncMode atomic.Bool  // stdio transport runs tools synchronously
}

// MCPServer returns the underlying MCP server for direct access (e.g., testing).
func (s *Server) MCPServer() *mcp.Server { return s.mcp }

// Tasks returns the task manager for inspecting async task state (e.g., testing).
func (s *Server) Tasks() *TaskManager { return s.tasks }

// IsSyncMode returns true if the server runs tools synchronously (stdio transport).
func (s *Server) IsSyncMode() bool { return s.syncMode.Load() }

// Stop shuts down background goroutines, cancels all running tasks, and
// waits for task goroutines to finish (with a 10s timeout to avoid
// blocking indefinitely on hung tasks).
func (s *Server) Stop() {
	s.tasks.Stop()
}

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
		cfg.PayloadDir = defaults.PayloadDir
	}
	if cfg.TemplateDir == "" {
		cfg.TemplateDir = defaults.TemplateDir
	}
	// Resolve template directory: extract embedded templates if path doesn't exist on disk.
	if resolved, err := templateresolver.ResolveNucleiDir(cfg.TemplateDir); err == nil {
		cfg.TemplateDir = resolved
	}

	// Load script tampers from directory if configured.
	if cfg.TamperDir != "" {
		scripts, errs := tampers.LoadScriptDir(cfg.TamperDir)
		for _, e := range errs {
			log.Printf("[mcp] script tamper warning: %v", e)
		}
		for _, st := range scripts {
			tampers.Register(st)
		}
		if len(scripts) > 0 {
			log.Printf("[mcp] loaded %d script tampers from %s", len(scripts), cfg.TamperDir)
		}
	}

	s := &Server{
		config: cfg,
		tasks:  NewTaskManager(),
	}

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
	s.registerSpecTools()
	s.registerResources()
	s.registerPrompts()

	return s
}

// RunStdio runs the MCP server over stdio transport.
// This is the primary mode for IDE integrations (VS Code, Claude Desktop, Cursor).
// In stdio mode, long-running tools execute synchronously because each
// client connection maps to a single process — async task state would be
// lost when the process exits between invocations.
func (s *Server) RunStdio(ctx context.Context) error {
	s.syncMode.Store(true)
	log.Println("[mcp] stdio transport: sync mode enabled (long-running tools will block)")
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
	mux.Handle("/sse", sseKeepAlive(sse))
	mux.Handle("/mcp", streamable)
	mux.Handle("/", streamable)

	return corsMiddleware(requestLogger(recoveryMiddleware(securityHeaders(mux))))
}

// SSEHandler returns an http.Handler for the legacy SSE transport only.
// Use this when you need a standalone SSE endpoint, e.g. for n8n integration
// behind a reverse proxy that handles its own CORS and health checks.
// Includes SSE keep-alive to prevent proxy idle timeouts.
func (s *Server) SSEHandler() http.Handler {
	sse := mcp.NewSSEHandler(
		func(_ *http.Request) *mcp.Server { return s.mcp },
		nil,
	)
	return recoveryMiddleware(securityHeaders(sseKeepAlive(sse)))
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

// requestLogger logs every incoming HTTP request with method, path, content
// type, session id, and remote address.  This is essential for diagnosing
// connectivity problems between MCP clients (n8n, Claude Desktop, etc.) and
// the server.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sessionID := r.Header.Get("Mcp-Session-Id")
		contentType := r.Header.Get("Content-Type")

		log.Printf("[mcp-http] --> %s %s  session=%q  content-type=%q  content-length=%d  remote=%s",
			r.Method, r.URL.Path, sessionID, contentType, r.ContentLength, r.RemoteAddr)

		// Wrap the ResponseWriter to capture the status code.
		lw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lw, r)

		log.Printf("[mcp-http] <-- %s %s  status=%d  duration=%s",
			r.Method, r.URL.Path, lw.statusCode, time.Since(start).Round(time.Millisecond))
	})
}

// loggingResponseWriter captures the HTTP status code written by downstream
// handlers so the request logger can include it in the response log line.
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
	if !lw.wroteHeader {
		lw.statusCode = code
		lw.wroteHeader = true
	}
	lw.ResponseWriter.WriteHeader(code)
}

func (lw *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return lw.ResponseWriter
}

// Flush implements http.Flusher. Required for SSE streaming — without this,
// the MCP SDK's streamable HTTP transport cannot flush events to the client
// and the connection hangs.
func (lw *loggingResponseWriter) Flush() {
	if f, ok := lw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// corsMiddleware wraps an http.Handler with CORS headers required
// by the MCP Streamable HTTP transport.
// Only localhost origins are allowed by default to prevent cross-site attacks.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Always set Vary: Origin so caches don't serve a CORS-enabled response
		// to a non-browser client or vice versa.
		w.Header().Add("Vary", "Origin")

		if origin == "" {
			// No Origin header = non-browser client; skip CORS headers entirely.
			// Setting "*" with Allow-Credentials violates the Fetch specification.
			next.ServeHTTP(w, r)
			return
		}

		// Only allow localhost origins to prevent cross-site attacks.
		if !isLocalhostOrigin(origin) {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers",
			strings.Join([]string{
				"Content-Type",
				"Authorization",
				"Mcp-Session-Id",
				"MCP-Protocol-Version",
				"Last-Event-ID",
				"Accept",
			}, ", "))
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isLocalhostOrigin checks if the origin is a localhost URL.
func isLocalhostOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// sseKeepAlive wraps an SSE handler to send periodic keep-alive comments.
// This prevents reverse proxies (nginx, AWS ALB, Cloudflare, Docker) from
// closing idle SSE connections. The keep-alive interval (15s) is well within
// the typical 60s idle timeout of most proxies.
const sseKeepAliveInterval = 15 * time.Second

// recoveryMiddleware catches panics in HTTP handlers and returns a 500 error
// instead of killing the connection. Every production MCP server (Mattermost,
// gomcp, go-sdk tests) includes this.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic in HTTP handler: %v\n%s", err, debug.Stack())

				// Best-effort error response: if headers were already sent
				// (e.g., during SSE streaming), WriteHeader is a no-op.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal server error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders adds standard defense-in-depth headers. These prevent
// MIME-sniffing, clickjacking, and cross-domain policy abuse — standard
// practice in production MCP servers (Mattermost, gomcp).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func sseKeepAlive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only apply keep-alive to SSE streams (text/event-stream).
		// Check if the client accepts SSE.
		accept := r.Header.Get("Accept")
		if !strings.Contains(accept, "text/event-stream") {
			next.ServeHTTP(w, r)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		// Wrap the ResponseWriter to intercept SSE streaming.
		kw := &keepAliveWriter{
			ResponseWriter: w,
			flusher:        flusher,
			done:           make(chan struct{}),
		}

		// Start keep-alive goroutine.
		go kw.keepAliveLoop()
		defer close(kw.done)

		next.ServeHTTP(kw, r)
	})
}

// keepAliveWriter wraps http.ResponseWriter to send SSE keep-alive comments.
// All writes are serialized through a mutex to prevent data races between
// the keep-alive goroutine and the SSE handler's event writes.
type keepAliveWriter struct {
	mu sync.Mutex
	http.ResponseWriter
	flusher http.Flusher
	done    chan struct{}
}

// WriteHeader serializes access to the underlying ResponseWriter.
func (kw *keepAliveWriter) WriteHeader(statusCode int) {
	kw.mu.Lock()
	defer kw.mu.Unlock()
	kw.ResponseWriter.WriteHeader(statusCode)
}

// Write serializes access to the underlying ResponseWriter.
func (kw *keepAliveWriter) Write(p []byte) (int, error) {
	kw.mu.Lock()
	defer kw.mu.Unlock()
	return kw.ResponseWriter.Write(p)
}

// Flush implements http.Flusher. Without this, the SSE SDK handler's
// w.(http.Flusher) type assertion fails on the wrapper, causing SSE events
// to buffer indefinitely and never reach the client.
func (kw *keepAliveWriter) Flush() {
	kw.mu.Lock()
	defer kw.mu.Unlock()
	kw.flusher.Flush()
}

// Unwrap returns the underlying ResponseWriter. This enables Go 1.20+
// http.ResponseController to discover capabilities (Flusher, Hijacker)
// through wrapped writers — standard practice for ResponseWriter middleware.
func (kw *keepAliveWriter) Unwrap() http.ResponseWriter {
	return kw.ResponseWriter
}

func (kw *keepAliveWriter) keepAliveLoop() {
	ticker := time.NewTicker(sseKeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-kw.done:
			return
		case <-ticker.C:
			// SSE comment line — ignored by clients, keeps connection alive.
			kw.mu.Lock()
			_, err := kw.ResponseWriter.Write([]byte(": keepalive\n\n"))
			if err != nil {
				kw.mu.Unlock()
				return // Connection closed.
			}
			kw.flusher.Flush()
			kw.mu.Unlock()
		}
	}
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
	// Best-effort: progress notifications are advisory; failure does not
	// affect tool execution and there is no meaningful recovery action.
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
	// Best-effort: log delivery is advisory; failure does not affect
	// tool execution and there is no meaningful recovery action.
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

// enrichedError creates a structured error response with recovery guidance
// for AI agents. The JSON envelope matches the enriched success responses so
// LLMs can use the same parsing logic for both success and error paths.
func enrichedError(msg string, recoverySteps []string) *mcp.CallToolResult {
	type errResponse struct {
		Error         string   `json:"error"`
		RecoverySteps []string `json:"recovery_steps"`
	}
	data, _ := json.MarshalIndent(errResponse{
		Error:         msg,
		RecoverySteps: recoverySteps,
	}, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
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
	dec := json.NewDecoder(bytes.NewReader(req.Params.Arguments))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parsing tool arguments: %w", err)
	}
	return nil
}

// validateTargetURL checks that target is a valid URL with http(s) scheme.
// Blocks cloud metadata endpoints to prevent SSRF when running in cloud environments.
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

	// Block cloud metadata endpoints to prevent SSRF credential exfiltration
	host := u.Hostname()
	if isCloudMetadataHost(host) {
		return fmt.Errorf("target URL %q points to a cloud metadata endpoint (SSRF protection)", target)
	}

	return nil
}

// isCloudMetadataHost returns true if the host is a known cloud metadata endpoint.
// Handles IPv6-mapped IPv4 addresses (e.g., ::ffff:169.254.169.254) to prevent
// SSRF bypasses.
func isCloudMetadataHost(host string) bool {
	// Normalize: if the host is an IPv6-mapped IPv4, extract the IPv4 portion.
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			host = v4.String()
		}
	}
	switch host {
	case "169.254.169.254", // AWS, GCP, Azure IMDS
		"metadata.google.internal", // GCP alternate
		"100.100.100.200":          // Alibaba Cloud
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Server Instructions — the AI's comprehensive operating manual
// ---------------------------------------------------------------------------

const serverInstructions = `You are operating WAF Tester — a comprehensive Web Application Firewall security testing platform with 24 tools, 2,800+ attack payloads, 26 WAF + 9 CDN detection signatures, and enterprise-grade assessment capabilities.

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
| "Find the attack surface" | discover | Crawls target, finds endpoints from robots/sitemap/JS/Wayback (ASYNC) |
| "Generate a test plan" | learn | Creates prioritized test plan from discovery results |
| "Run security tests" | scan | Executes WAF bypass tests with curated payloads (ASYNC) |
| "Test WAF effectiveness" | assess | Enterprise assessment with F1, precision, MCC, FPR metrics (ASYNC) |
| "Find WAF bypasses" | bypass | Systematic bypass testing with mutation matrix (ASYNC) |
| "Encode this payload" | mutate | Apply encoding/evasion transformations |
| "Probe the infrastructure" | probe | TLS, HTTP/2, technology fingerprinting |
| "What tampers are available?" | list_tampers | Browse tamper technique catalog (offline) |
| "Find tamper bypasses" | discover_bypasses | Test tamper scripts against live WAF (ASYNC) |
| "Find hidden JS endpoints" | event_crawl | Click DOM elements via headless browser (ASYNC) |
| "Generate CI/CD config" | generate_cicd | Create pipeline YAML for automated testing |
| "Check task progress" | get_task_status | Poll for async task results |
| "Cancel a task" | cancel_task | Stop a running async task |
| "List all tasks" | list_tasks | See all running/completed/failed tasks |

## RECOMMENDED WORKFLOWS

### ASYNC TOOL PATTERN (CRITICAL)

Long-running tools (scan, assess, bypass, discover) return a task_id immediately instead of blocking. Use the polling pattern to retrieve results:

1. Call the tool (e.g., scan) → receive {"task_id": "task_a1b2c3d4e5f6g7h8", "status": "running", "estimated_duration": "30-120s"}
2. IMMEDIATELY call get_task_status with {"task_id": "task_a1b2c3d4e5f6g7h8", "wait_seconds": 30}
3. If status is "running" → call get_task_status AGAIN with wait_seconds=30 (KEEP POLLING IN A LOOP)
4. If status is "completed" → full result is in the "result" field — NOW return to user
5. If status is "failed" → check "error" field
6. If status is "cancelled" → task was stopped

CROSS-SESSION RECOVERY: If you lost the task_id (e.g., new connection, session reset, reconnection):
- Call get_task_status WITHOUT task_id: {"wait_seconds": 30} → auto-discovers the latest active task
- Or filter by tool: {"tool_name": "assess", "wait_seconds": 30} → finds the latest task from that tool
- Or call list_tasks first to see all tasks: {} or {"status": "running"} → pick the correct task_id
- The server remembers ALL tasks across sessions for 30 minutes — only the task_id needs recovery

CRITICAL RULES:
- ALWAYS use wait_seconds=30 in get_task_status to avoid rapid polling
- NEVER tell the user "check back later" or "I'll keep checking" — poll until completion NOW
- NEVER return to the user while a task is still "running" — keep calling get_task_status in a loop
- The wait_seconds parameter makes the server wait up to 30s for completion, so you only need 2-4 polls for most operations
- If you lose connection to the task (task not found), call get_task_status without task_id to auto-discover, or re-run the original tool
- TASK ID FORMAT: task_ prefix + exactly 16 hex characters. Example: task_a1b2c3d4e5f6g7h8. NEVER use UUIDs or dashes.
- ALWAYS use the EXACT task_id string returned by the tool — do NOT modify it or generate your own

This pattern prevents timeout errors (e.g., MCP error -32001) that occur when long-running operations exceed client timeout limits (typically 60s for n8n, 30-120s for other clients).

NOTE: In stdio transport mode, long-running tools run synchronously and return complete results directly — no polling needed.

FAST TOOLS (return immediately): detect_waf, list_payloads, learn, mutate, probe, generate_cicd, list_tampers, get_task_status, cancel_task, list_tasks
ASYNC TOOLS (return task_id): scan, assess, bypass, discover, discover_bypasses, event_crawl

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
5. discover_bypasses → Test tamper scripts for additional bypass paths

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
- B  (F1 ≥ 0.80, FPR < 0.05): Good, minor tuning needed
- C  (F1 ≥ 0.70, FPR < 0.10): Significant gaps
- D  (F1 ≥ 0.50, FPR < 0.15): Major weaknesses
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
- waftester://payloads/unified — Combined payload inventory (JSON + Nuclei templates)
- waftester://guide — Comprehensive WAF testing methodology guide
- waftester://waf-signatures — 12 of 26 WAF vendors with detailed bypass tips
- waftester://evasion-techniques — Available evasion and encoding techniques
- waftester://owasp-mappings — OWASP Top 10 2021 category mappings
- waftester://templates — Nuclei template catalog with bypass/detection categories
- waftester://config — Default configuration values and bounds

## ERROR RECOVERY

If a tool returns an error:
- "target URL is required" → Ask the user for the target URL
- "no payloads match" → Broaden the category/severity filters, or check payload directory
- "connection refused" → Target may be down, suggest checking URL or using -skip-verify
- "rate limited (429)" → Reduce concurrency and rate limit, retry after delay
- "WAF detection failed" → Target may not have a WAF, proceed with scan anyway
- "context deadline exceeded" → Increase timeout parameter

Error responses for operational failures include structured JSON with "error" and "recovery_steps" fields. Parse recovery_steps for actionable guidance.

## RESPONSE FORMAT

All tool responses use a consistent enriched JSON envelope for AI agent consumption:
- "summary": Human/AI-readable narrative of what happened and the key findings
- "interpretation": Contextual analysis explaining what the results mean (scan, assess, bypass, probe)
- "next_steps": Array of actionable follow-up suggestions with tool names and example arguments
- Raw data is preserved alongside the narrative fields (e.g., "result", "metrics", "plan", "report", "pipeline")

Parse "summary" for a quick understanding of the result. Use "next_steps" to determine which tool to call next and with what arguments. Read "interpretation" for domain-expert analysis of the security posture.

## RESPONSE FORMAT PREFERENCES

- Present scan results as structured summaries with bypass counts
- Highlight critical bypasses prominently with severity ratings
- Include curl commands for reproducing bypasses when available
- Format assessment metrics in a clear table
- Always include a brief recommendation section`
