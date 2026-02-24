package mcpserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/mutation"
	"github.com/waftester/waftester/pkg/waf"
	"github.com/waftester/waftester/pkg/waf/strategy"
)

// ═══════════════════════════════════════════════════════════════════════════
// detect_waf — WAF/CDN Detection & Fingerprinting
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addDetectWAFTool() {
	s.addTool(
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
Covers 26+ WAF vendors with header analysis, behavioral probing, and TLS fingerprinting.

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
				ReadOnlyHint:   false, // Sends HTTP probes to target
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(true),
				Title:          "Detect WAF/CDN",
			},
		},
		loggedTool("detect_waf", s.handleDetectWAF),
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
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}

	notifyProgress(ctx, req, 0, 100, "Starting WAF detection on "+args.Target)
	logToSession(ctx, req, logInfo, "Initiating WAF/CDN detection for "+args.Target)

	detector := waf.NewDetector(timeout)

	notifyProgress(ctx, req, 15, 100, "Analyzing response headers…")
	notifyProgress(ctx, req, 30, 100, "Running behavioral probes…")

	result, err := detector.Detect(ctx, args.Target)
	if err != nil {
		return enrichedError(
			fmt.Sprintf("WAF detection failed: %v", err),
			[]string{
				"Verify the target URL is reachable and includes the scheme (https://).",
				"Use 'probe' with skip_verify=true to test connectivity first.",
				"Check network connectivity and DNS resolution for the target host.",
				"Use 'probe' to test basic connectivity before retrying detection.",
			}), nil
	}

	notifyProgress(ctx, req, 100, 100, "Detection complete")
	logToSession(ctx, req, logInfo, fmt.Sprintf("WAF detection complete for %s", args.Target))

	// Wrap result with rich summary and next steps
	wrapped := buildDetectWAFResponse(result, args.Target)
	return jsonResult(wrapped)
}

// detectWAFResponse wraps DetectionResult with narrative context for AI agents.
type detectWAFResponse struct {
	Summary   string               `json:"summary"`
	Result    *waf.DetectionResult `json:"result"`
	NextSteps []string             `json:"next_steps"`
}

func buildDetectWAFResponse(result *waf.DetectionResult, target string) *detectWAFResponse {
	resp := &detectWAFResponse{Result: result}

	var sb strings.Builder
	if !result.Detected {
		fmt.Fprintf(&sb, "No WAF detected on %s (confidence: %.0f%%). ", target, result.Confidence*100)
		sb.WriteString("The target may be unprotected, or the WAF uses stealth mode (no identifiable signatures).")
		resp.NextSteps = []string{
			fmt.Sprintf("Use 'scan' on %s to test if attacks are blocked despite no WAF signature being found.", target),
			fmt.Sprintf("Use 'discover' to map the full attack surface of %s.", target),
			"Use 'probe' to check TLS configuration and security headers.",
		}
		resp.Summary = sb.String()
		return resp
	}

	if len(result.WAFs) > 0 {
		w := result.WAFs[0]
		fmt.Fprintf(&sb, "Detected %s WAF (%s) on %s at %.0f%% confidence. ", w.Name, w.Vendor, target, w.Confidence*100)
		if w.Type != "" {
			fmt.Fprintf(&sb, "Type: %s. ", w.Type)
		}
		if len(w.BypassTips) > 0 {
			fmt.Fprintf(&sb, "Known bypass approaches: %s. ", strings.Join(w.BypassTips, "; "))
		}
		if len(result.WAFs) > 1 {
			names := make([]string, len(result.WAFs)-1)
			for i, ww := range result.WAFs[1:] {
				names[i] = ww.Name
			}
			fmt.Fprintf(&sb, "Also detected: %s. ", strings.Join(names, ", "))
		}
	} else {
		fmt.Fprintf(&sb, "WAF detected on %s at %.0f%% confidence but specific vendor could not be identified. ", target, result.Confidence*100)
	}

	if result.CDN != nil {
		fmt.Fprintf(&sb, "CDN: %s. ", result.CDN.Name)
	}

	resp.Summary = sb.String()

	// Build next steps
	steps := make([]string, 0, 4)
	steps = append(steps,
		fmt.Sprintf("Use 'discover' to map the full attack surface of %s.", target))
	steps = append(steps,
		fmt.Sprintf("Use 'scan' with specific categories to test WAF blocking against %s.", target))
	if len(result.WAFs) > 0 && len(result.WAFs[0].BypassTips) > 0 {
		steps = append(steps,
			"Use 'bypass' with known-blocked payloads to test the WAF-specific bypass techniques listed above.")
	}
	steps = append(steps,
		fmt.Sprintf("Use 'assess' for a full enterprise WAF grade with F1 score and false positive measurement on %s.", target))
	resp.NextSteps = steps

	return resp
}

// ═══════════════════════════════════════════════════════════════════════════
// bypass — WAF Bypass Discovery
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addBypassTool() {
	s.addTool(
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
• Smart mode (auto-detect WAF and optimize matrix): {"target": "https://example.com", "payloads": ["' OR 1=1--"], "smart": true}
• Smart stealth: {"target": "https://example.com", "payloads": ["' OR 1=1--"], "smart": true, "smart_mode": "stealth"}
• Self-signed cert: {"target": "https://internal.app", "payloads": ["{{7*7}}"], "skip_verify": true}

Returns: successful bypasses with exact payload + encoding + location, total mutations tested, bypass rate, reproduction details.

ASYNC TOOL: This tool returns a task_id immediately and runs in the background (30-300s). Poll with get_task_status to retrieve results.`,
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
					"smart": map[string]any{
						"type":        "boolean",
						"description": "Enable WAF-aware adaptive bypass testing. Detects the WAF vendor and optimizes the mutation matrix (encoders, evasions, locations) for that specific WAF.",
						"default":     false,
					},
					"smart_mode": map[string]any{
						"type":        "string",
						"description": "Smart mode profile. Controls mutation matrix depth and evasion intensity. Only used when smart=true.",
						"enum":        strategy.SmartModes(),
						"default":     "bypass",
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
		loggedTool("bypass", s.handleBypass),
	)
}

type bypassArgs struct {
	Target      string   `json:"target"`
	Payloads    []string `json:"payloads"`
	Concurrency int      `json:"concurrency"`
	RateLimit   int      `json:"rate_limit"`
	Timeout     int      `json:"timeout"`
	SkipVerify  bool     `json:"skip_verify"`
	Smart       bool     `json:"smart"`
	SmartMode   string   `json:"smart_mode"`
}

func (s *Server) handleBypass(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args bypassArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\", \"payloads\": [\"' OR 1=1--\"]}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}
	if len(args.Payloads) == 0 {
		return errorResult("at least one payload is required. Example: {\"payloads\": [\"' OR 1=1--\"]}"), nil
	}

	if args.Concurrency <= 0 {
		args.Concurrency = defaults.ConcurrencyLow
	} else if args.Concurrency > defaults.ConcurrencyMax {
		args.Concurrency = defaults.ConcurrencyMax
	}
	if args.RateLimit <= 0 {
		args.RateLimit = 10
	} else if args.RateLimit > 100 {
		args.RateLimit = 100
	}
	if args.Timeout <= 0 {
		args.Timeout = 10
	} else if args.Timeout > 60 {
		args.Timeout = 60
	}

	return s.launchAsync(ctx, "bypass", "30-300s depending on payload count and mutation matrix size", func(taskCtx context.Context, task *Task) {
		hosterrors.Clear(args.Target)

		task.SetProgress(0, 100, fmt.Sprintf("Preparing bypass matrix for %d payloads…", len(args.Payloads)))

		// Guard against mutation explosion — payloads × encoders × locations
		// can generate thousands of requests unexpectedly.
		const maxBypassPayloads = 50
		if len(args.Payloads) > maxBypassPayloads {
			task.Fail(fmt.Sprintf(
				"Too many payloads for bypass testing (%d). Each payload is tested with "+
					"multiple mutation techniques, generating thousands of requests. "+
					"Reduce to ≤%d payloads. Tip: use the most promising 5-10 payloads from a scan.",
				len(args.Payloads), maxBypassPayloads,
			))
			return
		}

		// Build pipeline config: WAF-optimized when smart mode is on, default otherwise.
		var pipeline *mutation.PipelineConfig
		if args.Smart {
			mode := args.SmartMode
			if mode == "" {
				mode = "bypass"
			}
			engine := strategy.NewStrategyEngine(time.Duration(args.Timeout) * time.Second)
			strat, err := engine.GetStrategy(taskCtx, args.Target)
			if err != nil {
				log.Printf("[mcp-bypass] smart mode WAF detection failed: %v (continuing with defaults)", err)
				pipeline = mutation.DefaultPipelineConfig()
			} else {
				pipeline = strategy.WAFOptimizedPipeline(strat, mode)

				// Override rate limit and concurrency with WAF-optimal values
				// if user didn't set them explicitly (schema defaults: 10 and 5).
				optimalRate, _ := strat.GetOptimalRateLimit(mode)
				if args.RateLimit == 10 {
					args.RateLimit = int(optimalRate)
				}
				optimalConcurrency := strat.GetRecommendedConcurrency(mode)
				if args.Concurrency == 5 {
					args.Concurrency = optimalConcurrency
				}

				task.SetProgress(5, 100, fmt.Sprintf("WAF detected: %s — optimizing bypass matrix…", strat.VendorName))
			}
		} else {
			pipeline = mutation.DefaultPipelineConfig()
		}

		executor := mutation.NewExecutor(&mutation.ExecutorConfig{
			TargetURL:   args.Target,
			Concurrency: args.Concurrency,
			RateLimit:   float64(args.RateLimit),
			Timeout:     time.Duration(args.Timeout) * time.Second,
			SkipVerify:  args.SkipVerify,
			Pipeline:    pipeline,
		})
		defer executor.Close()

		task.SetProgress(10, 100, "Running mutation matrix…")

		result := executor.FindBypasses(taskCtx, args.Payloads)

		cancelled := taskCtx.Err() != nil

		task.SetProgress(90, 100, fmt.Sprintf("Bypass testing complete — %d bypasses found, building report…", len(result.BypassPayloads)))

		wrapped := buildBypassResponse(result, args)
		if cancelled {
			wrapped.Summary = "PARTIAL RESULTS (bypass testing was cancelled): " + wrapped.Summary
		}
		data, err := json.Marshal(wrapped)
		if err != nil {
			task.Fail(fmt.Sprintf("marshaling result: %v", err))
			return
		}

		task.Complete(data)
	})
}

// bypassResponse wraps WAFBypassResult with narrative context for AI agents.
type bypassResponse struct {
	Summary        string                    `json:"summary"`
	Interpretation string                    `json:"interpretation"`
	Result         *mutation.WAFBypassResult `json:"result"`
	NextSteps      []string                  `json:"next_steps"`
}

func buildBypassResponse(result *mutation.WAFBypassResult, args bypassArgs) *bypassResponse {
	resp := &bypassResponse{Result: result}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Tested %d mutation variants of %d payloads against %s. ", result.TotalTested, len(args.Payloads), args.Target)
	if result.Found {
		fmt.Fprintf(&sb, "FOUND %d bypasses (%.1f%% bypass rate). ", len(result.BypassPayloads), result.BypassRate)
		sb.WriteString("The WAF fails to detect mutated/encoded variants of the input payloads.")
	} else {
		sb.WriteString("No bypasses found — all mutation variants were blocked by the WAF.")
	}
	resp.Summary = sb.String()

	if result.Found {
		resp.Interpretation = fmt.Sprintf("The mutation matrix found %d WAF bypasses across %d total variants (%.1f%% bypass rate). Each bypass represents a specific encoder × injection location × evasion technique combination that the WAF fails to detect. These are actionable findings that indicate WAF rule gaps.",
			len(result.BypassPayloads), result.TotalTested, result.BypassRate)
	} else {
		resp.Interpretation = fmt.Sprintf("All %d mutation variants were blocked. The WAF has strong coverage against encoded/mutated variants of these payloads. Consider testing with different base payloads or categories.", result.TotalTested)
	}

	steps := make([]string, 0, 4)
	if result.Found {
		steps = append(steps,
			"CRITICAL: Report each bypass to the WAF administrator with the exact payload, encoding, and injection location.")
		steps = append(steps,
			"Use 'mutate' to inspect the successful bypass encodings in detail and understand why the WAF missed them.")
		steps = append(steps,
			fmt.Sprintf("Use 'assess' on %s for a comprehensive WAF grade that factors in these bypasses.", args.Target))
		steps = append(steps,
			"Use 'generate_cicd' to set up automated bypass regression testing so fixed rules don't regress.")
	} else {
		steps = append(steps,
			"Try different payload categories — the WAF may be weak against other attack types (e.g., 'ssti', 'ssrf', 'xxe').")
		steps = append(steps,
			"Use 'list_payloads' to browse the full catalog and select different attack vectors.")
		steps = append(steps,
			fmt.Sprintf("Use 'assess' on %s for an enterprise-grade WAF evaluation with formal metrics.", args.Target))
	}
	resp.NextSteps = steps

	return resp
}

// ═══════════════════════════════════════════════════════════════════════════
// probe — Infrastructure Probing
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addProbeTool() {
	s.addTool(
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
				ReadOnlyHint:   false, // Sends HTTP and TLS probes to target
				IdempotentHint: true,
				OpenWorldHint:  boolPtr(true),
				Title:          "Probe Infrastructure",
			},
		},
		loggedTool("probe", s.handleProbe),
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
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}

	notifyProgress(ctx, req, 0, 100, "Probing "+args.Target+"…")
	report := probeTarget(ctx, args.Target, timeout, args.SkipVerify)
	notifyProgress(ctx, req, 100, 100, "Probe complete")

	wrapped := buildProbeResponse(report)
	return jsonResult(wrapped)
}

func probeTarget(ctx context.Context, target string, timeout time.Duration, skipVerify bool) *probeReport {
	report := &probeReport{
		Target:  target,
		Headers: make(map[string]string),
	}

	var redirectChain []string
	client := httpclient.New(httpclient.Config{
		Timeout:             timeout,
		InsecureSkipVerify:  skipVerify,
		TLSHandshakeTimeout: timeout,
	})
	client.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		redirectChain = append(redirectChain, r.URL.String())
		if len(redirectChain) > 10 {
			return http.ErrUseLastResponse
		}
		// Re-validate redirect target against SSRF blocklist.
		if err := validateTargetURL(r.URL.String()); err != nil {
			return fmt.Errorf("redirect blocked (SSRF protection): %w", err)
		}
		return nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		report.Error = fmt.Sprintf("invalid URL: %v", err)
		return report
	}
	httpReq.Header.Set("User-Agent", defaults.UserAgent("probe"))

	resp, err := client.Do(httpReq)
	if err != nil {
		report.Error = fmt.Sprintf("request failed: %v", err)
		return report
	}
	defer func() {
		// Drain up to 4KB so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()

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

// probeResponse wraps probeReport with narrative context for AI agents.
type probeResponse struct {
	Summary        string       `json:"summary"`
	Interpretation string       `json:"interpretation"`
	Report         *probeReport `json:"report"`
	NextSteps      []string     `json:"next_steps"`
}

func buildProbeResponse(report *probeReport) *probeResponse {
	resp := &probeResponse{Report: report}

	var sb strings.Builder
	if !report.Reachable {
		fmt.Fprintf(&sb, "Target %s is NOT reachable. Error: %s", report.Target, report.Error)
		resp.Summary = sb.String()
		resp.Interpretation = "The target is unreachable. This could indicate a network issue, DNS failure, firewall blocking, or the target is offline."
		resp.NextSteps = []string{
			"Verify the URL is correct and includes the scheme (https://).",
			"Check network connectivity and DNS resolution.",
			"If behind a VPN/firewall, ensure you have access.",
			"Try with skip_verify=true if the target uses a self-signed certificate.",
		}
		return resp
	}

	fmt.Fprintf(&sb, "Target %s is reachable (HTTP %d). ", report.Target, report.StatusCode)
	if report.Server != "" {
		fmt.Fprintf(&sb, "Server: %s. ", report.Server)
	}
	if report.TLS != nil {
		fmt.Fprintf(&sb, "TLS: %s (%s). ", report.TLS.Version, report.TLS.CipherSuite)
	}

	// Count security headers
	present := 0
	missing := 0
	for _, h := range report.SecurityHeaders {
		if h.Present {
			present++
		} else {
			missing++
		}
	}
	fmt.Fprintf(&sb, "Security headers: %d/%d present. ", present, present+missing)

	if len(report.RedirectChain) > 0 {
		fmt.Fprintf(&sb, "Redirects: %d hops. ", len(report.RedirectChain))
	}
	resp.Summary = sb.String()

	// Build interpretation
	var interp strings.Builder
	if report.TLS != nil {
		switch report.TLS.Version {
		case "TLS 1.3":
			interp.WriteString("TLS 1.3 — excellent, using the latest protocol. ")
		case "TLS 1.2":
			interp.WriteString("TLS 1.2 — acceptable, but TLS 1.3 is preferred for better security and performance. ")
		default:
			fmt.Fprintf(&interp, "%s — OUTDATED. Upgrade to TLS 1.2+ immediately. ", report.TLS.Version)
		}
	}

	if missing > 0 {
		missingNames := make([]string, 0, missing)
		for _, h := range report.SecurityHeaders {
			if !h.Present {
				missingNames = append(missingNames, h.Header)
			}
		}
		fmt.Fprintf(&interp, "Missing security headers (%d): %s. These should be added to harden the application. ", missing, strings.Join(missingNames, ", "))
	} else {
		interp.WriteString("All checked security headers are present — good security posture. ")
	}
	resp.Interpretation = interp.String()

	// Build next steps
	steps := make([]string, 0, 5)
	steps = append(steps,
		fmt.Sprintf("Use 'detect_waf' on %s to identify the WAF vendor and get bypass hints.", report.Target))
	steps = append(steps,
		fmt.Sprintf("Use 'discover' to map the full attack surface of %s.", report.Target))
	if missing > 0 {
		steps = append(steps,
			fmt.Sprintf("Add missing security headers (%d): configure HSTS, CSP, and X-Content-Type-Options at minimum.", missing))
	}
	if report.TLS != nil && report.TLS.Version != "TLS 1.3" && report.TLS.Version != "TLS 1.2" {
		steps = append(steps,
			"URGENT: Upgrade TLS to version 1.2 or 1.3. Older versions have known vulnerabilities.")
	}
	steps = append(steps,
		fmt.Sprintf("Use 'scan' on %s to test WAF blocking against attack payloads.", report.Target))
	resp.NextSteps = steps

	return resp
}
