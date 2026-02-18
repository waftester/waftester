package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/assessment"
	"github.com/waftester/waftester/pkg/core"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/metrics"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/payloads"
)

// ═══════════════════════════════════════════════════════════════════════════
// scan — WAF Security Scan
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addScanTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "scan",
			Title: "WAF Security Scan",
			Description: `Fire attack payloads at a target and see what the WAF blocks vs. lets through. This is the core scanning tool.

Bundled templates are available in templates/policies/ and templates/overrides/. Read waftester://templates to see all options.

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

Returns: detection rate, total/blocked/failed counts, bypass details with reproduction info, latency stats.

ASYNC TOOL: This tool returns a task_id immediately and runs in the background. Duration depends on payload count and target speed. Poll with get_task_status to retrieve results.`,
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
					"tamper": map[string]any{
						"type":        "string",
						"description": "Comma-separated tamper techniques to apply (e.g. 'unicode,double_encode'). Use 'list_tampers' to see available tampers.",
					},
					"tamper_profile": map[string]any{
						"type":        "string",
						"description": "Predefined tamper profile to apply. Ignored if 'tamper' is set.",
						"enum":        []string{"standard", "stealth", "aggressive", "bypass"},
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
		loggedTool("scan", s.handleScan),
	)
}

type scanArgs struct {
	Target        string   `json:"target"`
	Categories    []string `json:"categories"`
	Severity      string   `json:"severity"`
	Concurrency   int      `json:"concurrency"`
	RateLimit     int      `json:"rate_limit"`
	Timeout       int      `json:"timeout"`
	SkipVerify    bool     `json:"skip_verify"`
	Proxy         string   `json:"proxy"`
	Tamper        string   `json:"tamper"`
	TamperProfile string   `json:"tamper_profile"`
}

type scanResultSummary struct {
	Summary        string                   `json:"summary"`
	Target         string                   `json:"target"`
	DetectionRate  string                   `json:"detection_rate"`
	Interpretation string                   `json:"interpretation"`
	Results        *output.ExecutionResults `json:"results"`
	NextSteps      []string                 `json:"next_steps"`
}

func (s *Server) handleScan(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args scanArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Target == "" {
		return errorResult("target URL is required. Example: {\"target\": \"https://example.com\"}"), nil
	}
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	if args.Concurrency <= 0 {
		args.Concurrency = defaults.ConcurrencyMedium
	}
	if args.Concurrency > defaults.ConcurrencyDNS {
		args.Concurrency = defaults.ConcurrencyDNS
	}
	if args.RateLimit <= 0 {
		args.RateLimit = 50
	}
	if args.RateLimit > 1000 {
		args.RateLimit = 1000
	}
	if args.Timeout <= 0 {
		args.Timeout = int(duration.HTTPProbing.Seconds())
	}
	if args.Timeout > 60 {
		args.Timeout = 60
	}

	// Load payloads synchronously so validation errors return immediately.
	provider := payloadprovider.NewProvider(s.config.PayloadDir, s.config.TemplateDir)
	if err := provider.Load(); err != nil {
		return enrichedError(
			fmt.Sprintf("failed to load payloads: %v", err),
			[]string{
				"Verify the payload directory exists and contains JSON payload files.",
				"Use 'list_payloads' to check available categories before scanning.",
				"Check file permissions on the payload directory.",
			}), nil
	}

	all, err := provider.JSONPayloads()
	if err != nil {
		return enrichedError(
			fmt.Sprintf("failed to extract payloads: %v", err),
			[]string{
				"Verify the payload directory contains valid JSON payload files.",
			}), nil
	}

	// Enrich with Nuclei template payloads converted to payloads.Payload format
	unified, err := provider.GetAll()
	if err != nil {
		log.Printf("[mcp-scan] failed to load unified payloads for Nuclei enrichment: %v", err)
	}
	for _, up := range unified {
		if up.Source == payloadprovider.SourceNuclei {
			sev := up.Severity
			if sev == "" {
				sev = "Medium"
			}
			all = append(all, payloads.Payload{
				ID:            up.ID,
				Payload:       up.Payload,
				Category:      up.Category,
				Method:        up.Method,
				SeverityHint:  sev,
				ExpectedBlock: true,
				Tags:          up.Tags,
			})
		}
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

	// Apply tamper transformations if requested
	if args.Tamper != "" || args.TamperProfile != "" {
		profile := tampers.ProfileStandard
		switch args.TamperProfile {
		case "stealth":
			profile = tampers.ProfileStealth
		case "aggressive":
			profile = tampers.ProfileAggressive
		case "bypass":
			profile = tampers.ProfileBypass
		}
		if args.Tamper != "" {
			profile = tampers.ProfileCustom
			// Validate tamper names before proceeding — fail hard in MCP mode
			// since the caller can't see stderr warnings.
			_, invalid := tampers.ValidateTamperNames(tampers.ParseTamperList(args.Tamper))
			if len(invalid) > 0 {
				return errorResult(fmt.Sprintf("unknown tampers: %s. Use list_tampers to see available tampers.", strings.Join(invalid, ", "))), nil
			}
		}

		engine := tampers.NewEngine(&tampers.EngineConfig{
			Profile:       profile,
			CustomTampers: tampers.ParseTamperList(args.Tamper),
			EnableMetrics: false,
		})

		if profile == tampers.ProfileBypass && args.Tamper == "" {
			log.Printf("[mcp-tool] WARNING: tamper_profile=bypass without detected WAF vendor — falling back to aggressive tampers. Run detect_waf first for WAF-specific bypass chains.")
		}

		for i := range filtered {
			filtered[i].Payload = engine.Transform(filtered[i].Payload)
		}
	}

	estimatedDuration := estimateScanDuration(len(filtered), args.Concurrency, args.RateLimit)

	return s.launchAsync(ctx, "scan", estimatedDuration, func(taskCtx context.Context, task *Task) {
		// Clear stale host state from previous scans to prevent poisoned cache.
		// The global hosterrors + detection singletons persist across MCP sessions;
		// without this, 3 transient network errors permanently skip the host
		// for all subsequent scans until the 5-minute cache expires.
		hosterrors.Clear(args.Target)

		task.SetProgress(10, 100, fmt.Sprintf("Loaded %d payloads, scanning…", len(filtered)))

		total := len(filtered)
		var received atomic.Int64
		var bypasses atomic.Int64
		var skippedCount atomic.Int64

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
					bypasses.Add(1)
				}
				if r.Outcome == "Skipped" {
					skippedCount.Add(1)
				}
				if n%10 == 0 || n == int64(total) {
					pct := float64(n) / float64(total) * 80
					skip := skippedCount.Load()
					if skip > 0 {
						task.SetProgress(10+pct, 100,
							fmt.Sprintf("Tested %d/%d (bypasses: %d, skipped: %d)…", n, total, bypasses.Load(), skip))
					} else {
						task.SetProgress(10+pct, 100,
							fmt.Sprintf("Tested %d/%d (bypasses: %d)…", n, total, bypasses.Load()))
					}
				}
			},
		})
		defer executor.Close()

		execResults := executor.Execute(taskCtx, filtered, &discardWriter{})

		// Calculate detection rate.
		// tested = payloads that got a definitive result (blocked or passed through).
		// FailedTests are execution errors and don't count toward detection rate.
		detectionRate := ""
		tested := execResults.BlockedTests + execResults.PassedTests
		if tested > 0 {
			rate := float64(execResults.BlockedTests) / float64(tested) * 100
			if execResults.HostsSkipped > 0 {
				detectionRate = fmt.Sprintf("%.1f%% (%d skipped)", rate, execResults.HostsSkipped)
			} else {
				detectionRate = fmt.Sprintf("%.1f%%", rate)
			}
		}

		summary := &scanResultSummary{
			Target:        args.Target,
			DetectionRate: detectionRate,
			Results:       &execResults,
		}

		// Build interpretation based on detection rate
		cancelled := taskCtx.Err() != nil
		if tested > 0 {
			rate := float64(execResults.BlockedTests) / float64(tested) * 100
			bypassed := execResults.PassedTests
			switch {
			case rate >= 95:
				summary.Interpretation = fmt.Sprintf("Excellent WAF coverage (%.1f%%). The WAF blocked %d of %d attack payloads. Very few bypasses detected.", rate, execResults.BlockedTests, tested)
			case rate >= 85:
				summary.Interpretation = fmt.Sprintf("Good WAF coverage (%.1f%%), but %d payloads bypassed detection. Review the bypass details below and consider adding custom rules.", rate, bypassed)
			case rate >= 70:
				summary.Interpretation = fmt.Sprintf("Moderate WAF coverage (%.1f%%). %d payloads bypassed the WAF — significant gaps exist that need rule tuning.", rate, bypassed)
			case rate >= 50:
				summary.Interpretation = fmt.Sprintf("Weak WAF coverage (%.1f%%). %d of %d payloads bypassed detection. The WAF needs major rule updates or reconfiguration.", rate, bypassed, tested)
			default:
				summary.Interpretation = fmt.Sprintf("Critical: WAF is largely ineffective (%.1f%% detection). %d of %d payloads bypassed. Consider the WAF misconfigured or disabled for this endpoint.", rate, bypassed, tested)
			}
			if cancelled {
				summary.Interpretation = "PARTIAL RESULTS (scan was cancelled): " + summary.Interpretation
			}
		} else if execResults.HostsSkipped > 0 {
			// No real tests ran — everything was skipped
			summary.Interpretation = fmt.Sprintf("WARNING: %d of %d payloads were skipped because the target host became unreachable. "+
				"The WAF or CDN may be rate-limiting or IP-blocking the scanner. "+
				"Try again later, use a proxy, reduce concurrency/rate_limit, or test from a different IP.",
				execResults.HostsSkipped, execResults.TotalTests)
		}

		if execResults.HostsSkipped > 0 {
			summary.Summary = fmt.Sprintf("Scanned %s with %d payloads. Detection rate: %s. Blocked: %d, Bypassed: %d, Errors: %d, Skipped: %d (host unreachable).",
				args.Target, execResults.TotalTests, detectionRate, execResults.BlockedTests, execResults.PassedTests, execResults.ErrorTests, execResults.HostsSkipped)
		} else {
			summary.Summary = fmt.Sprintf("Scanned %s with %d payloads. Detection rate: %s. Blocked: %d, Bypassed: %d, Errors: %d.",
				args.Target, execResults.TotalTests, detectionRate, execResults.BlockedTests, execResults.PassedTests, execResults.ErrorTests)
		}

		summary.NextSteps = buildScanNextSteps(execResults, args)

		data, err := json.Marshal(summary)
		if err != nil {
			task.Fail(fmt.Sprintf("marshaling result: %v", err))
			return
		}
		task.Complete(data)
	})
}

// estimateScanDuration produces a human-readable time estimate for async
// task responses so the MCP client knows how long to poll.
func estimateScanDuration(payloadCount, concurrency, rateLimit int) string {
	if concurrency <= 0 {
		concurrency = 10
	}
	if rateLimit <= 0 {
		rateLimit = 50
	}

	// Bottleneck is min(concurrency throughput, rate limit).
	effectiveRPS := rateLimit
	if concurrency < rateLimit {
		effectiveRPS = concurrency
	}

	seconds := payloadCount / effectiveRPS
	if seconds < 10 {
		return "5-15s"
	}
	if seconds < 30 {
		return "10-30s"
	}
	if seconds < 120 {
		return fmt.Sprintf("%d-%ds", seconds/2, seconds*2)
	}
	return fmt.Sprintf("%d-%ds (consider narrowing categories for faster results)", seconds/2, seconds*2)
}

// discardWriter implements output.ResultWriter and discards all results.
// Used when results are collected via the OnResult callback instead.
type discardWriter struct{}

func (w *discardWriter) Write(_ *output.TestResult) error { return nil }
func (w *discardWriter) Close() error                     { return nil }

// buildScanNextSteps generates contextual next steps based on scan results.
func buildScanNextSteps(results output.ExecutionResults, args scanArgs) []string {
	steps := make([]string, 0, 4)
	bypassed := results.PassedTests // passedTests = payloads that got through the WAF

	if bypassed > 0 {
		steps = append(steps,
			fmt.Sprintf("CRITICAL: %d bypasses found. Use 'bypass' tool to test WAF-evasion mutations against %s and discover additional bypass variants.", bypassed, args.Target))
		steps = append(steps,
			"Use 'mutate' with the bypassed payloads to generate encoded variants (URL, double-URL, Unicode, HTML hex) for deeper testing.")
		steps = append(steps,
			fmt.Sprintf("Use 'assess' on %s for a formal enterprise assessment with F1 score, false positive rate, MCC, and letter grade.", args.Target))
	} else if results.BlockedTests > 0 {
		steps = append(steps,
			fmt.Sprintf("All %d payloads were blocked — excellent WAF coverage for these categories.", results.BlockedTests))
		steps = append(steps,
			"Use 'bypass' to test mutation-based evasions (encoding × location × technique) — WAF may miss encoded variants.")
		if len(args.Categories) > 0 {
			steps = append(steps,
				"Run 'scan' with additional categories to broaden coverage (try adding 'ssrf', 'ssti', 'cmdi', 'xxe').")
		}
		steps = append(steps,
			fmt.Sprintf("Use 'assess' on %s for enterprise metrics including false positive measurement.", args.Target))
	}

	if results.ErrorTests > 0 {
		steps = append(steps,
			fmt.Sprintf("%d errors occurred — check network connectivity, reduce rate_limit, or increase timeout.", results.ErrorTests))
	}

	if results.HostsSkipped > 0 {
		steps = append(steps,
			fmt.Sprintf("WARNING: %d payloads were skipped because the host became unreachable during scanning. "+
				"The target WAF/CDN may be rate-limiting or IP-blocking the scanner. Recommended actions: "+
				"1) Wait 5-10 minutes and retry, 2) Reduce concurrency and rate_limit, 3) Use a proxy.", results.HostsSkipped))
	}

	return steps
}

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

Returns: letter grade, category scores, F1/MCC/FPR metrics, bypass list, per-category breakdown, improvement recommendations.

ASYNC TOOL: This tool returns a task_id immediately and runs in the background (30-300s). Poll with get_task_status to retrieve results.`,
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
		loggedTool("assess", s.handleAssess),
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
	if err := validateTargetURL(args.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	cfg := assessment.DefaultConfig()
	cfg.TargetURL = args.Target
	cfg.PayloadDir = s.config.PayloadDir
	cfg.SkipTLSVerify = args.SkipVerify
	cfg.OutputFormat = "json"

	if args.Concurrency > 0 {
		cfg.Concurrency = args.Concurrency
	}
	if cfg.Concurrency > defaults.ConcurrencyDNS {
		cfg.Concurrency = defaults.ConcurrencyDNS
	}
	if args.RateLimit > 0 {
		cfg.RateLimit = float64(args.RateLimit)
	}
	if cfg.RateLimit > 500 {
		cfg.RateLimit = 500
	}
	if args.Timeout > 0 {
		cfg.Timeout = time.Duration(args.Timeout) * time.Second
	}
	if args.Timeout > int(duration.HTTPAPI.Seconds()) {
		cfg.Timeout = duration.HTTPAPI
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

	return s.launchAsync(ctx, "assess", "30-300s depending on payload count and target response time", func(taskCtx context.Context, task *Task) {
		hosterrors.Clear(args.Target)

		task.SetProgress(0, 100, "Starting enterprise assessment on "+args.Target)

		a := assessment.New(cfg)

		progressFn := func(completed, total int64, phase string) {
			if total > 0 {
				pct := float64(completed) / float64(total) * 90
				task.SetProgress(pct, 100, fmt.Sprintf("[%s] %d/%d", phase, completed, total))
			}
		}

		m, err := a.Run(taskCtx, progressFn)
		if err != nil {
			task.Fail(fmt.Sprintf("assessment failed: %v", err))
			return
		}

		cancelled := taskCtx.Err() != nil

		wrapped := buildAssessResponse(m, args.Target)
		if cancelled {
			wrapped.Summary = "PARTIAL RESULTS (assessment was cancelled): " + wrapped.Summary
		}
		data, err := json.Marshal(wrapped)
		if err != nil {
			task.Fail(fmt.Sprintf("marshaling result: %v", err))
			return
		}

		task.Complete(data)
	})
}

// assessResponse wraps EnterpriseMetrics with narrative context for AI agents.
type assessResponse struct {
	Summary        string                     `json:"summary"`
	Interpretation string                     `json:"interpretation"`
	Metrics        *metrics.EnterpriseMetrics `json:"metrics"`
	NextSteps      []string                   `json:"next_steps"`
}

func buildAssessResponse(m *metrics.EnterpriseMetrics, target string) *assessResponse {
	resp := &assessResponse{Metrics: m}

	var sb strings.Builder
	fmt.Fprintf(&sb, "WAF Assessment for %s: Grade %s. ", target, m.Grade)
	fmt.Fprintf(&sb, "Detection Rate: %.1f%%, F1 Score: %.3f, MCC: %.3f, False Positive Rate: %.1f%%. ",
		m.DetectionRate*100, m.F1Score, m.MCC, m.FalsePositiveRate*100)
	if m.GradeReason != "" {
		sb.WriteString(m.GradeReason)
	}
	resp.Summary = sb.String()

	// Build interpretation based on grade — direct field access, no JSON round-trip.
	switch {
	case strings.HasPrefix(m.Grade, "A"):
		resp.Interpretation = fmt.Sprintf("Excellent WAF performance (Grade %s). The WAF demonstrates strong detection across tested categories with a well-balanced precision-recall tradeoff. F1=%.3f indicates minimal false negatives. FPR=%.1f%% means legitimate traffic is rarely blocked.",
			m.Grade, m.F1Score, m.FalsePositiveRate*100)
	case strings.HasPrefix(m.Grade, "B"):
		resp.Interpretation = fmt.Sprintf("Good WAF performance (Grade %s) with room for improvement. Some attack categories may have gaps. Review per-category scores to identify weak areas. F1=%.3f, FPR=%.1f%%.",
			m.Grade, m.F1Score, m.FalsePositiveRate*100)
	case strings.HasPrefix(m.Grade, "C"):
		resp.Interpretation = fmt.Sprintf("Moderate WAF performance (Grade %s). Significant gaps in detection exist. Review bypassed payloads and consider rule tuning or switching to a more comprehensive ruleset (e.g., CRS 4.x for ModSecurity/Coraza).", m.Grade)
	case m.Grade == "D" || m.Grade == "F":
		resp.Interpretation = fmt.Sprintf("Poor WAF performance (Grade %s). The WAF is failing to block a majority of attacks. This indicates misconfiguration, disabled rules, or an inadequate ruleset. Immediate action required.", m.Grade)
	default:
		resp.Interpretation = fmt.Sprintf("WAF Grade: %s. Review the per-category breakdown for detailed analysis.", m.Grade)
	}

	// Build next steps based on grade
	steps := make([]string, 0, 5)
	if m.Grade == "D" || m.Grade == "F" || strings.HasPrefix(m.Grade, "C") {
		steps = append(steps,
			"PRIORITY: Review bypassed payloads in the per-category breakdown and add custom WAF rules for each bypass pattern.")
		steps = append(steps,
			"Use 'bypass' with specific payloads that were blocked to test if encoding variants can still evade the WAF.")
	}
	if m.FalsePositiveRate > 0.05 {
		steps = append(steps,
			fmt.Sprintf("WARNING: False positive rate is %.1f%% (%.1f%% of legitimate requests blocked). Review and tune WAF rules to reduce false positives.",
				m.FalsePositiveRate*100, m.FalsePositiveRate*100))
	}
	steps = append(steps,
		fmt.Sprintf("Use 'scan' with specific categories (e.g., {\"target\": \"%s\", \"categories\": [\"sqli\"]}) to drill into weak areas.", target))
	steps = append(steps,
		"Use 'generate_cicd' to set up automated regression testing and track WAF grade over time.")
	steps = append(steps,
		"Re-run 'assess' after rule changes to measure improvement.")
	resp.NextSteps = steps

	return resp
}
