package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/crawler"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/ui"
)

// runCrawl executes the web crawler
func runCrawl() {
	ui.PrintCompactBanner()
	ui.PrintSection("Web Crawler")

	crawlFlags := flag.NewFlagSet("crawl", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	crawlFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	crawlFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := crawlFlags.String("l", "", "File containing target URLs")
	stdinInput := crawlFlags.Bool("stdin", false, "Read targets from stdin")
	outputFile := crawlFlags.String("output", "", "Output file for results (JSON)")
	depth := crawlFlags.Int("depth", 3, "Maximum crawl depth")
	maxPages := crawlFlags.Int("max-pages", 100, "Maximum pages to crawl")
	concurrency := crawlFlags.Int("concurrency", 5, "Concurrent crawlers")
	timeout := crawlFlags.Int("timeout", 10, "Request timeout in seconds")
	delay := crawlFlags.Int("delay", 0, "Delay between requests in milliseconds")
	includeScope := crawlFlags.String("include", "", "Include URL pattern (regex)")
	excludeScope := crawlFlags.String("exclude", "", "Exclude URL pattern (regex)")
	includeSubdomains := crawlFlags.Bool("subdomains", false, "Include subdomains in scope")
	extractForms := crawlFlags.Bool("forms", true, "Extract forms")
	extractScripts := crawlFlags.Bool("scripts", true, "Extract scripts")
	jsonOutput := crawlFlags.Bool("json", false, "Output in JSON format")

	// === NEW CRAWL FLAGS ===

	// Additional extraction options
	extractLinks := crawlFlags.Bool("links", true, "Extract links")
	crawlFlags.BoolVar(extractLinks, "el", true, "Extract links (alias)")
	extractEmails := crawlFlags.Bool("emails", false, "Extract email addresses")
	crawlFlags.BoolVar(extractEmails, "ee", false, "Extract emails (alias)")
	extractComments := crawlFlags.Bool("comments", false, "Extract HTML comments")
	crawlFlags.BoolVar(extractComments, "ec", false, "Extract comments (alias)")
	extractEndpoints := crawlFlags.Bool("endpoints", true, "Extract API endpoints")
	crawlFlags.BoolVar(extractEndpoints, "eep", true, "Extract endpoints (alias)")
	extractParams := crawlFlags.Bool("params", true, "Extract URL parameters")
	crawlFlags.BoolVar(extractParams, "epa", true, "Extract params (alias)")
	extractSecrets := crawlFlags.Bool("secrets", false, "Extract potential secrets")
	crawlFlags.BoolVar(extractSecrets, "es", false, "Extract secrets (alias)")

	// Scope control
	sameDomain := crawlFlags.Bool("same-domain", true, "Stay within same domain")
	crawlFlags.BoolVar(sameDomain, "sd", true, "Same domain (alias)")
	samePort := crawlFlags.Bool("same-port", false, "Stay within same port")
	crawlFlags.BoolVar(samePort, "sp", false, "Same port (alias)")
	respectRobots := crawlFlags.Bool("respect-robots", false, "Respect robots.txt")
	crawlFlags.BoolVar(respectRobots, "rr", false, "Respect robots (alias)")
	respectNoFollow := crawlFlags.Bool("respect-nofollow", false, "Respect nofollow links")
	crawlFlags.BoolVar(respectNoFollow, "rnf", false, "Respect nofollow (alias)")

	// Output options
	outputURLs := crawlFlags.Bool("output-urls", false, "Output only URLs (one per line)")
	crawlFlags.BoolVar(outputURLs, "ou", false, "Output URLs (alias)")
	outputCSV := crawlFlags.Bool("csv", false, "Output in CSV format")
	outputMarkdown := crawlFlags.Bool("md", false, "Output in Markdown format")
	silent := crawlFlags.Bool("silent", false, "Silent mode")
	crawlFlags.BoolVar(silent, "s", false, "Silent (alias)")
	verbose := crawlFlags.Bool("verbose", false, "Verbose output")
	crawlFlags.BoolVar(verbose, "v", false, "Verbose (alias)")
	noColor := crawlFlags.Bool("no-color", false, "Disable colored output")
	crawlFlags.BoolVar(noColor, "nc", false, "No color (alias)")

	// Network options
	proxy := crawlFlags.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	crawlFlags.StringVar(proxy, "x", "", "Proxy (alias)")
	skipVerify := crawlFlags.Bool("skip-verify", false, "Skip TLS verification")
	crawlFlags.BoolVar(skipVerify, "k", false, "Skip verify (alias)")
	userAgent := crawlFlags.String("user-agent", "", "Custom User-Agent")
	crawlFlags.StringVar(userAgent, "ua", "", "User-Agent (alias)")
	randomAgent := crawlFlags.Bool("random-agent", false, "Use random User-Agent")
	crawlFlags.BoolVar(randomAgent, "ra", false, "Random agent (alias)")
	headers := crawlFlags.String("header", "", "Custom header (Name: Value)")
	crawlFlags.StringVar(headers, "H", "", "Header (alias)")
	cookies := crawlFlags.String("cookie", "", "Cookies to send")
	crawlFlags.StringVar(cookies, "b", "", "Cookie (alias)")

	// JavaScript handling
	jsRendering := crawlFlags.Bool("js", false, "Enable JavaScript rendering (headless)")
	crawlFlags.BoolVar(jsRendering, "javascript", false, "JavaScript (alias)")
	jsTimeout := crawlFlags.Int("js-timeout", 10, "JavaScript execution timeout (seconds)")
	crawlFlags.IntVar(jsTimeout, "jst", 10, "JS timeout (alias)")
	waitFor := crawlFlags.String("wait-for", "", "CSS selector to wait for")
	crawlFlags.StringVar(waitFor, "wf", "", "Wait for (alias)")

	// Resume and checkpointing
	resume := crawlFlags.Bool("resume", false, "Resume from previous checkpoint")
	checkpoint := crawlFlags.String("checkpoint", "", "Checkpoint file path")
	crawlFlags.StringVar(checkpoint, "cp", "", "Checkpoint (alias)")

	// Debug
	debug := crawlFlags.Bool("debug", false, "Debug mode")
	debugRequest := crawlFlags.Bool("debug-request", false, "Show request details")
	crawlFlags.BoolVar(debugRequest, "dreq", false, "Debug request (alias)")

	// Streaming mode (CI-friendly output)
	streamMode := crawlFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	// Register enterprise output flags
	var outputFlags OutputFlags
	outputFlags.RegisterEnterpriseFlags(crawlFlags)

	// Detection (v2.5.2)
	noDetect := crawlFlags.Bool("no-detect", false, "Disable connection drop and silent ban detection")

	crawlFlags.Parse(os.Args[2:])

	// Disable detection if requested
	if *noDetect {
		detection.Disable()
	}

	// Sync local flags to outputFlags for unified handling
	outputFlags.Silent = *silent
	outputFlags.NoColor = *noColor
	outputFlags.StreamMode = *streamMode

	// Apply UI settings via outputFlags
	outputFlags.ApplyUISettings()

	// Apply debug mode output
	if *debug || *debugRequest {
		ui.PrintInfo("Debug mode enabled")
	}

	// Handle resume from checkpoint
	if *resume {
		checkpointPath := *checkpoint
		if checkpointPath == "" {
			checkpointPath = "crawl-resume.cfg"
		}
		if _, err := os.Stat(checkpointPath); err == nil {
			ui.PrintInfo(fmt.Sprintf("Resuming from checkpoint: %s", checkpointPath))
		} else {
			ui.PrintWarning("No checkpoint file found, starting fresh")
		}
	}

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL is required. Use -u https://example.com, -l file.txt, or -stdin")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Max Depth", fmt.Sprintf("%d", *depth))
	ui.PrintConfigLine("Max Pages", fmt.Sprintf("%d", *maxPages))
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
	if *verbose {
		if *proxy != "" {
			ui.PrintConfigLine("Proxy", *proxy)
		}
		if *userAgent != "" {
			ui.PrintConfigLine("User-Agent", *userAgent)
		}
		if *jsRendering {
			ui.PrintConfigLine("JS Rendering", "Enabled")
		}
	}
	fmt.Println()

	// Build custom headers map
	customHeaders := make(map[string]string)
	if *headers != "" {
		parts := strings.SplitN(*headers, ":", 2)
		if len(parts) == 2 {
			customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Determine user agent
	effectiveUserAgent := *userAgent
	if effectiveUserAgent == "" {
		effectiveUserAgent = ui.UserAgent()
	}
	if *randomAgent {
		userAgents := []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		}
		effectiveUserAgent = userAgents[time.Now().UnixNano()%int64(len(userAgents))]
	}

	cfg := &crawler.Config{
		MaxDepth:          *depth,
		MaxPages:          *maxPages,
		MaxConcurrency:    *concurrency,
		Timeout:           time.Duration(*timeout) * time.Second,
		Delay:             time.Duration(*delay) * time.Millisecond,
		IncludeSubdomains: *includeSubdomains,
		ExtractForms:      *extractForms,
		ExtractScripts:    *extractScripts,
		ExtractLinks:      *extractLinks,
		ExtractComments:   *extractComments,
		FollowRobots:      *respectRobots,
		UserAgent:         effectiveUserAgent,
		Headers:           customHeaders,
		Proxy:             *proxy,
		SkipVerify:        *skipVerify,
		SameDomain:        *sameDomain,
		SamePort:          *samePort,
		Debug:             *debug,
		// Headless browser options
		JSRendering: *jsRendering,
		JSTimeout:   time.Duration(*jsTimeout) * time.Second,
		WaitFor:     *waitFor,
		// Extraction options
		ExtractEmails:    *extractEmails,
		ExtractEndpoints: *extractEndpoints,
		ExtractParams:    *extractParams,
		ExtractSecrets:   *extractSecrets,
	}

	if *includeScope != "" {
		cfg.IncludeScope = []string{*includeScope}
	}
	if *excludeScope != "" {
		cfg.ExcludeScope = []string{*excludeScope}
	}

	c := crawler.NewCrawler(cfg)

	sigCtx, sigCancel := cli.SignalContext(30 * time.Second)
	defer sigCancel()

	ctx, cancel := context.WithTimeout(sigCtx, duration.ContextExtended)
	defer cancel()

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER INITIALIZATION (Hooks: Slack, Teams, PagerDuty, OTEL, Prometheus)
	// ═══════════════════════════════════════════════════════════════════════════
	crawlScanID := fmt.Sprintf("crawl-%d", time.Now().Unix())
	crawlDispCtx, crawlDispErr := outputFlags.InitDispatcher(crawlScanID, target)
	if crawlDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Output dispatcher warning: %v", crawlDispErr))
	}
	if crawlDispCtx != nil {
		defer crawlDispCtx.Close()
		crawlDispCtx.RegisterDetectionCallbacks(ctx)
		_ = crawlDispCtx.EmitStart(ctx, target, 0, *concurrency, nil)
	}

	ui.PrintInfo("Starting crawler...")
	fmt.Println()

	results, err := c.Crawl(ctx, target)
	if err != nil {
		errMsg := fmt.Sprintf("Crawl error: %v", err)
		ui.PrintError(errMsg)
		if crawlDispCtx != nil {
			_ = crawlDispCtx.EmitError(ctx, "crawl", errMsg, true)
			_ = crawlDispCtx.Close()
		}
		os.Exit(1)
	}

	// Collect results with live progress
	var crawlResults []*crawler.CrawlResult
	var allForms []crawler.FormInfo
	var allScripts []string
	var allURLs []string

	// Progress tracking
	startTime := time.Now()
	var pageCount int64

	// Determine output mode for LiveProgress
	crawlOutputMode := ui.OutputModeInteractive
	if *streamMode {
		crawlOutputMode = ui.OutputModeStreaming
	} else if *silent || *jsonOutput {
		crawlOutputMode = ui.OutputModeSilent
	}

	// Use unified LiveProgress for crawl command
	crawlProgress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        0, // Unknown - will be updated dynamically
		DisplayLines: 3,
		Title:        "Crawling",
		Unit:         "pages",
		Mode:         crawlOutputMode,
		Metrics: []ui.MetricConfig{
			{Name: "links", Label: "Links", Icon: ui.Icon("🔗", "~")},
			{Name: "forms", Label: "Forms", Icon: ui.Icon("📝", "F")},
			{Name: "scripts", Label: "Scripts", Icon: ui.Icon("📜", "S")},
		},
		StreamFormat:   "[PROGRESS] {completed} pages | links: {metric:links} | forms: {metric:forms} | {elapsed}",
		StreamInterval: duration.StreamStd,
	})
	crawlProgress.Start()

	for result := range results {
		atomic.AddInt64(&pageCount, 1)
		crawlProgress.Increment()
		crawlResults = append(crawlResults, result)
		allURLs = append(allURLs, result.URL)
		allForms = append(allForms, result.Forms...)
		allScripts = append(allScripts, result.Scripts...)
		// Update metrics
		crawlProgress.SetMetric("links", int64(len(allURLs)))
		crawlProgress.SetMetric("forms", int64(len(allForms)))
		crawlProgress.SetMetric("scripts", int64(len(allScripts)))

		// Real-time streaming to hooks (Slack, Teams, PagerDuty, OTEL, etc.)
		// Emit forms as they're discovered (potential attack surfaces)
		if crawlDispCtx != nil && len(result.Forms) > 0 {
			for _, form := range result.Forms {
				formDesc := fmt.Sprintf("form[action=%s,method=%s,inputs=%d]", form.Action, form.Method, len(form.Inputs))
				_ = crawlDispCtx.EmitBypass(ctx, "crawl-form", "info", result.URL, formDesc, result.StatusCode)
			}
		}
		// Emit external scripts as potential attack surfaces
		if crawlDispCtx != nil && len(result.Scripts) > 0 {
			for _, script := range result.Scripts {
				// Only emit external scripts (those with src attribute containing http)
				if strings.HasPrefix(script, "http") || strings.Contains(script, "://") {
					_ = crawlDispCtx.EmitBypass(ctx, "crawl-external-script", "info", result.URL, script, result.StatusCode)
				}
			}
		}
	}

	crawlProgress.Stop()

	// Silence unused variable
	_ = startTime

	if !*jsonOutput && !*silent {
		ui.PrintSection("Crawl Results")
		ui.PrintConfigLine("Pages Crawled", fmt.Sprintf("%d", len(crawlResults)))
		ui.PrintConfigLine("URLs Found", fmt.Sprintf("%d", len(allURLs)))
		ui.PrintConfigLine("Forms Found", fmt.Sprintf("%d", len(allForms)))
		ui.PrintConfigLine("Scripts Found", fmt.Sprintf("%d", len(allScripts)))
		fmt.Println()

		if *verbose && len(allForms) > 0 {
			ui.PrintSection("Forms")
			for _, form := range allForms {
				ui.PrintConfigLine("Action", form.Action)
				ui.PrintConfigLine("Method", form.Method)
				if len(form.Inputs) > 0 {
					inputs := make([]string, 0, len(form.Inputs))
					for _, inp := range form.Inputs {
						inputs = append(inputs, fmt.Sprintf("%s(%s)", inp.Name, inp.Type))
					}
					ui.PrintInfo(fmt.Sprintf("  Inputs: %s", strings.Join(inputs, ", ")))
				}
			}
			fmt.Println()
		}

		if *verbose && len(allScripts) > 0 && len(allScripts) <= 10 {
			ui.PrintSection("Scripts")
			for _, script := range allScripts {
				ui.PrintInfo("  " + script)
			}
			fmt.Println()
		}
	}

	// Output URLs only mode
	if *outputURLs {
		for _, u := range allURLs {
			fmt.Println(u)
		}
		return
	}

	// CSV output mode
	if *outputCSV {
		fmt.Println("url,status_code,content_type,title")
		for _, r := range crawlResults {
			title := strings.ReplaceAll(r.Title, ",", " ")
			fmt.Printf("%s,%d,%s,%s\n", r.URL, r.StatusCode, r.ContentType, title)
		}
		return
	}

	// Markdown output mode
	if *outputMarkdown {
		fmt.Println("# Crawl Results")
		fmt.Println()
		fmt.Printf("**Target:** %s\n", target)
		fmt.Printf("**Pages Crawled:** %d\n", len(crawlResults))
		fmt.Printf("**URLs Found:** %d\n", len(allURLs))
		fmt.Println()
		fmt.Println("## URLs")
		fmt.Println()
		for _, u := range allURLs {
			fmt.Printf("- %s\n", u)
		}
		if len(allForms) > 0 {
			fmt.Println()
			fmt.Println("## Forms")
			fmt.Println()
			for _, form := range allForms {
				fmt.Printf("- **%s** `%s`\n", form.Method, form.Action)
			}
		}
		return
	}

	// Output results
	if *jsonOutput || *outputFile != "" {
		output := struct {
			Target  string                 `json:"target"`
			Results []*crawler.CrawlResult `json:"results"`
			Forms   []crawler.FormInfo     `json:"forms"`
			Scripts []string               `json:"scripts"`
			URLs    []string               `json:"urls"`
		}{
			Target:  target,
			Results: crawlResults,
			Forms:   allForms,
			Scripts: allScripts,
			URLs:    allURLs,
		}

		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			errMsg := fmt.Sprintf("JSON encoding error: %v", err)
			ui.PrintError(errMsg)
			if crawlDispCtx != nil {
				_ = crawlDispCtx.EmitError(context.Background(), "crawl", errMsg, true)
				_ = crawlDispCtx.Close()
			}
			os.Exit(1)
		}

		if *outputFile != "" {
			if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
				errMsg := fmt.Sprintf("Error writing output: %v", err)
				ui.PrintError(errMsg)
				if crawlDispCtx != nil {
					_ = crawlDispCtx.EmitError(context.Background(), "crawl", errMsg, true)
					_ = crawlDispCtx.Close()
				}
				os.Exit(1)
			}
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}

		if *jsonOutput {
			fmt.Println(string(jsonData))
		}
	}

	// Write enterprise export files (--json-export, --sarif-export, etc.)
	writeCrawlExports(&outputFlags, target, crawlResults, allForms, allScripts, allURLs, time.Since(startTime))

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER SUMMARY EMISSION
	// ═══════════════════════════════════════════════════════════════════════════
	// Notify all hooks that crawl is complete (pages discovered, forms found)
	if crawlDispCtx != nil {
		_ = crawlDispCtx.EmitSummary(ctx, len(crawlResults), len(allURLs), len(allForms), time.Since(startTime))
	}
}
