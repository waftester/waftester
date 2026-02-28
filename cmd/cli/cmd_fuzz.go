package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/detection"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	"github.com/waftester/waftester/pkg/fuzz"
	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

func runFuzz() {
	ui.PrintCompactBanner()
	ui.PrintSection("Content Fuzzer")

	fuzzFlags := flag.NewFlagSet("fuzz", flag.ExitOnError)
	// Target and input
	var targetURLs input.StringSliceFlag
	fuzzFlags.Var(&targetURLs, "u", "Target URL(s) with FUZZ keyword - comma-separated or repeated")
	fuzzFlags.Var(&targetURLs, "target", "Target URL(s) with FUZZ keyword")
	listFile := fuzzFlags.String("l", "", "File containing target URLs")
	stdinInput := fuzzFlags.Bool("stdin", false, "Read targets from stdin")
	wordlist := fuzzFlags.String("w", "", "Wordlist file or URL")
	wordlistType := fuzzFlags.String("wt", "directories", "Wordlist type: directories, files, parameters, subdomains")
	data := fuzzFlags.String("d", "", "POST data (can include FUZZ)")
	method := fuzzFlags.String("X", "GET", "HTTP method")

	// Execution
	concurrency := fuzzFlags.Int("t", 40, "Number of concurrent threads")
	rateLimit := fuzzFlags.Int("rate", 100, "Requests per second")
	timeout := fuzzFlags.Int("timeout", 10, "Request timeout in seconds")
	followRedirects := fuzzFlags.Bool("r", false, "Follow redirects")
	skipVerify := fuzzFlags.Bool("k", false, "Skip TLS verification")

	// Extensions
	extensions := fuzzFlags.String("e", "", "Extensions to append (comma-separated, e.g., php,html,txt)")

	// Headers
	headerStr := fuzzFlags.String("H", "", "Header to add (can be used multiple times, format: 'Name: Value')")
	cookies := fuzzFlags.String("b", "", "Cookies to send")

	// Matchers
	matchStatus := fuzzFlags.String("mc", "200,204,301,302,307,401,403,405", "Match status codes")
	matchSize := fuzzFlags.String("ms", "", "Match response size")
	matchWords := fuzzFlags.String("mw", "", "Match word count")
	matchLines := fuzzFlags.String("ml", "", "Match line count")
	matchRegex := fuzzFlags.String("mr", "", "Match body regex")

	// Filters
	filterStatus := fuzzFlags.String("fc", "", "Filter status codes")
	filterSize := fuzzFlags.String("fs", "", "Filter response size")
	filterWords := fuzzFlags.String("fw", "", "Filter word count")
	filterLines := fuzzFlags.String("fl", "", "Filter line count")
	filterRegex := fuzzFlags.String("fr", "", "Filter body regex")
	autoCalibrate := fuzzFlags.Bool("ac", false, "Auto-calibrate filters based on baseline responses")

	// Output
	outputFile := fuzzFlags.String("o", "", "Output file (JSON)")
	silent := fuzzFlags.Bool("s", false, "Silent mode")
	noColor := fuzzFlags.Bool("nc", false, "No color output")
	jsonOutput := fuzzFlags.Bool("json", false, "Output in JSON format")
	streamMode := fuzzFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	// === NEW FUZZ FLAGS ===

	// Additional output formats
	csvFuzz := fuzzFlags.Bool("csv", false, "Output in CSV format")
	htmlFuzz := fuzzFlags.Bool("html-output", false, "Output in HTML format")
	markdownFuzz := fuzzFlags.Bool("md", false, "Output in Markdown format")
	verbose := fuzzFlags.Bool("v", false, "Verbose output")
	fuzzFlags.BoolVar(verbose, "verbose", false, "Verbose output (alias)")
	timestamp := fuzzFlags.Bool("ts", false, "Add timestamp to output")
	fuzzFlags.BoolVar(timestamp, "timestamp", false, "Add timestamp (alias)")

	// Wordlist options
	wordlistMax := fuzzFlags.Int("wmax", 0, "Max words from wordlist (0=all)")
	wordlistSkip := fuzzFlags.Int("wskip", 0, "Skip first N words from wordlist")
	wordlistShuffle := fuzzFlags.Bool("wshuffle", false, "Shuffle wordlist before fuzzing")
	wordlistLower := fuzzFlags.Bool("wlower", false, "Convert wordlist to lowercase")
	wordlistUpper := fuzzFlags.Bool("wupper", false, "Convert wordlist to uppercase")
	wordlistPrefix := fuzzFlags.String("wprefix", "", "Add prefix to each word")
	wordlistSuffix := fuzzFlags.String("wsuffix", "", "Add suffix to each word")

	// Recursion options
	recursion := fuzzFlags.Bool("recursion", false, "Enable recursive fuzzing")
	recursionDepth := fuzzFlags.Int("recursion-depth", 2, "Max recursion depth")
	fuzzFlags.IntVar(recursionDepth, "rd", 2, "Recursion depth (alias)")

	// Sniper/clusterbomb modes
	fuzzMode := fuzzFlags.String("mode", "sniper", "Fuzzing mode: sniper, pitchfork, clusterbomb")
	fuzzPosition := fuzzFlags.String("fuzz-position", "", "Position to fuzz: url, header, body, cookie")
	fuzzFlags.StringVar(fuzzPosition, "fp", "", "Fuzz position (alias)")

	// Response analysis
	extractRegex := fuzzFlags.String("extract", "", "Extract matching content (regex)")
	fuzzFlags.StringVar(extractRegex, "er", "", "Extract regex (alias)")
	extractPreset := fuzzFlags.String("extract-preset", "", "Extract preset: emails, urls, ips, secrets")
	fuzzFlags.StringVar(extractPreset, "epr", "", "Extract preset (alias)")

	// Store responses
	storeResponse := fuzzFlags.Bool("sr", false, "Store HTTP responses to directory")
	fuzzFlags.BoolVar(storeResponse, "store-response", false, "Store response (alias)")
	storeResponseDir := fuzzFlags.String("srd", "./responses", "Directory for stored responses")
	fuzzFlags.StringVar(storeResponseDir, "store-response-dir", "./responses", "Store response dir (alias)")
	storeOnlyMatches := fuzzFlags.Bool("som", false, "Store only matching responses")
	fuzzFlags.BoolVar(storeOnlyMatches, "store-only-matches", false, "Store only matches (alias)")

	// Network options
	proxy := fuzzFlags.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	fuzzFlags.StringVar(proxy, "x", "", "Proxy (alias)")
	retries := fuzzFlags.Int("retries", 0, "Number of retries on failure")
	delay := fuzzFlags.Duration("delay", 0, "Delay between requests")
	jitter := fuzzFlags.Duration("jitter", 0, "Random jitter for delay")

	// Debug
	debug := fuzzFlags.Bool("debug", false, "Debug mode - show request/response")
	debugRequest := fuzzFlags.Bool("debug-request", false, "Show request content")
	fuzzFlags.BoolVar(debugRequest, "dreq", false, "Debug request (alias)")
	debugResponse := fuzzFlags.Bool("debug-response", false, "Show response content")
	fuzzFlags.BoolVar(debugResponse, "dresp", false, "Debug response (alias)")

	// Auto-calibration options
	calibrationWords := fuzzFlags.String("calibration-words", "", "Specific words for baseline (comma-separated)")
	fuzzFlags.StringVar(calibrationWords, "cw", "", "Calibration words (alias)")

	// Enterprise output flags (unified with other commands)
	var outputFlags OutputFlags
	outputFlags.RegisterFuzzEnterpriseFlags(fuzzFlags)

	// Detection (v2.5.2)
	noDetect := fuzzFlags.Bool("no-detect", false, "Disable connection drop and silent ban detection")

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	smartMode := fuzzFlags.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	smartModeType := fuzzFlags.String("smart-mode", "standard", "Smart mode type: quick, standard, full, bypass, stealth")
	smartVerbose := fuzzFlags.Bool("smart-verbose", false, "Show detailed WAF detection info")

	// Tamper scripts (70+ sqlmap-compatible WAF bypass transformations)
	tamperList := fuzzFlags.String("tamper", "", "Comma-separated tamper scripts: space2comment,randomcase,charencode")
	tamperAuto := fuzzFlags.Bool("tamper-auto", false, "Auto-select tampers based on detected WAF")
	tamperProfile := fuzzFlags.String("tamper-profile", "standard", "Tamper profile: stealth, standard, aggressive, bypass")
	tamperDir := fuzzFlags.String("tamper-dir", "", "Directory of .tengo script tampers to load")

	fuzzFlags.Parse(os.Args[2:])

	// Disable detection if requested
	if *noDetect {
		detection.Disable()
	}

	// Apply UI settings from OutputFlags (sync with local flags)
	outputFlags.Silent = *silent
	outputFlags.NoColor = *noColor
	outputFlags.JSONMode = *jsonOutput
	outputFlags.StreamMode = *streamMode
	outputFlags.ApplyUISettings()

	// Apply debug mode output
	if *debug || *debugRequest || *debugResponse {
		ui.PrintInfo("Debug mode enabled")
	}

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	targetURL, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL with FUZZ keyword is required. Use -u https://example.com/FUZZ, -l file.txt, or -stdin")
		os.Exit(1)
	}

	if !strings.Contains(targetURL, "FUZZ") && !strings.Contains(*data, "FUZZ") {
		ui.PrintError("FUZZ keyword not found in URL or POST data.")
		ui.PrintInfo("Example: waf-tester fuzz -u https://example.com/FUZZ -w wordlist.txt")
		os.Exit(1)
	}

	// Load wordlist
	var words []string
	if *wordlist != "" {
		// Reject non-HTTP URL schemes (SSRF protection)
		if strings.Contains(*wordlist, "://") && !strings.HasPrefix(*wordlist, "http://") && !strings.HasPrefix(*wordlist, "https://") {
			ui.PrintError("Wordlist URL must use http:// or https:// scheme")
			os.Exit(1)
		}
		if strings.HasPrefix(*wordlist, "http://") || strings.HasPrefix(*wordlist, "https://") {
			// Download wordlist with timeout
			dlCtx, dlCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer dlCancel()
			req, reqErr := http.NewRequestWithContext(dlCtx, http.MethodGet, *wordlist, nil)
			if reqErr != nil {
				ui.PrintError(fmt.Sprintf("Invalid wordlist URL: %v", reqErr))
				os.Exit(1)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				ui.PrintError(fmt.Sprintf("Failed to download wordlist: %v", err))
				os.Exit(1)
			}
			defer iohelper.DrainAndClose(resp.Body)
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					words = append(words, line)
				}
			}
			if err := scanner.Err(); err != nil {
				ui.PrintError(fmt.Sprintf("Failed to read wordlist: %v", err))
				os.Exit(1)
			}
		} else {
			// Read from file
			file, err := os.Open(*wordlist)
			if err != nil {
				ui.PrintError(fmt.Sprintf("Failed to open wordlist: %v", err))
				os.Exit(1)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					words = append(words, line)
				}
			}
			if err := scanner.Err(); err != nil {
				ui.PrintError(fmt.Sprintf("Failed to read wordlist: %v", err))
				os.Exit(1)
			}
		}
	} else {
		// Use built-in wordlist
		ui.PrintInfo(fmt.Sprintf("No wordlist specified, using built-in %s list", *wordlistType))
		words = getBuiltInWordlist(*wordlistType)
	}

	if len(words) == 0 {
		ui.PrintError("Wordlist is empty")
		os.Exit(1)
	}

	// Apply wordlist transformations
	if *wordlistSkip > 0 && *wordlistSkip < len(words) {
		words = words[*wordlistSkip:]
	}
	if *wordlistMax > 0 && *wordlistMax < len(words) {
		words = words[:*wordlistMax]
	}
	if *wordlistShuffle {
		rand.Shuffle(len(words), func(i, j int) {
			words[i], words[j] = words[j], words[i]
		})
	}
	if *wordlistLower {
		for i, w := range words {
			words[i] = strings.ToLower(w)
		}
	}
	if *wordlistUpper {
		for i, w := range words {
			words[i] = strings.ToUpper(w)
		}
	}
	if *wordlistPrefix != "" || *wordlistSuffix != "" {
		for i, w := range words {
			words[i] = *wordlistPrefix + w + *wordlistSuffix
		}
	}

	// Parse extensions
	var exts []string
	if *extensions != "" {
		for _, ext := range strings.Split(*extensions, ",") {
			ext = strings.TrimSpace(ext)
			if ext != "" {
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				exts = append(exts, ext)
			}
		}
	}

	// Parse headers
	headers := make(map[string]string)
	if *headerStr != "" {
		parts := strings.SplitN(*headerStr, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Parse regexes
	var matchRe, filterRe *regexp.Regexp
	if *matchRegex != "" {
		var err error
		matchRe, err = regexcache.Get(*matchRegex)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Invalid match regex: %v", err))
			os.Exit(1)
		}
	}
	if *filterRegex != "" {
		var err error
		filterRe, err = regexcache.Get(*filterRegex)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Invalid filter regex: %v", err))
			os.Exit(1)
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// SMART MODE: WAF DETECTION & OPTIMIZATION
	// ═══════════════════════════════════════════════════════════════════════════
	// Set up context early so smart mode detection can use it
	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()

	var smartResult *SmartModeResult
	if *smartMode {
		if !*silent && !*jsonOutput {
			ui.PrintSection("Smart Mode: WAF Detection & Optimization")
			fmt.Fprintln(os.Stderr)
		}

		smartConfig := &SmartModeConfig{
			DetectionTimeout: time.Duration(*timeout) * time.Second,
			Verbose:          *smartVerbose,
			Mode:             *smartModeType,
		}

		var detectErr error
		smartResult, detectErr = DetectAndOptimize(ctx, targetURL, smartConfig)
		if detectErr != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", detectErr))
		}

		if !*silent && !*jsonOutput {
			PrintSmartModeInfo(smartResult, *smartVerbose)
		}

		// Apply WAF-optimized rate limit and concurrency
		// Only override if the user didn't explicitly set these flags
		if smartResult != nil && smartResult.WAFDetected {
			userSetRL := false
			userSetConc := false
			fuzzFlags.Visit(func(f *flag.Flag) {
				if f.Name == "rate" {
					userSetRL = true
				}
				if f.Name == "t" {
					userSetConc = true
				}
			})

			if !userSetRL && smartResult.RateLimit > 0 {
				if !*silent && !*jsonOutput {
					ui.PrintInfo(fmt.Sprintf("Rate limit: %.0f req/sec (WAF-optimized for %s)",
						smartResult.RateLimit, smartResult.VendorName))
				}
				*rateLimit = int(smartResult.RateLimit)
			}
			if !userSetConc && smartResult.Concurrency > 0 {
				if !*silent && !*jsonOutput {
					ui.PrintInfo(fmt.Sprintf("Concurrency: %d workers (WAF-optimized)",
						smartResult.Concurrency))
				}
				*concurrency = smartResult.Concurrency
			}
		}
		if !*silent && !*jsonOutput {
			fmt.Fprintln(os.Stderr)
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// TAMPER ENGINE INITIALIZATION (Fuzz Command)
	// ═══════════════════════════════════════════════════════════════════════════
	var tamperEngine *tampers.Engine
	if *tamperList != "" || *tamperAuto || (*smartMode && smartResult != nil && smartResult.WAFDetected) {
		// Determine tamper profile
		profile := tampers.ProfileStandard
		switch *tamperProfile {
		case "stealth":
			profile = tampers.ProfileStealth
		case "aggressive":
			profile = tampers.ProfileAggressive
		case "bypass":
			profile = tampers.ProfileBypass
		}

		// If custom tamper list provided, use custom profile
		if *tamperList != "" {
			profile = tampers.ProfileCustom
		}

		// Get WAF vendor and strategy hints for intelligent selection
		wafVendor := "unknown"
		var strategyHints []string
		if smartResult != nil && smartResult.WAFDetected {
			wafVendor = smartResult.VendorName
		}
		if smartResult != nil && smartResult.Strategy != nil {
			strategyHints = smartResult.Strategy.Evasions
		}

		// Load script tampers from directory if specified
		if *tamperDir != "" {
			scripts, errs := tampers.LoadScriptDir(*tamperDir)
			for _, e := range errs {
				ui.PrintWarning(fmt.Sprintf("Script tamper: %v", e))
			}
			for _, st := range scripts {
				tampers.Register(st)
			}
			if len(scripts) > 0 && !*silent {
				ui.PrintInfo(fmt.Sprintf("Loaded %d script tampers from %s", len(scripts), *tamperDir))
			}
		}

		tamperEngine = tampers.NewEngine(&tampers.EngineConfig{
			Profile:       profile,
			CustomTampers: tampers.ParseTamperList(*tamperList),
			WAFVendor:     wafVendor,
			StrategyHints: strategyHints,
			EnableMetrics: true,
		})

		// Print tamper info
		if !*silent && !*jsonOutput {
			if *tamperList != "" {
				valid, invalid := tampers.ValidateTamperNames(tampers.ParseTamperList(*tamperList))
				if len(invalid) > 0 {
					ui.PrintWarning(fmt.Sprintf("Unknown tampers: %s", strings.Join(invalid, ", ")))
				}
				if len(valid) > 0 {
					ui.PrintInfo(fmt.Sprintf("Using %d custom tampers: %s", len(valid), strings.Join(valid, ", ")))
				}
			} else {
				selectedTampers := tamperEngine.GetSelectedTampers()
				if len(strategyHints) > 0 {
					ui.PrintInfo(fmt.Sprintf("Auto-selected %d tampers for %s (strategy hints: %d): %s",
						len(selectedTampers), wafVendor, len(strategyHints), strings.Join(selectedTampers, ", ")))
				} else {
					ui.PrintInfo(fmt.Sprintf("Auto-selected %d tampers: %s",
						len(selectedTampers), strings.Join(selectedTampers, ", ")))
				}
			}
		}
	}

	// Build fuzz config
	cfg := &fuzz.Config{
		TargetURL: targetURL,
		Words:     words,
		Base: attackconfig.Base{
			Concurrency: *concurrency,
			Timeout:     time.Duration(*timeout) * time.Second,
		},
		RateLimit:      *rateLimit,
		SkipVerify:     *skipVerify,
		Method:         *method,
		Headers:        headers,
		Data:           *data,
		Cookies:        *cookies,
		FollowRedir:    *followRedirects,
		Extensions:     exts,
		MatchStatus:    parseIntList(*matchStatus),
		MatchSize:      parseIntList(*matchSize),
		MatchWords:     parseIntList(*matchWords),
		MatchLines:     parseIntList(*matchLines),
		MatchRegex:     matchRe,
		FilterStatus:   parseIntList(*filterStatus),
		FilterSize:     parseIntList(*filterSize),
		FilterWords:    parseIntList(*filterWords),
		FilterLines:    parseIntList(*filterLines),
		FilterRegex:    filterRe,
		Recursive:      *recursion,
		RecursionDepth: *recursionDepth,
		Proxy:          *proxy,
		Retries:        *retries,
		Delay:          *delay,
		Jitter:         *jitter,
		Debug:          *debug,
		Verbose:        *verbose,
		StoreResponses: *storeResponse,
		StoreDir:       *storeResponseDir,
		StoreMatches:   *storeOnlyMatches,
		Mode:           *fuzzMode,
		ExtractRegex:   *extractRegex,
		ExtractPreset:  *extractPreset,
	}

	// Wire tamper engine into fuzz config (nil-safe: only set if engine was created)
	if tamperEngine != nil {
		cfg.Transformer = tamperEngine
	}

	// Apply noColor setting to UI
	if *noColor {
		// Colors are disabled in the UI package via environment
		os.Setenv("NO_COLOR", "1")
	}

	// Determine output mode for progress
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}
	if *silent {
		outputMode = ui.OutputModeSilent
	}

	// Print config or manifest
	if !*silent && !*jsonOutput {
		if *streamMode {
			// Streaming mode: simple line output
			fmt.Printf("[INFO] Starting fuzz: target=%s words=%d concurrency=%d rate=%d\n",
				targetURL, len(words), *concurrency, *rateLimit)
		} else {
			// Interactive mode: full manifest
			manifest := ui.NewExecutionManifest("CONTENT FUZZER")
			manifest.SetDescription("Fuzzing paths, parameters, or content")
			manifest.AddWithIcon("🎯", "Target", targetURL)
			manifest.AddWithIcon("📝", "Method", *method)
			manifest.AddEmphasis("📦", "Wordlist", fmt.Sprintf("%d words", len(words)))
			if len(exts) > 0 {
				manifest.AddWithIcon("📎", "Extensions", strings.Join(exts, ", "))
			}
			manifest.AddConcurrency(*concurrency, float64(*rateLimit))
			if smartResult != nil && smartResult.WAFDetected {
				manifest.AddWithIcon("🛡", "WAF Detected", fmt.Sprintf("%s (%.0f%% confidence)", smartResult.VendorName, smartResult.Confidence*100))
			}
			if tamperEngine != nil {
				selectedTampers := tamperEngine.GetSelectedTampers()
				manifest.AddWithIcon("🔧", "Tampers", fmt.Sprintf("%d active", len(selectedTampers)))
			}
			if *matchStatus != "" {
				manifest.AddWithIcon("✓", "Match Status", *matchStatus)
			}
			if *filterStatus != "" {
				manifest.AddWithIcon("✗", "Filter Status", *filterStatus)
			}
			manifest.AddEstimate(len(words), float64(*rateLimit))
			manifest.Print()
		}
	}

	// Create fuzzer
	fuzzer := fuzz.NewFuzzer(cfg)

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER INITIALIZATION (Hooks: Slack, Teams, PagerDuty, OTEL, Prometheus)
	// ═══════════════════════════════════════════════════════════════════════════
	fuzzScanID := fmt.Sprintf("fuzz-%d", time.Now().Unix())
	fuzzDispCtx, fuzzDispErr := outputFlags.InitDispatcher(fuzzScanID, targetURL)
	if fuzzDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Output dispatcher warning: %v", fuzzDispErr))
	}
	if fuzzDispCtx != nil {
		defer fuzzDispCtx.Close()
		fuzzDispCtx.RegisterDetectionCallbacks(ctx)
		_ = fuzzDispCtx.EmitStart(ctx, targetURL, len(words), *concurrency, nil)

		// Emit smart mode WAF detection to hooks
		if smartResult != nil && smartResult.WAFDetected {
			wafDesc := fmt.Sprintf("Smart mode detected: %s (%.0f%% confidence)", smartResult.VendorName, smartResult.Confidence*100)
			_ = fuzzDispCtx.EmitBypass(ctx, "smart-waf-detection", "info", targetURL, wafDesc, 0)
			for _, hint := range smartResult.BypassHints {
				_ = fuzzDispCtx.EmitBypass(ctx, "bypass-hint", "info", targetURL, hint, 0)
			}
		}
	}

	// Auto-calibration
	var calibration *fuzz.Calibration
	if *autoCalibrate {
		if !*silent {
			ui.PrintInfo("Auto-calibrating...")
		}
		calibration = fuzzer.Calibrate(ctx)
		if !*silent && calibration.BaselineSize > 0 {
			ui.PrintConfigLine("Baseline", fmt.Sprintf("Status=%d Size=%d Words=%d Lines=%d",
				calibration.BaselineStatus, calibration.BaselineSize,
				calibration.BaselineWords, calibration.BaselineLines))
			fmt.Println()
		}
	}

	// Collect results
	var results []*fuzz.Result
	var resultsMu sync.Mutex

	// Progress tracking
	var totalReqs, matchCount int64
	totalWords := len(words)
	if len(cfg.Extensions) > 0 {
		totalWords = len(words) * len(cfg.Extensions)
	}

	// Use unified LiveProgress for progress display
	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        totalWords,
		DisplayLines: 4,
		Title:        "Fuzzing",
		Unit:         "words",
		Mode:         outputMode,
		Metrics: []ui.MetricConfig{
			{Name: "matches", Label: "Matches", Icon: ui.Icon("✅", "+"), Highlight: true},
			{Name: "filtered", Label: "Filtered", Icon: ui.Icon("🔇", "-")},
		},
		Tips: []string{
			"Content fuzzing discovers hidden paths, parameters, and endpoints",
			"Response size and status code variations indicate interesting findings",
			"Use -ac for auto-calibration to filter baseline responses",
			"Extensions (-e) multiply wordlist entries for file discovery",
		},
		StreamFormat:   "[PROGRESS] {completed}/{total} ({percent}%) | matches: {metric:matches} | {status} | {elapsed}",
		StreamInterval: duration.StreamStd,
	})
	if !*jsonOutput {
		progress.Start()
		defer progress.Stop()
	}

	callback := func(result *fuzz.Result) {
		atomic.AddInt64(&totalReqs, 1)
		progress.Increment()
		progress.SetStatus(result.Input)

		// Apply auto-calibration filter
		if calibration != nil && calibration.ShouldFilter(result) {
			progress.AddMetric("filtered")
			return // Skip baseline matches
		}

		atomic.AddInt64(&matchCount, 1)
		progress.AddMetric("matches")
		resultsMu.Lock()
		results = append(results, result)
		resultsMu.Unlock()

		// Real-time streaming to hooks (Slack, Teams, PagerDuty, OTEL, Prometheus, etc.)
		// Emit each interesting finding (non-filtered match) as it's discovered
		if fuzzDispCtx != nil {
			// Classify severity based on status code
			severity := "info"
			if result.StatusCode >= 200 && result.StatusCode < 300 {
				severity = "medium"
			} else if result.StatusCode >= 500 {
				severity = "high"
			}
			_ = fuzzDispCtx.EmitBypass(ctx, "fuzz-discovery", severity, result.URL, result.Input, result.StatusCode)
		}

		// Print result (LiveProgress handles terminal management)
		if !*silent && !*jsonOutput {
			statusColor := ui.StatValueStyle
			switch {
			case result.StatusCode >= 200 && result.StatusCode < 300:
				statusColor = ui.PassStyle
			case result.StatusCode >= 300 && result.StatusCode < 400:
				statusColor = ui.ConfigValueStyle // 3xx redirects
			case result.StatusCode >= 400 && result.StatusCode < 500:
				statusColor = ui.FailStyle
			case result.StatusCode >= 500:
				statusColor = ui.ErrorStyle
			}

			// Include timestamp prefix if requested
			if *timestamp {
				ts := time.Now().Format("15:04:05")
				fmt.Printf("[%s] %s %-50s [%s] [%s] [%s] [%s]\n",
					ts,
					statusColor.Render(fmt.Sprintf("%d", result.StatusCode)),
					result.Input,
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d B", result.ContentLength)),
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d W", result.WordCount)),
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d L", result.LineCount)),
					ui.ConfigValueStyle.Render(result.ResponseTime.Round(time.Millisecond).String()),
				)
			} else {
				fmt.Printf("%s %-50s [%s] [%s] [%s] [%s]\n",
					statusColor.Render(fmt.Sprintf("%d", result.StatusCode)),
					result.Input,
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d B", result.ContentLength)),
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d W", result.WordCount)),
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d L", result.LineCount)),
					ui.ConfigValueStyle.Render(result.ResponseTime.Round(time.Millisecond).String()),
				)
			}
		}
	}

	// Run fuzzer
	fuzzStartTime := time.Now()
	stats := fuzzer.Run(ctx, callback)
	duration := time.Since(fuzzStartTime)

	// Print summary
	if !*silent && !*jsonOutput && !*csvFuzz && !*markdownFuzz && !*htmlFuzz {
		fmt.Println()
		ui.PrintSection("Summary")
		ui.PrintConfigLine("Total Requests", fmt.Sprintf("%d", stats.TotalRequests))
		ui.PrintConfigLine("Matches", fmt.Sprintf("%d", stats.Matches))
		ui.PrintConfigLine("Filtered", fmt.Sprintf("%d", stats.Filtered))
		ui.PrintConfigLine("Errors", fmt.Sprintf("%d", stats.Errors))
		ui.PrintConfigLine("Duration", duration.Round(time.Millisecond).String())
		ui.PrintConfigLine("Requests/sec", fmt.Sprintf("%.2f", stats.RequestsPerSec))
		fmt.Println()
	}

	// Enterprise file exports (--json-export, --sarif-export, etc.)
	// Must run BEFORE stdout format routing because those branches return early.
	outputFlags.MaybeExport(func() execResults {
		return fuzzResultsToExecution(targetURL, results, stats, duration)
	})

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER SUMMARY EMISSION
	// ═══════════════════════════════════════════════════════════════════════════
	// Notify all hooks that fuzz is complete (total requests, matches found)
	if fuzzDispCtx != nil {
		_ = fuzzDispCtx.EmitSummary(ctx, int(stats.TotalRequests), int(stats.Matches), int(stats.Filtered), duration)
	}

	// CSV output
	if *csvFuzz {
		fmt.Println("url,status,size,words,lines,time")
		for _, r := range results {
			fmt.Printf("%s,%d,%d,%d,%d,%s\n", r.URL, r.StatusCode, r.ContentLength, r.WordCount, r.LineCount, r.ResponseTime)
		}
		return
	}

	// Markdown output
	if *markdownFuzz {
		fmt.Println("# Fuzz Results")
		fmt.Println()
		fmt.Printf("**Target:** %s\n", targetURL)
		fmt.Printf("**Total Requests:** %d\n", stats.TotalRequests)
		fmt.Printf("**Matches:** %d\n", stats.Matches)
		fmt.Println()
		fmt.Println("| URL | Status | Size | Words | Lines |")
		fmt.Println("|-----|--------|------|-------|-------|")
		for _, r := range results {
			fmt.Printf("| %s | %d | %d | %d | %d |\n", r.URL, r.StatusCode, r.ContentLength, r.WordCount, r.LineCount)
		}
		return
	}

	// HTML output
	if *htmlFuzz {
		fmt.Println("<!DOCTYPE html><html><head><title>Fuzz Results</title>")
		fmt.Println("<style>table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#4CAF50;color:white}</style></head><body>")
		fmt.Printf("<h1>Fuzz Results</h1><p>Target: %s</p>\n", html.EscapeString(targetURL))
		fmt.Printf("<p>Total: %d | Matches: %d</p>\n", stats.TotalRequests, stats.Matches)
		fmt.Println("<table><tr><th>URL</th><th>Status</th><th>Size</th><th>Words</th><th>Lines</th></tr>")
		for _, r := range results {
			fmt.Printf("<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>\n", html.EscapeString(r.URL), r.StatusCode, r.ContentLength, r.WordCount, r.LineCount)
		}
		fmt.Println("</table></body></html>")
		return
	}

	// Output results
	if *jsonOutput || *outputFile != "" {
		output := struct {
			Target      string         `json:"target"`
			Wordlist    string         `json:"wordlist,omitempty"`
			Results     []*fuzz.Result `json:"results"`
			Stats       *fuzz.Stats    `json:"stats"`
			Duration    string         `json:"duration"`
			CompletedAt time.Time      `json:"completed_at"`
		}{
			Target:      targetURL,
			Wordlist:    *wordlist,
			Results:     results,
			Stats:       stats,
			Duration:    duration.String(),
			CompletedAt: time.Now(),
		}

		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			errMsg := fmt.Sprintf("JSON encoding error: %v", err)
			ui.PrintError(errMsg)
			if fuzzDispCtx != nil {
				_ = fuzzDispCtx.EmitError(context.Background(), "fuzz", errMsg, true)
				_ = fuzzDispCtx.Close()
			}
			os.Exit(1)
		}

		if *outputFile != "" {
			if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
				errMsg := fmt.Sprintf("Error writing output: %v", err)
				ui.PrintError(errMsg)
				if fuzzDispCtx != nil {
					_ = fuzzDispCtx.EmitError(context.Background(), "fuzz", errMsg, true)
					_ = fuzzDispCtx.Close()
				}
				os.Exit(1)
			}
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}

		if *jsonOutput {
			fmt.Println(string(jsonData))
		}
	}

}

// getBuiltInWordlist returns a built-in wordlist based on type
func getBuiltInWordlist(wlType string) []string {
	switch wlType {
	case "directories":
		return []string{
			"admin", "api", "app", "assets", "auth", "backup", "bin",
			"blog", "cache", "cgi-bin", "config", "console", "css",
			"dashboard", "data", "db", "debug", "dev", "docs", "downloads",
			"email", "files", "fonts", "forum", "help", "home", "html",
			"images", "img", "includes", "info", "install", "js", "lib",
			"log", "login", "logs", "mail", "media", "new", "old", "panel",
			"php", "phpmyadmin", "private", "public", "resources", "scripts",
			"search", "server", "service", "services", "setup", "shop",
			"site", "src", "staff", "static", "stats", "status", "storage",
			"store", "support", "system", "temp", "templates", "test",
			"tests", "themes", "tmp", "tools", "upload", "uploads", "user",
			"users", "vendor", "web", "webmail", "wp-admin", "wp-content",
			"wp-includes", "xml",
		}
	case "files":
		return []string{
			".htaccess", ".htpasswd", ".git/config", ".env", ".env.local",
			"robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
			".well-known/security.txt", "README.md", "readme.html",
			"CHANGELOG.md", "composer.json", "package.json", "webpack.config.js",
			"config.php", "config.json", "config.yml", "settings.php",
			"database.yml", "wp-config.php", "configuration.php",
			"web.config", "server-status", "phpinfo.php", "info.php",
			"test.php", "debug.php", "error.log", "access.log", "debug.log",
			"backup.sql", "dump.sql", "database.sql", "db.sql",
		}
	case "parameters":
		return []string{
			"id", "page", "file", "path", "dir", "url", "q", "query",
			"search", "name", "user", "username", "pass", "password",
			"email", "token", "key", "api_key", "apikey", "secret",
			"callback", "redirect", "return", "returnUrl", "next",
			"ref", "referer", "cmd", "exec", "command", "action",
			"type", "format", "lang", "locale", "size", "limit",
			"offset", "order", "sort", "filter", "category", "tag",
			"view", "mode", "debug", "test", "admin", "role",
		}
	case "subdomains":
		return []string{
			"www", "mail", "ftp", "admin", "api", "dev", "test", "stage",
			"staging", "prod", "production", "app", "mobile", "m", "blog",
			"shop", "store", "cdn", "static", "assets", "media", "images",
			"img", "ns1", "ns2", "dns", "mx", "smtp", "pop", "imap",
			"vpn", "remote", "secure", "login", "portal", "dashboard",
			"panel", "console", "monitor", "status", "docs", "wiki",
			"help", "support", "forum", "community", "git", "gitlab",
			"github", "jenkins", "ci", "jira", "confluence", "slack",
		}
	default:
		return []string{}
	}
}
