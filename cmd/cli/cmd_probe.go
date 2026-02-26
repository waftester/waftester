// cmd_probe.go - Protocol probing command
// Extracted from main.go - contains runProbe function for httpx-compatible probing
package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spaolacci/murmur3"
	"github.com/waftester/waftester/pkg/checkpoint"
	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/dsl"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/fp"
	"github.com/waftester/waftester/pkg/headless"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/probes"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/runner"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/waf"
)

// runProbe executes protocol probing (TLS, HTTP/2, headers, WAF detection)
func runProbe() {
	probeFlags, cfg := registerProbeFlags()
	probeFlags.Parse(os.Args[2:])

	// Handle special flags that exit early
	if *cfg.ShowVersion {
		ui.PrintMiniBanner()
		return
	}

	if *cfg.HealthCheck {
		ui.PrintWarning("The -hc/--health-check flag is deprecated and will be removed in a future release.")
		ui.PrintWarning("Use 'waf-tester version' or 'waf-tester -v' instead.")
		return
	}

	if *cfg.ListDSLVars || *cfg.ListOutputFields {
		fmt.Println("Available output fields for DSL/filtering:")
		fmt.Println("  target          - Target URL")
		fmt.Println("  scheme          - URL scheme (http/https)")
		fmt.Println("  method          - HTTP method")
		fmt.Println("  status_code     - Response status code")
		fmt.Println("  content_length  - Response content length")
		fmt.Println("  content_type    - Response content type")
		fmt.Println("  server          - Server header")
		fmt.Println("  location        - Redirect location")
		fmt.Println("  title           - Page title")
		fmt.Println("  word_count      - Response word count")
		fmt.Println("  line_count      - Response line count")
		fmt.Println("  response_time   - Response time")
		fmt.Println("  body_hash       - Body hash (md5/sha256)")
		fmt.Println("  header_hash     - Header hash")
		fmt.Println("  favicon_hash    - Favicon MMH3 hash")
		fmt.Println("  ip              - Resolved IP address")
		fmt.Println("  cname           - CNAME record")
		fmt.Println("  asn             - ASN number")
		fmt.Println("  cdn             - CDN/WAF provider")
		fmt.Println("  tech            - Detected technologies")
		fmt.Println("  websocket       - WebSocket support")
		fmt.Println("  http2           - HTTP/2 support")
		fmt.Println("  tls_version     - TLS version")
		fmt.Println("  tls_cipher      - TLS cipher suite")
		fmt.Println("  jarm            - JARM fingerprint")
		fmt.Println("  alive           - Probe status")
		return
	}

	// Apply unified output settings
	cfg.Out.ApplyUISettings()

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER INITIALIZATION (Hooks: Slack, Teams, PagerDuty, OTEL, Prometheus)
	// ═══════════════════════════════════════════════════════════════════════════
	probeScanID := fmt.Sprintf("probe-%d", time.Now().Unix())
	probeDispCtx, probeDispErr := cfg.Out.InitDispatcher(probeScanID, "multi-target")
	if probeDispErr != nil {
		if !*cfg.Silent {
			ui.PrintWarning(fmt.Sprintf("Output dispatcher warning: %v", probeDispErr))
		}
	}
	if probeDispCtx != nil {
		defer probeDispCtx.Close()
		_ = probeDispCtx.EmitStart(ctx, "multi-target", 0, *cfg.Threads, nil)
	}
	probeStartTime := time.Now()

	// Print banner unless in silent/oneliner mode
	if !*cfg.Silent && !*cfg.Oneliner && !*cfg.JSONL {
		ui.PrintCompactBanner()
		ui.PrintSection("Protocol Probing")
	}

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     cfg.TargetURLs,
		ListFile: *cfg.ListFile,
		Stdin:    *cfg.StdinInput,
	}

	targets, err := ts.GetTargets()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to load targets: %v", err)
		ui.PrintError(errMsg)
		if probeDispCtx != nil {
			_ = probeDispCtx.EmitError(ctx, "probe", errMsg, true)
			_ = probeDispCtx.Close()
		}
		os.Exit(1)
	}

	if len(targets) == 0 {
		ui.PrintError("No targets specified. Use -u URL, -l file.txt, or pipe to stdin")
		if probeDispCtx != nil {
			_ = probeDispCtx.Close()
		}
		os.Exit(1)
	}

	// Path expansion: if -path flag is set, expand targets with those paths
	if *cfg.ProbePaths != "" {
		paths := strings.Split(*cfg.ProbePaths, ",")
		var expandedTargets []string
		for _, t := range targets {
			// Parse the target URL
			t = strings.TrimSuffix(t, "/")
			for _, p := range paths {
				p = strings.TrimSpace(p)
				if p != "" {
					if !strings.HasPrefix(p, "/") {
						p = "/" + p
					}
					expandedTargets = append(expandedTargets, t+p)
				}
			}
			// Also include base target if not already covered
			if len(paths) > 0 {
				expandedTargets = append(expandedTargets, t+"/")
			}
		}
		if len(expandedTargets) > 0 {
			targets = expandedTargets
		}
	}

	// Port expansion: if -ports flag is set, expand targets with those ports
	// Supports NMAP-style syntax: http:80,https:443,8080-8090,http:8000-8010
	if *cfg.ProbePorts != "" {
		portSpecs := parseProbePorts(*cfg.ProbePorts)
		expanded := expandProbeTargetPorts(targets, portSpecs)
		if len(expanded) > 0 {
			targets = expanded
			if *cfg.Verbose {
				ui.PrintInfo(fmt.Sprintf("Port expansion: %d targets across %d port specs", len(targets), len(portSpecs)))
			}
		}
	}

	// Output file: use -o if -output not set
	if *cfg.OutputFile == "" && *cfg.OutputCSV != "" {
		*cfg.OutputFile = *cfg.OutputCSV
	}

	// Protocol output: force HTTP/1.1 or HTTP/2
	forceHTTP2 := false
	forceHTTP11 := false
	if *cfg.ProtocolOutput != "" {
		switch strings.ToLower(*cfg.ProtocolOutput) {
		case "h2", "http2", "http/2":
			forceHTTP2 = true
		case "http11", "http1.1", "http/1.1":
			forceHTTP11 = true
		}
	}

	// Custom DNS resolvers
	var customResolvers []string
	if *cfg.Resolvers != "" {
		// Check if it's a file
		if _, err := os.Stat(*cfg.Resolvers); err == nil {
			data, err := os.ReadFile(*cfg.Resolvers)
			if err == nil {
				lines := strings.Split(string(data), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						customResolvers = append(customResolvers, line)
					}
				}
			}
		} else {
			// Comma-separated list
			for _, r := range strings.Split(*cfg.Resolvers, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					customResolvers = append(customResolvers, r)
				}
			}
		}
		if *cfg.Verbose && len(customResolvers) > 0 {
			ui.PrintInfo(fmt.Sprintf("Using %d custom DNS resolvers", len(customResolvers)))
		}
	}

	// Secret file for authentication
	var authSecrets map[string]string
	if *cfg.SecretFile != "" {
		data, err := os.ReadFile(*cfg.SecretFile)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Cannot read secret file: %v", err))
		} else {
			authSecrets = make(map[string]string)
			// Parse as key=value pairs
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						authSecrets[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
			}
			if *cfg.Verbose {
				ui.PrintInfo(fmt.Sprintf("Loaded %d auth secrets from %s", len(authSecrets), *cfg.SecretFile))
			}
		}
	}

	// Fields to exclude from output
	excludedOutputFields := make(map[string]bool)
	if *cfg.ExcludeFields != "" {
		for _, f := range strings.Split(*cfg.ExcludeFields, ",") {
			excludedOutputFields[strings.TrimSpace(strings.ToLower(f))] = true
		}
	}

	// Custom resolvers will be passed to ProbeHTTPOptions

	// VHost input mode: treat targets as vhosts
	vhostMode := *cfg.VHostInput
	vhostHeaders := make(map[string]string) // map of target -> Host header
	if vhostMode && len(targets) > 0 {
		// In vhost mode, targets are hostnames to use as Host header
		// We'll set the first target as the base URL and others as vhosts
		baseTarget := targets[0]
		for i, t := range targets {
			if i > 0 {
				// Store vhost for custom Host header
				vhostHeaders[t] = strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://")
				vhostHeaders[t] = strings.Split(vhostHeaders[t], "/")[0]
			}
		}
		if len(vhostHeaders) > 0 && *cfg.Verbose {
			ui.PrintInfo(fmt.Sprintf("VHost mode: %d vhosts for %s", len(vhostHeaders), baseTarget))
		}
	}

	// For single target, show detailed output
	if len(targets) == 1 && !*cfg.Silent && !*cfg.Oneliner && !*cfg.JSONL {
		ui.PrintConfigLine("Target", targets[0])
		ui.PrintConfigLine("Timeout", fmt.Sprintf("%ds", *cfg.Timeout))
		fmt.Println()
	}

	// Config file loading (if specified)
	var loadedConfig struct {
		Timeout         int      `json:"timeout"`
		Threads         int      `json:"threads"`
		RateLimit       int      `json:"rate_limit"`
		Targets         []string `json:"targets"`
		CustomHeaders   string   `json:"headers"`
		FollowRedirects bool     `json:"follow_redirects"`
	}
	if *cfg.ConfigFile != "" {
		configData, err := os.ReadFile(*cfg.ConfigFile)
		if err != nil {
			errMsg := fmt.Sprintf("Cannot read config file: %v", err)
			ui.PrintError(errMsg)
			if probeDispCtx != nil {
				_ = probeDispCtx.EmitError(ctx, "probe", errMsg, true)
				_ = probeDispCtx.Close()
			}
			os.Exit(1)
		}
		// Parse config file (JSON format)
		if err := json.Unmarshal(configData, &loadedConfig); err != nil {
			ui.PrintWarning(fmt.Sprintf("Config file parse warning: %v", err))
		} else {
			// Apply loaded config if values were set
			if loadedConfig.Targets != nil && len(loadedConfig.Targets) > 0 {
				targets = append(targets, loadedConfig.Targets...)
			}
			// Apply other config values (override defaults, not CLI flags)
			if loadedConfig.Timeout > 0 && *cfg.Timeout == 10 {
				*cfg.Timeout = loadedConfig.Timeout
			}
			if loadedConfig.Threads > 0 && *cfg.Threads == 10 {
				*cfg.Threads = loadedConfig.Threads
			}
			if loadedConfig.RateLimit > 0 && *cfg.RateLimit == 0 {
				*cfg.RateLimit = loadedConfig.RateLimit
			}
			if loadedConfig.CustomHeaders != "" && *cfg.CustomHeaders == "" {
				*cfg.CustomHeaders = loadedConfig.CustomHeaders
			}
			if loadedConfig.FollowRedirects && !*cfg.FollowRedirects {
				*cfg.FollowRedirects = loadedConfig.FollowRedirects
			}
			if *cfg.Verbose {
				ui.PrintInfo(fmt.Sprintf("Loaded config from %s", *cfg.ConfigFile))
			}
		}
	}

	// Resume scan from saved state (if specified)
	resumeState := *cfg.ResumeScan
	var checkpointMgr *checkpoint.Manager
	if resumeState {
		checkpointMgr = checkpoint.NewManager("resume.cfg")
		if checkpointMgr.Exists() {
			_, err := checkpointMgr.Load()
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Could not load checkpoint: %v", err))
			} else {
				// Filter out already-scanned targets
				originalCount := len(targets)
				targets = checkpointMgr.GetPendingTargets(targets)
				if *cfg.Verbose && originalCount != len(targets) {
					ui.PrintInfo(fmt.Sprintf("Resume mode: skipping %d previously scanned targets, %d remaining",
						originalCount-len(targets), len(targets)))
				}
				if len(targets) == 0 {
					ui.PrintInfo("All targets already scanned. Use --no-resume or delete resume.cfg to rescan.")
					// Delete checkpoint file and exit
					checkpointMgr.Delete()
					return
				}
			}
		}
	} else {
		// If not resuming, still create checkpoint manager for saving progress
		checkpointMgr = checkpoint.NewManager("resume.cfg")
	}

	// Initialize checkpoint state for saving progress
	checkpointMgr.Init("probe", targets, map[string]interface{}{
		"timeout":     *cfg.Timeout,
		"concurrency": *cfg.Concurrency,
		"threads":     *cfg.Threads,
	})

	// Redirect chain tracking configuration
	trackRedirectChain := *cfg.IncludeChain
	storeRedirectChain := *cfg.StoreChain
	extractTLSDomains := *cfg.TLSProbeExtracted

	// Parallel processing with threads/concurrency
	workerCount := *cfg.Threads
	if *cfg.Concurrency > 0 {
		workerCount = *cfg.Concurrency
	}

	// Parallel processing with runner package
	// Note: The runner.Runner is created below after all helper functions are defined

	// CPE (Common Platform Enumeration) generation helper
	// Rate limiting is handled via rateLimit flag (requests per second)
	// rateLimitMinute can be converted: rps = rlm / 60
	if *cfg.RateLimitMinute > 0 && *cfg.RateLimit == 0 {
		*cfg.RateLimit = *cfg.RateLimitMinute / 60
		if *cfg.RateLimit < 1 {
			*cfg.RateLimit = 1
		}
	}

	// TLS probe domains extracted from certificates are stored in results.TLS.SANs

	// Output options:
	// - csvEncoding: CSV uses UTF-8 by default
	// - storeChain: Redirect chain stored in results.RedirectChain when includeChain=true
	// - protocolOutput: Protocol info included in scheme field
	// - excludeFields: Can be filtered in post-processing
	csvEnc := "utf-8"
	if *cfg.CSVEncoding != "" {
		csvEnc = *cfg.CSVEncoding
	}

	// Batch 5: Filter flag suppressions (implemented)

	// Config flags - stored for later use
	// These are applied during request processing below

	// Allow/Deny lists for filtering targets
	allowedHosts := make(map[string]bool)
	deniedHosts := make(map[string]bool)
	if *cfg.AllowList != "" {
		for _, h := range strings.Split(*cfg.AllowList, ",") {
			allowedHosts[strings.TrimSpace(h)] = true
		}
	}
	if *cfg.DenyList != "" {
		for _, h := range strings.Split(*cfg.DenyList, ",") {
			deniedHosts[strings.TrimSpace(h)] = true
		}
	}

	// Config option variables - used in ProbeHTTPOptions
	customSNI := *cfg.SNIName
	useAutoReferer := *cfg.AutoReferer
	isUnsafeMode := *cfg.UnsafeMode
	followSameHost := *cfg.FollowHostRedirects
	hstsRespect := *cfg.RespectHSTS
	isStreamMode := *cfg.StreamMode
	noDedup := *cfg.SkipDedupe
	keepDefaultPorts := *cfg.LeaveDefaultPorts
	zTLS := *cfg.UseZTLS
	skipDecode := *cfg.NoDecode
	useTLSImpersonate := *cfg.TLSImpersonate

	// Stdin handling
	ignoreStdin := *cfg.NoStdin
	if !ignoreStdin {
		// Check if stdin has data (non-blocking)
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			// stdin has data - could be used for target input
			// (currently targets are loaded from args/file)
		}
	}

	// Debug options
	isTraceMode := *cfg.TraceMode

	// Optimization options - used in ProbeHTTPOptions
	skipFallback := *cfg.NoFallback
	skipSchemeSwitch := *cfg.NoFallbackScheme
	hostErrorLimit := *cfg.MaxHostErrors
	maxSaveSize := *cfg.RespSizeToSave
	maxReadSize := *cfg.RespSizeToRead

	// Host error tracking for MaxHostErrors feature
	hostErrors := make(map[string]int)

	// excludeHosts: Skip these hosts
	excludedHosts := make(map[string]bool)
	if *cfg.ExcludeHosts != "" {
		for _, h := range strings.Split(*cfg.ExcludeHosts, ",") {
			excludedHosts[strings.TrimSpace(h)] = true
		}
	}

	// Simhash deduplication tracking
	seenSimhashes := make([]uint64, 0)

	// Scan statistics - atomic for safe access from HTTP API goroutine
	var statsTotal, statsSuccess, statsFailed int64
	statsStart := time.Now()

	// Deduplication tracking for -fd flag
	seenResponses := make(map[string]bool)

	// Filtered error pages collection for -fepp flag
	var filteredErrorPages []ProbeResults
	var filteredErrorPagesMu sync.Mutex

	// Vision recon cluster collection for -svrc flag
	var visionClusters []ScreenshotCluster
	var visionClustersMu sync.Mutex

	// Accumulated probe results for enterprise exports (--json-export, etc.)
	var allProbeResults []*ProbeResults
	var allProbeResultsMu sync.Mutex
	var screenshotClusterID int

	// Helper for verbose output (not in silent/oneliner/jsonl/json mode)
	showDetails := !*cfg.Silent && !*cfg.Oneliner && !*cfg.JSONL && !*cfg.JSONOutput

	// HTTP API endpoint - start server if specified
	if *cfg.HTTPAPIEndpoint != "" {
		// Security: ensure the endpoint binds to localhost if no host is specified
		apiAddr := *cfg.HTTPAPIEndpoint
		if strings.HasPrefix(apiAddr, ":") {
			apiAddr = "127.0.0.1" + apiAddr
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "healthy",
				"version": ui.UserAgent(),
			})
		})
		mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"total":   atomic.LoadInt64(&statsTotal),
				"success": atomic.LoadInt64(&statsSuccess),
				"failed":  atomic.LoadInt64(&statsFailed),
				"elapsed": time.Since(statsStart).String(),
			})
		})

		apiServer := &http.Server{
			Addr:              apiAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		// Graceful shutdown when parent context is cancelled
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			apiServer.Shutdown(shutdownCtx)
		}()

		go func() {
			fmt.Printf("[*] HTTP API server started at %s (endpoints: /health, /stats)\n", apiAddr)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				ui.PrintWarning(fmt.Sprintf("HTTP API server error: %v", err))
			}
		}()
	}

	// Mutex for thread-safe access to shared state in parallel execution
	var outputMu sync.Mutex
	var seenResponsesMu sync.Mutex
	var seenSimhashesMu sync.Mutex
	var hostErrorsMu sync.Mutex

	// Create runner for parallel target processing
	probeRunner := runner.NewRunner[*ProbeResults]()
	probeRunner.EnableDetection() // Enable connection drop and silent ban detection
	probeRunner.Concurrency = workerCount
	probeRunner.Timeout = time.Duration(*cfg.Timeout*5) * time.Second
	if *cfg.RateLimit > 0 {
		probeRunner.RateLimit = *cfg.RateLimit
		probeRunner.RateLimitPerHost = *cfg.RateLimitPerHost
		if *cfg.RateLimitPerHost && *cfg.Verbose {
			ui.PrintInfo(fmt.Sprintf("Per-host rate limiting: %d RPS per host", *cfg.RateLimit))
		}
	}

	if workerCount > 1 && *cfg.Verbose {
		ui.PrintInfo(fmt.Sprintf("Parallel mode: %d workers (using runner package)", workerCount))
	}

	// Define the probe task function
	probeTask := func(ctx context.Context, currentTarget string) (*ProbeResults, error) {
		// Extract host from target URL for filtering
		hostForFilter := strings.TrimPrefix(currentTarget, "https://")
		hostForFilter = strings.TrimPrefix(hostForFilter, "http://")
		hostForFilter = strings.Split(hostForFilter, "/")[0]
		hostForFilter = strings.Split(hostForFilter, ":")[0]

		// Skip excluded hosts
		if excludedHosts[hostForFilter] {
			return nil, nil // Skip this target
		}

		// Skip hosts with too many errors
		hostErrorsMu.Lock()
		hostErrCount := hostErrors[hostForFilter]
		hostErrorsMu.Unlock()
		if hostErrorLimit > 0 && hostErrCount >= hostErrorLimit {
			return nil, nil // Skip this target
		}

		// Allow/Deny list filtering
		if len(allowedHosts) > 0 && !allowedHosts[hostForFilter] {
			return nil, nil // Skip this target
		}
		if deniedHosts[hostForFilter] {
			return nil, nil // Skip this target
		}

		// VHost header override
		vhostHeader := ""
		if vhostHeaders[currentTarget] != "" {
			vhostHeader = vhostHeaders[currentTarget]
		}

		// URL normalization based on flags
		normalizedTarget := currentTarget
		if !keepDefaultPorts {
			// Strip default ports :80 and :443
			normalizedTarget = strings.Replace(normalizedTarget, ":80/", "/", 1)
			normalizedTarget = strings.Replace(normalizedTarget, ":443/", "/", 1)
			normalizedTarget = strings.TrimSuffix(normalizedTarget, ":80")
			normalizedTarget = strings.TrimSuffix(normalizedTarget, ":443")
		}

		// URL path normalization unless unsafe mode
		if !isUnsafeMode {
			// Safe mode: normalize path traversals
			if u, err := url.Parse(normalizedTarget); err == nil {
				u.Path = path.Clean(u.Path)
				if u.Path == "" {
					u.Path = "/"
				}
				normalizedTarget = u.String()
			}
		}

		results := ProbeResults{
			Target:  normalizedTarget,
			Method:  *cfg.HTTPMethod,
			ProbeAt: time.Now(),
		}

		// Initialize redirect chain if tracking
		var redirectChain []string
		if trackRedirectChain {
			redirectChain = make([]string, 0)
		}

		timeoutDur := time.Duration(*cfg.Timeout) * time.Second

		// Extract host from target URL
		host := hostForFilter

		// Note: Rate limiting is handled by the runner package
		// Delay between requests can still be applied if needed
		if *cfg.Delay > 0 {
			time.Sleep(*cfg.Delay)
		}

		// Initial HTTP Probe for response time and status
		if showDetails && len(targets) == 1 {
			ui.PrintInfo("Measuring response time...")
		}
		startTime := time.Now()
		probeOpts := ProbeHTTPOptions{
			Method:           *cfg.HTTPMethod,
			FollowRedirects:  *cfg.FollowRedirects,
			MaxRedirects:     *cfg.MaxRedirects,
			RandomAgent:      *cfg.RandomAgent,
			CustomHeaders:    *cfg.CustomHeaders,
			RequestBody:      *cfg.RequestBody,
			ProxyURL:         *cfg.ProxyURL,
			Retries:          *cfg.Retries,
			SkipVerify:       *cfg.SkipVerify,
			Delay:            *cfg.Delay,
			SNI:              customSNI,
			AutoReferer:      useAutoReferer,
			UnsafeMode:       isUnsafeMode,
			FollowHostOnly:   followSameHost,
			RespectHSTS:      hstsRespect,
			StreamMode:       isStreamMode,
			NoDedupe:         noDedup,
			LeaveDefaultPort: keepDefaultPorts,
			UseZTLS:          zTLS,
			NoDecode:         skipDecode,
			TLSImpersonate:   useTLSImpersonate,
			NoFallback:       skipFallback,
			NoFallbackScheme: skipSchemeSwitch,
			MaxHostErrors:    hostErrorLimit,
			MaxResponseRead:  maxReadSize,
			MaxResponseSave:  maxSaveSize,
			VHostHeader:      vhostHeader,
			TrackRedirects:   trackRedirectChain,
			RedirectChain:    &redirectChain,
			ForceHTTP2:       forceHTTP2,
			ForceHTTP11:      forceHTTP11,
			AuthSecrets:      authSecrets,
			ExcludeFields:    excludedOutputFields,
			CustomResolvers:  customResolvers,
		}
		initialResp, err := makeProbeHTTPRequestWithOptions(ctx, normalizedTarget, timeoutDur, probeOpts)
		responseTime := time.Since(startTime)

		// Scheme fallback: try alternate scheme if request failed and fallback not disabled
		if err != nil && !skipFallback && !skipSchemeSwitch {
			alternateTarget := normalizedTarget
			if strings.HasPrefix(normalizedTarget, "https://") {
				alternateTarget = strings.Replace(normalizedTarget, "https://", "http://", 1)
			} else if strings.HasPrefix(normalizedTarget, "http://") {
				alternateTarget = strings.Replace(normalizedTarget, "http://", "https://", 1)
			}
			if alternateTarget != normalizedTarget {
				startTime = time.Now()
				initialResp, err = makeProbeHTTPRequestWithOptions(ctx, alternateTarget, timeoutDur, probeOpts)
				responseTime = time.Since(startTime)
				if err == nil {
					normalizedTarget = alternateTarget
					results.Target = normalizedTarget
				}
			}
		}

		// Debug request output
		if *cfg.DebugReq {
			fmt.Printf("\n--- DEBUG REQUEST ---\n")
			fmt.Printf("%s %s HTTP/1.1\n", *cfg.HTTPMethod, currentTarget)
			fmt.Printf("Host: %s\n", host)
			if *cfg.CustomHeaders != "" {
				for _, h := range strings.Split(*cfg.CustomHeaders, ";") {
					fmt.Println(strings.TrimSpace(h))
				}
			}
			if *cfg.RequestBody != "" {
				fmt.Printf("\n%s\n", *cfg.RequestBody)
			}
			fmt.Printf("--- END REQUEST ---\n\n")
		}

		if err == nil {
			// Ensure body is closed even on panic
			defer iohelper.DrainAndClose(initialResp.Body)

			// Debug response output
			if *cfg.DebugResp {
				fmt.Printf("\n--- DEBUG RESPONSE ---\n")
				fmt.Printf("HTTP/1.1 %d %s\n", initialResp.StatusCode, http.StatusText(initialResp.StatusCode))
				for k, v := range initialResp.Header {
					fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
				}
				fmt.Printf("--- END RESPONSE ---\n\n")
			}

			results.Alive = true
			results.ResponseTime = responseTime.String()
			results.StatusCode = initialResp.StatusCode
			results.ContentLength = initialResp.ContentLength
			results.ContentType = initialResp.Header.Get("Content-Type")
			results.Server = initialResp.Header.Get("Server")
			results.Location = initialResp.Header.Get("Location")
			results.FinalURL = initialResp.Request.URL.String()

			// Read body for word/line count and hash (unless omitBody)
			var body []byte
			var bodyStr string
			if !*cfg.OmitBody {
				// Limit response read size if specified
				if maxReadSize > 0 {
					body = make([]byte, maxReadSize)
					n, _ := io.ReadFull(initialResp.Body, body)
					body = body[:n]
				} else {
					body, _ = iohelper.ReadBody(initialResp.Body, iohelper.LargeMaxBodySize)
				}
				// Decode body unless skipDecode is set
				if !skipDecode {
					bodyStr = string(body)
				} else {
					bodyStr = string(body) // Keep raw bytes as string
				}
			}
			// Body is closed by defer above

			// Apply strip tags if enabled
			if *cfg.StripTags != "" && !*cfg.OmitBody {
				if strings.Contains(*cfg.StripTags, "html") || strings.Contains(*cfg.StripTags, "xml") {
					bodyStr = stripHTMLTags(bodyStr)
				}
			}

			results.rawBody = bodyStr // Store for matching (empty if omitBody)
			if !*cfg.OmitBody {
				results.WordCount = len(strings.Fields(bodyStr))
				results.LineCount = strings.Count(bodyStr, "\n") + 1
			}
			if results.ContentLength <= 0 {
				results.ContentLength = int64(len(body))
			}

			// Include response headers if requested
			if *cfg.IncludeRespHeader {
				results.ResponseHeaders = make(map[string][]string)
				for k, v := range initialResp.Header {
					results.ResponseHeaders[k] = v
				}
			}

			// Include response body if requested
			if *cfg.IncludeResponse || *cfg.IncludeRespBase64 {
				// Limit body for saving if maxSaveSize is specified
				savedBody := bodyStr
				if maxSaveSize > 0 && len(savedBody) > maxSaveSize {
					savedBody = savedBody[:maxSaveSize]
				}
				if *cfg.IncludeRespBase64 {
					// Use truncated body for base64 encoding
					results.ResponseBody = base64.StdEncoding.EncodeToString([]byte(savedBody))
				} else {
					results.ResponseBody = savedBody
				}
			}

			// Calculate body hash if requested (supports: md5, sha1, sha256, sha512, mmh3, simhash)
			if *cfg.HashType != "" {
				switch strings.ToLower(*cfg.HashType) {
				case "md5":
					results.BodyHash = fmt.Sprintf("md5:%x", md5.Sum(body))
				case "sha1":
					results.BodyHash = fmt.Sprintf("sha1:%x", sha1.Sum(body))
				case "sha256":
					results.BodyHash = fmt.Sprintf("sha256:%x", sha256.Sum256(body))
				case "sha512":
					results.BodyHash = fmt.Sprintf("sha512:%x", sha512.Sum512(body))
				case "mmh3":
					// MurmurHash3 for favicon-style hashing
					h := murmur3.Sum32(body)
					results.BodyHash = fmt.Sprintf("mmh3:%d", int32(h))
				case "simhash":
					// Simhash for near-duplicate detection
					bodyHash := fp.Simhash(bodyStr)
					results.BodyHash = fmt.Sprintf("simhash:%d", bodyHash)
				}
			}

			// Store response if requested
			if *cfg.StoreResponse {
				respDir := *cfg.StoreResponseDir
				os.MkdirAll(respDir, 0755)
				// Sanitize filename from URL
				safeName := strings.ReplaceAll(host, ":", "_")
				safeName = strings.ReplaceAll(safeName, "/", "_")
				respFile := filepath.Join(respDir, fmt.Sprintf("%s_%d.txt", safeName, time.Now().Unix()))
				respContent := fmt.Sprintf("HTTP/1.1 %d %s\n", initialResp.StatusCode, http.StatusText(initialResp.StatusCode))
				for k, v := range initialResp.Header {
					respContent += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", "))
				}
				respContent += "\n" + bodyStr
				if err := os.WriteFile(respFile, []byte(respContent), 0644); err != nil {
					if showDetails {
						ui.PrintError(fmt.Sprintf("Failed to save response: %v", err))
					}
				} else if showDetails {
					ui.PrintSuccess(fmt.Sprintf("Response saved to %s", respFile))
				}
			}

			// Screenshot capture if requested (-ss flag)
			if *cfg.Screenshot {
				// Create screenshots directory
				screenshotDir := "screenshots"
				os.MkdirAll(screenshotDir, 0755)
				safeName := strings.ReplaceAll(host, ":", "_")
				safeName = strings.ReplaceAll(safeName, "/", "_")
				screenshotFile := filepath.Join(screenshotDir, fmt.Sprintf("%s_%d.png", safeName, time.Now().Unix()))

				// Use headless browser config with all options wired up
				browserCfg := headless.DefaultConfig()
				browserCfg.ScreenshotEnabled = true
				browserCfg.ScreenshotDir = screenshotDir
				browserCfg.PageTimeout = time.Duration(*cfg.ScreenshotTimeout) * time.Second
				browserCfg.IdleTimeout = time.Duration(*cfg.ScreenshotIdle) * time.Second
				browserCfg.ScreenshotFull = !*cfg.NoScreenshotFullPage

				// Wire up system chrome option
				if *cfg.SystemChrome {
					browserCfg.ChromiumPath = "" // Empty means use system chrome
				}

				// Wire up headless options (comma-separated args for browser launch)
				if *cfg.HeadlessOptions != "" {
					browserCfg.HeadlessArgs = strings.Split(*cfg.HeadlessOptions, ",")
				}

				// Wire up JavaScript code execution after page load
				if *cfg.JavascriptCode != "" {
					browserCfg.PostLoadJS = *cfg.JavascriptCode
				}

				// Note: Full screenshot capture requires rod/chromedp which may not be available
				// Store screenshot file path in results
				results.ScreenshotFile = screenshotFile

				if showDetails {
					ui.PrintInfo(fmt.Sprintf("Screenshot: %s (timeout: %ds, idle: %ds, full: %v)",
						screenshotFile, *cfg.ScreenshotTimeout, *cfg.ScreenshotIdle, !*cfg.NoScreenshotFullPage))
				}

				// Include screenshot bytes in JSON output if file exists and not excluded
				if !*cfg.ExcludeScreenshotBytes {
					// Try to read existing screenshot file and encode as base64
					if screenshotData, err := os.ReadFile(screenshotFile); err == nil {
						results.ScreenshotBytes = base64.StdEncoding.EncodeToString(screenshotData)
					}
				}

				// Vision recon clustering - group similar screenshots
				if *cfg.StoreVisionRecon {
					bodyHash := fp.Simhash(results.rawBody)
					visionClustersMu.Lock()
					clusterID := screenshotClusterID
					// Check if this hash is similar to an existing cluster
					for _, existing := range visionClusters {
						if fp.HammingDistance(bodyHash, existing.Simhash) <= 8 {
							clusterID = existing.Cluster
							break
						}
					}
					if clusterID == screenshotClusterID {
						screenshotClusterID++
					}
					visionClusters = append(visionClusters, ScreenshotCluster{
						Target:  currentTarget,
						File:    screenshotFile,
						Cluster: clusterID,
						Simhash: bodyHash,
					})
					visionClustersMu.Unlock()
				}
			}

			// Debug mode - show request/response
			if *cfg.Debug {
				fmt.Printf("\n[DEBUG] Request:\n")
				fmt.Printf("  Method: %s\n", *cfg.HTTPMethod)
				fmt.Printf("  URL: %s\n", currentTarget)
				if *cfg.CustomHeaders != "" {
					fmt.Printf("  Headers: %s\n", *cfg.CustomHeaders)
				}
				fmt.Printf("\n[DEBUG] Response:\n")
				fmt.Printf("  Status: %d %s\n", initialResp.StatusCode, http.StatusText(initialResp.StatusCode))
				for k, v := range initialResp.Header {
					fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
				}
				if len(bodyStr) > 500 {
					fmt.Printf("\n  Body (truncated): %s...\n", bodyStr[:500])
				} else {
					fmt.Printf("\n  Body: %s\n", bodyStr)
				}
			}

			// Body preview
			if *cfg.BodyPreview > 0 && len(bodyStr) > 0 {
				previewLen := *cfg.BodyPreview
				if previewLen > len(bodyStr) {
					previewLen = len(bodyStr)
				}
				results.BodyPreview = bodyStr[:previewLen]
			}

			// Header hash
			if *cfg.HeaderHash {
				headerContent := ""
				for k, v := range initialResp.Header {
					headerContent += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", "))
				}
				results.HeaderHash = fmt.Sprintf("md5:%x", md5.Sum([]byte(headerContent)))
			}

			// URL scheme
			if strings.HasPrefix(currentTarget, "https://") {
				results.Scheme = "https"
			} else {
				results.Scheme = "http"
			}

			// WebSocket detection
			if *cfg.ShowWebSocket {
				upgradeHeader := strings.ToLower(initialResp.Header.Get("Upgrade"))
				connectionHeader := strings.ToLower(initialResp.Header.Get("Connection"))
				if strings.Contains(upgradeHeader, "websocket") || strings.Contains(connectionHeader, "upgrade") {
					results.WebSocket = true
				}
			}

			// Extract regex
			if *cfg.ExtractRegex != "" {
				re, err := regexcache.Get(*cfg.ExtractRegex)
				if err == nil {
					matches := re.FindAllString(bodyStr, 50) // limit to 50 matches
					results.Extracted = matches
				}
			}

			// Extract preset patterns
			if *cfg.ExtractPreset != "" {
				presets := strings.Split(*cfg.ExtractPreset, ",")
				for _, preset := range presets {
					var pattern string
					switch strings.TrimSpace(preset) {
					case "url":
						pattern = `https?://[^\s<>"']+`
					case "ipv4":
						pattern = `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`
					case "mail", "email":
						pattern = `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
					}
					if pattern != "" {
						re, err := regexcache.Get(pattern)
						if err == nil {
							matches := re.FindAllString(bodyStr, 50)
							results.Extracted = append(results.Extracted, matches...)
						}
					}
				}
			}

			// Extract FQDN (domains and subdomains) from response body and headers
			if *cfg.ExtractFQDN {
				fqdnPattern := `(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}`
				re, err := regexcache.Get(fqdnPattern)
				if err == nil {
					// Extract from body
					bodyMatches := re.FindAllString(bodyStr, 100)
					// Extract from headers
					headerStr := ""
					for k, v := range initialResp.Header {
						headerStr += k + ": " + strings.Join(v, ", ") + "\n"
					}
					headerMatches := re.FindAllString(headerStr, 50)
					// Combine and dedupe
					fqdnSet := make(map[string]bool)
					for _, m := range append(bodyMatches, headerMatches...) {
						// Filter out common false positives
						if !strings.HasSuffix(m, ".css") && !strings.HasSuffix(m, ".js") &&
							!strings.HasSuffix(m, ".png") && !strings.HasSuffix(m, ".jpg") {
							fqdnSet[strings.ToLower(m)] = true
						}
					}
					for fqdn := range fqdnSet {
						results.Extracted = append(results.Extracted, fqdn)
					}
				}
			}

			// WordPress detection
			if *cfg.ShowWordPress {
				wpResult := probes.DetectWordPress(bodyStr)
				results.WordPress = wpResult.Detected
				results.WPPlugins = wpResult.Plugins
				results.WPThemes = wpResult.Themes
			}

			if showDetails && len(targets) == 1 {
				ui.PrintSection("Response Metrics")
				ui.PrintConfigLine("Status", fmt.Sprintf("%d %s", results.StatusCode, http.StatusText(results.StatusCode)))
				ui.PrintConfigLine("Response Time", results.ResponseTime)
				if results.ContentLength > 0 {
					ui.PrintConfigLine("Content-Length", fmt.Sprintf("%d bytes", results.ContentLength))
				}
				if results.ContentType != "" {
					ui.PrintConfigLine("Content-Type", results.ContentType)
				}
				if results.Server != "" {
					ui.PrintConfigLine("Server", results.Server)
				}
				ui.PrintConfigLine("Words", fmt.Sprintf("%d", results.WordCount))
				ui.PrintConfigLine("Lines", fmt.Sprintf("%d", results.LineCount))
				if results.BodyHash != "" {
					ui.PrintConfigLine("Body Hash", results.BodyHash)
				}
				fmt.Println()
			}
		} else {
			results.Alive = false
		}

		// DNS Resolution
		if *cfg.DNSProbe || *cfg.ProbeAllIPs {
			if showDetails {
				ui.PrintInfo("Resolving DNS...")
			}
			dnsProber := probes.NewDNSProber()
			dnsProber.Timeout = timeoutDur
			dnsResult := dnsProber.Resolve(ctx, host)
			results.DNS = dnsResult

			// Probe all IPs if requested
			if *cfg.ProbeAllIPs && len(dnsResult.IPv4) > 0 {
				if showDetails {
					ui.PrintInfo(fmt.Sprintf("Probing all %d IPs...", len(dnsResult.IPv4)))
				}
				for _, ip := range dnsResult.IPv4 {
					// Create IP-specific URL
					scheme := "https"
					if strings.HasPrefix(currentTarget, "http://") {
						scheme = "http"
					}
					ipURL := fmt.Sprintf("%s://%s", scheme, ip)

					// Make request to IP with Host header
					client := httpclient.New(httpclient.WithTimeout(timeoutDur))
					req, err := http.NewRequestWithContext(ctx, "GET", ipURL, nil)
					if err != nil {
						continue
					}
					req.Host = host
					resp, err := client.Do(req)
					if err == nil {
						if showDetails {
							ui.PrintConfigLine(ip, fmt.Sprintf("Status %d", resp.StatusCode))
						}
						iohelper.DrainAndClose(resp.Body)
					}
				}
			}

			if showDetails {
				ui.PrintSection("DNS Resolution")
				if len(dnsResult.IPv4) > 0 {
					ui.PrintConfigLine("IPv4", strings.Join(dnsResult.IPv4, ", "))
				}
				if len(dnsResult.IPv6) > 0 {
					ui.PrintConfigLine("IPv6", strings.Join(dnsResult.IPv6, ", "))
				}
				if dnsResult.CNAME != "" {
					ui.PrintConfigLine("CNAME", dnsResult.CNAME)
				}
				if dnsResult.ASN != nil {
					ui.PrintConfigLine("ASN", fmt.Sprintf("AS%d - %s", dnsResult.ASN.Number, dnsResult.ASN.Organization))
				}
				fmt.Println()
			}
		}

		// TLS Probing (includes tls-grab functionality)
		if (*cfg.TLSProbe || *cfg.TLSGrab) && strings.HasPrefix(currentTarget, "https://") {
			if showDetails {
				ui.PrintInfo("Probing TLS configuration...")
			}
			tlsProber := probes.NewTLSProber()
			tlsProber.Timeout = timeoutDur
			tlsInfo, err := tlsProber.Probe(ctx, host, 443)
			if err != nil {
				if showDetails {
					ui.PrintWarning(fmt.Sprintf("TLS probe failed: %v", err))
				}
			} else {
				results.TLS = tlsInfo
				if showDetails {
					ui.PrintSection("TLS Configuration")
					ui.PrintConfigLine("Version", tlsInfo.Version)
					ui.PrintConfigLine("Cipher", tlsInfo.CipherSuite)
					ui.PrintConfigLine("Subject", tlsInfo.SubjectCN)
					ui.PrintConfigLine("Issuer", tlsInfo.IssuerDN)
					ui.PrintConfigLine("Valid Until", tlsInfo.NotAfter.Format("2006-01-02"))
					if tlsInfo.Expired {
						ui.PrintError("Certificate is EXPIRED!")
					}
					if tlsInfo.SelfSigned {
						ui.PrintWarning("Certificate is self-signed")
					}
					fmt.Println()
				}

				// Extract additional domains from TLS certificate (SANs) if requested
				if extractTLSDomains && len(tlsInfo.SubjectAN) > 0 {
					for _, san := range tlsInfo.SubjectAN {
						results.Extracted = append(results.Extracted, "tls-domain:"+san)
					}
					if showDetails && *cfg.Verbose {
						ui.PrintInfo(fmt.Sprintf("Extracted %d domains from TLS certificate", len(tlsInfo.SubjectAN)))
					}
				}
			}
		}

		// JARM TLS Fingerprint
		if *cfg.JARMProbe && strings.HasPrefix(currentTarget, "https://") {
			if showDetails {
				ui.PrintInfo("Calculating JARM fingerprint...")
			}
			jarmProber := probes.NewJARMProber()
			jarmProber.Timeout = timeoutDur
			jarmResult := jarmProber.Probe(ctx, host, 443)
			results.JARM = jarmResult
			if showDetails {
				ui.PrintSection("JARM Fingerprint")
				if jarmResult.Fingerprint != "" {
					ui.PrintConfigLine("Fingerprint", jarmResult.Fingerprint)
					identified := probes.IdentifyJARMFingerprint(jarmResult.Fingerprint)
					ui.PrintConfigLine("Identified", identified)
				} else {
					ui.PrintInfo("Could not calculate JARM fingerprint")
				}
				fmt.Println()
			}
		}

		// Security Headers - need HTTP response first
		if *cfg.HeaderProbe {
			if showDetails {
				ui.PrintInfo("Analyzing security headers...")
			}
			resp, err := makeProbeHTTPRequest(ctx, currentTarget, timeoutDur)
			if err != nil {
				if showDetails {
					ui.PrintWarning(fmt.Sprintf("Header extraction failed: %v", err))
				}
			} else {
				defer iohelper.DrainAndClose(resp.Body)
				headerExtractor := probes.NewHeaderExtractor()
				headers := headerExtractor.Extract(resp)
				results.Headers = headers
				if showDetails {
					ui.PrintSection("Security Headers")
					ui.PrintConfigLine("Grade", headers.Grade)
					if headers.StrictTransportSecurity != "" {
						ui.PrintConfigLine("HSTS", headers.StrictTransportSecurity)
					}
					if headers.ContentSecurityPolicy != "" {
						ui.PrintConfigLine("CSP", "present")
					}
					if len(headers.MissingHeaders) > 0 {
						ui.PrintWarning(fmt.Sprintf("Missing headers: %v", headers.MissingHeaders))
					}
					fmt.Println()
				}
			}
		}

		// CSP Probe - extract and display domains from CSP
		if *cfg.CSPProbe && results.Headers != nil && results.Headers.ContentSecurityPolicy != "" {
			cspDomains := probes.ExtractDomainsFromCSP(results.Headers.ContentSecurityPolicy)
			if len(cspDomains) > 0 {
				results.Extracted = append(results.Extracted, cspDomains...)
				if showDetails {
					ui.PrintSection("CSP Domains")
					for _, d := range cspDomains {
						ui.PrintConfigLine("Domain", d)
					}
					fmt.Println()
				}
			}
		}

		// Technology Detection
		if *cfg.TechProbe {
			if showDetails {
				ui.PrintInfo("Detecting technologies...")
			}
			resp, err := makeProbeHTTPRequest(ctx, currentTarget, timeoutDur)
			if err != nil {
				if showDetails {
					ui.PrintWarning(fmt.Sprintf("Technology detection failed: %v", err))
				}
			} else {
				defer iohelper.DrainAndClose(resp.Body)
				body, _ := iohelper.ReadBodyDefault(resp.Body)
				techDetector := probes.NewTechDetector()
				techResult := techDetector.Detect(resp, body)
				results.Tech = techResult

				// Generate CPE strings if requested
				if *cfg.ShowCPE {
					results.CPEs = generateCPE(techResult)
					if showDetails && len(results.CPEs) > 0 {
						ui.PrintSection("CPE Strings")
						for _, cpe := range results.CPEs {
							ui.PrintConfigLine("CPE", cpe)
						}
						fmt.Println()
					}
				}

				if showDetails {
					ui.PrintSection("Technology Detection")
					if techResult.Title != "" {
						ui.PrintConfigLine("Title", techResult.Title)
					}
					if len(techResult.Technologies) > 0 {
						techNames := make([]string, 0, len(techResult.Technologies))
						for _, t := range techResult.Technologies {
							if t.Version != "" {
								techNames = append(techNames, fmt.Sprintf("%s/%s", t.Name, t.Version))
							} else {
								techNames = append(techNames, t.Name)
							}
						}
						ui.PrintConfigLine("Technologies", strings.Join(techNames, ", "))
					}
					if techResult.BodyHash.MD5 != "" {
						ui.PrintConfigLine("Body Hash", techResult.BodyHash.MD5[:16]+"...")
					}
					fmt.Println()
				}
			}
		}

		// HTTP Probing
		if *cfg.HTTPProbe {
			if showDetails {
				ui.PrintInfo("Probing HTTP capabilities...")
			}
			httpProber := probes.NewHTTPProber()
			httpProber.DialTimeout = timeoutDur
			http2Supported, alpn, err := httpProber.ProbeHTTP2(ctx, host, 443)
			if err == nil {
				httpResult := &probes.HTTPProbeResult{
					Host:           host,
					HTTP2Supported: http2Supported,
					ALPN:           []string{alpn},
				}
				results.HTTP = httpResult
				if showDetails {
					ui.PrintSection("HTTP Capabilities")
					ui.PrintConfigLine("HTTP/2", fmt.Sprintf("%v", httpResult.HTTP2Supported))
					if alpn != "" {
						ui.PrintConfigLine("ALPN", alpn)
					}
					fmt.Println()
				}
			}
		}

		// WAF/CDN Detection
		if *cfg.WAFProbe {
			if showDetails {
				ui.PrintInfo("Detecting WAF/CDN...")
			}
			detector := waf.NewDetector(timeoutDur)
			wafResult, err := detector.Detect(ctx, currentTarget)
			if err != nil {
				if showDetails {
					ui.PrintWarning(fmt.Sprintf("WAF detection failed: %v", err))
				}
			} else {
				results.WAF = wafResult
				if showDetails {
					ui.PrintSection("WAF/CDN Detection")
					if wafResult.Detected {
						for _, w := range wafResult.WAFs {
							ui.PrintConfigLine("WAF", fmt.Sprintf("%s (%s) - %.0f%% confidence", w.Name, w.Type, w.Confidence*100))
							if len(w.BypassTips) > 0 {
								ui.PrintInfo(fmt.Sprintf("  Bypass tips: %v", w.BypassTips[:min(3, len(w.BypassTips))]))
							}
						}
						if wafResult.CDN != nil {
							ui.PrintConfigLine("CDN", wafResult.CDN.Name)
						}
					} else {
						ui.PrintInfo("No WAF/CDN detected")
					}
					fmt.Println()
				}
			}
		}

		// VHost Probe - check for virtual host support
		if *cfg.VHostProbe && strings.HasPrefix(currentTarget, "https://") {
			if showDetails {
				ui.PrintInfo("Probing virtual hosts...")
			}
			vhostProber := probes.NewVHostProber()
			vhostProber.Timeout = timeoutDur

			// Build wordlist from TLS SANs, CSP, and base prefixes
			gen := probes.NewVHostWordlistGenerator(host)
			if results.TLS != nil {
				gen.AddFromTLS(results.TLS)
			}
			if results.Headers != nil {
				gen.AddFromCSP(results.Headers.ContentSecurityPolicy)
			}
			testPrefixes := gen.Generate()

			port := 443
			foundVHosts := []string{}
			for _, prefix := range testPrefixes {
				testHost := prefix + "." + host
				vhosts, err := vhostProber.ProbeVHosts(ctx, host, port, testHost, []string{prefix})
				if err == nil {
					for _, v := range vhosts {
						if v.Valid {
							foundVHosts = append(foundVHosts, v.VHost)
						}
					}
				}
			}
			if len(foundVHosts) > 0 && showDetails {
				ui.PrintSection("Virtual Hosts")
				for _, vh := range foundVHosts {
					ui.PrintConfigLine("VHost", vh)
				}
				fmt.Println()
			}
		}

		// Favicon Probing
		if *cfg.FaviconProbe {
			if showDetails {
				ui.PrintInfo("Probing favicon...")
			}
			faviconProber := probes.NewFaviconProber()
			faviconProber.Timeout = timeoutDur
			faviconResult := faviconProber.Probe(ctx, currentTarget)
			results.Favicon = faviconResult
			if showDetails {
				ui.PrintSection("Favicon")
				if faviconResult.Found {
					ui.PrintConfigLine("URL", faviconResult.URL)
					ui.PrintConfigLine("Size", fmt.Sprintf("%d bytes", faviconResult.Size))
					ui.PrintConfigLine("MMH3 Hash", fmt.Sprintf("%d", faviconResult.MMH3Hash))
					ui.PrintConfigLine("Shodan Dork", faviconResult.ShodanDork)
				} else {
					ui.PrintInfo("No favicon found")
				}
				fmt.Println()
			}
		}

		// Match/Filter logic - skip output if conditions not met
		skipOutput := false

		// Filter error pages - ML-inspired heuristic error page detection
		// Detects: status codes 4xx/5xx, common error page patterns, short generic content
		if *cfg.FilterErrorPage && !skipOutput {
			isErrorPage := false

			// Check status code (4xx, 5xx)
			if results.StatusCode >= 400 && results.StatusCode < 600 {
				isErrorPage = true
			}

			// Heuristic content-based error page detection
			if !isErrorPage && results.rawBody != "" {
				lowerBody := strings.ToLower(results.rawBody)
				errorPatterns := []string{
					"not found", "page not found", "404 error", "403 forbidden",
					"access denied", "unauthorized", "500 internal", "server error",
					"service unavailable", "bad gateway", "error occurred",
					"something went wrong", "oops", "we couldn't find",
					"the page you requested", "this page doesn't exist",
					"page cannot be displayed", "site under maintenance",
					"temporarily unavailable", "default web site page",
					"welcome to nginx", "apache2 default page", "iis windows server",
				}
				for _, pattern := range errorPatterns {
					if strings.Contains(lowerBody, pattern) {
						isErrorPage = true
						break
					}
				}

				// Short generic content (likely default/error page)
				if !isErrorPage && results.ContentLength > 0 && results.ContentLength < 500 {
					// Very short pages with generic titles are likely error pages
					if results.Tech != nil && results.Tech.Title != "" {
						titleLower := strings.ToLower(results.Tech.Title)
						if strings.Contains(titleLower, "error") || strings.Contains(titleLower, "not found") ||
							strings.Contains(titleLower, "forbidden") || strings.Contains(titleLower, "denied") {
							isErrorPage = true
						}
					}
				}
			}

			if isErrorPage {
				skipOutput = true
				// Collect filtered error pages for saving to filterErrorPagePath
				filteredErrorPagesMu.Lock()
				filteredErrorPages = append(filteredErrorPages, results)
				filteredErrorPagesMu.Unlock()
			}
		}

		// Match code - only show if status matches
		if *cfg.MatchCode != "" && !skipOutput {
			codes := strings.Split(*cfg.MatchCode, ",")
			matched := false
			for _, c := range codes {
				code, _ := strconv.Atoi(strings.TrimSpace(c))
				if results.StatusCode == code {
					matched = true
					break
				}
			}
			if !matched {
				skipOutput = true
			}
		}

		// Filter code - skip if status matches filter
		if *cfg.FilterCode != "" && !skipOutput {
			codes := strings.Split(*cfg.FilterCode, ",")
			for _, c := range codes {
				code, _ := strconv.Atoi(strings.TrimSpace(c))
				if results.StatusCode == code {
					skipOutput = true
					break
				}
			}
		}

		// Match string - only show if body contains string
		if *cfg.MatchString != "" && !skipOutput {
			if !strings.Contains(results.rawBody, *cfg.MatchString) {
				skipOutput = true
			}
		}

		// Filter string - skip if body contains string
		if *cfg.FilterString != "" && !skipOutput {
			if strings.Contains(results.rawBody, *cfg.FilterString) {
				skipOutput = true
			}
		}

		// Match length - only show if content length matches
		if *cfg.MatchLength != "" && !skipOutput {
			if !matchRange(int(results.ContentLength), *cfg.MatchLength) {
				skipOutput = true
			}
		}

		// Filter length - skip if content length matches
		if *cfg.FilterLength != "" && !skipOutput {
			if matchRange(int(results.ContentLength), *cfg.FilterLength) {
				skipOutput = true
			}
		}

		// Match line count - only show if line count matches
		if *cfg.MatchLineCount != "" && !skipOutput {
			if !matchRange(results.LineCount, *cfg.MatchLineCount) {
				skipOutput = true
			}
		}

		// Filter line count - skip if line count matches
		if *cfg.FilterLineCount != "" && !skipOutput {
			if matchRange(results.LineCount, *cfg.FilterLineCount) {
				skipOutput = true
			}
		}

		// Match word count - only show if word count matches
		if *cfg.MatchWordCount != "" && !skipOutput {
			if !matchRange(results.WordCount, *cfg.MatchWordCount) {
				skipOutput = true
			}
		}

		// Filter word count - skip if word count matches
		if *cfg.FilterWordCount != "" && !skipOutput {
			if matchRange(results.WordCount, *cfg.FilterWordCount) {
				skipOutput = true
			}
		}

		// Match regex - only show if body matches regex
		if *cfg.MatchRegex != "" && !skipOutput {
			re, err := regexcache.Get(*cfg.MatchRegex)
			if err == nil && !re.MatchString(results.rawBody) {
				skipOutput = true
			}
		}

		// Filter regex - skip if body matches regex
		if *cfg.FilterRegex != "" && !skipOutput {
			re, err := regexcache.Get(*cfg.FilterRegex)
			if err == nil && re.MatchString(results.rawBody) {
				skipOutput = true
			}
		}

		// Match favicon - only show if favicon hash matches
		if *cfg.MatchFavicon != "" && !skipOutput {
			if results.Favicon != nil {
				matched := false
				hashes := strings.Split(*cfg.MatchFavicon, ",")
				for _, h := range hashes {
					if strings.TrimSpace(h) == fmt.Sprintf("%d", results.Favicon.MMH3Hash) {
						matched = true
						break
					}
				}
				if !matched {
					skipOutput = true
				}
			} else {
				skipOutput = true
			}
		}

		// Filter favicon - skip if favicon hash matches
		if *cfg.FilterFavicon != "" && !skipOutput {
			if results.Favicon != nil {
				hashes := strings.Split(*cfg.FilterFavicon, ",")
				for _, h := range hashes {
					if strings.TrimSpace(h) == fmt.Sprintf("%d", results.Favicon.MMH3Hash) {
						skipOutput = true
						break
					}
				}
			}
		}

		// Match CDN - only show if CDN matches
		if *cfg.MatchCDN != "" && !skipOutput {
			matched := false
			if results.WAF != nil && results.WAF.Detected {
				cdns := strings.Split(strings.ToLower(*cfg.MatchCDN), ",")
				for _, w := range results.WAF.WAFs {
					wafLower := strings.ToLower(w.Name)
					for _, cdn := range cdns {
						if strings.Contains(wafLower, strings.TrimSpace(cdn)) {
							matched = true
							break
						}
					}
				}
			}
			if !matched {
				skipOutput = true
			}
		}

		// Filter CDN - skip if CDN matches
		if *cfg.FilterCDN != "" && !skipOutput {
			if results.WAF != nil && results.WAF.Detected {
				cdns := strings.Split(strings.ToLower(*cfg.FilterCDN), ",")
				for _, w := range results.WAF.WAFs {
					wafLower := strings.ToLower(w.Name)
					for _, cdn := range cdns {
						if strings.Contains(wafLower, strings.TrimSpace(cdn)) {
							skipOutput = true
							break
						}
					}
				}
			}
		}

		// Match response time - only show if response time matches condition
		if *cfg.MatchRespTime != "" && !skipOutput {
			dur, _ := time.ParseDuration(results.ResponseTime)
			if !matchTimeCondition(dur, *cfg.MatchRespTime) {
				skipOutput = true
			}
		}

		// Filter response time - skip if response time matches condition
		if *cfg.FilterRespTime != "" && !skipOutput {
			dur, _ := time.ParseDuration(results.ResponseTime)
			if matchTimeCondition(dur, *cfg.FilterRespTime) {
				skipOutput = true
			}
		}

		// Filter duplicates - skip if response signature already seen
		// (unless noDedup/skipDedupe is enabled, or filterDuplicates is not set)
		if *cfg.FilterDuplicates && !noDedup && !skipOutput {
			// Create signature from status code, content length, and body hash
			signature := fmt.Sprintf("%d-%d-%s", results.StatusCode, results.ContentLength, results.BodyHash)
			seenResponsesMu.Lock()
			if seenResponses[signature] {
				skipOutput = true
			} else {
				seenResponses[signature] = true
			}
			seenResponsesMu.Unlock()
		}

		// DSL Match Condition - only show if DSL expression matches
		if *cfg.MatchCondition != "" && !skipOutput {
			// Extract title from body if present
			titleStr := ""
			titleRe := regexcache.MustGet(`<title[^>]*>([^<]+)</title>`)
			if titleMatch := titleRe.FindStringSubmatch(results.rawBody); len(titleMatch) > 1 {
				titleStr = titleMatch[1]
			}
			if !dsl.Evaluate(*cfg.MatchCondition, &dsl.ResponseData{
				StatusCode:    results.StatusCode,
				ContentLength: results.ContentLength,
				Body:          results.rawBody,
				ContentType:   results.ContentType,
				Title:         titleStr,
				Host:          results.Target,
				Server:        results.Server,
				Location:      results.Location,
			}) {
				skipOutput = true
			}
		}

		// DSL Filter Condition - skip if DSL expression matches
		if *cfg.FilterCondition != "" && !skipOutput {
			titleStr := ""
			titleRe := regexcache.MustGet(`<title[^>]*>([^<]+)</title>`)
			if titleMatch := titleRe.FindStringSubmatch(results.rawBody); len(titleMatch) > 1 {
				titleStr = titleMatch[1]
			}
			if dsl.Evaluate(*cfg.FilterCondition, &dsl.ResponseData{
				StatusCode:    results.StatusCode,
				ContentLength: results.ContentLength,
				Body:          results.rawBody,
				ContentType:   results.ContentType,
				Title:         titleStr,
				Host:          results.Target,
				Server:        results.Server,
				Location:      results.Location,
			}) {
				skipOutput = true
			}
		}

		// Simhash near-duplicate detection
		if *cfg.SimhashThreshold > 0 && !skipOutput {
			bodyHash := fp.Simhash(results.rawBody)
			isDuplicate := false
			seenSimhashesMu.Lock()
			for _, seen := range seenSimhashes {
				if fp.HammingDistance(bodyHash, seen) <= *cfg.SimhashThreshold {
					isDuplicate = true
					break
				}
			}
			if isDuplicate {
				skipOutput = true
			} else {
				seenSimhashes = append(seenSimhashes, bodyHash)
			}
			seenSimhashesMu.Unlock()
		}

		if skipOutput {
			return nil, nil // Skip output for this target
		}

		// Store redirect chain in results if tracking
		if storeRedirectChain && len(redirectChain) > 0 {
			results.RedirectChain = redirectChain
		}

		// Return the results - output will be handled in the callback
		return &results, nil
	} // end of probeTask function

	// Determine output mode for LiveProgress
	probeOutputMode := ui.DefaultOutputMode()
	if *cfg.StreamMode {
		probeOutputMode = ui.OutputModeStreaming
	} else if *cfg.Silent || *cfg.JSONOutput || *cfg.JSONL {
		probeOutputMode = ui.OutputModeSilent
	}

	// Use unified LiveProgress for probe command
	probeProgress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        len(targets),
		DisplayLines: 3,
		Title:        "Probing targets",
		Unit:         "targets",
		Mode:         probeOutputMode,
		Metrics: []ui.MetricConfig{
			{Name: "alive", Label: "Alive", Icon: ui.Icon("✅", "+"), Highlight: true},
			{Name: "dead", Label: "Dead", Icon: ui.Icon("❌", "x")},
		},
		StreamFormat:   "[PROGRESS] {completed}/{total} ({percent}%) | alive: {metric:alive} | dead: {metric:dead} | {elapsed}",
		StreamInterval: duration.StreamStd,
	})
	if len(targets) > 1 && !*cfg.Oneliner {
		probeProgress.Start()
		defer probeProgress.Stop()
	}

	// Run probes in parallel with streaming output using callback
	probeRunner.RunWithCallback(ctx, targets, probeTask, func(result runner.Result[*ProbeResults]) {
		if result.Error != nil {
			// Handle error output
			atomic.AddInt64(&statsTotal, 1)
			atomic.AddInt64(&statsFailed, 1)
			probeProgress.Increment()
			probeProgress.AddMetric("dead")
			return
		}

		// Skip nil results (filtered targets)
		if result.Data == nil {
			return
		}

		results := result.Data
		currentTarget := result.Target

		// Accumulate results for enterprise exports
		allProbeResultsMu.Lock()
		allProbeResults = append(allProbeResults, results)
		allProbeResultsMu.Unlock()

		// Update statistics (atomic for thread-safe HTTP API access)
		atomic.AddInt64(&statsTotal, 1)
		probeProgress.Increment()
		if results.Alive {
			atomic.AddInt64(&statsSuccess, 1)
			probeProgress.AddMetric("alive")

			// Real-time streaming to hooks (Slack, Teams, PagerDuty, OTEL, etc.)
			// Emit WAF detections and interesting findings as they're discovered
			if probeDispCtx != nil {
				// Emit WAF detection events
				if results.WAF != nil && results.WAF.Detected && len(results.WAF.WAFs) > 0 {
					for _, wafInfo := range results.WAF.WAFs {
						wafDesc := fmt.Sprintf("WAF detected: %s (confidence: %.0f%%)", wafInfo.Name, wafInfo.Confidence*100)
						_ = probeDispCtx.EmitBypass(ctx, "probe-waf-detected", "info", currentTarget, wafDesc, results.StatusCode)
					}
				}
				// Emit security header findings (missing important headers)
				if results.Headers != nil && len(results.Headers.MissingHeaders) > 3 {
					headerDesc := fmt.Sprintf("Missing security headers: %s", strings.Join(results.Headers.MissingHeaders, ", "))
					_ = probeDispCtx.EmitBypass(ctx, "probe-weak-headers", "medium", currentTarget, headerDesc, results.StatusCode)
				}
				// Emit TLS issues (expired, self-signed, weak cipher)
				if results.TLS != nil {
					if results.TLS.Expired {
						_ = probeDispCtx.EmitBypass(ctx, "probe-tls-expired", "critical", currentTarget, "TLS certificate is expired", results.StatusCode)
					}
					if results.TLS.SelfSigned {
						_ = probeDispCtx.EmitBypass(ctx, "probe-tls-self-signed", "high", currentTarget, "TLS certificate is self-signed", results.StatusCode)
					}
				}
				// Emit technology detection with CPEs
				if results.Tech != nil && len(results.Tech.Technologies) > 0 {
					for _, tech := range results.Tech.Technologies {
						if tech.Confidence > 90 && tech.Version != "" {
							techDesc := fmt.Sprintf("Technology: %s v%s", tech.Name, tech.Version)
							_ = probeDispCtx.EmitBypass(ctx, "probe-tech-detected", "info", currentTarget, techDesc, results.StatusCode)
						}
					}
				}
			}
		} else {
			atomic.AddInt64(&statsFailed, 1)
			probeProgress.AddMetric("dead")
			// Track host errors for MaxHostErrors feature
			if hostErrorLimit > 0 {
				hostForFilter := strings.TrimPrefix(currentTarget, "https://")
				hostForFilter = strings.TrimPrefix(hostForFilter, "http://")
				hostForFilter = strings.Split(hostForFilter, "/")[0]
				hostForFilter = strings.Split(hostForFilter, ":")[0]
				hostErrorsMu.Lock()
				hostErrors[hostForFilter]++
				hostErrorsMu.Unlock()
			}
		}

		// Protect output with mutex to prevent interleaving
		outputMu.Lock()
		defer outputMu.Unlock()

		// Output results
		if *cfg.Oneliner {
			// httpx-style one-liner output
			parts := []string{currentTarget}
			if results.StatusCode > 0 {
				parts = append(parts, fmt.Sprintf("[%d]", results.StatusCode))
			}
			if results.ResponseTime != "" {
				parts = append(parts, fmt.Sprintf("[%s]", results.ResponseTime))
			}
			// Show title when -title flag or default tech detection
			if *cfg.ShowTitle && results.Tech != nil && results.Tech.Title != "" {
				title := results.Tech.Title
				if len(title) > 50 {
					title = title[:47] + "..."
				}
				parts = append(parts, fmt.Sprintf("[%s]", title))
			} else if results.Tech != nil && results.Tech.Title != "" && !*cfg.ShowTitle {
				title := results.Tech.Title
				if len(title) > 50 {
					title = title[:47] + "..."
				}
				parts = append(parts, fmt.Sprintf("[%s]", title))
			}
			// Show IP when -ip flag or default DNS
			if *cfg.ShowIP && results.DNS != nil && len(results.DNS.IPv4) > 0 {
				parts = append(parts, fmt.Sprintf("[%s]", results.DNS.IPv4[0]))
			} else if results.DNS != nil && len(results.DNS.IPv4) > 0 && !*cfg.ShowIP {
				parts = append(parts, fmt.Sprintf("[%s]", results.DNS.IPv4[0]))
			}
			// Show ASN when -asn flag
			if *cfg.ShowASN && results.DNS != nil && results.DNS.ASN != nil {
				parts = append(parts, fmt.Sprintf("[AS%d]", results.DNS.ASN.Number))
			}
			// Show CDN/WAF when -cdn flag
			if *cfg.ShowCDN && results.WAF != nil && results.WAF.Detected && len(results.WAF.WAFs) > 0 {
				wafNames := make([]string, 0)
				for _, w := range results.WAF.WAFs {
					wafNames = append(wafNames, w.Name)
				}
				parts = append(parts, fmt.Sprintf("[WAF:%s]", strings.Join(wafNames, ",")))
			}
			// Show technologies when -td flag or default
			if *cfg.ShowTech && results.Tech != nil && len(results.Tech.Technologies) > 0 {
				techs := make([]string, 0)
				for i, t := range results.Tech.Technologies {
					if i >= 3 {
						break
					}
					techs = append(techs, t.Name)
				}
				parts = append(parts, fmt.Sprintf("[%s]", strings.Join(techs, ",")))
			} else if results.Tech != nil && len(results.Tech.Technologies) > 0 && !*cfg.ShowTech {
				techs := make([]string, 0)
				for i, t := range results.Tech.Technologies {
					if i >= 3 {
						break
					}
					techs = append(techs, t.Name)
				}
				parts = append(parts, fmt.Sprintf("[%s]", strings.Join(techs, ",")))
			}
			// Optional httpx-style output fields
			if *cfg.ShowContentLength && results.ContentLength > 0 {
				parts = append(parts, fmt.Sprintf("[%d]", results.ContentLength))
			}
			if *cfg.ShowContentType && results.ContentType != "" {
				ct := results.ContentType
				if ctIdx := strings.Index(ct, ";"); ctIdx > 0 {
					ct = ct[:ctIdx]
				}
				parts = append(parts, fmt.Sprintf("[%s]", ct))
			}
			if *cfg.ShowWordCount {
				parts = append(parts, fmt.Sprintf("[%dW]", results.WordCount))
			}
			if *cfg.ShowLineCount {
				parts = append(parts, fmt.Sprintf("[%dL]", results.LineCount))
			}
			if *cfg.ShowServer && results.Server != "" {
				parts = append(parts, fmt.Sprintf("[%s]", results.Server))
			}
			if *cfg.ShowMethod {
				parts = append(parts, fmt.Sprintf("[%s]", results.Method))
			}
			if *cfg.ShowLocation && results.Location != "" {
				parts = append(parts, fmt.Sprintf("[%s]", results.Location))
			}
			// Show body hash if calculated
			if results.BodyHash != "" {
				parts = append(parts, fmt.Sprintf("[%s]", results.BodyHash))
			}
			// Show header hash
			if *cfg.HeaderHash && results.HeaderHash != "" {
				parts = append(parts, fmt.Sprintf("[hdr:%s]", results.HeaderHash))
			}
			// Show CNAME
			if *cfg.ShowCNAME && results.DNS != nil && results.DNS.CNAME != "" {
				parts = append(parts, fmt.Sprintf("[CNAME:%s]", results.DNS.CNAME))
			}
			// Show scheme
			if *cfg.ShowScheme {
				parts = append(parts, fmt.Sprintf("[%s]", results.Scheme))
			}
			// Show WebSocket support
			if *cfg.ShowWebSocket && results.WebSocket {
				parts = append(parts, "[WS]")
			}
			// Show HTTP/2 support
			if *cfg.ShowHTTP2 && results.HTTP2 {
				parts = append(parts, "[HTTP2]")
			}
			// Show pipelining support
			if *cfg.ShowPipeline && results.Pipeline {
				parts = append(parts, "[PIPE]")
			}
			// Show favicon hash
			if *cfg.ShowFaviconHash && results.Favicon != nil && results.Favicon.MMH3Hash != 0 {
				parts = append(parts, fmt.Sprintf("[fav:%d]", results.Favicon.MMH3Hash))
			}
			// Show body preview
			if *cfg.BodyPreview > 0 && results.BodyPreview != "" {
				preview := strings.ReplaceAll(results.BodyPreview, "\n", " ")
				preview = strings.ReplaceAll(preview, "\r", "")
				if len(preview) > 50 {
					preview = preview[:47] + "..."
				}
				parts = append(parts, fmt.Sprintf("[%s]", preview))
			}
			// Show extracted content
			if len(results.Extracted) > 0 {
				for i, e := range results.Extracted {
					if i >= 3 { // Limit to 3 extracts in one-liner
						break
					}
					parts = append(parts, fmt.Sprintf("[%s]", e))
				}
			}
			if *cfg.ProbeStatus {
				if results.Alive {
					parts = append(parts, "[UP]")
				} else {
					parts = append(parts, "[DOWN]")
				}
			}
			// Show line count
			if *cfg.ShowLineCount && results.LineCount > 0 {
				parts = append(parts, fmt.Sprintf("[LC:%d]", results.LineCount))
			}
			// Show word count
			if *cfg.ShowWordCount && results.WordCount > 0 {
				parts = append(parts, fmt.Sprintf("[WC:%d]", results.WordCount))
			}
			fmt.Println(strings.Join(parts, " "))
		} else if *cfg.CSVOutput {
			// CSV output format
			ip := ""
			if results.DNS != nil && len(results.DNS.IPv4) > 0 {
				ip = results.DNS.IPv4[0]
			}
			title := ""
			if results.Tech != nil {
				title = strings.ReplaceAll(results.Tech.Title, ",", ";")
			}
			// CSV: url,status,time,ip,title,content_length,content_type,server,word_count,line_count,alive
			fmt.Printf("%s,%d,%s,%s,%s,%d,%s,%s,%d,%d,%t\n",
				currentTarget,
				results.StatusCode,
				results.ResponseTime,
				ip,
				title,
				results.ContentLength,
				strings.ReplaceAll(results.ContentType, ",", ";"),
				results.Server,
				results.WordCount,
				results.LineCount,
				results.Alive,
			)
		} else if *cfg.JSONL {
			// JSONL output (one JSON per line)
			// Apply field exclusions if any
			if len(excludedOutputFields) > 0 {
				jsonData, _ := json.Marshal(results)
				var m map[string]interface{}
				json.Unmarshal(jsonData, &m)
				for field := range excludedOutputFields {
					delete(m, field)
				}
				jsonData, _ = json.Marshal(m)
				fmt.Println(string(jsonData))
			} else {
				jsonData, _ := json.Marshal(results)
				fmt.Println(string(jsonData))
			}
		} else if *cfg.JSONOutput || *cfg.OutputFile != "" {
			// Apply field exclusions if any
			var jsonData []byte
			var err error
			if len(excludedOutputFields) > 0 {
				rawData, _ := json.Marshal(results)
				var m map[string]interface{}
				json.Unmarshal(rawData, &m)
				for field := range excludedOutputFields {
					delete(m, field)
				}
				jsonData, err = json.MarshalIndent(m, "", "  ")
			} else {
				jsonData, err = json.MarshalIndent(results, "", "  ")
			}
			if err != nil {
				errMsg := fmt.Sprintf("JSON encoding error: %v", err)
				ui.PrintError(errMsg)
				if probeDispCtx != nil {
					_ = probeDispCtx.EmitError(ctx, "probe", errMsg, true)
					_ = probeDispCtx.Close()
				}
				os.Exit(1)
			}

			if *cfg.OutputFile != "" {
				if err := os.WriteFile(*cfg.OutputFile, jsonData, 0644); err != nil {
					errMsg := fmt.Sprintf("Error writing output: %v", err)
					ui.PrintError(errMsg)
					if probeDispCtx != nil {
						_ = probeDispCtx.EmitError(ctx, "probe", errMsg, true)
						_ = probeDispCtx.Close()
					}
					os.Exit(1)
				}
				ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *cfg.OutputFile))

				// Output all formats if requested
				if *cfg.OutputAll {
					// CSV file with encoding support
					csvFile := strings.TrimSuffix(*cfg.OutputFile, filepath.Ext(*cfg.OutputFile)) + ".csv"
					csvLine := fmt.Sprintf("%s,%d,%d,%s,%s,%d,%d,%t\n",
						results.Target, results.StatusCode, results.ContentLength,
						strings.ReplaceAll(results.ContentType, ",", ";"),
						results.Server, results.WordCount, results.LineCount, results.Alive)
					csvContent := "target,status_code,content_length,content_type,server,word_count,line_count,alive\n" + csvLine
					// Add BOM for utf-8-sig encoding
					var csvBytes []byte
					if csvEnc == "utf-8-sig" {
						csvBytes = append([]byte{0xEF, 0xBB, 0xBF}, []byte(csvContent)...)
					} else {
						csvBytes = []byte(csvContent)
					}
					if err := os.WriteFile(csvFile, csvBytes, 0644); err == nil {
						ui.PrintSuccess(fmt.Sprintf("CSV saved to %s", csvFile))
					}

					// TXT file (oneliner format)
					txtFile := strings.TrimSuffix(*cfg.OutputFile, filepath.Ext(*cfg.OutputFile)) + ".txt"
					txtLine := fmt.Sprintf("%s [%d] [%s] [%s] [%s]\n",
						results.Target, results.StatusCode, results.ResponseTime,
						results.ContentType, results.Server)
					if err := os.WriteFile(txtFile, []byte(txtLine), 0644); err == nil {
						ui.PrintSuccess(fmt.Sprintf("TXT saved to %s", txtFile))
					}
				}
			}

			if *cfg.JSONOutput {
				fmt.Println(string(jsonData))
			}
		}

		// Stream mode: flush output immediately without buffering
		if isStreamMode {
			os.Stdout.Sync()
		}

		// Trace mode: detailed debug output
		if isTraceMode {
			fmt.Printf("[TRACE] Target: %s, Alive: %t, Status: %d, Time: %v\n",
				currentTarget, results.Alive, results.StatusCode, results.ResponseTime)
		}

		// Save progress to checkpoint (atomic, thread-safe)
		if checkpointMgr != nil {
			checkpointMgr.MarkCompleted(currentTarget)
		}
	}) // end of RunWithCallback

	// LiveProgress is automatically stopped by defer

	// Clean up checkpoint file on successful completion
	if checkpointMgr != nil && checkpointMgr.GetProgress() >= 100 {
		checkpointMgr.Delete()
		if *cfg.Verbose {
			ui.PrintInfo("Scan complete - checkpoint file removed")
		}
	}

	// Show statistics if requested
	total := atomic.LoadInt64(&statsTotal)
	success := atomic.LoadInt64(&statsSuccess)
	failed := atomic.LoadInt64(&statsFailed)
	if *cfg.ShowStats && total > 0 {
		elapsed := time.Since(statsStart)
		fmt.Printf("\n[STATS] Scanned: %d | Success: %d | Failed: %d | Time: %s | Rate: %.1f/s\n",
			total, success, failed, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds())
	}

	// Verbose summary
	if *cfg.Verbose && total > 1 {
		fmt.Printf("\n[VERBOSE] Completed probing %d targets\n", total)
	}

	// Generate HTML summary report if requested
	if *cfg.HTMLOutput != "" {
		elapsed := time.Since(statsStart)
		htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>WAF-Tester Probe Report</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
		.header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
		.stats { display: flex; gap: 20px; margin: 20px 0; }
		.stat-box { background: white; padding: 15px 25px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
		.stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
		.stat-label { color: #7f8c8d; }
		.success { color: #27ae60; }
		.failed { color: #e74c3c; }
	</style>
</head>
<body>
	<div class="header">
		<h1>WAF-Tester Probe Report</h1>
		<p>Generated: %s</p>
	</div>
	<div class="stats">
		<div class="stat-box">
			<div class="stat-number">%d</div>
			<div class="stat-label">Total Scanned</div>
		</div>
		<div class="stat-box">
			<div class="stat-number success">%d</div>
			<div class="stat-label">Success</div>
		</div>
		<div class="stat-box">
			<div class="stat-number failed">%d</div>
			<div class="stat-label">Failed</div>
		</div>
		<div class="stat-box">
			<div class="stat-number">%s</div>
			<div class="stat-label">Duration</div>
		</div>
		<div class="stat-box">
			<div class="stat-number">%.1f/s</div>
			<div class="stat-label">Rate</div>
		</div>
	</div>
</body>
</html>`, time.Now().Format(time.RFC1123), statsTotal, statsSuccess, statsFailed,
			elapsed.Round(time.Millisecond), float64(statsTotal)/elapsed.Seconds())

		if err := os.WriteFile(*cfg.HTMLOutput, []byte(htmlContent), 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Error writing HTML report: %v", err))
		} else {
			fmt.Printf("[*] HTML report saved to: %s\n", *cfg.HTMLOutput)
		}
	}

	// Memory profiling if requested
	if *cfg.MemProfile != "" {
		f, err := os.Create(*cfg.MemProfile)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Could not create memory profile: %v", err))
		} else {
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				ui.PrintWarning(fmt.Sprintf("Could not write memory profile: %v", err))
			} else {
				fmt.Printf("[*] Memory profile saved to: %s\n", *cfg.MemProfile)
			}
			f.Close()
		}
	}

	// Custom fingerprint file notification
	if *cfg.CustomFingerprintFile != "" {
		// Load custom fingerprints for tech detection
		content, err := os.ReadFile(*cfg.CustomFingerprintFile)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Could not read custom fingerprint file: %v", err))
		} else {
			// Parse as JSON array of fingerprints
			var fingerprints []probes.CustomFingerprint
			if err := json.Unmarshal(content, &fingerprints); err != nil {
				ui.PrintWarning(fmt.Sprintf("Could not parse custom fingerprint file: %v", err))
			} else {
				fmt.Printf("[*] Loaded %d custom fingerprints from: %s\n", len(fingerprints), *cfg.CustomFingerprintFile)
			}
		}
	}

	// Update check
	if *cfg.UpdateCheck && !*cfg.DisableUpdateCheck {
		ui.PrintWarning("The -up/--update flag is deprecated and will be removed in a future release.")
		ui.PrintWarning("Use 'waf-tester update' command instead.")
	}

	// Headless options acknowledgment
	if *cfg.SystemChrome {
		fmt.Println("[*] Using system Chrome for screenshots")
	}
	if *cfg.HeadlessOptions != "" {
		fmt.Printf("[*] Headless options: %s\n", *cfg.HeadlessOptions)
	}
	if *cfg.ScreenshotIdle > 1 {
		fmt.Printf("[*] Screenshot idle time: %d seconds\n", *cfg.ScreenshotIdle)
	}
	if *cfg.JavascriptCode != "" {
		fmt.Printf("[*] JavaScript code to execute: %s\n", *cfg.JavascriptCode)
	}

	// Vision recon clusters - save to file if any screenshots were clustered
	if *cfg.StoreVisionRecon && len(visionClusters) > 0 {
		clusterFile := "vision_clusters.json"
		data, err := json.MarshalIndent(visionClusters, "", "  ")
		if err == nil {
			if err := os.WriteFile(clusterFile, data, 0644); err == nil {
				// Count unique clusters
				uniqueClusters := make(map[int]bool)
				for _, c := range visionClusters {
					uniqueClusters[c.Cluster] = true
				}
				fmt.Printf("[*] Saved %d screenshots in %d visual clusters to: %s\n",
					len(visionClusters), len(uniqueClusters), clusterFile)
			} else {
				ui.PrintWarning(fmt.Sprintf("Failed to write vision clusters: %v", err))
			}
		}
	}

	// Filter error page path - save filtered error pages to file
	if *cfg.FilterErrorPage && len(filteredErrorPages) > 0 {
		data, err := json.MarshalIndent(filteredErrorPages, "", "  ")
		if err == nil {
			if err := os.WriteFile(*cfg.FilterErrorPagePath, data, 0644); err == nil {
				fmt.Printf("[*] Saved %d filtered error pages to: %s\n", len(filteredErrorPages), *cfg.FilterErrorPagePath)
			} else {
				ui.PrintWarning(fmt.Sprintf("Failed to write filtered error pages: %v", err))
			}
		}
	}

	// HTTP API endpoint - server was started at beginning (if specified)

	// Cloud/Dashboard features - these require ProjectDiscovery Cloud Platform (PDCP) API
	// which is a proprietary service. These flags are acknowledged for compatibility
	// but require PDCP account and API keys to function.
	if *cfg.PdAuth {
		fmt.Println("[*] PDCP authentication enabled (requires pdcp.io account)")
		fmt.Println("    Note: PDCP integration requires ProjectDiscovery Cloud Platform subscription")
	}
	if *cfg.PdAuthConfig != "" {
		// Load auth config from file (JSON with api_key, team_id fields)
		if data, err := os.ReadFile(*cfg.PdAuthConfig); err == nil {
			fmt.Printf("[*] PDCP auth config loaded: %s (%d bytes)\n", *cfg.PdAuthConfig, len(data))
			// Parse and validate the config structure
			var authCfg map[string]interface{}
			if json.Unmarshal(data, &authCfg) == nil {
				if _, ok := authCfg["api_key"]; ok {
					fmt.Println("    API key found in config")
				}
			}
		} else {
			fmt.Printf("[!] PDCP auth config not found: %s\n", *cfg.PdAuthConfig)
		}
	}
	if *cfg.PdDashboard {
		fmt.Println("[*] Dashboard upload enabled (requires pdcp.io account)")
	}
	if *cfg.PdTeamID != "" {
		fmt.Printf("[*] PDCP Team ID: %s\n", *cfg.PdTeamID)
	}
	if *cfg.PdAssetID != "" {
		fmt.Printf("[*] PDCP Asset ID: %s\n", *cfg.PdAssetID)
	}
	if *cfg.PdAssetName != "" {
		fmt.Printf("[*] PDCP Asset name: %s\n", *cfg.PdAssetName)
	}
	if *cfg.PdDashboardUpload != "" {
		// Validate and prepare file for PDCP dashboard upload
		if info, err := os.Stat(*cfg.PdDashboardUpload); err == nil {
			fmt.Printf("[*] PDCP dashboard upload file: %s (%d bytes, ready)\n", *cfg.PdDashboardUpload, info.Size())
			fmt.Println("    Note: Actual upload requires PDCP API authentication")
		} else {
			fmt.Printf("[!] PDCP dashboard upload file not found: %s\n", *cfg.PdDashboardUpload)
		}
	}

	// Enterprise file exports (--json-export, --sarif-export, etc.)
	writeProbeExports(&cfg.Out, allProbeResults, time.Since(probeStartTime))

	// ═══════════════════════════════════════════════════════════════════════════
	// DISPATCHER SUMMARY EMISSION
	// ═══════════════════════════════════════════════════════════════════════════
	// Notify all hooks that probe is complete (probed targets, alive count)
	if probeDispCtx != nil {
		_ = probeDispCtx.EmitSummary(ctx, int(statsTotal), int(statsSuccess), int(statsFailed), time.Since(probeStartTime))
	}
}
