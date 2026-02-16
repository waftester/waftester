package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/waftester/waftester/pkg/apispec"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/headless"
	"github.com/waftester/waftester/pkg/mcpserver"
	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/templateresolver"
	"github.com/waftester/waftester/pkg/ui"
)

// runMCP starts the MCP (Model Context Protocol) server.
// Supports two transport modes:
//   - --stdio (default): For IDE integrations (VS Code, Claude Desktop, Cursor)
//   - --http <addr>:     For remote/Docker deployments with session management
func runMCP() {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)

	stdio := fs.Bool("stdio", true, "Use stdio transport (default, for IDE integration)")
	httpAddr := fs.String("http", "", "HTTP address to listen on (e.g. :8080). Disables stdio.")
	payloadDir := fs.String("payloads", envOrDefault("WAF_TESTER_PAYLOAD_DIR", defaults.PayloadDir), "Payload directory")
	templateDir := fs.String("templates", envOrDefault("WAF_TESTER_TEMPLATE_DIR", defaults.TemplateDir), "Nuclei template directory")
	tamperDir := fs.String("tamper-dir", "", "Directory of .tengo script tampers to load")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: waf-tester mcp [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Start an MCP server for AI-driven WAF testing.\n\n")
		fmt.Fprintf(os.Stderr, "Transports:\n")
		fmt.Fprintf(os.Stderr, "  --stdio          Stdio transport for IDE integration (default)\n")
		fmt.Fprintf(os.Stderr, "  --http <addr>    Streamable HTTP transport for remote/Docker\n\n")
		fmt.Fprintf(os.Stderr, "Environment variables:\n")
		fmt.Fprintf(os.Stderr, "  WAF_TESTER_PAYLOAD_DIR   Payload directory (default: %s)\n", defaults.PayloadDir)
		fmt.Fprintf(os.Stderr, "  WAF_TESTER_TEMPLATE_DIR  Nuclei template directory (default: %s)\n", defaults.TemplateDir)
		fmt.Fprintf(os.Stderr, "  WAF_TESTER_HTTP_ADDR     HTTP listen address (same as --http)\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  waf-tester mcp --stdio\n")
		fmt.Fprintf(os.Stderr, "  waf-tester mcp --http :8080\n")
		fmt.Fprintf(os.Stderr, "  WAF_TESTER_PAYLOAD_DIR=/data/payloads waf-tester mcp --http :8080\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Resolve nuclei template directory with embedded fallback.
	if resolved, resolveErr := templateresolver.ResolveNucleiDir(*templateDir); resolveErr == nil {
		*templateDir = resolved
	}

	// Allow env var override for HTTP address (useful in Docker/K8s)
	if *httpAddr == "" {
		if envAddr := os.Getenv("WAF_TESTER_HTTP_ADDR"); envAddr != "" {
			*httpAddr = envAddr
		}
	}

	// --- Startup validation: payload directory ---
	payloadCount, err := validatePayloadDir(*payloadDir, *templateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: payload directory %q: %v\n", *payloadDir, err)
		fmt.Fprintf(os.Stderr, "hint: set --payloads or WAF_TESTER_PAYLOAD_DIR to the directory containing payload JSON files\n")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%s payload directory: %s (%d payloads loaded)\n", ui.UserAgent(), *payloadDir, payloadCount)

	srv := mcpserver.New(&mcpserver.Config{
		PayloadDir:   *payloadDir,
		TemplateDir:  *templateDir,
		TamperDir:    *tamperDir,
		SpecScanFn:   mcpSpecScanFn(),
		EventCrawlFn: mcpEventCrawlFn(),
	})
	srv.MarkReady()  // Signal that startup validation passed
	defer srv.Stop() // Cancel running tasks and wait for goroutine drain

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *httpAddr != "" {
		// HTTP transport mode
		*stdio = false
		handler := srv.HTTPHandler()

		httpSrv := &http.Server{
			Addr:              *httpAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			// WriteTimeout intentionally 0: SSE streams are long-lived and
			// any non-zero value sets an absolute deadline that kills SSE
			// connections. Async tools return task_id immediately so non-SSE
			// endpoints don't need a write timeout either.
			// ReadHeaderTimeout + ReadTimeout protect against slowloris.
			IdleTimeout:    30 * time.Second, // Short to release idle TCP connections quickly (Railway serverless sleep).
			MaxHeaderBytes: 1 << 20,          // 1 MB
		}

		go func() {
			<-ctx.Done()
			// Graceful shutdown: drain in-flight requests within 15 seconds
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer shutdownCancel()
			fmt.Fprintf(os.Stderr, "%s shutting down gracefully…\n", ui.UserAgent())
			if err := httpSrv.Shutdown(shutdownCtx); err != nil {
				fmt.Fprintf(os.Stderr, "error during shutdown: %v\n", err)
			}
		}()

		fmt.Fprintf(os.Stderr, "%s MCP server listening on %s (HTTP transport)\n",
			ui.UserAgent(), *httpAddr)

		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Stdio transport mode (default)
	if *stdio {
		if err := srv.RunStdio(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Fprintf(os.Stderr, "error: no transport selected — use --stdio or --http <addr>\n")
	os.Exit(1)
}

// envOrDefault returns the environment variable value if set, otherwise the default.
func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// validatePayloadDir checks that the payload directory exists, contains JSON
// files, and that payloads can be loaded. Returns the total unified payload count.
// templateDir is the Nuclei template directory to include in unified counts.
func validatePayloadDir(dir, templateDir string) (int, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return 0, fmt.Errorf("not found: %w", err)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("not a directory")
	}

	provider := payloadprovider.NewProvider(dir, templateDir)
	if err := provider.Load(); err != nil {
		return 0, fmt.Errorf("failed to load payloads: %w", err)
	}

	stats, err := provider.GetStats()
	if err != nil {
		return 0, fmt.Errorf("failed to compute stats: %w", err)
	}
	if stats.TotalPayloads == 0 {
		return 0, fmt.Errorf("no payloads found (directory exists but contains no payload files)")
	}

	return stats.TotalPayloads, nil
}

// mcpSpecScanFn returns the ScanFunc bridge for MCP spec scanning.
// It wraps runScannerForSpec (cmd_scan_spec.go) with reasonable defaults.
func mcpSpecScanFn() apispec.ScanFunc {
	return func(ctx context.Context, name string, targetURL string, ep apispec.Endpoint) ([]apispec.SpecFinding, error) {
		cf := &CommonFlags{
			Timeout:    30,
			SkipVerify: true,
		}
		return runScannerForSpec(ctx, name, targetURL, ep, cf, "")
	}
}

// mcpEventCrawlFn returns the EventCrawlFn bridge for MCP event crawling.
// It wraps headless.EventCrawl with chromedp browser lifecycle management.
func mcpEventCrawlFn() mcpserver.EventCrawlFn {
	return func(ctx context.Context, targetURL string, maxClicks, clickTimeoutSec int) ([]mcpserver.EventCrawlResult, []string, error) {
		allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
		)

		allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
		defer allocCancel()

		browserCtx, browserCancel := chromedp.NewContext(allocCtx)
		defer browserCancel()

		eventConfig := headless.DefaultEventCrawlConfig()
		eventConfig.MaxClicks = maxClicks
		eventConfig.ClickTimeout = time.Duration(clickTimeoutSec) * time.Second

		results, err := headless.EventCrawl(browserCtx, targetURL, eventConfig)
		if err != nil {
			return nil, nil, err
		}

		// Convert headless.EventCrawlResult to mcpserver.EventCrawlResult
		mcpResults := make([]mcpserver.EventCrawlResult, 0, len(results))
		for _, r := range results {
			mcpResults = append(mcpResults, mcpserver.EventCrawlResult{
				Element: map[string]any{
					"selector": r.Element.Selector,
					"tag":      r.Element.Tag,
					"text":     r.Element.Text,
					"type":     r.Element.Type,
					"href":     r.Element.Href,
					"onclick":  r.Element.OnClick,
				},
				DiscoveredURLs: r.DiscoveredURLs,
				XHRRequests:    r.XHRRequests,
				NavigatedTo:    r.NavigatedTo,
				DOMChanged:     r.DOMChanged,
			})
		}

		discoveredURLs := headless.CollectDiscoveredURLs(results, targetURL, true)
		return mcpResults, discoveredURLs, nil
	}
}
