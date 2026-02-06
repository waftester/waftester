package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/waftester/waftester/pkg/mcpserver"
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
	payloadDir := fs.String("payloads", "./payloads", "Payload directory")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: waf-tester mcp [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Start an MCP server for AI-driven WAF testing.\n\n")
		fmt.Fprintf(os.Stderr, "Transports:\n")
		fmt.Fprintf(os.Stderr, "  --stdio          Stdio transport for IDE integration (default)\n")
		fmt.Fprintf(os.Stderr, "  --http <addr>    Streamable HTTP transport for remote/Docker\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  waf-tester mcp --stdio\n")
		fmt.Fprintf(os.Stderr, "  waf-tester mcp --http :8080\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	srv := mcpserver.New(&mcpserver.Config{
		PayloadDir: *payloadDir,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *httpAddr != "" {
		// HTTP transport mode
		*stdio = false
		handler := srv.HTTPHandler()

		httpSrv := &http.Server{
			Addr:    *httpAddr,
			Handler: handler,
		}

		go func() {
			<-ctx.Done()
			_ = httpSrv.Close()
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
	}
}
