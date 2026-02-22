package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/ui"
)

// runAnalyze performs JavaScript static analysis
func runAnalyze() {
	ui.PrintCompactBanner()
	ui.PrintSection("JavaScript Analysis")

	analyzeFlags := flag.NewFlagSet("analyze", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	analyzeFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	analyzeFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := analyzeFlags.String("l", "", "File containing target URLs")
	stdinInput := analyzeFlags.Bool("stdin", false, "Read targets from stdin")
	file := analyzeFlags.String("file", "", "Local JavaScript file to analyze")
	outputFile := analyzeFlags.String("output", "", "Output file for results (JSON)")
	extractURLs := analyzeFlags.Bool("urls", true, "Extract URLs")
	extractEndpoints := analyzeFlags.Bool("endpoints", true, "Extract API endpoints")
	extractSecrets := analyzeFlags.Bool("secrets", true, "Extract secrets/credentials")
	extractDOMSinks := analyzeFlags.Bool("sinks", true, "Extract DOM XSS sinks")
	jsonOutput := analyzeFlags.Bool("json", false, "Output in JSON format")

	// Enterprise hook flags (Slack, Teams, PagerDuty, OTEL, etc.)
	analyzeSlack := analyzeFlags.String("slack-webhook", "", "Slack webhook URL for notifications")
	analyzeTeams := analyzeFlags.String("teams-webhook", "", "Teams webhook URL for notifications")
	analyzePagerDuty := analyzeFlags.String("pagerduty-key", "", "PagerDuty routing key")
	analyzeOtel := analyzeFlags.String("otel-endpoint", "", "OpenTelemetry endpoint")
	analyzeWebhook := analyzeFlags.String("webhook-url", "", "Generic webhook URL")

	analyzeFlags.Parse(os.Args[2:])

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil && *file == "" {
		ui.PrintError("Target URL or file is required. Use -u https://example.com/app.js, -l file.txt, -stdin, or -file script.js")
		os.Exit(1)
	}

	var jsCode string

	if *file != "" {
		ui.PrintConfigLine("File", *file)
		data, err := os.ReadFile(*file)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Error reading file: %v", err))
			os.Exit(1)
		}
		jsCode = string(data)
	} else {
		ui.PrintConfigLine("Target", target)
		// Fetch JavaScript from URL
		ctx, cancel := context.WithTimeout(context.Background(), duration.ContextShort)
		defer cancel()

		// Use a simple HTTP client to fetch
		req, err := createRequest(ctx, target)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Error creating request: %v", err))
			os.Exit(1)
		}
		jsCode, err = fetchContent(req)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Error fetching JavaScript: %v", err))
			os.Exit(1)
		}
	}
	fmt.Println()

	analyzer := js.NewAnalyzer()
	result := analyzer.Analyze(jsCode)
	analyzeStartTime := time.Now()

	// Initialize dispatcher for hooks (Slack, Teams, PagerDuty, OTEL, etc.)
	analyzeOutputFlags := OutputFlags{
		SlackWebhook: *analyzeSlack,
		TeamsWebhook: *analyzeTeams,
		PagerDutyKey: *analyzePagerDuty,
		OTelEndpoint: *analyzeOtel,
		WebhookURL:   *analyzeWebhook,
	}
	analyzeScanID := fmt.Sprintf("analyze-%d", time.Now().Unix())
	analyzeTarget := target
	if analyzeTarget == "" {
		analyzeTarget = *file
	}
	analyzeDispCtx, analyzeDispErr := analyzeOutputFlags.InitDispatcher(analyzeScanID, analyzeTarget)
	if analyzeDispErr != nil {
		ui.PrintWarning(fmt.Sprintf("Dispatcher warning: %v", analyzeDispErr))
	}
	if analyzeDispCtx != nil {
		defer analyzeDispCtx.Close()
	}

	// Emit security findings to hooks in real-time
	ctx, ctxCancel := cli.SignalContext(30 * time.Second)
	defer ctxCancel()

	// Emit start event for scan lifecycle hooks
	if analyzeDispCtx != nil {
		_ = analyzeDispCtx.EmitStart(ctx, analyzeTarget, 0, 1, nil)
	}
	if analyzeDispCtx != nil {
		// Emit secrets as critical findings
		for _, secret := range result.Secrets {
			secretDesc := fmt.Sprintf("Secret found: %s", secret.Type)
			_ = analyzeDispCtx.EmitBypass(ctx, "js-secret-exposure", "critical", analyzeTarget, secretDesc, 0)
		}
		// Emit DOM XSS sinks
		for _, sink := range result.DOMSinks {
			sinkDesc := fmt.Sprintf("DOM XSS sink: %s at line %d", sink.Sink, sink.Line)
			_ = analyzeDispCtx.EmitBypass(ctx, "js-dom-xss", sink.Severity, analyzeTarget, sinkDesc, 0)
		}
		// Emit cloud URLs (potential misconfigurations)
		for _, cloud := range result.CloudURLs {
			cloudDesc := fmt.Sprintf("Cloud resource: %s (%s)", cloud.URL, cloud.Service)
			_ = analyzeDispCtx.EmitBypass(ctx, "js-cloud-url", "medium", analyzeTarget, cloudDesc, 0)
		}
		// Emit subdomains
		for _, sub := range result.Subdomains {
			subDesc := fmt.Sprintf("Subdomain discovered: %s", sub)
			_ = analyzeDispCtx.EmitBypass(ctx, "js-subdomain", "info", analyzeTarget, subDesc, 0)
		}
		// Emit discovered endpoints (potential attack surface)
		for _, ep := range result.Endpoints {
			method := ep.Method
			if method == "" {
				method = "GET"
			}
			epDesc := fmt.Sprintf("Endpoint discovered: %s %s (source: %s)", method, ep.Path, ep.Source)
			_ = analyzeDispCtx.EmitBypass(ctx, "js-endpoint", "info", analyzeTarget, epDesc, 0)
		}
	}

	if !*jsonOutput {
		ui.PrintSection("Analysis Results")

		if *extractURLs && len(result.URLs) > 0 {
			ui.PrintConfigLine("URLs Found", fmt.Sprintf("%d", len(result.URLs)))
			for _, u := range result.URLs[:min(10, len(result.URLs))] {
				ui.PrintInfo(fmt.Sprintf("  [%s] %s", u.Type, u.URL))
			}
			if len(result.URLs) > 10 {
				ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(result.URLs)-10))
			}
			fmt.Println()
		}

		if *extractEndpoints && len(result.Endpoints) > 0 {
			ui.PrintConfigLine("Endpoints Found", fmt.Sprintf("%d", len(result.Endpoints)))
			for _, ep := range result.Endpoints[:min(10, len(result.Endpoints))] {
				method := ep.Method
				if method == "" {
					method = "GET"
				}
				ui.PrintInfo(fmt.Sprintf("  [%s] %s %s", ep.Source, method, ep.Path))
			}
			if len(result.Endpoints) > 10 {
				ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(result.Endpoints)-10))
			}
			fmt.Println()
		}

		if *extractSecrets && len(result.Secrets) > 0 {
			ui.PrintSection("🔑 Secrets Detected")
			for _, secret := range result.Secrets {
				severity := strings.ToUpper(secret.Confidence)
				if severity == "" {
					severity = "LOW"
				}
				ui.PrintError(fmt.Sprintf("  [%s] %s: %s", severity, secret.Type, truncateSecret(secret.Value)))
			}
			fmt.Println()
		}

		if *extractDOMSinks && len(result.DOMSinks) > 0 {
			ui.PrintSection("⚠️  DOM XSS Sinks")
			for _, sink := range result.DOMSinks {
				ui.PrintWarning(fmt.Sprintf("  [%s] %s at line %d", sink.Severity, sink.Sink, sink.Line))
			}
			fmt.Println()
		}

		if len(result.CloudURLs) > 0 {
			ui.PrintSection("☁️  Cloud Resources")
			for _, cloud := range result.CloudURLs {
				ui.PrintInfo(fmt.Sprintf("  [%s] %s", cloud.Service, cloud.URL))
			}
			fmt.Println()
		}

		if len(result.Subdomains) > 0 {
			ui.PrintConfigLine("Subdomains Found", fmt.Sprintf("%d", len(result.Subdomains)))
			for _, sub := range result.Subdomains[:min(10, len(result.Subdomains))] {
				ui.PrintInfo("  " + sub)
			}
			fmt.Println()
		}
	}

	// Output results
	if *jsonOutput || *outputFile != "" {
		outputData := result
		if !*extractURLs {
			outputData.URLs = nil
		}
		if !*extractEndpoints {
			outputData.Endpoints = nil
		}
		if !*extractSecrets {
			outputData.Secrets = nil
		}
		if !*extractDOMSinks {
			outputData.DOMSinks = nil
		}

		jsonData, err := json.MarshalIndent(outputData, "", "  ")
		if err != nil {
			errMsg := fmt.Sprintf("JSON encoding error: %v", err)
			ui.PrintError(errMsg)
			if analyzeDispCtx != nil {
				_ = analyzeDispCtx.EmitError(context.Background(), "analyze", errMsg, true)
				_ = analyzeDispCtx.Close()
			}
			os.Exit(1)
		}

		if *outputFile != "" {
			if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
				errMsg := fmt.Sprintf("Error writing output: %v", err)
				ui.PrintError(errMsg)
				if analyzeDispCtx != nil {
					_ = analyzeDispCtx.EmitError(context.Background(), "analyze", errMsg, true)
					_ = analyzeDispCtx.Close()
				}
				os.Exit(1)
			}
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}

		if *jsonOutput {
			fmt.Println(string(jsonData))
		}
	}

	// Emit summary to hooks
	if analyzeDispCtx != nil {
		analyzeDuration := time.Since(analyzeStartTime)
		totalFindings := len(result.Secrets) + len(result.DOMSinks) + len(result.CloudURLs)
		_ = analyzeDispCtx.EmitSummary(ctx, totalFindings, 0, totalFindings, analyzeDuration)
	}
}

func createRequest(ctx context.Context, targetURL string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, "GET", targetURL, nil)
}

func fetchContent(req *http.Request) (string, error) {
	client := httpclient.Probing()

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, err := iohelper.ReadBody(resp.Body, iohelper.LargeMaxBodySize)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func truncateSecret(s string) string {
	if len(s) <= 20 {
		return s
	}
	return s[:10] + "..." + s[len(s)-5:]
}
