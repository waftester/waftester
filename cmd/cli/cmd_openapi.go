package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/cli"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/openapi"
	"github.com/waftester/waftester/pkg/templateresolver"
	"github.com/waftester/waftester/pkg/ui"
)

// =============================================================================
// OPENAPI COMMAND - OpenAPI Specification Fuzzing
// =============================================================================

func runOpenAPI() {
	ui.PrintCompactBanner()
	ui.PrintSection("OpenAPI Security Scanner")
	ui.PrintWarning("DEPRECATED: 'openapi' command will be removed in a future release. Use 'auto --spec <file>' instead.")

	openapiFlags := flag.NewFlagSet("openapi", flag.ExitOnError)

	// Spec options
	specFile := openapiFlags.String("spec", "", "OpenAPI specification file (YAML/JSON)")
	specShort := openapiFlags.String("s", "", "OpenAPI spec file (shorthand)")
	specURL := openapiFlags.String("spec-url", "", "OpenAPI specification URL")

	// Target options
	baseURL := openapiFlags.String("base-url", "", "Base URL to override servers from spec")
	targetShort := openapiFlags.String("u", "", "Base URL (shorthand)")

	// Scan options
	listEndpoints := openapiFlags.Bool("list", false, "List all endpoints from spec")
	fuzz := openapiFlags.Bool("fuzz", false, "Fuzz all endpoints with attack payloads")
	scanType := openapiFlags.String("scan-type", "all", "Scan type: all, sqli, xss, idor, auth")
	path := openapiFlags.String("path", "", "Only test specific path (e.g., /api/users)")
	method := openapiFlags.String("method", "", "Only test specific method (GET, POST, etc.)")

	// Auth options
	authHeader := openapiFlags.String("auth-header", "", "Authorization header value")
	apiKey := openapiFlags.String("api-key", "", "API key value")
	apiKeyHeader := openapiFlags.String("api-key-header", "X-API-Key", "API key header name")
	bearerToken := openapiFlags.String("bearer", "", "Bearer token")

	// Payload and template directories
	payloadDir := openapiFlags.String("payloads", defaults.PayloadDir, "Payload directory")
	templateDir := openapiFlags.String("template-dir", defaults.TemplateDir, "Nuclei template directory")

	// Output options
	outputFile := openapiFlags.String("o", "", "Output file (JSON)")
	jsonOutput := openapiFlags.Bool("json", false, "Output in JSON format")
	verbose := openapiFlags.Bool("v", false, "Verbose output")

	openapiFlags.Parse(os.Args[2:])

	// Resolve nuclei template directory with embedded fallback.
	if resolved, err := templateresolver.ResolveNucleiDir(*templateDir); err == nil {
		*templateDir = resolved
	}

	// Get spec path
	specPath := *specFile
	if specPath == "" {
		specPath = *specShort
	}
	if specPath == "" {
		specPath = *specURL
	}

	if specPath == "" {
		ui.PrintError("OpenAPI specification required")
		fmt.Println()
		fmt.Println("Usage: waf-tester openapi -spec <file> [options]")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  waf-tester openapi -spec openapi.yaml --list")
		fmt.Println("  waf-tester openapi -spec openapi.yaml --fuzz -u https://api.example.com")
		fmt.Println("  waf-tester openapi --spec-url https://api.example.com/openapi.json --fuzz")
		os.Exit(1)
	}

	// Get base URL
	targetBaseURL := *baseURL
	if targetBaseURL == "" {
		targetBaseURL = *targetShort
	}

	if !*jsonOutput {
		ui.PrintConfigLine("Spec", specPath)
		if targetBaseURL != "" {
			ui.PrintConfigLine("Base URL", targetBaseURL)
		}
		if *listEndpoints {
			ui.PrintConfigLine("Mode", "List Endpoints")
		} else if *fuzz {
			ui.PrintConfigLine("Mode", fmt.Sprintf("Fuzz (%s)", *scanType))
		}
		fmt.Println()
	}

	// Parse spec
	var spec *openapi.Spec
	var err error

	if strings.HasPrefix(specPath, "http://") || strings.HasPrefix(specPath, "https://") {
		spec, err = openapi.ParseFromURL(specPath)
	} else {
		spec, err = openapi.ParseFromFile(specPath)
	}

	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to parse OpenAPI spec: %v", err))
		os.Exit(1)
	}

	if !*jsonOutput {
		ui.PrintSuccess(fmt.Sprintf("Parsed: %s v%s", spec.Info.Title, spec.Info.Version))
		fmt.Println()
	}

	// Determine base URL
	if targetBaseURL == "" && len(spec.Servers) > 0 {
		targetBaseURL = spec.Servers[0].URL
	}

	// Setup context
	ctx, cancel := cli.SignalContext(30 * time.Second)
	defer cancel()

	ctx, tCancel := context.WithTimeout(ctx, 30*time.Minute)
	defer tCancel()

	// Build auth headers
	authHeaders := make(map[string]string)
	if *authHeader != "" {
		authHeaders["Authorization"] = *authHeader
	} else if *bearerToken != "" {
		authHeaders["Authorization"] = "Bearer " + *bearerToken
	}
	if *apiKey != "" {
		authHeaders[*apiKeyHeader] = *apiKey
	}

	// Execute requested operation
	switch {
	case *listEndpoints:
		runOpenAPIList(spec, targetBaseURL, *jsonOutput)

	case *fuzz:
		runOpenAPIFuzz(ctx, spec, targetBaseURL, *payloadDir, *templateDir, *scanType, *path, *method, authHeaders,
			*outputFile, *jsonOutput, *verbose)

	default:
		// Default to listing endpoints
		runOpenAPIList(spec, targetBaseURL, *jsonOutput)
	}
}

func runOpenAPIList(spec *openapi.Spec, baseURL string, jsonOutput bool) {
	type endpointInfo struct {
		Path        string   `json:"path"`
		Method      string   `json:"method"`
		OperationID string   `json:"operation_id,omitempty"`
		Summary     string   `json:"summary,omitempty"`
		Tags        []string `json:"tags,omitempty"`
		Parameters  int      `json:"parameters"`
		HasBody     bool     `json:"has_body"`
	}

	var endpoints []endpointInfo

	for path, pathItem := range spec.Paths {
		methods := map[string]*openapi.Operation{
			"GET":     pathItem.Get,
			"POST":    pathItem.Post,
			"PUT":     pathItem.Put,
			"DELETE":  pathItem.Delete,
			"PATCH":   pathItem.Patch,
			"OPTIONS": pathItem.Options,
			"HEAD":    pathItem.Head,
		}

		for method, op := range methods {
			if op == nil {
				continue
			}

			ep := endpointInfo{
				Path:        path,
				Method:      method,
				OperationID: op.OperationID,
				Summary:     op.Summary,
				Tags:        op.Tags,
				Parameters:  len(op.Parameters),
				HasBody:     op.RequestBody != nil,
			}
			endpoints = append(endpoints, ep)
		}
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"base_url":  baseURL,
			"title":     spec.Info.Title,
			"version":   spec.Info.Version,
			"endpoints": endpoints,
			"count":     len(endpoints),
		}, "", "  ")
		fmt.Println(string(data))
		return
	}

	ui.PrintSection("API Endpoints")
	for _, ep := range endpoints {
		color := getMethodColor(ep.Method)
		paramInfo := ""
		if ep.Parameters > 0 {
			paramInfo = fmt.Sprintf(" [%d params]", ep.Parameters)
		}
		if ep.HasBody {
			paramInfo += " [body]"
		}

		fmt.Printf("  %s%-7s%s %s%s\n", color, ep.Method, ui.Reset, ep.Path, paramInfo)
		if ep.Summary != "" {
			fmt.Printf("          %s\n", ep.Summary)
		}
	}
	fmt.Println()
	ui.PrintSuccess(fmt.Sprintf("Found %d endpoints", len(endpoints)))
}

func runOpenAPIFuzz(ctx context.Context, spec *openapi.Spec, baseURL, payloadDir, templateDir, scanType, filterPath, filterMethod string,
	authHeaders map[string]string, outputFile string, jsonOutput, verbose bool) {

	type fuzzResult struct {
		Path       string `json:"path"`
		Method     string `json:"method"`
		Parameter  string `json:"parameter"`
		Location   string `json:"location"`
		Payload    string `json:"payload"`
		StatusCode int    `json:"status_code"`
		Blocked    bool   `json:"blocked"`
		Latency    string `json:"latency"`
		Error      string `json:"error,omitempty"`
	}

	var results []fuzzResult

	// Map OpenAPI scan types to unified payload categories
	categoryMap := map[string]string{
		"sqli": "SQL-Injection",
		"xss":  "XSS",
		"idor": "idor",
		"auth": "Authentication",
		"all":  "",
	}
	unifiedCat := categoryMap[scanType]
	if unifiedCat == "" && scanType != "all" {
		unifiedCat = scanType
	}

	// Load payloads from unified engine (replaces hardcoded lists)
	var fuzzPayloads []string
	if scanType == "all" {
		// For "all" scan type, get a mix of categories
		for _, cat := range []string{"SQL-Injection", "XSS", "Command-Injection", "Path-Traversal", "SSTI"} {
			fuzzPayloads = append(fuzzPayloads, getUnifiedFuzzPayloads(payloadDir, templateDir, cat, 5, verbose)...)
		}
	} else {
		fuzzPayloads = getUnifiedFuzzPayloads(payloadDir, templateDir, unifiedCat, 50, verbose)
	}
	payloads := fuzzPayloads

	// Generate test cases
	generator := openapi.NewTestGenerator(spec)
	testCases := generator.GenerateTests(openapi.GeneratorOptions{
		BaseURL:      baseURL,
		PathFilter:   filterPath,
		MethodFilter: filterMethod,
		AuthHeaders:  authHeaders,
	})

	if !jsonOutput {
		ui.PrintConfigLine("Test Cases", fmt.Sprintf("%d", len(testCases)))
		ui.PrintConfigLine("Payloads", fmt.Sprintf("%d per location", len(payloads)))
		fmt.Println()
	}

	for _, tc := range testCases {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		// Fuzz each parameter with payloads
		for _, param := range tc.Parameters {
			for _, payload := range payloads {
				select {
				case <-ctx.Done():
					goto done
				default:
				}
				result, err := generator.ExecuteFuzzTest(ctx, tc, param.Name, payload)

				fr := fuzzResult{
					Path:      tc.Path,
					Method:    tc.Method,
					Parameter: param.Name,
					Location:  param.In,
					Payload:   payload,
				}

				if err != nil {
					fr.Error = err.Error()
					fr.Blocked = true
				} else {
					fr.StatusCode = result.StatusCode
					fr.Blocked = result.Blocked
					fr.Latency = fmt.Sprintf("%dms", result.Latency)
				}

				results = append(results, fr)

				if !jsonOutput && verbose {
					if fr.Blocked {
						ui.PrintWarning(fmt.Sprintf("[BLOCKED] %s %s (%s=%s)",
							tc.Method, tc.Path, param.Name, truncatePayload(payload, 30)))
					}
				}
			}
		}

		// Progress
		if !jsonOutput && len(tc.Parameters) > 0 {
			fmt.Printf("\r[%s] %s - tested %d parameters",
				tc.Method, tc.Path, len(tc.Parameters))
		}
	}

done:
	if !jsonOutput {
		fmt.Println()
	}

	// Output results
	if outputFile != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to write output: %v", err))
		} else {
			ui.PrintSuccess(fmt.Sprintf("Results written to %s", outputFile))
		}
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Println()
		blocked := 0
		for _, r := range results {
			if r.Blocked {
				blocked++
			}
		}
		ui.PrintSection("Summary")
		ui.PrintConfigLine("Total Tests", fmt.Sprintf("%d", len(results)))
		ui.PrintConfigLine("Blocked", fmt.Sprintf("%d", blocked))
		ui.PrintConfigLine("Bypassed", fmt.Sprintf("%d", len(results)-blocked))
		if len(results) > 0 {
			blockRate := float64(blocked) / float64(len(results)) * 100
			ui.PrintConfigLine("Block Rate", fmt.Sprintf("%.1f%%", blockRate))
		}
	}
}

func getMethodColor(method string) string {
	switch method {
	case "GET":
		return ui.Green
	case "POST":
		return ui.Yellow
	case "PUT":
		return ui.Blue
	case "DELETE":
		return ui.Red
	case "PATCH":
		return ui.Cyan
	default:
		return ui.Reset
	}
}
