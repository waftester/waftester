package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/apispec"
	"github.com/waftester/waftester/pkg/defaults"
)

// isWindowsAbsPath detects Windows-style drive-letter paths (e.g. C:\... or D:/).
// filepath.IsAbs only recognizes these on Windows; on Linux it returns false,
// letting attackers bypass path traversal checks in CI or Linux-hosted servers.
func isWindowsAbsPath(p string) bool {
	if len(p) < 3 {
		return false
	}
	drive := p[0]
	return ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) &&
		p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

// isUNCPath detects Windows UNC paths (\\server\share) on any OS.
// filepath.IsAbs only catches these on Windows; on Linux backslashes are
// literal characters so the check must be string-based.
func isUNCPath(p string) bool {
	return len(p) >= 2 && p[0] == '\\' && p[1] == '\\'
}

// registerSpecTools adds spec-related MCP tools.
func (s *Server) registerSpecTools() {
	s.addValidateSpecTool()
	s.addListSpecEndpointsTool()
	s.addPlanSpecTool()
	s.addScanSpecTool()
	s.addCompareBaselinesTool()
	s.addPreviewSpecScanTool()
	s.addSpecIntelligenceTool()
	s.addDescribeSpecAuthTool()
	s.addExportSpecTool()
}

// specInputProperties returns the shared input schema properties for spec
// tools that accept spec_content, spec_path, or spec_url. Exactly one must be provided.
func specInputProperties() map[string]any {
	return map[string]any{
		"spec_content": map[string]any{
			"type":        "string",
			"description": "The full API specification content (YAML or JSON). Provide the entire spec inline.",
		},
		"spec_path": map[string]any{
			"type":        "string",
			"description": "File path to an API specification. Alternative to spec_content.",
		},
		"spec_url": map[string]any{
			"type":        "string",
			"description": "URL to fetch an API specification from. Alternative to spec_content.",
		},
	}
}

// resolveSpecInput parses a spec from one of: spec_content (inline), spec_path (file), or spec_url (URL).
// Returns the parsed spec or an error result. Exactly one source must be provided.
func resolveSpecInput(ctx context.Context, content, path, url string) (*apispec.Spec, *mcp.CallToolResult) {
	sources := 0
	if content != "" {
		sources++
	}
	if path != "" {
		sources++
	}
	if url != "" {
		sources++
	}

	if sources == 0 {
		return nil, enrichedError("one of spec_content, spec_path, or spec_url is required", []string{
			"Provide the spec inline (spec_content), as a file path (spec_path), or as a URL (spec_url).",
		})
	}
	if sources > 1 {
		return nil, errorResult("provide only one of spec_content, spec_path, or spec_url")
	}

	var spec *apispec.Spec
	var err error

	switch {
	case content != "":
		spec, err = apispec.ParseContentContext(ctx, content)
	case path != "":
		// Reject path traversal, absolute, and rooted paths to prevent arbitrary file reads.
		clean := filepath.Clean(path)
		if filepath.IsAbs(clean) || isWindowsAbsPath(clean) || isUNCPath(clean) || strings.Contains(clean, "..") || strings.HasPrefix(clean, string(filepath.Separator)) {
			return nil, errorResult("spec_path must be a relative path without '..' components")
		}
		spec, err = apispec.ParseContext(ctx, clean)
	case url != "":
		// Validate spec_url against SSRF blocklist before fetching.
		if urlErr := validateTargetURL(url); urlErr != nil {
			return nil, errorResult(fmt.Sprintf("spec_url blocked: %v", urlErr))
		}
		spec, err = apispec.ParseContext(ctx, url)
	}

	if err != nil {
		return nil, enrichedError(fmt.Sprintf("failed to parse spec: %v", err), []string{
			"Check that the spec content is valid YAML or JSON.",
			"Supported formats: OpenAPI 3.x, Swagger 2.0, Postman, HAR, GraphQL, gRPC, AsyncAPI 2.x.",
		})
	}

	// Resolve spec-embedded variable defaults so SSRF check sees real URLs.
	apispec.ResolveVariables(spec, nil, nil)

	// SSRF blocklist: reject specs targeting internal/private addresses.
	if ssrfErr := apispec.CheckServerURLs(spec); ssrfErr != nil {
		return nil, errorResult(ssrfErr.Error())
	}

	return spec, nil
}

// --- validate_spec ---

func (s *Server) addValidateSpecTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "validate_spec",
			Title: "Validate API Specification",
			Description: `Validate an API specification file for correctness and completeness.

USE when:
- You have an API spec (OpenAPI, Swagger, Postman, HAR) and want to check it before scanning
- You need to verify a spec parses correctly
- You want to see validation warnings and errors with line numbers

DON'T USE when:
- You want to actually scan — use scan_spec instead
- You want to list endpoints — use list_spec_endpoints instead

Supported formats: OpenAPI 3.x (YAML/JSON), Swagger 2.0 (YAML/JSON), Postman Collection v2.x (JSON), HAR 1.2 (JSON), GraphQL (introspection), gRPC (reflection), AsyncAPI 2.x (YAML/JSON).

Example:
  {"spec_content": "openapi: \"3.0.0\"\ninfo:\n  title: My API\n  version: 1.0\npaths:\n  /users:\n    get:\n      summary: List users"}

Result format: JSON with fields: valid (bool), format (string), endpoint_count (int), warnings ([]string), errors ([]string).`,
			InputSchema: map[string]any{
				"type":       "object",
				"properties": specInputProperties(),
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("validate_spec", s.handleValidateSpec),
	)
}

func (s *Server) handleValidateSpec(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
		SpecPath    string `json:"spec_path"`
		SpecURL     string `json:"spec_url"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	// Validate that exactly one source is provided.
	sources := 0
	if args.SpecContent != "" {
		sources++
	}
	if args.SpecPath != "" {
		sources++
	}
	if args.SpecURL != "" {
		sources++
	}
	if sources == 0 {
		return enrichedError("one of spec_content, spec_path, or spec_url is required", []string{
			"Provide the spec inline (spec_content), as a file path (spec_path), or as a URL (spec_url).",
		}), nil
	}
	if sources > 1 {
		return errorResult("provide only one of spec_content, spec_path, or spec_url"), nil
	}

	type validationResult struct {
		Valid         bool     `json:"valid"`
		Format        string   `json:"format,omitempty"`
		EndpointCount int      `json:"endpoint_count"`
		Title         string   `json:"title,omitempty"`
		Version       string   `json:"version,omitempty"`
		Warnings      []string `json:"warnings,omitempty"`
		Errors        []string `json:"errors,omitempty"`
	}

	// Parse the spec — failures are validation results, not tool errors.
	// Security guards mirror resolveSpecInput: reject path traversal and SSRF
	// before attempting to read from the user-supplied source.
	var spec *apispec.Spec
	var parseErr error
	switch {
	case args.SpecContent != "":
		spec, parseErr = apispec.ParseContentContext(ctx, args.SpecContent)
	case args.SpecPath != "":
		// Reject path traversal, absolute, and rooted paths to prevent arbitrary file reads.
		clean := filepath.Clean(args.SpecPath)
		if filepath.IsAbs(clean) || isWindowsAbsPath(clean) || isUNCPath(clean) || strings.Contains(clean, "..") || strings.HasPrefix(clean, string(filepath.Separator)) {
			return errorResult("spec_path must be a relative path without '..' components"), nil
		}
		spec, parseErr = apispec.ParseContext(ctx, clean)
	case args.SpecURL != "":
		// Validate spec_url against SSRF blocklist before fetching.
		if urlErr := validateTargetURL(args.SpecURL); urlErr != nil {
			return errorResult(fmt.Sprintf("spec_url blocked: %v", urlErr)), nil
		}
		spec, parseErr = apispec.ParseContext(ctx, args.SpecURL)
	}
	if parseErr != nil {
		return jsonResult(validationResult{
			Valid:  false,
			Errors: []string{parseErr.Error()},
		})
	}

	// Resolve spec-embedded variable defaults so SSRF check sees real URLs.
	apispec.ResolveVariables(spec, nil, nil)

	// SSRF blocklist: report blocked server URLs as validation errors.
	if ssrfErr := apispec.CheckServerURLs(spec); ssrfErr != nil {
		return jsonResult(validationResult{
			Valid:         false,
			Format:        string(spec.Format),
			EndpointCount: len(spec.Endpoints),
			Title:         spec.Title,
			Version:       spec.Version,
			Errors:        []string{ssrfErr.Error()},
		})
	}

	result := validationResult{
		Valid:         true,
		Format:        string(spec.Format),
		EndpointCount: len(spec.Endpoints),
		Title:         spec.Title,
		Version:       spec.Version,
	}

	return jsonResult(result)
}

// --- list_spec_endpoints ---

func (s *Server) addListSpecEndpointsTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "list_spec_endpoints",
			Title: "List Spec Endpoints",
			Description: `Parse an API specification and list all endpoints with their methods, parameters, and auth requirements.

USE when:
- You want to see what endpoints are in a spec before scanning
- You need to understand the API surface area
- You want to filter by group or path

DON'T USE when:
- You want to validate the spec — use validate_spec instead
- You want to scan — use scan_spec instead

Supported formats: OpenAPI 3.x, Swagger 2.0, Postman Collection v2.x, HAR 1.2, GraphQL, gRPC, AsyncAPI 2.x.

Example:
  {"spec_content": "<yaml or json spec>", "group": "users"}

Result format: JSON array of endpoints with method, path, parameters, auth, tags.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": func() map[string]any {
					p := specInputProperties()
					p["group"] = map[string]any{
						"type":        "string",
						"description": "Filter endpoints by group/tag name. Omit to list all.",
					}
					return p
				}(),
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("list_spec_endpoints", s.handleListSpecEndpoints),
	)
}

func (s *Server) handleListSpecEndpoints(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
		SpecPath    string `json:"spec_path"`
		SpecURL     string `json:"spec_url"`
		Group       string `json:"group"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	spec, errResult := resolveSpecInput(ctx, args.SpecContent, args.SpecPath, args.SpecURL)
	if errResult != nil {
		return errResult, nil
	}

	endpoints := spec.Endpoints
	if args.Group != "" {
		endpoints = spec.EndpointsByGroup(args.Group)
	}

	type endpointSummary struct {
		Method     string   `json:"method"`
		Path       string   `json:"path"`
		Summary    string   `json:"summary,omitempty"`
		Tags       []string `json:"tags,omitempty"`
		Auth       []string `json:"auth,omitempty"`
		ParamCount int      `json:"param_count"`
		Deprecated bool     `json:"deprecated,omitempty"`
	}

	summaries := make([]endpointSummary, 0, len(endpoints))
	for _, ep := range endpoints {
		summaries = append(summaries, endpointSummary{
			Method:     ep.Method,
			Path:       ep.Path,
			Summary:    ep.Summary,
			Tags:       ep.Tags,
			Auth:       ep.Auth,
			ParamCount: len(ep.Parameters),
			Deprecated: ep.Deprecated,
		})
	}

	return jsonResult(summaries)
}

// --- plan_spec ---

func (s *Server) addPlanSpecTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "plan_spec",
			Title: "Generate Spec Scan Plan",
			Description: `Parse an API specification and generate an intelligent scan plan using 8 analysis layers.

USE when:
- You want to see what attacks would be selected before scanning
- You want to understand the intelligence engine's analysis
- You need a dry-run preview of the scan

DON'T USE when:
- You want to execute the scan — use scan_spec instead
- You just want to list endpoints — use list_spec_endpoints instead

The intelligence engine analyzes: parameter types, parameter names, endpoint paths, auth context, schema constraints, content-type mutations, method confusion, and cross-endpoint correlations.

Example:
  {"spec_content": "<spec>", "intensity": "deep"}

Result format: JSON with entries (attack plan), total_tests, priority breakdown, and category summary.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": func() map[string]any {
					p := specInputProperties()
					p["intensity"] = map[string]any{
						"type":        "string",
						"description": "Scanning intensity: quick, normal, deep, paranoid. Default: normal.",
						"enum":        apispec.Intensities(),
					}
					p["group"] = map[string]any{
						"type":        "string",
						"description": "Filter to endpoints in this group/tag.",
					}
					p["scan_types"] = map[string]any{
						"type":        "string",
						"description": "Comma-separated list of attack categories to include (e.g., 'sqli,xss'). Omit for auto-selection.",
					}
					p["skip_types"] = map[string]any{
						"type":        "string",
						"description": "Comma-separated list of attack categories to exclude.",
					}
					return p
				}(),
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("plan_spec", s.handlePlanSpec),
	)
}

func (s *Server) handlePlanSpec(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
		SpecPath    string `json:"spec_path"`
		SpecURL     string `json:"spec_url"`
		Intensity   string `json:"intensity"`
		Group       string `json:"group"`
		ScanTypes   string `json:"scan_types"`
		SkipTypes   string `json:"skip_types"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	spec, errResult := resolveSpecInput(ctx, args.SpecContent, args.SpecPath, args.SpecURL)
	if errResult != nil {
		return errResult, nil
	}

	// Apply group filter.
	if args.Group != "" {
		spec.Endpoints = spec.EndpointsByGroup(args.Group)
	}

	opts := apispec.IntelligenceOptions{
		Intensity:        apispec.Intensity(args.Intensity),
		IncludeMetaScans: true,
	}
	if opts.Intensity == "" {
		opts.Intensity = apispec.IntensityNormal
	}
	if args.ScanTypes != "" {
		opts.ScanTypes = splitCSV(args.ScanTypes)
	}
	if args.SkipTypes != "" {
		opts.SkipTypes = splitCSV(args.SkipTypes)
	}

	plan := apispec.BuildIntelligentPlan(spec, opts)

	// Build a preview summary alongside the raw plan.
	type planSummary struct {
		Plan    *apispec.ScanPlan `json:"plan"`
		Preview string            `json:"preview"`
	}

	var buf bytes.Buffer
	apispec.RenderPreview(&buf, plan, spec, apispec.DefaultPreviewConfig())

	return jsonResult(planSummary{
		Plan:    plan,
		Preview: buf.String(),
	})
}

// --- scan_spec ---

func (s *Server) addScanSpecTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "scan_spec",
			Title: "Scan from API Specification",
			Description: `Parse an API spec, auto-select attacks using the intelligence engine, and execute a security scan.

USE when:
- You have an API spec and want to run a full security scan
- You want spec-driven attack selection (smarter than manual category selection)
- You need findings mapped back to specific endpoints and parameters

DON'T USE when:
- You want a single-URL scan without a spec — use scan instead
- You just want to see the plan — use plan_spec instead
- You want to validate the spec — use validate_spec instead

Supported formats: OpenAPI 3.x, Swagger 2.0, Postman Collection v2.x, HAR 1.2, GraphQL, gRPC, AsyncAPI 2.x.

Example:
  {"spec_content": "<spec>", "target": "https://api.example.com", "intensity": "deep", "dry_run": true}

Result format: JSON with findings, endpoint results, attack summary, and scan duration.`,
			Annotations: &mcp.ToolAnnotations{
				IdempotentHint: false,
			},
			InputSchema: map[string]any{
				"type": "object",
				"properties": func() map[string]any {
					p := specInputProperties()
					p["target"] = map[string]any{
						"type":        "string",
						"description": "Target base URL. Overrides spec server URLs. Required if spec has no server URLs.",
					}
					p["intensity"] = map[string]any{
						"type":        "string",
						"description": "Scanning intensity: quick, normal, deep, paranoid.",
						"enum":        apispec.Intensities(),
					}
					p["group"] = map[string]any{
						"type":        "string",
						"description": "Filter to endpoints in this group/tag.",
					}
					p["variables"] = map[string]any{
						"type":        "string",
						"description": "Comma-separated key=value pairs for spec variable substitution.",
					}
					p["env"] = map[string]any{
						"type":        "string",
						"description": "Path to a Postman environment file for variable resolution.",
					}
					p["dry_run"] = map[string]any{
						"type":        "boolean",
						"description": "If true, generate the plan without executing. Returns the scan plan.",
					}
					p["scan_types"] = map[string]any{
						"type":        "string",
						"description": "Comma-separated list of attack categories to include.",
					}
					p["skip_types"] = map[string]any{
						"type":        "string",
						"description": "Comma-separated list of attack categories to exclude.",
					}
					return p
				}(),
			},
		},
		loggedTool("scan_spec", s.handleScanSpec),
	)
}

func (s *Server) handleScanSpec(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
		SpecPath    string `json:"spec_path"`
		SpecURL     string `json:"spec_url"`
		Target      string `json:"target"`
		Intensity   string `json:"intensity"`
		Group       string `json:"group"`
		Variables   string `json:"variables"`
		Env         string `json:"env"`
		DryRun      bool   `json:"dry_run"`
		ScanTypes   string `json:"scan_types"`
		SkipTypes   string `json:"skip_types"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	spec, errResult := resolveSpecInput(ctx, args.SpecContent, args.SpecPath, args.SpecURL)
	if errResult != nil {
		return errResult, nil
	}

	// Apply group filter.
	if args.Group != "" {
		spec.Endpoints = spec.EndpointsByGroup(args.Group)
	}

	// Resolve target.
	target := args.Target
	if target == "" {
		target = spec.BaseURL()
	}

	// Build intelligence plan.
	opts := apispec.IntelligenceOptions{
		Intensity:        apispec.Intensity(args.Intensity),
		IncludeMetaScans: true,
	}
	if opts.Intensity == "" {
		opts.Intensity = apispec.IntensityNormal
	}
	if args.ScanTypes != "" {
		opts.ScanTypes = splitCSV(args.ScanTypes)
	}
	if args.SkipTypes != "" {
		opts.SkipTypes = splitCSV(args.SkipTypes)
	}

	plan := apispec.BuildIntelligentPlan(spec, opts)

	// Dry run — return plan without executing.
	if args.DryRun {
		type dryRunResult struct {
			DryRun  bool              `json:"dry_run"`
			Target  string            `json:"target"`
			Plan    *apispec.ScanPlan `json:"plan"`
			Preview string            `json:"preview"`
		}
		var buf bytes.Buffer
		apispec.RenderPreview(&buf, plan, spec, apispec.DefaultPreviewConfig())
		return jsonResult(dryRunResult{
			DryRun:  true,
			Target:  target,
			Plan:    plan,
			Preview: buf.String(),
		})
	}

	// Execute scan.
	if target == "" {
		return enrichedError("target URL required", []string{
			"Provide a 'target' URL or ensure the spec has server URLs.",
			"Example: {\"target\": \"https://api.example.com\"}",
		}), nil
	}
	if err := validateTargetURL(target); err != nil {
		return errorResult(err.Error()), nil
	}

	// Launch async scan.
	estimatedDuration := estimateSpecDuration(plan)
	return s.launchAsync(ctx, "scan_spec", estimatedDuration, func(taskCtx context.Context, task *Task) {
		slog.Info("scan_spec: starting", "target", target, "entries", len(plan.Entries))

		startTime := time.Now()

		executor := &apispec.SimpleExecutor{
			BaseURL:     target,
			Concurrency: defaults.ConcurrencyLow,
			ScanFn:      s.specScanFn(),
			OnEndpointStart: func(ep apispec.Endpoint, scanType string) {
				slog.Info("scan_spec: scanning", "method", ep.Method, "path", ep.Path, "scan_type", scanType)
			},
		}

		session, execErr := executor.Execute(taskCtx, plan)
		if execErr != nil {
			task.Fail(fmt.Sprintf("execution error: %v", execErr))
			return
		}

		// Use the executor's result which has complete data
		// (findings, errors, TotalEndpoints, TotalTests).
		scanResult := session.Result

		type scanOutput struct {
			Target   string                  `json:"target"`
			Duration string                  `json:"duration"`
			Result   *apispec.SpecScanResult `json:"result"`
		}

		data, err := json.MarshalIndent(scanOutput{
			Target:   target,
			Duration: time.Since(startTime).Round(time.Millisecond).String(),
			Result:   scanResult,
		}, "", "  ")
		if err != nil {
			task.Fail(fmt.Sprintf("marshaling scan result: %v", err))
			return
		}

		task.Complete(json.RawMessage(data))
	})
}

// estimateSpecDuration provides a rough time estimate for async response.
func estimateSpecDuration(plan *apispec.ScanPlan) string {
	if plan == nil || plan.TotalTests == 0 {
		return "10s"
	}
	seconds := plan.TotalTests / 10 // ~10 requests/sec estimate
	if seconds < 10 {
		seconds = 10
	}
	if seconds > 600 {
		seconds = 600
	}
	return fmt.Sprintf("%ds", seconds)
}

// splitCSV splits a comma-separated string into trimmed, non-empty values.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// --- compare_baselines ---

func (s *Server) addCompareBaselinesTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "compare_baselines",
			Title: "Compare Scan Baselines",
			Description: `Compare current scan findings against a saved baseline to detect regressions, fixes, and new findings.

USE when:
- You want to diff two scan results to see what changed
- You need to detect regressions after making changes
- You want to verify fixes

Result format: JSON with fixed, regressed, new, unchanged arrays and counts.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"baseline_findings": map[string]any{
						"type":        "string",
						"description": "JSON array of baseline findings.",
					},
					"current_findings": map[string]any{
						"type":        "string",
						"description": "JSON array of current findings.",
					},
				},
				"required": []string{"baseline_findings", "current_findings"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("compare_baselines", s.handleCompareBaselines),
	)
}

func (s *Server) handleCompareBaselines(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		BaselineFindings string `json:"baseline_findings"`
		CurrentFindings  string `json:"current_findings"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.BaselineFindings == "" {
		return errorResult("baseline_findings is required"), nil
	}
	if args.CurrentFindings == "" {
		return errorResult("current_findings is required"), nil
	}

	var baseline []apispec.SpecFinding
	if err := json.Unmarshal([]byte(args.BaselineFindings), &baseline); err != nil {
		return errorResult(fmt.Sprintf("invalid baseline_findings JSON: %v", err)), nil
	}

	var current []apispec.SpecFinding
	if err := json.Unmarshal([]byte(args.CurrentFindings), &current); err != nil {
		return errorResult(fmt.Sprintf("invalid current_findings JSON: %v", err)), nil
	}

	result := apispec.CompareFindings(baseline, current)
	return jsonResult(result)
}

// --- preview_spec_scan ---

func (s *Server) addPreviewSpecScanTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "preview_spec_scan",
			Title: "Preview Spec Scan Plan",
			Description: `Preview what a scan would do without sending any requests.
Shows endpoints to test, attack types per endpoint, estimated payload counts, and total request budget.

USE when:
- You want to see what will be tested before committing to a scan
- You need to estimate how long a scan will take
- You want to filter by group or intensity first

Result format: JSON with entries (endpoint, attack category, payload count), total_tests, estimated_duration.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": func() map[string]any {
					p := specInputProperties()
					p["intensity"] = map[string]any{
						"type":        "string",
						"enum":        apispec.Intensities(),
						"description": "Scanning depth. Default: normal.",
					}
					p["group"] = map[string]any{
						"type":        "string",
						"description": "Only include endpoints in this tag/group.",
					}
					return p
				}(),
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("preview_spec_scan", s.handlePreviewSpecScan),
	)
}

func (s *Server) handlePreviewSpecScan(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
		SpecPath    string `json:"spec_path"`
		SpecURL     string `json:"spec_url"`
		Intensity   string `json:"intensity"`
		Group       string `json:"group"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	spec, errResult := resolveSpecInput(ctx, args.SpecContent, args.SpecPath, args.SpecURL)
	if errResult != nil {
		return errResult, nil
	}

	intensity := apispec.IntensityNormal
	if args.Intensity != "" {
		intensity = apispec.Intensity(args.Intensity)
	}

	var endpoints []apispec.Endpoint
	if args.Group != "" {
		endpoints = spec.EndpointsByGroup(args.Group)
	} else {
		endpoints = spec.Endpoints
	}

	filteredSpec := *spec
	filteredSpec.Endpoints = endpoints

	plan := apispec.BuildIntelligentPlan(&filteredSpec, apispec.IntelligenceOptions{
		Intensity: intensity,
	})

	type previewEntry struct {
		Method       string `json:"method"`
		Path         string `json:"path"`
		Category     string `json:"category"`
		PayloadCount int    `json:"payload_count"`
		Reason       string `json:"reason"`
	}

	var entries []previewEntry
	for _, e := range plan.Entries {
		entries = append(entries, previewEntry{
			Method:       e.Endpoint.Method,
			Path:         e.Endpoint.Path,
			Category:     e.Attack.Category,
			PayloadCount: e.Attack.PayloadCount,
			Reason:       e.Attack.Reason,
		})
	}

	result := map[string]any{
		"entries":            entries,
		"total_tests":        plan.TotalTests,
		"estimated_duration": plan.EstimatedDuration.String(),
		"intensity":          string(intensity),
		"endpoint_count":     len(endpoints),
	}

	return jsonResult(result)
}

// --- spec_intelligence ---

func (s *Server) addSpecIntelligenceTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "spec_intelligence",
			Title: "Spec Intelligence Analysis",
			Description: `Analyze an API specification to identify security-relevant patterns,
attack surface, and recommended scan configuration.

USE when:
- You want to understand what makes this API interesting from a security perspective
- You need to decide which scan types to focus on
- You want parameter-level analysis (names that suggest injection, auth patterns, etc.)

Result format: JSON with attack_surface, auth_analysis, parameter_insights, recommended_scan_types.`,
			InputSchema: map[string]any{
				"type":       "object",
				"properties": specInputProperties(),
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("spec_intelligence", s.handleSpecIntelligence),
	)
}

func (s *Server) handleSpecIntelligence(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
		SpecPath    string `json:"spec_path"`
		SpecURL     string `json:"spec_url"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	spec, errResult := resolveSpecInput(ctx, args.SpecContent, args.SpecPath, args.SpecURL)
	if errResult != nil {
		return errResult, nil
	}

	// Build an intelligent plan to extract the intelligence selections.
	plan := apispec.BuildIntelligentPlan(spec, apispec.IntelligenceOptions{
		AllScans: true,
	})

	// Aggregate attack selections by category.
	categoryReasons := make(map[string][]string)
	for _, entry := range plan.Entries {
		cat := entry.Attack.Category
		if entry.Attack.Reason != "" {
			categoryReasons[cat] = append(categoryReasons[cat], entry.Attack.Reason)
		}
	}

	// Deduplicate reasons per category.
	categoryInfo := make(map[string]any)
	for cat, reasons := range categoryReasons {
		seen := make(map[string]bool)
		var unique []string
		for _, r := range reasons {
			if !seen[r] {
				seen[r] = true
				unique = append(unique, r)
			}
		}
		sort.Strings(unique)
		categoryInfo[cat] = map[string]any{
			"endpoint_count": len(reasons),
			"reasons":        unique,
		}
	}

	// Auth analysis.
	var authSummary []map[string]any
	for _, scheme := range spec.AuthSchemes {
		info := map[string]any{
			"name": scheme.Name,
			"type": string(scheme.Type),
		}
		if scheme.Scheme != "" {
			info["scheme"] = scheme.Scheme
		}
		if scheme.FieldName != "" {
			info["field_name"] = scheme.FieldName
		}
		if len(scheme.Flows) > 0 {
			info["flows"] = len(scheme.Flows)
		}
		authSummary = append(authSummary, info)
	}

	// Count params by location.
	paramLocations := make(map[string]int)
	for _, ep := range spec.Endpoints {
		for _, p := range ep.Parameters {
			paramLocations[string(p.In)]++
		}
	}

	result := map[string]any{
		"attack_surface": map[string]any{
			"total_endpoints":     len(spec.Endpoints),
			"total_plan_entries":  len(plan.Entries),
			"total_tests":         plan.TotalTests,
			"categories_detected": len(categoryInfo),
			"parameter_locations": paramLocations,
		},
		"auth_analysis":          authSummary,
		"recommended_categories": categoryInfo,
	}

	return jsonResult(result)
}

// --- describe_spec_auth ---

func (s *Server) addDescribeSpecAuthTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "describe_spec_auth",
			Title: "Describe Spec Authentication",
			Description: `Extract and describe all authentication schemes declared in an API specification.

USE when:
- You need to understand what auth the API expects
- You want to configure auth tokens before scanning
- You need OAuth flow details (token URLs, scopes)

Result format: JSON with schemes array, each containing name, type, details, and per-endpoint auth requirements.`,
			InputSchema: map[string]any{
				"type":       "object",
				"properties": specInputProperties(),
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("describe_spec_auth", s.handleDescribeSpecAuth),
	)
}

func (s *Server) handleDescribeSpecAuth(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
		SpecPath    string `json:"spec_path"`
		SpecURL     string `json:"spec_url"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	spec, errResult := resolveSpecInput(ctx, args.SpecContent, args.SpecPath, args.SpecURL)
	if errResult != nil {
		return errResult, nil
	}

	var schemes []map[string]any
	for _, scheme := range spec.AuthSchemes {
		info := map[string]any{
			"name": scheme.Name,
			"type": string(scheme.Type),
		}
		if scheme.Scheme != "" {
			info["scheme"] = scheme.Scheme
		}
		if scheme.BearerFormat != "" {
			info["bearer_format"] = scheme.BearerFormat
		}
		if scheme.In != "" {
			info["in"] = string(scheme.In)
		}
		if scheme.FieldName != "" {
			info["field_name"] = scheme.FieldName
		}
		if len(scheme.Flows) > 0 {
			var flows []map[string]any
			for _, f := range scheme.Flows {
				flow := map[string]any{"type": f.Type}
				if f.AuthURL != "" {
					flow["auth_url"] = f.AuthURL
				}
				if f.TokenURL != "" {
					flow["token_url"] = f.TokenURL
				}
				if len(f.Scopes) > 0 {
					flow["scopes"] = f.Scopes
				}
				flows = append(flows, flow)
			}
			info["flows"] = flows
		}
		schemes = append(schemes, info)
	}

	// Per-endpoint auth requirements.
	type epAuth struct {
		Method string   `json:"method"`
		Path   string   `json:"path"`
		Auth   []string `json:"auth,omitempty"`
	}
	var endpointAuth []epAuth
	for _, ep := range spec.Endpoints {
		if len(ep.Auth) > 0 {
			endpointAuth = append(endpointAuth, epAuth{
				Method: ep.Method,
				Path:   ep.Path,
				Auth:   ep.Auth,
			})
		}
	}

	result := map[string]any{
		"schemes":       schemes,
		"scheme_count":  len(schemes),
		"endpoint_auth": endpointAuth,
	}

	return jsonResult(result)
}

// --- export_spec ---

func (s *Server) addExportSpecTool() {
	s.addTool(
		&mcp.Tool{
			Name:  "export_spec",
			Title: "Export Parsed Spec",
			Description: `Parse an API specification and export the normalized internal representation.
Useful for debugging spec parsing, or for piping into other tools.

USE when:
- You want to see how WAFtester interprets a spec
- You need to verify endpoints were parsed correctly
- You want the spec in WAFtester's normalized format

Result format: JSON with the normalized Spec object (endpoints, servers, auth, metadata).`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": func() map[string]any {
					props := specInputProperties()
					props["include_schemas"] = map[string]any{
						"type":        "boolean",
						"description": "Include full schema definitions in the export. Default: false.",
					}
					return props
				}(),
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("export_spec", s.handleExportSpec),
	)
}

func (s *Server) handleExportSpec(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent    string `json:"spec_content"`
		SpecPath       string `json:"spec_path"`
		SpecURL        string `json:"spec_url"`
		IncludeSchemas bool   `json:"include_schemas"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	spec, errResult := resolveSpecInput(ctx, args.SpecContent, args.SpecPath, args.SpecURL)
	if errResult != nil {
		return errResult, nil
	}

	// Optionally strip schemas to reduce output size.
	if !args.IncludeSchemas {
		for i := range spec.Endpoints {
			for j := range spec.Endpoints[i].Parameters {
				spec.Endpoints[i].Parameters[j].Schema = apispec.SchemaInfo{}
			}
		}
	}

	return jsonResult(spec)
}

// specScanFn returns the scanner bridge function for spec-driven scanning.
// If Config.SpecScanFn is set (injected from cmd/cli), it is used.
// Otherwise returns a no-op that logs a warning.
func (s *Server) specScanFn() apispec.ScanFunc {
	if s.config.SpecScanFn != nil {
		return s.config.SpecScanFn
	}
	return func(_ context.Context, name string, _ string, ep apispec.Endpoint) ([]apispec.SpecFinding, error) {
		slog.Warn("scan_spec: no scanner bridge configured", "method", ep.Method, "path", ep.Path, "scan_type", name)
		return nil, nil
	}
}
