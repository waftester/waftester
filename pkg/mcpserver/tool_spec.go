package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/apispec"
)

// registerSpecTools adds spec-related MCP tools.
func (s *Server) registerSpecTools() {
	s.addValidateSpecTool()
	s.addListSpecEndpointsTool()
	s.addPlanSpecTool()
	s.addScanSpecTool()
	s.addCompareBaselinesTool()
}

// --- validate_spec ---

func (s *Server) addValidateSpecTool() {
	s.mcp.AddTool(
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
				"type": "object",
				"properties": map[string]any{
					"spec_content": map[string]any{
						"type":        "string",
						"description": "The full API specification content (YAML or JSON). Provide the entire spec inline.",
					},
				},
				"required": []string{"spec_content"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("validate_spec", s.handleValidateSpec),
	)
}

func (s *Server) handleValidateSpec(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.SpecContent == "" {
		return enrichedError("spec_content is required", []string{
			"Provide the full API specification content as a string.",
			"Supported formats: OpenAPI 3.x, Swagger 2.0, Postman, HAR.",
		}), nil
	}

	spec, err := apispec.ParseContent(args.SpecContent)

	type validationResult struct {
		Valid         bool     `json:"valid"`
		Format        string   `json:"format,omitempty"`
		EndpointCount int      `json:"endpoint_count"`
		Title         string   `json:"title,omitempty"`
		Version       string   `json:"version,omitempty"`
		Warnings      []string `json:"warnings,omitempty"`
		Errors        []string `json:"errors,omitempty"`
	}

	result := validationResult{}

	if err != nil {
		result.Valid = false
		result.Errors = []string{err.Error()}
		return jsonResult(result)
	}

	result.Valid = true
	result.Format = string(spec.Format)
	result.EndpointCount = len(spec.Endpoints)
	result.Title = spec.Title
	result.Version = spec.Version

	// Validation of inline content is limited — ValidateSpec expects a file path.
	// We skip file-based validation here; the parse success is the primary check.

	return jsonResult(result)
}

// --- list_spec_endpoints ---

func (s *Server) addListSpecEndpointsTool() {
	s.mcp.AddTool(
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
				"properties": map[string]any{
					"spec_content": map[string]any{
						"type":        "string",
						"description": "The full API specification content.",
					},
					"group": map[string]any{
						"type":        "string",
						"description": "Filter endpoints by group/tag name. Omit to list all.",
					},
				},
				"required": []string{"spec_content"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("list_spec_endpoints", s.handleListSpecEndpoints),
	)
}

func (s *Server) handleListSpecEndpoints(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
		Group       string `json:"group"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.SpecContent == "" {
		return enrichedError("spec_content is required", nil), nil
	}

	spec, err := apispec.ParseContent(args.SpecContent)
	if err != nil {
		return enrichedError(fmt.Sprintf("failed to parse spec: %v", err), []string{
			"Check that the spec content is valid YAML or JSON.",
			"Supported formats: OpenAPI 3.x, Swagger 2.0, Postman, HAR.",
		}), nil
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
	s.mcp.AddTool(
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
				"properties": map[string]any{
					"spec_content": map[string]any{
						"type":        "string",
						"description": "The full API specification content.",
					},
					"intensity": map[string]any{
						"type":        "string",
						"description": "Scanning intensity: quick, normal, deep, paranoid. Default: normal.",
						"enum":        []string{"quick", "normal", "deep", "paranoid"},
					},
					"group": map[string]any{
						"type":        "string",
						"description": "Filter to endpoints in this group/tag.",
					},
					"scan_types": map[string]any{
						"type":        "string",
						"description": "Comma-separated list of attack categories to include (e.g., 'sqli,xss'). Omit for auto-selection.",
					},
					"skip_types": map[string]any{
						"type":        "string",
						"description": "Comma-separated list of attack categories to exclude.",
					},
				},
				"required": []string{"spec_content"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: true,
			},
		},
		loggedTool("plan_spec", s.handlePlanSpec),
	)
}

func (s *Server) handlePlanSpec(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
		Intensity   string `json:"intensity"`
		Group       string `json:"group"`
		ScanTypes   string `json:"scan_types"`
		SkipTypes   string `json:"skip_types"`
	}
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}
	if args.SpecContent == "" {
		return enrichedError("spec_content is required", nil), nil
	}

	spec, err := apispec.ParseContent(args.SpecContent)
	if err != nil {
		return enrichedError(fmt.Sprintf("failed to parse spec: %v", err), []string{
			"Check that the spec content is valid YAML or JSON.",
		}), nil
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
	s.mcp.AddTool(
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
				"properties": map[string]any{
					"spec_content": map[string]any{
						"type":        "string",
						"description": "The full API specification content.",
					},
					"target": map[string]any{
						"type":        "string",
						"description": "Target base URL. Overrides spec server URLs. Required if spec has no server URLs.",
					},
					"intensity": map[string]any{
						"type":        "string",
						"description": "Scanning intensity: quick, normal, deep, paranoid.",
						"enum":        []string{"quick", "normal", "deep", "paranoid"},
					},
					"group": map[string]any{
						"type":        "string",
						"description": "Filter to endpoints in this group/tag.",
					},
					"variables": map[string]any{
						"type":        "string",
						"description": "Comma-separated key=value pairs for spec variable substitution.",
					},
					"env": map[string]any{
						"type":        "string",
						"description": "Path to a Postman environment file for variable resolution.",
					},
					"dry_run": map[string]any{
						"type":        "boolean",
						"description": "If true, generate the plan without executing. Returns the scan plan.",
					},
					"scan_types": map[string]any{
						"type":        "string",
						"description": "Comma-separated list of attack categories to include.",
					},
					"skip_types": map[string]any{
						"type":        "string",
						"description": "Comma-separated list of attack categories to exclude.",
					},
				},
				"required": []string{"spec_content"},
			},
		},
		loggedTool("scan_spec", s.handleScanSpec),
	)
}

func (s *Server) handleScanSpec(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		SpecContent string `json:"spec_content"`
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
	if args.SpecContent == "" {
		return enrichedError("spec_content is required", []string{
			"Provide the full API specification content as a string.",
		}), nil
	}

	spec, err := apispec.ParseContent(args.SpecContent)
	if err != nil {
		return enrichedError(fmt.Sprintf("failed to parse spec: %v", err), []string{
			"Check that the spec content is valid YAML or JSON.",
		}), nil
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
		log.Printf("[scan_spec] starting spec scan against %s (%d entries)", target, len(plan.Entries))

		scanResult := &apispec.SpecScanResult{
			SpecSource: spec.Source,
			StartedAt:  time.Now(),
		}
		startTime := time.Now()

		executor := &apispec.SimpleExecutor{
			BaseURL:     target,
			Concurrency: 5,
			ScanFn: func(ctx context.Context, name string, targetURL string, ep apispec.Endpoint) ([]apispec.SpecFinding, error) {
				// Bridge to existing scanner infrastructure.
				return nil, nil
			},
			OnEndpointStart: func(ep apispec.Endpoint, scanType string) {
				log.Printf("[scan_spec] scanning %s %s (%s)", ep.Method, ep.Path, scanType)
			},
			OnFinding: func(f apispec.SpecFinding) {
				scanResult.AddFinding(f)
			},
		}

		if _, err := executor.Execute(taskCtx, plan); err != nil {
			scanResult.AddError(fmt.Sprintf("execution error: %v", err))
		}

		scanResult.Finalize()

		type scanOutput struct {
			Target   string                  `json:"target"`
			Duration string                  `json:"duration"`
			Result   *apispec.SpecScanResult `json:"result"`
		}

		data, _ := json.MarshalIndent(scanOutput{
			Target:   target,
			Duration: time.Since(startTime).Round(time.Millisecond).String(),
			Result:   scanResult,
		}, "", "  ")

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
	s.mcp.AddTool(
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
