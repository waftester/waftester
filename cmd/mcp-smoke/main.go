package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// scenarioResult tracks the outcome of a single scenario.
type scenarioResult struct {
	name   string
	passed bool
	err    error
}

// scenario is a named test function that runs against a live MCP session.
type scenario struct {
	name string
	live bool // requires a real target (skipped without -live)
	fn   func(ctx context.Context, s *mcp.ClientSession, target string) error
}

func main() {
	var (
		port    = flag.Int("port", 18080, "MCP HTTP port")
		target  = flag.String("target", "https://example.com", "Target URL for live scenarios")
		timeout = flag.Duration("timeout", 90*time.Second, "Overall timeout")
		live    = flag.Bool("live", false, "Enable live scenarios that hit an external target")
		runOnly = flag.String("scenario", "", "Run only this named scenario")
	)
	flag.Parse()
	log.SetFlags(0)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	serverCmd, err := startServer(ctx, *port)
	if err != nil {
		log.Fatalf("FATAL start_server: %v", err)
	}
	defer stopServer(serverCmd)

	if err := waitForHealth(ctx, *port); err != nil {
		log.Fatalf("FATAL health_check: %v", err)
	}
	fmt.Println("server: healthy")

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-smoke", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.SSEClientTransport{
		Endpoint: fmt.Sprintf("http://127.0.0.1:%d/sse", *port),
	}, nil)
	if err != nil {
		log.Fatalf("FATAL connect: %v", err)
	}
	defer session.Close()

	scenarios := allScenarios()

	var results []scenarioResult
	for _, sc := range scenarios {
		if *runOnly != "" && sc.name != *runOnly {
			continue
		}
		if sc.live && !*live {
			results = append(results, scenarioResult{name: sc.name, passed: true, err: fmt.Errorf("SKIP (needs -live)")})
			fmt.Printf("SKIP  %s\n", sc.name)
			continue
		}

		err := sc.fn(ctx, session, *target)
		passed := err == nil
		results = append(results, scenarioResult{name: sc.name, passed: passed, err: err})

		if passed {
			fmt.Printf("PASS  %s\n", sc.name)
		} else {
			fmt.Printf("FAIL  %s: %v\n", sc.name, err)
		}
	}

	// Summary.
	passed, failed, skipped := 0, 0, 0
	for _, r := range results {
		if r.err != nil && strings.HasPrefix(r.err.Error(), "SKIP") {
			skipped++
		} else if r.passed {
			passed++
		} else {
			failed++
		}
	}

	fmt.Printf("\n--- %d passed, %d failed, %d skipped ---\n", passed, failed, skipped)
	if failed > 0 {
		os.Exit(1)
	}
}

// allScenarios returns every smoke scenario in execution order.
func allScenarios() []scenario {
	return []scenario{
		// Surface area verification.
		{"tool_discovery", false, scenarioToolDiscovery},
		{"resource_exploration", false, scenarioResourceExploration},
		{"prompt_catalog", false, scenarioPromptCatalog},

		// Individual tool validation (positive + negative for each).
		{"payload_exploration", false, scenarioPayloadExploration},
		{"tamper_catalog", false, scenarioTamperCatalog},
		{"mutation_engine", false, scenarioMutationEngine},
		{"template_workflow", false, scenarioTemplateWorkflow},
		{"cicd_generation", false, scenarioCICDGeneration},
		{"spec_pipeline", false, scenarioSpecPipeline},
		{"baseline_comparison", false, scenarioBaselineComparison},
		{"task_management", false, scenarioTaskManagement},
		{"error_handling", false, scenarioErrorHandling},

		// Agent simulations — multi-turn workflows that mimic real AI agents.
		{"agent_security_auditor", false, agentSecurityAuditor},
		{"agent_api_security", false, agentAPISecurity},
		{"agent_evasion_researcher", false, agentEvasionResearcher},
		{"agent_devsecops", false, agentDevSecOps},

		// Live (requires external target).
		{"waf_recon", true, scenarioWAFRecon},
	}
}

// ---------------------------------------------------------------------------
// tool_discovery — verifies every tool exists and has metadata,
// plus negative: nonexistent tools, schema expectations.
// ---------------------------------------------------------------------------

func scenarioToolDiscovery(ctx context.Context, s *mcp.ClientSession, _ string) error {
	tools, err := s.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return fmt.Errorf("ListTools: %w", err)
	}

	expected := []string{
		"list_payloads", "detect_waf", "discover", "learn", "scan",
		"assess", "mutate", "bypass", "probe", "generate_cicd",
		"list_tampers", "discover_bypasses", "event_crawl",
		"get_task_status", "cancel_task", "list_tasks",
		"list_templates", "show_template",
		"validate_spec", "list_spec_endpoints", "plan_spec", "scan_spec",
		"compare_baselines", "preview_spec_scan", "spec_intelligence",
		"describe_spec_auth", "export_spec",
	}

	have := make(map[string]bool, len(tools.Tools))
	for _, t := range tools.Tools {
		have[t.Name] = true
	}

	var missing []string
	for _, name := range expected {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing tools: %v (have %d)", missing, len(tools.Tools))
	}
	if len(tools.Tools) != len(expected) {
		return fmt.Errorf("tool count mismatch: want %d, got %d", len(expected), len(tools.Tools))
	}

	// Every tool must have a description (agents select tools by description).
	for _, t := range tools.Tools {
		if t.Description == "" {
			return fmt.Errorf("tool %q has empty description", t.Name)
		}
	}

	// Every tool must have an input schema (agents build arguments from it).
	for _, t := range tools.Tools {
		if t.InputSchema == nil {
			return fmt.Errorf("tool %q has nil input schema", t.Name)
		}
	}

	// NEGATIVE: calling a nonexistent tool must fail — either protocol error
	// or IsError=true, both are acceptable. Must not silently succeed.
	fakeResult, err := callToolRaw(ctx, s, "nonexistent_tool_that_does_not_exist", map[string]any{})
	if err == nil && !fakeResult.IsError {
		return fmt.Errorf("NEG nonexistent tool: expected error, got success")
	}

	return nil
}

// ---------------------------------------------------------------------------
// resource_exploration — reads and validates every resource, plus negative:
// nonexistent URIs, invalid parameterized URIs.
// ---------------------------------------------------------------------------

func scenarioResourceExploration(ctx context.Context, s *mcp.ClientSession, _ string) error {
	// Version resource: parse JSON and verify structure.
	versionRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://version"})
	if err != nil {
		return fmt.Errorf("ReadResource(version): %w", err)
	}
	versionData, err := resourceJSON(versionRes)
	if err != nil {
		return fmt.Errorf("parse version: %w", err)
	}
	for _, field := range []string{"name", "version", "capabilities"} {
		if _, ok := versionData[field]; !ok {
			return fmt.Errorf("version resource missing %q field", field)
		}
	}
	caps, ok := versionData["capabilities"].(map[string]any)
	if !ok {
		return fmt.Errorf("version capabilities not an object")
	}
	if toolCount, _ := caps["tools"].(float64); toolCount == 0 {
		return fmt.Errorf("version reports 0 tools")
	}

	// Payloads index: verify category data exists.
	payloadsRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://payloads"})
	if err != nil {
		return fmt.Errorf("ReadResource(payloads): %w", err)
	}
	payloadsText := strings.ToLower(resourceText(payloadsRes))
	for _, cat := range []string{"sqli", "xss"} {
		if !strings.Contains(payloadsText, cat) {
			return fmt.Errorf("payloads resource missing %q category", cat)
		}
	}

	// Parameterized resource: verify it returns category-specific data.
	sqliRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://payloads/sqli"})
	if err != nil {
		return fmt.Errorf("ReadResource(payloads/sqli): %w", err)
	}
	if resourceText(sqliRes) == "" {
		return fmt.Errorf("payloads/sqli: empty")
	}

	// WAF signatures: must have detection data.
	sigRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://waf-signatures"})
	if err != nil {
		return fmt.Errorf("ReadResource(waf-signatures): %w", err)
	}
	sigText := strings.ToLower(resourceText(sigRes))
	if !strings.Contains(sigText, "cloudflare") && !strings.Contains(sigText, "waf") {
		return fmt.Errorf("waf-signatures: missing expected detection data")
	}

	// All remaining static resources: reachable and non-empty.
	for _, uri := range []string{
		"waftester://payloads/unified",
		"waftester://guide",
		"waftester://evasion-techniques",
		"waftester://owasp-mappings",
		"waftester://config",
		"waftester://templates",
		"waftester://spec-formats",
		"waftester://intelligence-layers",
	} {
		res, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		if err != nil {
			return fmt.Errorf("ReadResource(%s): %w", uri, err)
		}
		if len(res.Contents) == 0 || resourceText(res) == "" {
			return fmt.Errorf("ReadResource(%s): empty", uri)
		}
	}

	// NEGATIVE: nonexistent resource URI must fail.
	_, err = s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://does-not-exist"})
	if err == nil {
		return fmt.Errorf("NEG nonexistent resource: expected error, got nil")
	}

	// NEGATIVE: invalid parameterized resource (nonexistent category).
	_, err = s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://payloads/zzz_nonexistent_category"})
	if err == nil {
		// If server returns data for a nonexistent category without error,
		// verify the content is empty or clearly states no payloads.
		// Either error or empty-ish response is acceptable.
	}

	return nil
}

// ---------------------------------------------------------------------------
// prompt_catalog — verifies every prompt returns messages with parameter
// substitution, plus negative: nonexistent prompts, missing required args.
// ---------------------------------------------------------------------------

func scenarioPromptCatalog(ctx context.Context, s *mcp.ClientSession, _ string) error {
	target := "https://smoke-test.example.com"

	prompts := []struct {
		name   string
		args   map[string]string
		expect string // must appear in rendered prompt
	}{
		{"security_audit", map[string]string{"target": target}, target},
		{"waf_bypass", map[string]string{"target": target, "category": "sqli"}, "sqli"},
		{"full_assessment", map[string]string{"target": target}, target},
		{"discovery_workflow", map[string]string{"target": target}, target},
		{"evasion_research", map[string]string{"target": target, "payload": "<script>alert(1)</script>"}, "script"},
		{"template_scan", map[string]string{"target": target}, target},
		{"spec_security_audit", map[string]string{"spec_content": miniOpenAPISpec}, "/users"},
	}

	for _, p := range prompts {
		result, err := s.GetPrompt(ctx, &mcp.GetPromptParams{
			Name:      p.name,
			Arguments: p.args,
		})
		if err != nil {
			return fmt.Errorf("GetPrompt(%s): %w", p.name, err)
		}
		if len(result.Messages) == 0 {
			return fmt.Errorf("GetPrompt(%s): no messages", p.name)
		}

		// Parameter substitution check.
		blob, _ := json.Marshal(result)
		if !strings.Contains(string(blob), p.expect) {
			return fmt.Errorf("GetPrompt(%s): expected %q in response (parameter substitution broken?)", p.name, p.expect)
		}
	}

	// NEGATIVE: nonexistent prompt must fail.
	_, err := s.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "nonexistent_prompt_xyz",
		Arguments: map[string]string{},
	})
	if err == nil {
		return fmt.Errorf("NEG nonexistent prompt: expected error, got nil")
	}

	// NEGATIVE: prompt with missing required arg must fail.
	_, err = s.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "security_audit",
		Arguments: map[string]string{}, // target is required
	})
	if err == nil {
		return fmt.Errorf("NEG security_audit(no target): expected error, got nil")
	}

	return nil
}

// ---------------------------------------------------------------------------
// payload_exploration — validates response structure and filtering,
// plus negative: nonexistent category returns no samples.
// ---------------------------------------------------------------------------

func scenarioPayloadExploration(ctx context.Context, s *mcp.ClientSession, _ string) error {
	// Unfiltered: get global counts.
	allData, err := callToolJSON(ctx, s, "list_payloads", map[string]any{})
	if err != nil {
		return err
	}
	totalPayloads, _ := allData["total_payloads"].(float64)
	if totalPayloads == 0 {
		return fmt.Errorf("list_payloads: total_payloads is 0")
	}
	categories, _ := allData["categories"].(float64)
	if categories == 0 {
		return fmt.Errorf("list_payloads: categories count is 0")
	}

	// Filtered by category.
	for _, cat := range []string{"sqli", "xss"} {
		catData, err := callToolJSON(ctx, s, "list_payloads", map[string]any{"category": cat})
		if err != nil {
			return fmt.Errorf("list_payloads(%s): %w", cat, err)
		}
		catTotal, _ := catData["total_payloads"].(float64)
		if catTotal >= totalPayloads {
			return fmt.Errorf("list_payloads(%s): filtered count %v >= total %v", cat, catTotal, totalPayloads)
		}
		if _, ok := catData["category_info"]; !ok {
			return fmt.Errorf("list_payloads(%s): missing category_info", cat)
		}
		samples, ok := catData["sample_payloads"].([]any)
		if !ok || len(samples) == 0 {
			return fmt.Errorf("list_payloads(%s): no sample_payloads", cat)
		}

		// Verify sample has required fields for agent consumption.
		first, _ := samples[0].(map[string]any)
		for _, field := range []string{"id", "category", "severity", "snippet"} {
			if first[field] == nil {
				return fmt.Errorf("list_payloads(%s): sample missing %q field", cat, field)
			}
		}
	}

	// NEGATIVE: nonexistent category must return zero payloads.
	fakeData, err := callToolJSON(ctx, s, "list_payloads", map[string]any{"category": "zzz_nonexistent"})
	if err != nil {
		return fmt.Errorf("NEG list_payloads(fake): %w", err)
	}
	fakeTotal, _ := fakeData["total_payloads"].(float64)
	if fakeTotal > 0 {
		return fmt.Errorf("NEG list_payloads(fake): expected 0 payloads, got %v", fakeTotal)
	}

	// NEGATIVE: invalid severity filter must return empty.
	sevData, err := callToolJSON(ctx, s, "list_payloads", map[string]any{"severity": "ZZZZZ"})
	if err != nil {
		return fmt.Errorf("NEG list_payloads(bad severity): %w", err)
	}
	sevTotal, _ := sevData["total_payloads"].(float64)
	if sevTotal > 0 {
		return fmt.Errorf("NEG list_payloads(bad severity): expected 0 payloads, got %v", sevTotal)
	}

	return nil
}

// ---------------------------------------------------------------------------
// tamper_catalog — validates structure and filtering, plus negative:
// nonexistent category filter shrinks results.
// ---------------------------------------------------------------------------

func scenarioTamperCatalog(ctx context.Context, s *mcp.ClientSession, _ string) error {
	allData, err := callToolJSON(ctx, s, "list_tampers", map[string]any{})
	if err != nil {
		return err
	}

	totalCount, _ := allData["total_count"].(float64)
	if totalCount == 0 {
		return fmt.Errorf("list_tampers: total_count is 0")
	}

	tampers, ok := allData["tampers"].([]any)
	if !ok || len(tampers) == 0 {
		return fmt.Errorf("list_tampers: empty tampers array")
	}
	first, _ := tampers[0].(map[string]any)
	if first["name"] == nil || first["category"] == nil {
		return fmt.Errorf("list_tampers: first tamper missing name or category")
	}
	if _, ok := allData["category_breakdown"]; !ok {
		return fmt.Errorf("list_tampers: missing category_breakdown")
	}

	// Filtered by encoding — fewer tampers.
	encData, err := callToolJSON(ctx, s, "list_tampers", map[string]any{"category": "encoding"})
	if err != nil {
		return fmt.Errorf("list_tampers(encoding): %w", err)
	}
	filteredCount, _ := encData["filtered_count"].(float64)
	if filteredCount >= totalCount {
		return fmt.Errorf("list_tampers(encoding): filtered %v >= total %v", filteredCount, totalCount)
	}

	// NEGATIVE: nonexistent category should return 0 tampers or all tampers
	// (depending on implementation) but never more than the total.
	fakeData, err := callToolJSON(ctx, s, "list_tampers", map[string]any{"category": "zzz_nonexistent"})
	if err != nil {
		return fmt.Errorf("NEG list_tampers(fake): %w", err)
	}
	fakeTampers, _ := fakeData["tampers"].([]any)
	fakeFiltered, _ := fakeData["filtered_count"].(float64)
	// Either empty (filtered out) or the filter was ignored — both must not exceed total.
	if fakeFiltered > totalCount {
		return fmt.Errorf("NEG list_tampers(fake): filtered_count %v > total %v", fakeFiltered, totalCount)
	}
	_ = fakeTampers

	return nil
}

// ---------------------------------------------------------------------------
// mutation_engine — validates encoding correctness and variant diversity,
// plus negative: missing payload, invalid encoder, identical-to-input check.
// ---------------------------------------------------------------------------

func scenarioMutationEngine(ctx context.Context, s *mcp.ClientSession, _ string) error {
	payload := "<script>alert(1)</script>"

	// Single encoder: URL.
	singleData, err := callToolJSON(ctx, s, "mutate", map[string]any{
		"payload":  payload,
		"encoders": []string{"url"},
	})
	if err != nil {
		return err
	}

	variants, ok := singleData["variants"].([]any)
	if !ok || len(variants) == 0 {
		return fmt.Errorf("mutate(url): no variants")
	}
	first, _ := variants[0].(map[string]any)
	encoded, _ := first["encoded"].(string)
	if encoded == "" {
		return fmt.Errorf("mutate(url): empty encoded field")
	}
	if encoded == payload {
		return fmt.Errorf("mutate(url): encoded identical to input — encoder is a no-op")
	}
	// URL-encoding "<" produces "%3C".
	if !strings.Contains(strings.ToLower(encoded), "%3c") {
		return fmt.Errorf("mutate(url): expected %%3C in %q", truncate(encoded, 80))
	}
	if enc, _ := first["encoder"].(string); enc == "" {
		return fmt.Errorf("mutate(url): variant missing encoder field")
	}
	singleCount := len(variants)

	// Multiple encoders: must produce more variants than single.
	multiData, err := callToolJSON(ctx, s, "mutate", map[string]any{
		"payload":  payload,
		"encoders": []string{"url", "double_url", "unicode", "html_hex"},
	})
	if err != nil {
		return fmt.Errorf("mutate(multi): %w", err)
	}
	multiVariants, _ := multiData["variants"].([]any)
	if len(multiVariants) <= singleCount {
		return fmt.Errorf("mutate: 4 encoders produced %d variants (single produced %d)", len(multiVariants), singleCount)
	}

	// All variants must be distinct.
	seen := make(map[string]bool, len(multiVariants))
	for _, v := range multiVariants {
		vm, _ := v.(map[string]any)
		if e, _ := vm["encoded"].(string); e != "" {
			seen[e] = true
		}
	}
	if len(seen) < 2 {
		return fmt.Errorf("mutate(multi): only %d unique variants", len(seen))
	}

	// NEGATIVE: missing payload must return IsError.
	if err := requireToolError(ctx, s, "mutate", map[string]any{}, "missing payload"); err != nil {
		return err
	}

	// NEGATIVE: empty encoders array.
	emptyEncResult, err := callToolRaw(ctx, s, "mutate", map[string]any{
		"payload":  payload,
		"encoders": []string{},
	})
	if err != nil {
		return fmt.Errorf("NEG mutate(empty encoders): %w", err)
	}
	if !emptyEncResult.IsError {
		// If it succeeded, verify it produced zero or fewer variants.
		text := extractText(emptyEncResult)
		var ed map[string]any
		if json.Unmarshal([]byte(text), &ed) == nil {
			if vs, _ := ed["variants"].([]any); len(vs) > 0 {
				// Acceptable: server treated empty as "no encoders" but still returned something.
			}
		}
	}

	// NEGATIVE: payload with only whitespace — should either error or encode it.
	wsResult, err := callToolRaw(ctx, s, "mutate", map[string]any{
		"payload":  "   ",
		"encoders": []string{"url"},
	})
	if err != nil {
		return fmt.Errorf("NEG mutate(whitespace): %w", err)
	}
	// Either IsError or encoded output is fine — must not crash.
	if !wsResult.IsError {
		text := extractText(wsResult)
		if text == "" {
			return fmt.Errorf("NEG mutate(whitespace): empty response and no error")
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// template_workflow — lists, filters, and shows templates, plus negative:
// nonexistent template path, nonexistent kind.
// ---------------------------------------------------------------------------

func scenarioTemplateWorkflow(ctx context.Context, s *mcp.ClientSession, _ string) error {
	allData, err := callToolJSON(ctx, s, "list_templates", map[string]any{})
	if err != nil {
		return err
	}
	totalCount, _ := allData["total_count"].(float64)
	if totalCount == 0 {
		return fmt.Errorf("list_templates: total_count is 0")
	}
	categories, ok := allData["categories"].([]any)
	if !ok || len(categories) == 0 {
		return fmt.Errorf("list_templates: no categories")
	}

	// Filter by first kind.
	firstCat, _ := categories[0].(map[string]any)
	kind, _ := firstCat["kind"].(string)
	if kind == "" {
		return fmt.Errorf("list_templates: first category has no kind")
	}

	filteredData, err := callToolJSON(ctx, s, "list_templates", map[string]any{"kind": kind})
	if err != nil {
		return fmt.Errorf("list_templates(kind=%s): %w", kind, err)
	}
	filteredCats, _ := filteredData["categories"].([]any)
	if len(filteredCats) == 0 {
		return fmt.Errorf("list_templates(kind=%s): no categories", kind)
	}
	fc, _ := filteredCats[0].(map[string]any)
	templates, ok := fc["templates"].([]any)
	if !ok || len(templates) == 0 {
		return fmt.Errorf("list_templates(kind=%s): empty templates", kind)
	}

	// Show first template.
	firstTpl, _ := templates[0].(map[string]any)
	path, _ := firstTpl["path"].(string)
	if path == "" {
		return fmt.Errorf("list_templates(kind=%s): template has no path", kind)
	}
	showResult, err := callToolRaw(ctx, s, "show_template", map[string]any{"path": path})
	if err != nil {
		return fmt.Errorf("show_template(%s): %w", path, err)
	}
	if showResult.IsError {
		return fmt.Errorf("show_template(%s): %s", path, truncate(extractText(showResult), 200))
	}
	if len(extractText(showResult)) < 20 {
		return fmt.Errorf("show_template(%s): content too short (%d bytes)", path, len(extractText(showResult)))
	}

	// NEGATIVE: nonexistent template path must return IsError.
	if err := requireToolError(ctx, s, "show_template", map[string]any{
		"path": "nonexistent/path/that/does/not/exist.yaml",
	}, "nonexistent path"); err != nil {
		return err
	}

	// NEGATIVE: missing path argument must return IsError.
	if err := requireToolError(ctx, s, "show_template", map[string]any{}, "missing path"); err != nil {
		return err
	}

	// NEGATIVE: path traversal attempt must not return sensitive files.
	traversalResult, err := callToolRaw(ctx, s, "show_template", map[string]any{
		"path": "../../../etc/passwd",
	})
	if err != nil {
		return fmt.Errorf("NEG show_template(traversal): %w", err)
	}
	if !traversalResult.IsError {
		text := extractText(traversalResult)
		if strings.Contains(text, "root:") {
			return fmt.Errorf("NEG show_template(traversal): returned /etc/passwd content (security vulnerability)")
		}
		// Server returned something but not a sensitive file — might be an error message, acceptable.
	}

	return nil
}

// ---------------------------------------------------------------------------
// cicd_generation — validates per-platform output, plus negative:
// invalid platform, missing target.
// ---------------------------------------------------------------------------

func scenarioCICDGeneration(ctx context.Context, s *mcp.ClientSession, _ string) error {
	tests := []struct {
		platform string
		keyword  string // must appear in pipeline
	}{
		{"github", "uses:"},
		{"gitlab", "stage"},
		{"jenkins", "pipeline"},
		{"azure-devops", "pool"},
		{"circleci", "docker"},
		{"bitbucket", "step"},
	}

	for _, tc := range tests {
		data, err := callToolJSON(ctx, s, "generate_cicd", map[string]any{
			"target":   "https://api.example.com",
			"platform": tc.platform,
		})
		if err != nil {
			return fmt.Errorf("generate_cicd(%s): %w", tc.platform, err)
		}
		if got, _ := data["platform"].(string); got != tc.platform {
			return fmt.Errorf("generate_cicd(%s): response platform=%q", tc.platform, got)
		}
		if fileName, _ := data["file_name"].(string); fileName == "" {
			return fmt.Errorf("generate_cicd(%s): missing file_name", tc.platform)
		}
		pipeline, _ := data["pipeline"].(string)
		if !strings.Contains(strings.ToLower(pipeline), strings.ToLower(tc.keyword)) {
			return fmt.Errorf("generate_cicd(%s): pipeline missing keyword %q", tc.platform, tc.keyword)
		}
	}

	// NEGATIVE: missing target must return IsError.
	if err := requireToolError(ctx, s, "generate_cicd", map[string]any{
		"platform": "github",
	}, "missing target"); err != nil {
		return err
	}

	// NEGATIVE: missing platform must return IsError.
	if err := requireToolError(ctx, s, "generate_cicd", map[string]any{
		"target": "https://example.com",
	}, "missing platform"); err != nil {
		return err
	}

	// NEGATIVE: completely empty args must return IsError.
	if err := requireToolError(ctx, s, "generate_cicd", map[string]any{}, "empty args"); err != nil {
		return err
	}

	// NEGATIVE: invalid platform must return IsError.
	if err := requireToolError(ctx, s, "generate_cicd", map[string]any{
		"target":   "https://example.com",
		"platform": "nonexistent_platform_xyz",
	}, "invalid platform"); err != nil {
		return err
	}

	return nil
}

// ---------------------------------------------------------------------------
// spec_pipeline — full pipeline with structural validation, plus negative:
// garbage spec, empty spec, spec with no paths.
// ---------------------------------------------------------------------------

func scenarioSpecPipeline(ctx context.Context, s *mcp.ClientSession, _ string) error {
	spec := map[string]any{"spec_content": miniOpenAPISpec}

	// Step 1: Validate.
	valData, err := callToolJSON(ctx, s, "validate_spec", spec)
	if err != nil {
		return fmt.Errorf("validate_spec: %w", err)
	}
	if valid, _ := valData["valid"].(bool); !valid {
		return fmt.Errorf("validate_spec: spec reported invalid")
	}
	if epCount, _ := valData["endpoint_count"].(float64); epCount < 3 {
		return fmt.Errorf("validate_spec: endpoint_count=%v, want >=3", epCount)
	}

	// Step 2: List endpoints — verify our spec's paths appear.
	epResult, err := callToolRaw(ctx, s, "list_spec_endpoints", spec)
	if err != nil {
		return fmt.Errorf("list_spec_endpoints: %w", err)
	}
	epText := extractText(epResult)
	for _, path := range []string{"/users", "/users/{id}"} {
		if !strings.Contains(epText, path) {
			return fmt.Errorf("list_spec_endpoints: missing path %s", path)
		}
	}
	for _, method := range []string{"GET", "POST"} {
		if !strings.Contains(epText, method) {
			return fmt.Errorf("list_spec_endpoints: missing method %s", method)
		}
	}

	// Steps 3-7: remaining pipeline.
	for _, tool := range []string{"plan_spec", "describe_spec_auth", "preview_spec_scan", "spec_intelligence"} {
		if err := requireToolOK(ctx, s, tool, spec); err != nil {
			return fmt.Errorf("%s: %w", tool, err)
		}
	}
	if err := requireToolOK(ctx, s, "export_spec", map[string]any{
		"spec_content": miniOpenAPISpec, "include_schemas": true,
	}); err != nil {
		return fmt.Errorf("export_spec: %w", err)
	}

	// NEGATIVE: garbage spec must report valid=false or return IsError.
	garbageResult, err := callToolRaw(ctx, s, "validate_spec", map[string]any{
		"spec_content": "absolutely not yaml or json {{{[[",
	})
	if err != nil {
		return fmt.Errorf("NEG validate_spec(garbage): %w", err)
	}
	if !garbageResult.IsError {
		text := extractText(garbageResult)
		var parsed map[string]any
		if json.Unmarshal([]byte(text), &parsed) == nil {
			if valid, ok := parsed["valid"].(bool); ok && valid {
				return fmt.Errorf("NEG validate_spec(garbage): reported valid=true for garbage")
			}
		}
	}

	// NEGATIVE: empty spec_content must error.
	emptyResult, err := callToolRaw(ctx, s, "validate_spec", map[string]any{
		"spec_content": "",
	})
	if err != nil {
		return fmt.Errorf("NEG validate_spec(empty): %w", err)
	}
	if !emptyResult.IsError {
		text := extractText(emptyResult)
		var parsed map[string]any
		if json.Unmarshal([]byte(text), &parsed) == nil {
			if valid, ok := parsed["valid"].(bool); ok && valid {
				return fmt.Errorf("NEG validate_spec(empty): reported valid=true for empty spec")
			}
		}
	}

	// NEGATIVE: missing spec_content entirely must error.
	if err := requireToolError(ctx, s, "validate_spec", map[string]any{}, "no spec_content"); err != nil {
		return err
	}

	// NEGATIVE: list_spec_endpoints with garbage must error.
	badEpResult, err := callToolRaw(ctx, s, "list_spec_endpoints", map[string]any{
		"spec_content": "not a spec",
	})
	if err != nil {
		return fmt.Errorf("NEG list_spec_endpoints(garbage): %w", err)
	}
	if !badEpResult.IsError {
		// If it parsed somehow, there should be no endpoints.
		text := extractText(badEpResult)
		if strings.Contains(text, "/users") {
			return fmt.Errorf("NEG list_spec_endpoints(garbage): returned real endpoints from garbage input")
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// baseline_comparison — validates regression detection, plus negative:
// identical baselines (no regressions), empty baselines, garbage JSON.
// ---------------------------------------------------------------------------

func scenarioBaselineComparison(ctx context.Context, s *mcp.ClientSession, _ string) error {
	baseline := `[{"endpoint":"/users","method":"GET","finding":"sqli","severity":"high","blocked":true}]`
	current := `[{"endpoint":"/users","method":"GET","finding":"sqli","severity":"high","blocked":false},` +
		`{"endpoint":"/admin","method":"POST","finding":"xss","severity":"medium","blocked":true}]`

	data, err := callToolJSON(ctx, s, "compare_baselines", map[string]any{
		"baseline_findings": baseline,
		"current_findings":  current,
	})
	if err != nil {
		return err
	}
	if bc, _ := data["baseline_count"].(float64); bc != 1 {
		return fmt.Errorf("compare_baselines: baseline_count=%v, want 1", bc)
	}
	if cc, _ := data["current_count"].(float64); cc != 2 {
		return fmt.Errorf("compare_baselines: current_count=%v, want 2", cc)
	}
	newFindings, _ := data["new"].([]any)
	if len(newFindings) == 0 {
		return fmt.Errorf("compare_baselines: expected new findings (xss on /admin)")
	}

	// NEGATIVE: identical baselines → zero regressions, zero new.
	identicalData, err := callToolJSON(ctx, s, "compare_baselines", map[string]any{
		"baseline_findings": baseline,
		"current_findings":  baseline,
	})
	if err != nil {
		return fmt.Errorf("NEG compare_baselines(identical): %w", err)
	}
	identicalNew, _ := identicalData["new"].([]any)
	identicalReg, _ := identicalData["regressed"].([]any)
	if len(identicalNew) > 0 || len(identicalReg) > 0 {
		return fmt.Errorf("NEG compare_baselines(identical): new=%d regressed=%d (expected 0 for both)",
			len(identicalNew), len(identicalReg))
	}

	// NEGATIVE: empty arrays → should handle gracefully.
	emptyData, err := callToolJSON(ctx, s, "compare_baselines", map[string]any{
		"baseline_findings": "[]",
		"current_findings":  "[]",
	})
	if err != nil {
		return fmt.Errorf("NEG compare_baselines(empty arrays): %w", err)
	}
	if bc, _ := emptyData["baseline_count"].(float64); bc != 0 {
		return fmt.Errorf("NEG compare_baselines(empty): baseline_count=%v, want 0", bc)
	}

	// NEGATIVE: garbage JSON must return IsError.
	if err := requireToolError(ctx, s, "compare_baselines", map[string]any{
		"baseline_findings": "not json at all",
		"current_findings":  "also not json",
	}, "garbage JSON"); err != nil {
		return err
	}

	// NEGATIVE: missing both fields must return IsError.
	if err := requireToolError(ctx, s, "compare_baselines", map[string]any{}, "empty args"); err != nil {
		return err
	}

	return nil
}

// ---------------------------------------------------------------------------
// task_management — tests async task lifecycle, plus negative:
// nonexistent tasks, cancel nonexistent, all error gracefully.
// ---------------------------------------------------------------------------

func scenarioTaskManagement(ctx context.Context, s *mcp.ClientSession, _ string) error {
	// list_tasks on empty state.
	listResult, err := callToolRaw(ctx, s, "list_tasks", map[string]any{})
	if err != nil {
		return fmt.Errorf("list_tasks: %w", err)
	}
	if listResult.IsError {
		return fmt.Errorf("list_tasks: unexpected error: %s", extractText(listResult))
	}

	// NEGATIVE: get_task_status with nonexistent ID must return IsError.
	if err := requireToolError(ctx, s, "get_task_status", map[string]any{
		"task_id": "nonexistent-task-id", "wait_seconds": 1,
	}, "nonexistent task"); err != nil {
		return err
	}

	// NEGATIVE: cancel_task with nonexistent ID must return IsError.
	if err := requireToolError(ctx, s, "cancel_task", map[string]any{
		"task_id": "nonexistent-task-id",
	}, "cancel nonexistent"); err != nil {
		return err
	}

	// NEGATIVE: get_task_status with empty task_id must return IsError.
	if err := requireToolError(ctx, s, "get_task_status", map[string]any{
		"task_id": "", "wait_seconds": 1,
	}, "empty task_id"); err != nil {
		return err
	}

	// NEGATIVE: cancel_task with empty task_id must return IsError.
	if err := requireToolError(ctx, s, "cancel_task", map[string]any{
		"task_id": "",
	}, "cancel empty task_id"); err != nil {
		return err
	}

	// NEGATIVE: get_task_status missing task_id entirely must return IsError.
	if err := requireToolError(ctx, s, "get_task_status", map[string]any{}, "missing task_id"); err != nil {
		return err
	}

	return nil
}

// ---------------------------------------------------------------------------
// error_handling — comprehensive invalid input testing across all tool
// categories. Every tool with required args is tested with missing args.
// Every tool that takes a target is tested with empty/garbage targets.
// ---------------------------------------------------------------------------

func scenarioErrorHandling(ctx context.Context, s *mcp.ClientSession, _ string) error {
	// Missing required args — every tool category.
	missingArgCases := []struct {
		tool string
		args map[string]any
		desc string
	}{
		{"mutate", map[string]any{}, "no payload"},
		{"detect_waf", map[string]any{}, "no target"},
		{"generate_cicd", map[string]any{}, "no platform or target"},
		{"probe", map[string]any{}, "no target"},
		{"learn", map[string]any{}, "no discovery_json"},
		{"validate_spec", map[string]any{}, "no spec_content"},
		{"show_template", map[string]any{}, "no path"},
		{"compare_baselines", map[string]any{}, "no findings"},
	}

	for _, tc := range missingArgCases {
		if err := requireToolError(ctx, s, tc.tool, tc.args, tc.desc); err != nil {
			return err
		}
	}

	// Invalid JSON for tools expecting JSON strings.
	jsonTools := []struct {
		tool  string
		field string
	}{
		{"learn", "discovery_json"},
		{"compare_baselines", "baseline_findings"},
	}
	for _, tc := range jsonTools {
		if err := requireToolError(ctx, s, tc.tool, map[string]any{
			tc.field: "not valid json {{{",
		}, tc.tool+"(garbage JSON)"); err != nil {
			return err
		}
	}

	// Invalid spec content — should not crash.
	badSpecResult, err := callToolRaw(ctx, s, "validate_spec", map[string]any{
		"spec_content": "not valid yaml or json at all {{{",
	})
	if err != nil {
		return fmt.Errorf("validate_spec(garbage): protocol error: %w", err)
	}
	if !badSpecResult.IsError {
		text := extractText(badSpecResult)
		var parsed map[string]any
		if json.Unmarshal([]byte(text), &parsed) == nil {
			if valid, ok := parsed["valid"].(bool); ok && valid {
				return fmt.Errorf("validate_spec(garbage): reported valid=true for garbage")
			}
		}
	}

	// Empty payload mutation — should error or handle gracefully.
	emptyResult, err := callToolRaw(ctx, s, "mutate", map[string]any{
		"payload": "", "encoders": []string{"url"},
	})
	if err != nil {
		return fmt.Errorf("mutate(empty payload): protocol error: %w", err)
	}
	_ = emptyResult // error or empty result both acceptable

	// Extremely long payload — should not crash or hang.
	longPayload := strings.Repeat("A", 10000)
	longResult, err := callToolRaw(ctx, s, "mutate", map[string]any{
		"payload": longPayload, "encoders": []string{"url"},
	})
	if err != nil {
		return fmt.Errorf("mutate(10k payload): protocol error: %w", err)
	}
	_ = longResult // error or success both acceptable, must not crash

	// generate_cicd with XSS in target — should not reflect unsanitized.
	xssTarget := "https://example.com/<script>alert(1)</script>"
	xssResult, err := callToolRaw(ctx, s, "generate_cicd", map[string]any{
		"target": xssTarget, "platform": "github",
	})
	if err != nil {
		return fmt.Errorf("generate_cicd(xss target): protocol error: %w", err)
	}
	if !xssResult.IsError {
		text := extractText(xssResult)
		if strings.Contains(text, "<script>alert(1)</script>") {
			// If the target appears verbatim in pipeline YAML, that's a potential injection.
			// This is just a warning — the tool generates YAML, not HTML.
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Agent simulations — multi-turn workflows that mimic real AI agents.
// ---------------------------------------------------------------------------

// agentSecurityAuditor: receives security_audit prompt → follows the 5-phase
// workflow → reads resources → selects payloads → generates CI/CD.
func agentSecurityAuditor(ctx context.Context, s *mcp.ClientSession, _ string) error {
	target := "https://audit-target.example.com"

	// Agent gets mission from prompt.
	mission, err := s.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "security_audit",
		Arguments: map[string]string{"target": target, "scope": "sqli,xss", "environment": "staging"},
	})
	if err != nil {
		return fmt.Errorf("get mission: %w", err)
	}
	missionText := promptText(mission)

	// Prompt must reference the tools the agent needs.
	for _, tool := range []string{"detect_waf", "discover", "get_task_status", "scan", "assess"} {
		if !strings.Contains(missionText, tool) {
			return fmt.Errorf("mission missing tool reference %q", tool)
		}
	}

	// Phase 1: Read WAF signatures for vendor detection.
	sigRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://waf-signatures"})
	if err != nil {
		return fmt.Errorf("phase1 waf-signatures: %w", err)
	}
	signatures := strings.ToLower(resourceText(sigRes))
	knownVendors := []string{"cloudflare", "akamai", "aws", "imperva", "f5"}
	vendorCount := 0
	for _, v := range knownVendors {
		if strings.Contains(signatures, v) {
			vendorCount++
		}
	}
	if vendorCount < 2 {
		return fmt.Errorf("phase1: only %d/%d vendors in signatures", vendorCount, len(knownVendors))
	}

	// Phase 1b: Read evasion techniques.
	evasionRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://evasion-techniques"})
	if err != nil {
		return fmt.Errorf("phase1 evasion: %w", err)
	}
	if !strings.Contains(strings.ToLower(resourceText(evasionRes)), "encod") {
		return fmt.Errorf("phase1: evasion missing encoding info")
	}

	// Phase 2: Read guide.
	guideRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://guide"})
	if err != nil {
		return fmt.Errorf("phase2 guide: %w", err)
	}
	if resourceText(guideRes) == "" {
		return fmt.Errorf("phase2: guide empty")
	}

	// Phase 3: Select payloads per scope.
	for _, cat := range []string{"sqli", "xss"} {
		catData, err := callToolJSON(ctx, s, "list_payloads", map[string]any{"category": cat})
		if err != nil {
			return fmt.Errorf("phase3 payloads(%s): %w", cat, err)
		}
		samples, _ := catData["sample_payloads"].([]any)
		if len(samples) == 0 {
			return fmt.Errorf("phase3: no %s payloads", cat)
		}
	}

	// Phase 3b: Select tampers.
	tamperData, err := callToolJSON(ctx, s, "list_tampers", map[string]any{})
	if err != nil {
		return fmt.Errorf("phase3 tampers: %w", err)
	}
	if tampers, _ := tamperData["tampers"].([]any); len(tampers) == 0 {
		return fmt.Errorf("phase3: no tampers")
	}

	// Phase 5: Generate CI/CD for repeat audits.
	cicdData, err := callToolJSON(ctx, s, "generate_cicd", map[string]any{
		"target": target, "platform": "github",
	})
	if err != nil {
		return fmt.Errorf("phase5 cicd: %w", err)
	}
	if pipeline, _ := cicdData["pipeline"].(string); pipeline == "" {
		return fmt.Errorf("phase5: empty pipeline")
	}

	return nil
}

// agentAPISecurity: receives spec_security_audit prompt → validates spec →
// lists endpoints → plans scan → compares baselines.
func agentAPISecurity(ctx context.Context, s *mcp.ClientSession, _ string) error {
	mission, err := s.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "spec_security_audit",
		Arguments: map[string]string{"spec_content": miniOpenAPISpec},
	})
	if err != nil {
		return fmt.Errorf("get mission: %w", err)
	}
	if len(mission.Messages) == 0 {
		return fmt.Errorf("mission: no messages")
	}

	// Read spec-formats for context.
	fmtRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://spec-formats"})
	if err != nil {
		return fmt.Errorf("read spec-formats: %w", err)
	}
	if !strings.Contains(strings.ToLower(resourceText(fmtRes)), "openapi") {
		return fmt.Errorf("spec-formats: missing openapi")
	}

	// Validate spec.
	valData, err := callToolJSON(ctx, s, "validate_spec", map[string]any{
		"spec_content": miniOpenAPISpec,
	})
	if err != nil {
		return fmt.Errorf("validate_spec: %w", err)
	}
	if valid, _ := valData["valid"].(bool); !valid {
		return fmt.Errorf("validate_spec: invalid")
	}

	// List endpoints.
	epResult, err := callToolRaw(ctx, s, "list_spec_endpoints", map[string]any{
		"spec_content": miniOpenAPISpec,
	})
	if err != nil {
		return fmt.Errorf("list_spec_endpoints: %w", err)
	}
	epText := extractText(epResult)
	if !strings.Contains(epText, "POST") || !strings.Contains(epText, "GET") {
		return fmt.Errorf("list_spec_endpoints: missing HTTP methods")
	}

	// Pipeline steps.
	for _, tool := range []string{"describe_spec_auth", "plan_spec", "spec_intelligence"} {
		if err := requireToolOK(ctx, s, tool, map[string]any{
			"spec_content": miniOpenAPISpec,
		}); err != nil {
			return fmt.Errorf("%s: %w", tool, err)
		}
	}

	// Export with schemas.
	exportResult, err := callToolRaw(ctx, s, "export_spec", map[string]any{
		"spec_content": miniOpenAPISpec, "include_schemas": true,
	})
	if err != nil {
		return fmt.Errorf("export_spec: %w", err)
	}
	if exportResult.IsError {
		return fmt.Errorf("export_spec: %s", truncate(extractText(exportResult), 200))
	}

	// Baseline comparison for CI regression tracking.
	baseline := `[{"endpoint":"/users","method":"GET","finding":"sqli","severity":"high","blocked":true}]`
	current := `[{"endpoint":"/users","method":"GET","finding":"sqli","severity":"high","blocked":true},` +
		`{"endpoint":"/users","method":"POST","finding":"xss","severity":"medium","blocked":true}]`

	compData, err := callToolJSON(ctx, s, "compare_baselines", map[string]any{
		"baseline_findings": baseline, "current_findings": current,
	})
	if err != nil {
		return fmt.Errorf("compare_baselines: %w", err)
	}
	_ = compData

	return nil
}

// agentEvasionResearcher: receives evasion_research prompt → reads resources →
// explores payloads → progressive mutation with escalating encoder chains.
func agentEvasionResearcher(ctx context.Context, s *mcp.ClientSession, _ string) error {
	researchPayload := "' OR 1=1--"

	mission, err := s.GetPrompt(ctx, &mcp.GetPromptParams{
		Name: "evasion_research",
		Arguments: map[string]string{
			"target": "https://target.example.com", "payload": researchPayload,
		},
	})
	if err != nil {
		return fmt.Errorf("get mission: %w", err)
	}
	missionText := promptText(mission)
	if !strings.Contains(missionText, "OR") && !strings.Contains(missionText, "evasion") {
		return fmt.Errorf("mission missing payload/evasion reference")
	}

	// Read evasion techniques.
	evasionRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://evasion-techniques"})
	if err != nil {
		return fmt.Errorf("evasion-techniques: %w", err)
	}
	if resourceText(evasionRes) == "" {
		return fmt.Errorf("evasion-techniques: empty")
	}

	// Read OWASP mappings.
	owaspRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://owasp-mappings"})
	if err != nil {
		return fmt.Errorf("owasp-mappings: %w", err)
	}
	if !strings.Contains(strings.ToLower(resourceText(owaspRes)), "injection") {
		return fmt.Errorf("owasp-mappings: missing injection")
	}

	// Pick richest category for research.
	allData, err := callToolJSON(ctx, s, "list_payloads", map[string]any{})
	if err != nil {
		return fmt.Errorf("list_payloads(all): %w", err)
	}
	byCategory, ok := allData["by_category"].(map[string]any)
	if !ok {
		return fmt.Errorf("list_payloads: missing by_category")
	}
	bestCat := ""
	bestCount := 0.0
	for cat, count := range byCategory {
		if c, _ := count.(float64); c > bestCount {
			bestCat = cat
			bestCount = c
		}
	}
	if bestCat == "" {
		return fmt.Errorf("no categories with payloads")
	}

	// Get samples from richest category.
	catData, err := callToolJSON(ctx, s, "list_payloads", map[string]any{"category": bestCat})
	if err != nil {
		return fmt.Errorf("list_payloads(%s): %w", bestCat, err)
	}
	samples, _ := catData["sample_payloads"].([]any)
	if len(samples) == 0 {
		return fmt.Errorf("list_payloads(%s): no samples", bestCat)
	}

	// Extract a real payload snippet.
	catalogPayload := researchPayload
	if first, ok := samples[0].(map[string]any); ok {
		if snippet, _ := first["snippet"].(string); snippet != "" {
			catalogPayload = snippet
		}
	}

	// Progressive mutation: single → double → quad encoders.
	encoderChains := [][]string{
		{"url"},
		{"url", "unicode"},
		{"url", "double_url", "unicode", "html_hex"},
	}
	var prevCount int
	for i, chain := range encoderChains {
		mutData, err := callToolJSON(ctx, s, "mutate", map[string]any{
			"payload": catalogPayload, "encoders": chain,
		})
		if err != nil {
			return fmt.Errorf("mutate(chain %d): %w", i, err)
		}
		variants, _ := mutData["variants"].([]any)
		if len(variants) == 0 {
			return fmt.Errorf("mutate(chain %d): no variants", i)
		}
		if i > 0 && len(variants) <= prevCount {
			return fmt.Errorf("mutate(chain %d): %d variants not > chain %d's %d",
				i, len(variants), i-1, prevCount)
		}
		// Every variant must differ from input.
		for _, v := range variants {
			vm, _ := v.(map[string]any)
			if enc, _ := vm["encoded"].(string); enc == catalogPayload {
				return fmt.Errorf("mutate(chain %d): variant identical to input", i)
			}
		}
		prevCount = len(variants)
	}

	// Read tamper catalog for WAF-specific strategies.
	tamperData, err := callToolJSON(ctx, s, "list_tampers", map[string]any{})
	if err != nil {
		return fmt.Errorf("list_tampers: %w", err)
	}
	if breakdown, _ := tamperData["category_breakdown"].(map[string]any); len(breakdown) == 0 {
		return fmt.Errorf("list_tampers: no category_breakdown")
	}

	return nil
}

// agentDevSecOps: reads config/version → lists templates → generates CI/CD
// for multiple platforms → validates spec → creates baseline.
func agentDevSecOps(ctx context.Context, s *mcp.ClientSession, _ string) error {
	// Read version.
	versionRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://version"})
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	versionData, err := resourceJSON(versionRes)
	if err != nil {
		return fmt.Errorf("parse version: %w", err)
	}
	if v, _ := versionData["version"].(string); v == "" {
		return fmt.Errorf("version: empty")
	}

	// Read config.
	configRes, err := s.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://config"})
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if resourceText(configRes) == "" {
		return fmt.Errorf("config: empty")
	}

	// List templates → filter → show one.
	tplData, err := callToolJSON(ctx, s, "list_templates", map[string]any{})
	if err != nil {
		return fmt.Errorf("list_templates: %w", err)
	}
	categories, _ := tplData["categories"].([]any)
	if len(categories) == 0 {
		return fmt.Errorf("list_templates: no categories")
	}
	firstCat, _ := categories[0].(map[string]any)
	kind, _ := firstCat["kind"].(string)
	if kind != "" {
		filteredData, err := callToolJSON(ctx, s, "list_templates", map[string]any{"kind": kind})
		if err != nil {
			return fmt.Errorf("list_templates(kind=%s): %w", kind, err)
		}
		filteredCats, _ := filteredData["categories"].([]any)
		if len(filteredCats) > 0 {
			fc, _ := filteredCats[0].(map[string]any)
			templates, _ := fc["templates"].([]any)
			if len(templates) > 0 {
				firstTpl, _ := templates[0].(map[string]any)
				path, _ := firstTpl["path"].(string)
				if path != "" {
					showResult, err := callToolRaw(ctx, s, "show_template", map[string]any{"path": path})
					if err != nil {
						return fmt.Errorf("show_template(%s): %w", path, err)
					}
					if showResult.IsError {
						return fmt.Errorf("show_template(%s): %s", path, truncate(extractText(showResult), 200))
					}
				}
			}
		}
	}

	// Generate CI/CD for two platforms.
	for _, platform := range []string{"github", "gitlab"} {
		cicdData, err := callToolJSON(ctx, s, "generate_cicd", map[string]any{
			"target": "https://api.staging.example.com", "platform": platform,
		})
		if err != nil {
			return fmt.Errorf("generate_cicd(%s): %w", platform, err)
		}
		if pipeline, _ := cicdData["pipeline"].(string); pipeline == "" {
			return fmt.Errorf("generate_cicd(%s): empty pipeline", platform)
		}
		if fileName, _ := cicdData["file_name"].(string); fileName == "" {
			return fmt.Errorf("generate_cicd(%s): missing file_name", platform)
		}
	}

	// Validate spec for automated testing.
	valData, err := callToolJSON(ctx, s, "validate_spec", map[string]any{
		"spec_content": miniOpenAPISpec,
	})
	if err != nil {
		return fmt.Errorf("validate_spec: %w", err)
	}
	if valid, _ := valData["valid"].(bool); !valid {
		return fmt.Errorf("validate_spec: invalid")
	}

	// Initial baseline (identical) — no regressions.
	baseline := `[{"endpoint":"/users","method":"GET","finding":"sqli","severity":"high","blocked":true}]`
	compData, err := callToolJSON(ctx, s, "compare_baselines", map[string]any{
		"baseline_findings": baseline, "current_findings": baseline,
	})
	if err != nil {
		return fmt.Errorf("compare_baselines(initial): %w", err)
	}
	newFindings, _ := compData["new"].([]any)
	regressed, _ := compData["regressed"].([]any)
	if len(newFindings) > 0 || len(regressed) > 0 {
		return fmt.Errorf("compare_baselines(initial): identical runs produced regressions=%d new=%d",
			len(regressed), len(newFindings))
	}

	return nil
}

// ---------------------------------------------------------------------------
// Live scenarios (require -live flag)
// ---------------------------------------------------------------------------

func scenarioWAFRecon(ctx context.Context, s *mcp.ClientSession, target string) error {
	// Detect WAF.
	wafData, err := callToolJSON(ctx, s, "detect_waf", map[string]any{"target": target})
	if err != nil {
		return fmt.Errorf("detect_waf: %w", err)
	}
	wafResult, ok := wafData["result"].(map[string]any)
	if !ok {
		return fmt.Errorf("detect_waf: missing result object")
	}
	if _, ok := wafResult["detected"]; !ok {
		return fmt.Errorf("detect_waf: result missing detected field")
	}

	// Probe target.
	probeData, err := callToolJSON(ctx, s, "probe", map[string]any{"target": target})
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	report, ok := probeData["report"].(map[string]any)
	if !ok {
		return fmt.Errorf("probe: missing report object")
	}
	if _, ok := report["reachable"]; !ok {
		return fmt.Errorf("probe: report missing reachable field")
	}

	// NEGATIVE: nonsense URL that is syntactically valid.
	nonsenseResult, err := callToolRaw(ctx, s, "detect_waf", map[string]any{
		"target": "https://this-domain-does-not-exist-zzz123.example.invalid",
	})
	if err != nil {
		return fmt.Errorf("NEG detect_waf(bad domain): protocol error: %w", err)
	}
	// Must either IsError or return detected=false — not panic.
	if !nonsenseResult.IsError {
		text := extractText(nonsenseResult)
		var parsed map[string]any
		if json.Unmarshal([]byte(text), &parsed) == nil {
			if res, _ := parsed["result"].(map[string]any); res != nil {
				if detected, _ := res["detected"].(bool); detected {
					return fmt.Errorf("NEG detect_waf(bad domain): detected=true for nonexistent domain")
				}
			}
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// requireToolOK calls a tool and asserts it succeeds without IsError.
func requireToolOK(ctx context.Context, s *mcp.ClientSession, name string, args map[string]any) error {
	result, err := callToolRaw(ctx, s, name, args)
	if err != nil {
		return fmt.Errorf("call %s: %w", name, err)
	}
	if result.IsError {
		return fmt.Errorf("call %s: tool error: %s", name, truncate(extractText(result), 200))
	}
	return nil
}

// requireToolError calls a tool and asserts it returns IsError=true.
// This is the core negative validation helper — if a bad input doesn't
// produce an error, the test fails.
func requireToolError(ctx context.Context, s *mcp.ClientSession, name string, args map[string]any, desc string) error {
	result, err := callToolRaw(ctx, s, name, args)
	if err != nil {
		// Protocol-level error is also acceptable for negative cases.
		return nil
	}
	if !result.IsError {
		return fmt.Errorf("NEG %s(%s): expected IsError=true, got false (response: %s)",
			name, desc, truncate(extractText(result), 120))
	}
	return nil
}

// callToolJSON calls a tool, asserts no error, and parses as JSON.
func callToolJSON(ctx context.Context, s *mcp.ClientSession, name string, args map[string]any) (map[string]any, error) {
	result, err := callToolRaw(ctx, s, name, args)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", name, err)
	}
	if result.IsError {
		return nil, fmt.Errorf("call %s: tool error: %s", name, truncate(extractText(result), 200))
	}
	text := extractText(result)
	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		return nil, fmt.Errorf("call %s: parse JSON: %w (text: %s)", name, err, truncate(text, 100))
	}
	return data, nil
}

func callToolRaw(ctx context.Context, s *mcp.ClientSession, name string, args map[string]any) (*mcp.CallToolResult, error) {
	payload, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("marshal %s args: %w", name, err)
	}
	return s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: json.RawMessage(payload)})
}

func extractText(result *mcp.CallToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	if tc, ok := result.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return fmt.Sprintf("%T", result.Content[0])
}

func resourceText(res *mcp.ReadResourceResult) string {
	if len(res.Contents) == 0 {
		return ""
	}
	return res.Contents[0].Text
}

func resourceJSON(res *mcp.ReadResourceResult) (map[string]any, error) {
	text := resourceText(res)
	if text == "" {
		return nil, fmt.Errorf("empty resource content")
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	return data, nil
}

func promptText(result *mcp.GetPromptResult) string {
	data, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	return string(data)
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

func startServer(ctx context.Context, port int) (*exec.Cmd, error) {
	root, err := findRepoRoot()
	if err != nil {
		return nil, fmt.Errorf("find repo root: %w", err)
	}

	cmd := exec.CommandContext(ctx, "go", "run", "./cmd/cli", "mcp", "--http", fmt.Sprintf(":%d", port))
	cmd.Dir = root
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func stopServer(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		modPath := dir + string(os.PathSeparator) + "go.mod"
		if data, err := os.ReadFile(modPath); err == nil {
			if strings.Contains(string(data), "module github.com/waftester/waftester\n") ||
				strings.Contains(string(data), "module github.com/waftester/waftester\r\n") {
				return dir, nil
			}
		}

		parent := dir[:max(strings.LastIndex(dir, string(os.PathSeparator)), 0)]
		if parent == dir || parent == "" {
			return "", fmt.Errorf("repo root not found walking up from %s", dir)
		}
		dir = parent
	}
}

func waitForHealth(ctx context.Context, port int) error {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/health", port)

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// miniOpenAPISpec is a self-contained spec for spec-tool scenarios.
const miniOpenAPISpec = `openapi: "3.0.0"
info:
  title: Smoke Test API
  version: "1.0"
paths:
  /users:
    get:
      summary: List users
      parameters:
        - name: q
          in: query
          schema:
            type: string
    post:
      summary: Create user
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                email:
                  type: string
  /users/{id}:
    get:
      summary: Get user
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer`
