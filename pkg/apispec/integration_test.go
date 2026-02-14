package apispec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Integration tests validating the full spec scanning pipeline end-to-end:
//   - V1: Scan produces findings, findings reference correct endpoint/param
//   - V3: Full pipeline works for OpenAPI 3.0, Swagger 2.0, Postman, URL
//   - V9: CLI commands, output formats with endpoint-level data
// ===========================================================================

// mockVulnerableAPI returns an httptest.Server that responds with
// predictable status codes for testing. Endpoints under /admin return 200
// (simulating unrestricted access), others return 200 with reflected params.
func mockVulnerableAPI(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"path": %q, "method": %q}`, r.URL.Path, r.Method)
	}))
}

// vulnScanFunc is a ScanFunc that generates deterministic findings
// for each endpoint, simulating what real scanners would produce.
func vulnScanFunc(_ context.Context, category string, targetURL string, ep Endpoint) ([]SpecFinding, error) {
	// Generate one finding per scan entry.
	param := "id"
	for _, p := range ep.Parameters {
		param = p.Name
		break
	}

	return []SpecFinding{
		{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: CorrelationTag(ep.Method, ep.Path),
			Category:       category,
			Parameter:      param,
			Location:       "query",
			Payload:        "' OR 1=1--",
			Title:          fmt.Sprintf("%s vulnerability in %s %s", category, ep.Method, ep.Path),
			Description:    "Test finding from integration test",
			Severity:       "high",
			Type:           "vulnerability",
			Evidence:       "HTTP 200 with payload reflected",
			CWE:            "CWE-89",
		},
	}, nil
}

// buildTestOpenAPI3Spec returns an OpenAPI 3.0 spec YAML targeting the given base URL.
func buildTestOpenAPI3Spec(baseURL string) string {
	return fmt.Sprintf(`openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: %s
paths:
  /users:
    get:
      operationId: listUsers
      summary: List users
      parameters:
        - name: search
          in: query
          schema:
            type: string
      responses:
        "200":
          description: OK
    post:
      operationId: createUser
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
      responses:
        "201":
          description: Created
  /users/{id}:
    get:
      operationId: getUser
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      responses:
        "200":
          description: OK
  /admin/settings:
    get:
      operationId: adminSettings
      security:
        - bearerAuth: []
      responses:
        "200":
          description: OK
`, baseURL)
}

// buildTestSwagger2Spec returns a Swagger 2.0 spec JSON targeting the given base URL.
func buildTestSwagger2Spec(baseURL string) string {
	// Strip scheme for host field.
	host := strings.TrimPrefix(strings.TrimPrefix(baseURL, "http://"), "https://")
	scheme := "http"
	if strings.HasPrefix(baseURL, "https://") {
		scheme = "https"
	}

	return fmt.Sprintf(`{
  "swagger": "2.0",
  "info": {"title": "Test API", "version": "1.0"},
  "host": %q,
  "schemes": [%q],
  "basePath": "/",
  "paths": {
    "/users": {
      "get": {
        "operationId": "listUsers",
        "parameters": [
          {"name": "search", "in": "query", "type": "string"}
        ],
        "responses": {"200": {"description": "OK"}}
      }
    },
    "/users/{id}": {
      "get": {
        "operationId": "getUser",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "type": "integer"}
        ],
        "responses": {"200": {"description": "OK"}}
      }
    }
  }
}`, host, scheme)
}

// buildTestPostmanCollection returns a Postman v2.1 collection JSON targeting the given base URL.
func buildTestPostmanCollection(baseURL string) string {
	return fmt.Sprintf(`{
  "info": {
    "name": "Test Collection",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [
    {"key": "baseUrl", "value": %q}
  ],
  "item": [
    {
      "name": "List Users",
      "request": {
        "method": "GET",
        "url": {
          "raw": "{{baseUrl}}/users?search=test",
          "host": ["{{baseUrl}}"],
          "path": ["users"],
          "query": [{"key": "search", "value": "test"}]
        }
      }
    },
    {
      "name": "Get User",
      "request": {
        "method": "GET",
        "url": {
          "raw": "{{baseUrl}}/users/123",
          "host": ["{{baseUrl}}"],
          "path": ["users", "123"]
        }
      }
    }
  ]
}`, baseURL)
}

// ---------------------------------------------------------------------------
// V1: Scan produces findings with correct endpoint and parameter references
// ---------------------------------------------------------------------------

func TestIntegration_ScanProducesFindings(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	spec, err := ParseContent(specYAML)
	require.NoError(t, err)
	require.NotNil(t, spec)

	cfg := &SpecConfig{
		ScanTypes: []string{"sqli"},
		Intensity: IntensityNormal,
	}
	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)
	require.NotEmpty(t, plan.Entries, "plan should have entries")

	exec := &SimpleExecutor{
		BaseURL:     srv.URL,
		ScanFn:      vulnScanFunc,
		Concurrency: 1,
	}

	session, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)
	require.NotNil(t, session)

	// V1 checklist item: "Scan produces findings (at least one)"
	assert.Greater(t, session.TotalFindings, 0, "should produce at least one finding")

	result := session.Result
	require.NotNil(t, result)

	for _, f := range result.Findings {
		// V1 checklist item: "Each finding references the correct endpoint (method + path)"
		assert.NotEmpty(t, f.Method, "finding must have Method")
		assert.NotEmpty(t, f.Path, "finding must have Path")
		assert.True(t, f.Method == "GET" || f.Method == "POST",
			"finding Method should be GET or POST, got %s", f.Method)
		assert.True(t, strings.HasPrefix(f.Path, "/"),
			"finding Path should start with /, got %s", f.Path)

		// V1 checklist item: "Findings include parameter injection point"
		assert.NotEmpty(t, f.Parameter, "finding must include parameter name")
		assert.NotEmpty(t, f.Category, "finding must include category")
	}
}

func TestIntegration_FindingsReferenceCorrectEndpoint(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	spec, err := ParseContent(specYAML)
	require.NoError(t, err)

	cfg := &SpecConfig{
		ScanTypes: []string{"sqli"},
		Intensity: IntensityNormal,
	}
	plan := BuildSimplePlan(spec, cfg)

	// Track which endpoints were scanned.
	scannedEndpoints := make(map[string]bool)

	exec := &SimpleExecutor{
		BaseURL: srv.URL,
		ScanFn:  vulnScanFunc,
		OnEndpointStart: func(ep Endpoint, scanType string) {
			scannedEndpoints[ep.Method+" "+ep.Path] = true
		},
		Concurrency: 1,
	}

	session, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)

	// Every finding's method+path should match a planned endpoint.
	for _, f := range session.Result.Findings {
		key := f.Method + " " + f.Path
		assert.True(t, scannedEndpoints[key],
			"finding references %s but that endpoint was not scanned", key)
	}
}

// ---------------------------------------------------------------------------
// V3: Full pipeline works for each spec format
// ---------------------------------------------------------------------------

func TestIntegration_OpenAPI3EndToEnd(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	session := runFullPipeline(t, specYAML, srv.URL)

	assert.Greater(t, session.TotalFindings, 0, "OpenAPI 3.0 scan should produce findings")
	assert.Greater(t, session.TotalEndpoints, 0, "should scan at least one endpoint")
}

func TestIntegration_Swagger2EndToEnd(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specJSON := buildTestSwagger2Spec(srv.URL)
	session := runFullPipeline(t, specJSON, srv.URL)

	assert.Greater(t, session.TotalFindings, 0, "Swagger 2.0 scan should produce findings")
	assert.Greater(t, session.TotalEndpoints, 0, "should scan at least one endpoint")
}

func TestIntegration_PostmanEndToEnd(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specJSON := buildTestPostmanCollection(srv.URL)
	session := runFullPipeline(t, specJSON, srv.URL)

	assert.Greater(t, session.TotalFindings, 0, "Postman scan should produce findings")
	assert.Greater(t, session.TotalEndpoints, 0, "should scan at least one endpoint")
}

func TestIntegration_SpecFromURL(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)

	// Serve the spec itself via HTTP.
	specServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Write([]byte(specYAML))
	}))
	defer specServer.Close()

	// Parse from URL.
	spec, err := Parse(specServer.URL + "/api.yaml")
	require.NoError(t, err)
	require.NotNil(t, spec)
	assert.NotEmpty(t, spec.Endpoints, "spec from URL should have endpoints")

	cfg := &SpecConfig{
		ScanTypes: []string{"sqli"},
		Intensity: IntensityNormal,
	}
	plan := BuildSimplePlan(spec, cfg)
	require.NotEmpty(t, plan.Entries)

	exec := &SimpleExecutor{
		BaseURL:     srv.URL,
		ScanFn:      vulnScanFunc,
		Concurrency: 1,
	}

	session, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)
	assert.Greater(t, session.TotalFindings, 0, "scan from URL-fetched spec should produce findings")
}

// ---------------------------------------------------------------------------
// V9: JSON output contains endpoint-level data
// ---------------------------------------------------------------------------

func TestIntegration_JSONOutputContainsEndpointData(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	session := runFullPipeline(t, specYAML, srv.URL)

	// Serialize result to JSON.
	data, err := json.MarshalIndent(session.Result, "", "  ")
	require.NoError(t, err)

	// Parse it back to verify structure.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))

	// Findings array must exist and have entries.
	findings, ok := parsed["findings"].([]any)
	require.True(t, ok, "JSON output must contain 'findings' array")
	require.NotEmpty(t, findings, "findings should not be empty")

	// Each finding must have endpoint-level fields.
	for i, f := range findings {
		fm, ok := f.(map[string]any)
		require.True(t, ok, "finding %d should be an object", i)
		assert.NotEmpty(t, fm["method"], "finding %d missing 'method'", i)
		assert.NotEmpty(t, fm["path"], "finding %d missing 'path'", i)
		assert.NotEmpty(t, fm["category"], "finding %d missing 'category'", i)
		assert.NotEmpty(t, fm["severity"], "finding %d missing 'severity'", i)
	}

	// Top-level spec context fields.
	assert.NotEmpty(t, parsed["spec_source"], "JSON should contain spec_source")
	assert.NotNil(t, parsed["total_endpoints"], "JSON should contain total_endpoints")
}

func TestIntegration_DryRunOutputIsValidJSON(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	spec, err := ParseContent(specYAML)
	require.NoError(t, err)

	cfg := &SpecConfig{
		ScanTypes: []string{"sqli", "xss"},
		Intensity: IntensityNormal,
	}
	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)

	// Serialize plan (this is what --dry-run outputs).
	data, err := json.MarshalIndent(plan, "", "  ")
	require.NoError(t, err)

	// Must be valid JSON.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed), "dry-run output must be valid JSON")

	// Must contain entries with endpoint info.
	entries, ok := parsed["entries"].([]any)
	require.True(t, ok, "plan JSON must contain 'entries' array")
	require.NotEmpty(t, entries)

	for i, e := range entries {
		em, ok := e.(map[string]any)
		require.True(t, ok, "entry %d should be an object", i)
		ep, ok := em["endpoint"].(map[string]any)
		require.True(t, ok, "entry %d should have 'endpoint' object", i)
		assert.NotEmpty(t, ep["method"], "entry %d endpoint missing 'method'", i)
		assert.NotEmpty(t, ep["path"], "entry %d endpoint missing 'path'", i)
	}
}

// ---------------------------------------------------------------------------
// V9: Preview (table) output includes endpoint-level data
// ---------------------------------------------------------------------------

func TestIntegration_PreviewOutputContainsEndpoints(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	spec, err := ParseContent(specYAML)
	require.NoError(t, err)

	cfg := &SpecConfig{
		ScanTypes: []string{"sqli"},
		Intensity: IntensityNormal,
	}
	plan := BuildSimplePlan(spec, cfg)

	var buf bytes.Buffer
	RenderPreview(&buf, plan, spec, DefaultPreviewConfig())

	output := buf.String()

	// Preview should contain endpoint paths.
	assert.Contains(t, output, "/users", "preview should mention /users endpoint")
	assert.Contains(t, output, "Endpoints:", "preview should show endpoint count")
	assert.Contains(t, output, "Total tests:", "preview should show total tests")
}

// ---------------------------------------------------------------------------
// Gap 129: Golden file tests for JSON and table output
// ---------------------------------------------------------------------------

func TestGolden_JSONOutput(t *testing.T) {
	t.Parallel()

	result := buildDeterministicResult()
	data, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)

	compareWithGolden(t, "result.json", data)
}

func TestGolden_PreviewOutput(t *testing.T) {
	t.Parallel()

	spec, plan := buildDeterministicPlanForGolden()

	var buf bytes.Buffer
	RenderPreview(&buf, plan, spec, PreviewConfig{
		MaxEndpoints:      50,
		ShowReasons:       true,
		ShowPayloadCounts: true,
	})

	compareWithGolden(t, "preview.txt", buf.Bytes())
}

func TestGolden_DryRunJSON(t *testing.T) {
	t.Parallel()

	_, plan := buildDeterministicPlanForGolden()
	data, err := json.MarshalIndent(plan, "", "  ")
	require.NoError(t, err)

	compareWithGolden(t, "dryrun.json", data)
}

// ---------------------------------------------------------------------------
// V9: Resume from checkpoint (scan --spec ... --resume)
// Validates that a checkpoint can be saved, loaded, and resumed mid-scan.
// ---------------------------------------------------------------------------

func TestIntegration_ResumeFromCheckpoint(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	spec, err := ParseContent(specYAML)
	require.NoError(t, err)

	cfg := &SpecConfig{
		SpecContent: specYAML,
		ScanTypes:   []string{"sqli"},
		Intensity:   IntensityNormal,
	}
	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)
	require.True(t, len(plan.Entries) >= 2, "need at least 2 entries for resume test")

	// Create a checkpoint simulating partial completion (first entry done).
	cp := NewCheckpoint("test-resume-session", plan)
	cp.MarkCompleted(0)

	// Verify progress.
	assert.Greater(t, cp.Progress(), 0.0, "progress should be > 0 after marking one entry")
	assert.Less(t, cp.Progress(), 1.0, "progress should be < 1 before all entries complete")

	// Save checkpoint to the standard checkpoint directory.
	require.NoError(t, cp.Save())
	defer func() { _ = DeleteCheckpoint("test-resume-session") }()

	// Load checkpoint and verify state.
	loaded, loadErr := LoadCheckpoint("test-resume-session")
	require.NoError(t, loadErr)
	require.NotNil(t, loaded)

	remaining := loaded.RemainingEntries(len(plan.Entries))
	assert.Less(t, len(remaining), len(plan.Entries),
		"remaining entries should be fewer than total after partial completion")
	assert.Equal(t, len(plan.Entries)-1, len(remaining),
		"should have completed exactly one entry")

	// Validate resume compatibility — same plan should return empty string.
	msg := ValidateResume(loaded, plan)
	assert.Empty(t, msg, "checkpoint should be compatible with the same plan")
}

// ---------------------------------------------------------------------------
// V9: Compare baselines (auto --spec ... --compare baseline.json)
// Validates that baseline save+load+compare works through the pipeline.
// ---------------------------------------------------------------------------

func TestIntegration_CompareBaseline(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	session := runFullPipeline(t, specYAML, srv.URL)
	require.NotEmpty(t, session.Result.Findings)

	// Save findings as baseline.
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	require.NoError(t, SaveBaseline(baselinePath, session.Result.Findings, "test-spec"))

	// Load baseline.
	loaded, loadErr := LoadBaseline(baselinePath)
	require.NoError(t, loadErr)
	assert.Equal(t, len(session.Result.Findings), len(loaded.Findings))

	// Compare: same findings → nothing new, nothing fixed.
	diff := CompareFindings(loaded.Findings, session.Result.Findings)
	assert.Empty(t, diff.New, "same findings should produce no new entries")
	assert.Empty(t, diff.Fixed, "same findings should produce no fixed entries")
	assert.Equal(t, len(session.Result.Findings), len(diff.Unchanged),
		"all findings should be unchanged")
}

// ---------------------------------------------------------------------------
// V9: Export correlations (auto --spec ... --export-correlations out.json)
// Validates that correlation tracking + export works through the pipeline.
// ---------------------------------------------------------------------------

func TestIntegration_ExportCorrelations(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	spec, err := ParseContent(specYAML)
	require.NoError(t, err)

	// Build plan with correlation tracking.
	cfg := &SpecConfig{
		SpecContent: specYAML,
		ScanTypes:   []string{"sqli"},
		Intensity:   IntensityNormal,
	}
	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)

	// Create a correlation tracker and record entries.
	tracker := NewCorrelationTracker(plan.SessionID)
	for _, entry := range plan.Entries {
		tag := EndpointTag(entry.Endpoint.Method, entry.Endpoint.Path)
		tracker.Record(tag, entry.Attack.Category, entry.InjectionTarget.Parameter, "test-payload", false, "200 OK")
	}

	// Export to file.
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "correlations.json")
	require.NoError(t, tracker.ExportJSON(outPath))

	// Load and verify.
	records, loadErr := LoadCorrelationRecords(outPath)
	require.NoError(t, loadErr)
	assert.Len(t, records, len(plan.Entries),
		"exported records should match plan entries")

	// Every record should have required fields.
	for _, r := range records {
		assert.NotEmpty(t, r.CorrelationID, "record needs correlation ID")
		assert.NotEmpty(t, r.EndpointTag, "record needs endpoint tag")
		assert.NotEmpty(t, r.AttackCategory, "record needs attack category")
	}
}

// ---------------------------------------------------------------------------
// V9: All output formats include endpoint-level data
// Validates JSON output contains method, path, category, severity per finding.
// ---------------------------------------------------------------------------

func TestIntegration_OutputFormatsContainEndpointData(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	session := runFullPipeline(t, specYAML, srv.URL)

	// JSON marshaling.
	data, err := json.MarshalIndent(session.Result, "", "  ")
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))

	// Verify top-level fields.
	assert.Contains(t, parsed, "spec_source", "JSON should contain spec_source")
	assert.Contains(t, parsed, "findings", "JSON should contain findings")
	assert.Contains(t, parsed, "total_tests", "JSON should contain total_tests")

	// Verify each finding has endpoint-level fields.
	findings, ok := parsed["findings"].([]any)
	require.True(t, ok, "findings should be an array")
	require.NotEmpty(t, findings)

	for i, f := range findings {
		finding, ok := f.(map[string]any)
		require.True(t, ok, "finding %d should be an object", i)
		assert.Contains(t, finding, "method", "finding %d needs method", i)
		assert.Contains(t, finding, "path", "finding %d needs path", i)
		assert.Contains(t, finding, "category", "finding %d needs category", i)
		assert.Contains(t, finding, "severity", "finding %d needs severity", i)
	}

	// Verify endpoint_results.
	if epResults, ok := parsed["endpoint_results"].([]any); ok {
		for i, er := range epResults {
			epResult, ok := er.(map[string]any)
			require.True(t, ok, "endpoint_result %d should be an object", i)
			assert.Contains(t, epResult, "method", "endpoint_result %d needs method", i)
			assert.Contains(t, epResult, "path", "endpoint_result %d needs path", i)
		}
	}
}

// ---------------------------------------------------------------------------
// V9: Scan types filter works (scan --spec ... --scan-type sqli)
// ---------------------------------------------------------------------------

func TestIntegration_ScanTypeFilter(t *testing.T) {
	t.Parallel()

	srv := mockVulnerableAPI(t)
	defer srv.Close()

	specYAML := buildTestOpenAPI3Spec(srv.URL)
	spec, err := ParseContent(specYAML)
	require.NoError(t, err)

	// Only sqli scan type.
	cfg := &SpecConfig{
		SpecContent: specYAML,
		ScanTypes:   []string{"sqli"},
		Intensity:   IntensityNormal,
	}
	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)

	// Every entry should be sqli.
	for _, entry := range plan.Entries {
		assert.Equal(t, "sqli", entry.Attack.Category,
			"plan should only contain sqli entries when filtered")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// runFullPipeline parses a spec, builds a plan, executes with vulnScanFunc,
// and returns the session. Fails the test on any error.
func runFullPipeline(t *testing.T, specContent string, baseURL string) *ScanSession {
	t.Helper()

	spec, err := ParseContent(specContent)
	require.NoError(t, err, "spec parse failed")
	require.NotNil(t, spec)
	require.NotEmpty(t, spec.Endpoints, "spec should have endpoints")

	cfg := &SpecConfig{
		SpecContent: specContent,
		ScanTypes:   []string{"sqli"},
		Intensity:   IntensityNormal,
	}
	plan := BuildSimplePlan(spec, cfg)
	require.NotNil(t, plan)
	require.NotEmpty(t, plan.Entries, "plan should have entries")

	exec := &SimpleExecutor{
		BaseURL:     baseURL,
		ScanFn:      vulnScanFunc,
		Concurrency: 1,
	}

	session, err := exec.Execute(context.Background(), plan)
	require.NoError(t, err)
	require.NotNil(t, session)

	return session
}

// buildDeterministicResult constructs a SpecScanResult with fixed,
// predictable data suitable for golden file comparison.
func buildDeterministicResult() *SpecScanResult {
	return &SpecScanResult{
		SpecSource:     "testdata/petstore.yaml",
		TotalEndpoints: 2,
		TotalTests:     4,
		Findings: []SpecFinding{
			{
				Method:         "GET",
				Path:           "/users",
				CorrelationTag: "get-users",
				Category:       "sqli",
				Parameter:      "search",
				Location:       "query",
				Payload:        "' OR 1=1--",
				Title:          "SQL Injection in /users",
				Severity:       "high",
				CWE:            "CWE-89",
			},
			{
				Method:         "POST",
				Path:           "/users",
				CorrelationTag: "post-users",
				Category:       "xss",
				Parameter:      "name",
				Location:       "body",
				Payload:        "<script>alert(1)</script>",
				Title:          "XSS in /users",
				Severity:       "medium",
				CWE:            "CWE-79",
			},
		},
		EndpointResults: []EndpointResult{
			{
				Method:         "GET",
				Path:           "/users",
				CorrelationTag: "get-users",
				ScanTypes:      []string{"sqli"},
				Findings: []SpecFinding{
					{
						Method:    "GET",
						Path:      "/users",
						Category:  "sqli",
						Parameter: "search",
						Severity:  "high",
						Title:     "SQL Injection in /users",
					},
				},
			},
			{
				Method:         "POST",
				Path:           "/users",
				CorrelationTag: "post-users",
				ScanTypes:      []string{"xss"},
				Findings: []SpecFinding{
					{
						Method:    "POST",
						Path:      "/users",
						Category:  "xss",
						Parameter: "name",
						Severity:  "medium",
						Title:     "XSS in /users",
					},
				},
			},
		},
	}
}

// buildDeterministicPlanForGolden builds a Spec and ScanPlan with fixed data.
func buildDeterministicPlanForGolden() (*Spec, *ScanPlan) {
	spec := &Spec{
		Format:  FormatOpenAPI3,
		Version: "3.0.0",
		Title:   "Test API",
		Servers: []Server{{URL: "https://api.example.com"}},
		Endpoints: []Endpoint{
			{
				Method:      "GET",
				Path:        "/users",
				OperationID: "listUsers",
				Parameters: []Parameter{
					{Name: "search", In: LocationQuery, Schema: SchemaInfo{Type: "string"}},
				},
			},
			{
				Method:      "POST",
				Path:        "/users",
				OperationID: "createUser",
			},
		},
	}

	plan := &ScanPlan{
		SessionID:  "test-session-001",
		SpecSource: "testdata/petstore.yaml",
		Intensity:  IntensityNormal,
		TotalTests: 6,
		Entries: []ScanPlanEntry{
			{
				Endpoint: spec.Endpoints[0],
				Attack: AttackSelection{
					Category:     "sqli",
					Reason:       "Query parameter 'search' is injectable (string type)",
					PayloadCount: 3,
					Layers:       []string{"param_type", "param_name"},
					RiskScore:    75,
				},
				InjectionTarget: InjectionTarget{
					Parameter: "search",
					Location:  LocationQuery,
				},
			},
			{
				Endpoint: spec.Endpoints[0],
				Attack: AttackSelection{
					Category:     "xss",
					Reason:       "Query parameter 'search' may be reflected",
					PayloadCount: 3,
					Layers:       []string{"param_type"},
					RiskScore:    60,
				},
				InjectionTarget: InjectionTarget{
					Parameter: "search",
					Location:  LocationQuery,
				},
			},
		},
	}

	return spec, plan
}

// compareWithGolden compares actual output with a golden file. Set
// UPDATE_GOLDEN=true to create/update golden files.
func compareWithGolden(t *testing.T, name string, actual []byte) {
	t.Helper()

	goldenDir := filepath.Join("testdata", "golden")
	goldenPath := filepath.Join(goldenDir, name)

	if os.Getenv("UPDATE_GOLDEN") == "true" {
		require.NoError(t, os.MkdirAll(goldenDir, 0o755))
		require.NoError(t, os.WriteFile(goldenPath, actual, 0o644))
		t.Logf("updated golden file: %s", goldenPath)
		return
	}

	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("golden file %s not found; run with UPDATE_GOLDEN=true to create it: %v",
			goldenPath, err)
	}

	// Normalize line endings to LF for cross-platform comparison.
	normalizedExpected := bytes.ReplaceAll(expected, []byte("\r\n"), []byte("\n"))
	normalizedActual := bytes.ReplaceAll(actual, []byte("\r\n"), []byte("\n"))

	if !bytes.Equal(normalizedExpected, normalizedActual) {
		t.Errorf("output does not match golden file %s\n--- Expected (len=%d):\n%s\n--- Actual (len=%d):\n%s",
			goldenPath, len(expected), string(expected), len(actual), string(actual))
	}
}
