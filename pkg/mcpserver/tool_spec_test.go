package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waftester/waftester/pkg/apispec"
)

const testOpenAPISpec = `openapi: "3.0.0"
info:
  title: Test API
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
            type: integer
`

func callTool(t *testing.T, handler toolHandler, args any) *mcp.CallToolResult {
	t.Helper()
	argBytes, err := json.Marshal(args)
	require.NoError(t, err)

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Arguments: json.RawMessage(argBytes),
		},
	}

	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	return result
}

func resultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.NotNil(t, result)
	require.NotEmpty(t, result.Content)
	tc, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok, "expected TextContent, got %T", result.Content[0])
	return tc.Text
}

func TestValidateSpec_Valid(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleValidateSpec, map[string]string{
		"spec_content": testOpenAPISpec,
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, `"valid": true`)
	assert.Contains(t, text, `"format": "openapi3"`)
	assert.Contains(t, text, `"endpoint_count": 3`)
}

func TestValidateSpec_Invalid(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleValidateSpec, map[string]string{
		"spec_content": "this is not valid yaml or json {{{}}}",
	})

	assert.False(t, result.IsError) // Tool returns result, not error
	text := resultText(t, result)
	assert.Contains(t, text, `"valid": false`)
	assert.Contains(t, text, `"errors"`)
}

func TestValidateSpec_EmptyContent(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleValidateSpec, map[string]string{
		"spec_content": "",
	})

	assert.True(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, "one of spec_content, spec_path, or spec_url is required")
}

func TestListSpecEndpoints_AllEndpoints(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleListSpecEndpoints, map[string]string{
		"spec_content": testOpenAPISpec,
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)

	var endpoints []map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &endpoints))
	assert.Len(t, endpoints, 3)
}

func TestListSpecEndpoints_EmptyContent(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleListSpecEndpoints, map[string]string{
		"spec_content": "",
	})
	assert.True(t, result.IsError)
}

func TestPlanSpec_GeneratesPlan(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handlePlanSpec, map[string]any{
		"spec_content": testOpenAPISpec,
		"intensity":    "normal",
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, `"plan"`)
	assert.Contains(t, text, `"preview"`)
	assert.Contains(t, text, "Endpoints:")
}

func TestPlanSpec_WithScanTypes(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handlePlanSpec, map[string]any{
		"spec_content": testOpenAPISpec,
		"scan_types":   "sqli,xss",
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)

	// Plan should only contain sqli and xss categories.
	var data struct {
		Plan struct {
			Entries []struct {
				Attack struct {
					Category string `json:"category"`
				} `json:"attack"`
			} `json:"entries"`
		} `json:"plan"`
	}
	require.NoError(t, json.Unmarshal([]byte(text), &data))

	for _, entry := range data.Plan.Entries {
		cat := entry.Attack.Category
		assert.True(t, cat == "sqli" || cat == "xss",
			"expected sqli or xss, got %s", cat)
	}
}

func TestPlanSpec_EmptyContent(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handlePlanSpec, map[string]string{
		"spec_content": "",
	})
	assert.True(t, result.IsError)
}

func TestScanSpec_DryRun(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleScanSpec, map[string]any{
		"spec_content": testOpenAPISpec,
		"target":       "https://api.example.com",
		"dry_run":      true,
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, `"dry_run": true`)
	assert.Contains(t, text, `"target": "https://api.example.com"`)
	assert.Contains(t, text, `"plan"`)
}

func TestScanSpec_EmptyContent(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleScanSpec, map[string]string{
		"spec_content": "",
	})
	assert.True(t, result.IsError)
}

func TestScanSpec_NoTargetAndNoSpecServer(t *testing.T) {
	t.Parallel()
	s := &Server{}
	// Spec without server URLs + no target = error when not dry_run.
	result := callTool(t, s.handleScanSpec, map[string]any{
		"spec_content": testOpenAPISpec,
		"dry_run":      false,
	})

	assert.True(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, "target URL required")
}

func TestScanSpec_SyncModeReturnsFindings(t *testing.T) {
	t.Parallel()

	// Start a mock target server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"path": %q, "method": %q}`, r.URL.Path, r.Method)
	}))
	defer ts.Close()

	// Create server with sync mode and injected ScanFn that produces findings.
	srv := New(&Config{
		SpecScanFn: func(_ context.Context, category string, _ string, ep apispec.Endpoint) ([]apispec.SpecFinding, error) {
			param := "id"
			for _, p := range ep.Parameters {
				param = p.Name
				break
			}
			return []apispec.SpecFinding{{
				Method:    ep.Method,
				Path:      ep.Path,
				Category:  category,
				Parameter: param,
				Severity:  "high",
				Title:     fmt.Sprintf("%s in %s %s", category, ep.Method, ep.Path),
			}}, nil
		},
	})
	srv.syncMode.Store(true)
	defer srv.Stop()

	result := callTool(t, srv.handleScanSpec, map[string]any{
		"spec_content": testOpenAPISpec,
		"target":       ts.URL,
		"dry_run":      false,
	})

	require.False(t, result.IsError, "scan_spec should not return an error")
	text := resultText(t, result)

	// The sync mode returns the full result JSON.
	assert.Contains(t, text, `"findings"`, "result should contain findings array")
	assert.Contains(t, text, `"/users"`, "findings should reference /users path")
	assert.Contains(t, text, `"GET"`, "findings should include GET method")
	assert.Contains(t, text, `"high"`, "findings should include severity")

	// Parse the full output to verify structure.
	var output struct {
		Result struct {
			Findings []struct {
				Method    string `json:"method"`
				Path      string `json:"path"`
				Category  string `json:"category"`
				Parameter string `json:"parameter"`
				Severity  string `json:"severity"`
			} `json:"findings"`
			TotalEndpoints int `json:"total_endpoints"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(text), &output), "result should be valid JSON")
	assert.NotEmpty(t, output.Result.Findings, "should have at least one finding")

	// Every finding should have method, path, and category populated.
	for _, f := range output.Result.Findings {
		assert.NotEmpty(t, f.Method, "finding method should not be empty")
		assert.NotEmpty(t, f.Path, "finding path should not be empty")
		assert.NotEmpty(t, f.Category, "finding category should not be empty")
	}
}

func TestSplitCSV(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  []string
	}{
		{"sqli,xss", []string{"sqli", "xss"}},
		{"sqli, xss, cors", []string{"sqli", "xss", "cors"}},
		{"", []string{}},
		{",,,", []string{}},
		{"single", []string{"single"}},
	}
	for _, tt := range tests {
		got := splitCSV(tt.input)
		assert.Equal(t, tt.want, got, "splitCSV(%q)", tt.input)
	}
}

func TestEstimateSpecDuration(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "10s", estimateSpecDuration(nil))
	assert.Equal(t, "10s", estimateSpecDuration(&apispec.ScanPlan{TotalTests: 50}))
	assert.Equal(t, "100s", estimateSpecDuration(&apispec.ScanPlan{TotalTests: 1000}))
	assert.Equal(t, "600s", estimateSpecDuration(&apispec.ScanPlan{TotalTests: 100000}))
}

// --- compare_baselines tests ---

func TestCompareBaselines_NewAndFixed(t *testing.T) {
	t.Parallel()
	s := &Server{}

	baseline := `[{"method":"GET","path":"/users","category":"sqli","parameter":"q","severity":"high"}]`
	current := `[{"method":"POST","path":"/users","category":"xss","parameter":"name","severity":"medium"}]`

	result := callTool(t, s.handleCompareBaselines, map[string]string{
		"baseline_findings": baseline,
		"current_findings":  current,
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, `"baseline_count": 1`)
	assert.Contains(t, text, `"current_count": 1`)
	assert.Contains(t, text, `"fixed"`)
	assert.Contains(t, text, `"new"`)
}

func TestCompareBaselines_EmptyBaseline(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleCompareBaselines, map[string]string{
		"baseline_findings": "",
		"current_findings":  "[]",
	})
	assert.True(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, "baseline_findings is required")
}

func TestCompareBaselines_InvalidJSON(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleCompareBaselines, map[string]string{
		"baseline_findings": "not json",
		"current_findings":  "[]",
	})
	assert.True(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, "invalid baseline_findings JSON")
}

// --- preview_spec_scan tests ---

func TestPreviewSpecScan_DefaultIntensity(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handlePreviewSpecScan, map[string]string{
		"spec_content": testOpenAPISpec,
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, `"entries"`)
	assert.Contains(t, text, `"total_tests"`)
	assert.Contains(t, text, `"estimated_duration"`)
	assert.Contains(t, text, `"intensity": "normal"`)
	assert.Contains(t, text, `"endpoint_count": 3`)
}

func TestPreviewSpecScan_EmptyContent(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handlePreviewSpecScan, map[string]string{
		"spec_content": "",
	})
	assert.True(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, "one of spec_content, spec_path, or spec_url is required")
}

// --- spec_intelligence tests ---

func TestSpecIntelligence_AnalyzesSpec(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleSpecIntelligence, map[string]string{
		"spec_content": testOpenAPISpec,
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, `"attack_surface"`)
	assert.Contains(t, text, `"total_endpoints": 3`)
	assert.Contains(t, text, `"recommended_categories"`)

	// Should have param location counts.
	assert.Contains(t, text, `"parameter_locations"`)
}

func TestSpecIntelligence_EmptyContent(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleSpecIntelligence, map[string]string{
		"spec_content": "",
	})
	assert.True(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, "one of spec_content, spec_path, or spec_url is required")
}

// --- describe_spec_auth tests ---

func TestDescribeSpecAuth_NoAuth(t *testing.T) {
	t.Parallel()
	s := &Server{}
	// testOpenAPISpec has no security schemes.
	result := callTool(t, s.handleDescribeSpecAuth, map[string]string{
		"spec_content": testOpenAPISpec,
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, `"scheme_count": 0`)
}

func TestDescribeSpecAuth_WithBearerAuth(t *testing.T) {
	t.Parallel()
	s := &Server{}

	specWithAuth := `openapi: "3.0.0"
info:
  title: Auth API
  version: "1.0"
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
security:
  - bearerAuth: []
paths:
  /protected:
    get:
      summary: Protected endpoint
      security:
        - bearerAuth: []
`
	result := callTool(t, s.handleDescribeSpecAuth, map[string]string{
		"spec_content": specWithAuth,
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, `"scheme_count": 1`)
	assert.Contains(t, text, `"bearer"`)
	assert.Contains(t, text, `"JWT"`)
}

func TestDescribeSpecAuth_EmptyContent(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleDescribeSpecAuth, map[string]string{
		"spec_content": "",
	})
	assert.True(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, "one of spec_content, spec_path, or spec_url is required")
}

func TestDescribeSpecAuth_WithOAuthAndApiKeyMetadata(t *testing.T) {
	t.Parallel()
	s := &Server{}

	specWithMultipleAuth := `openapi: "3.0.0"
info:
  title: Multi Auth API
  version: "1.0"
components:
  securitySchemes:
    oauth2Auth:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://idp.example.com/auth
          tokenUrl: https://idp.example.com/token
          scopes:
            read: Read access
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
paths:
  /reports:
    get:
      security:
        - oauth2Auth: [read]
  /internal:
    get:
      security:
        - apiKeyAuth: []
`

	result := callTool(t, s.handleDescribeSpecAuth, map[string]string{
		"spec_content": specWithMultipleAuth,
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, `"scheme_count": 2`)
	assert.Contains(t, text, `"oauth2Auth"`)
	assert.Contains(t, text, `"apiKeyAuth"`)
	assert.Contains(t, text, `"token_url": "https://idp.example.com/token"`)
	assert.Contains(t, text, `"auth_url": "https://idp.example.com/auth"`)
	assert.Contains(t, text, `"scopes"`)
	assert.Contains(t, text, `"in": "header"`)
	assert.Contains(t, text, `"field_name": "X-API-Key"`)
	assert.Contains(t, text, `"endpoint_auth"`)
	assert.Contains(t, text, `"path": "/reports"`)
	assert.Contains(t, text, `"path": "/internal"`)
}

// --- export_spec tests ---

func TestExportSpec_NormalizedOutput(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleExportSpec, map[string]any{
		"spec_content": testOpenAPISpec,
	})

	assert.False(t, result.IsError)
	text := resultText(t, result)

	// Should contain normalized endpoint data.
	assert.Contains(t, text, `"/users"`)
	assert.Contains(t, text, `"/users/{id}"`)
	assert.Contains(t, text, `"GET"`)
	assert.Contains(t, text, `"POST"`)
}

func TestExportSpec_EmptyContent(t *testing.T) {
	t.Parallel()
	s := &Server{}
	result := callTool(t, s.handleExportSpec, map[string]string{
		"spec_content": "",
	})
	assert.True(t, result.IsError)
	text := resultText(t, result)
	assert.Contains(t, text, "one of spec_content, spec_path, or spec_url is required")
}
