package mcpserver

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/metrics"
	"github.com/waftester/waftester/pkg/mutation"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/waf"
)

// ---------------------------------------------------------------------------
// buildDetectWAFResponse
// ---------------------------------------------------------------------------

func TestBuildDetectWAFResponse_Detected(t *testing.T) {
	result := &waf.DetectionResult{
		Detected:   true,
		Confidence: 0.95,
		WAFs: []waf.WAFInfo{
			{Vendor: "Cloudflare", Confidence: 0.95},
		},
	}
	resp := buildDetectWAFResponse(result, "https://example.com")

	if resp.Result != result {
		t.Error("Result should point to the original DetectionResult")
	}
	if !strings.Contains(resp.Summary, "Cloudflare") {
		t.Error("summary should mention the detected WAF vendor")
	}
	if !strings.Contains(resp.Summary, "95") {
		t.Error("summary should mention confidence percentage")
	}
	if len(resp.NextSteps) == 0 {
		t.Error("next_steps should not be empty for a detected WAF")
	}
}

func TestBuildDetectWAFResponse_NotDetected(t *testing.T) {
	result := &waf.DetectionResult{
		Detected:   false,
		Confidence: 0.1,
	}
	resp := buildDetectWAFResponse(result, "https://no-waf.example.com")

	if !strings.Contains(resp.Summary, "No WAF detected") {
		t.Error("summary should indicate no WAF was found")
	}
	if len(resp.NextSteps) == 0 {
		t.Error("next_steps should not be empty")
	}
}

func TestBuildDetectWAFResponse_EmptyWAFs(t *testing.T) {
	result := &waf.DetectionResult{
		Detected:   true,
		Confidence: 0.6,
		WAFs:       []waf.WAFInfo{}, // detected but empty slice
	}
	resp := buildDetectWAFResponse(result, "https://edge.example.com")

	// Should not panic with empty WAFs slice
	if resp.Summary == "" {
		t.Error("summary should not be empty")
	}
}

// ---------------------------------------------------------------------------
// buildDiscoverySummary
// ---------------------------------------------------------------------------

func TestBuildDiscoverySummary_WithEndpoints(t *testing.T) {
	result := &discovery.DiscoveryResult{
		Target:         "https://app.example.com",
		WAFDetected:    true,
		WAFFingerprint: "Cloudflare",
		Technologies:   []string{"nginx", "Express"},
		Endpoints: []discovery.Endpoint{
			{Path: "/api/login", Method: "POST", Parameters: []discovery.Parameter{{Name: "user"}}},
			{Path: "/api/data", Method: "GET"},
		},
		Secrets: map[string][]discovery.Secret{
			"api_keys": {{Type: "api_key", Value: "leaked-key-1", Severity: "high"}},
		},
	}
	s := buildDiscoverySummary(result)

	if s.EndpointCount != 2 {
		t.Errorf("EndpointCount = %d, want 2", s.EndpointCount)
	}
	if !s.WAFDetected {
		t.Error("WAFDetected should be true")
	}
	if s.SecretsFound != 1 {
		t.Errorf("SecretsFound = %d, want 1", s.SecretsFound)
	}
	if !strings.Contains(s.Summary, "2 endpoints") {
		t.Error("summary should mention endpoint count")
	}
	if !strings.Contains(s.Summary, "Cloudflare") {
		t.Error("summary should mention WAF fingerprint")
	}
	if !strings.Contains(s.Summary, "WARNING") {
		t.Error("summary should warn about exposed secrets")
	}
	if len(s.NextSteps) == 0 {
		t.Error("next_steps should not be empty")
	}
}

func TestBuildDiscoverySummary_EmptyEndpoints(t *testing.T) {
	result := &discovery.DiscoveryResult{
		Target:    "https://empty.example.com",
		Endpoints: nil,
	}
	s := buildDiscoverySummary(result)

	if s.EndpointCount != 0 {
		t.Errorf("EndpointCount = %d, want 0", s.EndpointCount)
	}
	if s.Summary == "" {
		t.Error("summary should not be empty even with no endpoints")
	}
}

// ---------------------------------------------------------------------------
// buildAssessResponse
// ---------------------------------------------------------------------------

func TestBuildAssessResponse_GradeA(t *testing.T) {
	m := &metrics.EnterpriseMetrics{
		Grade:             "A",
		GradeReason:       "Strong detection across categories.",
		F1Score:           0.92,
		DetectionRate:     0.95,
		FalsePositiveRate: 0.01,
		MCC:               0.88,
	}
	resp := buildAssessResponse(m, "https://example.com")

	if resp.Metrics != m {
		t.Error("Metrics should point to the original EnterpriseMetrics")
	}
	if !strings.Contains(resp.Summary, "Grade A") {
		t.Error("summary should mention Grade A")
	}
	if !strings.Contains(resp.Summary, "95.0%") {
		t.Error("summary should show detection rate as percentage")
	}
	if !strings.Contains(resp.Interpretation, "Excellent") {
		t.Error("interpretation should say Excellent for Grade A")
	}
	if len(resp.NextSteps) == 0 {
		t.Error("next_steps should not be empty")
	}
}

func TestBuildAssessResponse_GradeF(t *testing.T) {
	m := &metrics.EnterpriseMetrics{
		Grade:             "F",
		F1Score:           0.2,
		DetectionRate:     0.15,
		FalsePositiveRate: 0.20,
	}
	resp := buildAssessResponse(m, "https://weak.example.com")

	if !strings.Contains(resp.Interpretation, "Poor") {
		t.Error("interpretation should say Poor for Grade F")
	}
	// Should have priority steps for bad grades
	foundPriority := false
	for _, s := range resp.NextSteps {
		if strings.Contains(s, "PRIORITY") {
			foundPriority = true
			break
		}
	}
	if !foundPriority {
		t.Error("next_steps should include PRIORITY for Grade F")
	}
	// Should warn about high FPR
	foundFPR := false
	for _, s := range resp.NextSteps {
		if strings.Contains(s, "WARNING") && strings.Contains(s, "False positive") {
			foundFPR = true
			break
		}
	}
	if !foundFPR {
		t.Error("next_steps should warn about high false positive rate")
	}
}

func TestBuildAssessResponse_ZeroValues(t *testing.T) {
	m := &metrics.EnterpriseMetrics{} // all zeros
	resp := buildAssessResponse(m, "https://zero.example.com")

	// Should not panic on zero-value metrics
	if resp.Summary == "" {
		t.Error("summary should not be empty even with zero metrics")
	}
	if resp.Interpretation == "" {
		t.Error("interpretation should not be empty")
	}
}

// ---------------------------------------------------------------------------
// buildScanNextSteps
// ---------------------------------------------------------------------------

func TestBuildScanNextSteps_WithBypasses(t *testing.T) {
	results := output.ExecutionResults{
		TotalTests:   100,
		BlockedTests: 85,
		FailedTests:  15,
	}
	args := scanArgs{Target: "https://example.com"}
	steps := buildScanNextSteps(results, args)

	if len(steps) == 0 {
		t.Error("next_steps should not be empty when bypasses exist")
	}
	foundCritical := false
	for _, s := range steps {
		if strings.Contains(s, "CRITICAL") {
			foundCritical = true
			break
		}
	}
	if !foundCritical {
		t.Error("next_steps should flag bypasses as CRITICAL")
	}
}

func TestBuildScanNextSteps_AllBlocked(t *testing.T) {
	results := output.ExecutionResults{
		TotalTests:   50,
		BlockedTests: 50,
		FailedTests:  0,
	}
	args := scanArgs{Target: "https://secure.example.com"}
	steps := buildScanNextSteps(results, args)

	if len(steps) == 0 {
		t.Error("next_steps should not be empty even when all blocked")
	}
	// Should congratulate, not alarm
	foundExcellent := false
	for _, s := range steps {
		if strings.Contains(s, "blocked") || strings.Contains(s, "excellent") {
			foundExcellent = true
			break
		}
	}
	if !foundExcellent {
		t.Error("next_steps should acknowledge all payloads were blocked")
	}
}

// ---------------------------------------------------------------------------
// buildBypassResponse
// ---------------------------------------------------------------------------

func TestBuildBypassResponse_WithBypasses(t *testing.T) {
	result := &mutation.WAFBypassResult{
		Found:       true,
		TotalTested: 100,
		BypassRate:  15.0,
		BypassPayloads: []*mutation.TestResult{
			{OriginalPayload: "' OR 1=1--", Blocked: false},
		},
	}
	args := bypassArgs{Target: "https://example.com"}
	resp := buildBypassResponse(result, args)

	if resp.Result != result {
		t.Error("Result should point to the original WAFBypassResult")
	}
	if !strings.Contains(resp.Summary, "15.0%") {
		t.Error("summary should mention bypass rate")
	}
	if resp.Interpretation == "" {
		t.Error("interpretation should not be empty")
	}
	if len(resp.NextSteps) == 0 {
		t.Error("next_steps should not be empty")
	}
}

func TestBuildBypassResponse_ZeroTested(t *testing.T) {
	result := &mutation.WAFBypassResult{
		TotalTested: 0,
		BypassRate:  0,
	}
	args := bypassArgs{Target: "https://example.com"}
	resp := buildBypassResponse(result, args)

	// Should not panic with zero tested  
	if resp.Summary == "" {
		t.Error("summary should not be empty even with zero tests")
	}
}

// ---------------------------------------------------------------------------
// buildCICDResponse
// ---------------------------------------------------------------------------

func TestBuildCICDResponse_GitHub(t *testing.T) {
	args := cicdArgs{
		Platform:  "github",
		Target:    "https://example.com",
		ScanTypes: []string{"sqli", "xss"},
	}
	resp := buildCICDResponse("name: WAF Test\non: push:", args)

	if resp.Platform != "github" {
		t.Errorf("Platform = %q, want github", resp.Platform)
	}
	if resp.FileName != ".github/workflows/waf-test.yml" {
		t.Errorf("FileName = %q, want .github/workflows/waf-test.yml", resp.FileName)
	}
	if !strings.Contains(resp.Summary, "github") {
		t.Error("summary should mention the platform")
	}
	if !strings.Contains(resp.Pipeline, "WAF Test") {
		t.Error("pipeline should contain the generated config")
	}
	if len(resp.NextSteps) == 0 {
		t.Error("next_steps should not be empty")
	}
	// Verify security guidance in next_steps
	foundSecurity := false
	for _, s := range resp.NextSteps {
		if strings.Contains(s, "secret") || strings.Contains(s, "SECRET") {
			foundSecurity = true
			break
		}
	}
	if !foundSecurity {
		t.Error("next_steps should include security guidance about secrets")
	}
}

func TestBuildCICDResponse_AllPlatforms(t *testing.T) {
	platforms := []string{"github", "gitlab", "jenkins", "azure-devops", "circleci", "bitbucket"}
	for _, p := range platforms {
		t.Run(p, func(t *testing.T) {
			args := cicdArgs{Platform: p, Target: "https://example.com"}
			resp := buildCICDResponse("config content", args)
			if resp.FileName == "" {
				t.Errorf("FileName should not be empty for platform %q", p)
			}
			if resp.Summary == "" {
				t.Error("summary should not be empty")
			}
		})
	}
}

func TestBuildCICDResponse_WithSchedule(t *testing.T) {
	args := cicdArgs{
		Platform: "github",
		Target:   "https://example.com",
		Schedule: "0 2 * * 1",
	}
	resp := buildCICDResponse("pipeline yaml", args)

	foundSchedule := false
	for _, s := range resp.NextSteps {
		if strings.Contains(s, "0 2 * * 1") {
			foundSchedule = true
			break
		}
	}
	if !foundSchedule {
		t.Error("next_steps should mention the configured schedule")
	}
}

// ---------------------------------------------------------------------------
// buildListPayloadsSummary / buildListPayloadsNextSteps
// ---------------------------------------------------------------------------

func TestBuildListPayloadsSummary_WithCategory(t *testing.T) {
	stats := payloads.LoadStats{
		TotalPayloads:  20,
		CategoriesUsed: 1,
		ByCategory:     map[string]int{"sqli": 20},
	}
	args := listPayloadsArgs{Category: "sqli"}
	bySeverity := map[string]int{"Critical": 14, "High": 6}
	summary := buildListPayloadsSummary(args, stats, 100, bySeverity)

	if !strings.Contains(summary, "SQL Injection") {
		t.Error("summary should mention the category name")
	}
	if !strings.Contains(summary, "20") {
		t.Error("summary should mention payload count")
	}
}

func TestBuildListPayloadsSummary_NoFilter(t *testing.T) {
	stats := payloads.LoadStats{
		TotalPayloads:  100,
		CategoriesUsed: 3,
		ByCategory:     map[string]int{"sqli": 50, "xss": 30, "cmdi": 20},
	}
	args := listPayloadsArgs{}
	bySeverity := map[string]int{"Critical": 60, "High": 40}
	summary := buildListPayloadsSummary(args, stats, 100, bySeverity)

	if !strings.Contains(summary, "100") {
		t.Error("summary should mention total payload count")
	}
	if !strings.Contains(summary, "3 categories") {
		t.Error("summary should mention number of categories")
	}
}

func TestBuildListPayloadsNextSteps_WithCategory(t *testing.T) {
	args := listPayloadsArgs{Category: "sqli"}
	stats := payloads.LoadStats{TotalPayloads: 20, CategoriesUsed: 1}
	steps := buildListPayloadsNextSteps(args, stats)
	if len(steps) == 0 {
		t.Error("next_steps should not be empty")
	}
	foundScan := false
	for _, s := range steps {
		if strings.Contains(s, "scan") {
			foundScan = true
			break
		}
	}
	if !foundScan {
		t.Error("next_steps should suggest using 'scan'")
	}
}

func TestBuildListPayloadsNextSteps_NoCategory(t *testing.T) {
	args := listPayloadsArgs{}
	stats := payloads.LoadStats{TotalPayloads: 100, CategoriesUsed: 5}
	steps := buildListPayloadsNextSteps(args, stats)
	if len(steps) == 0 {
		t.Error("next_steps should not be empty")
	}
}

// ---------------------------------------------------------------------------
// enrichedError
// ---------------------------------------------------------------------------

func TestEnrichedError_HasStructuredFields(t *testing.T) {
	result := enrichedError("test error", []string{"step 1", "step 2"})

	if !result.IsError {
		t.Error("enrichedError should set IsError=true")
	}
	if len(result.Content) == 0 {
		t.Error("enrichedError should have content")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("content should be TextContent")
	}
	if !strings.Contains(text.Text, "test error") {
		t.Error("text should contain the error message")
	}
	if !strings.Contains(text.Text, "step 1") {
		t.Error("text should contain recovery steps")
	}
}
