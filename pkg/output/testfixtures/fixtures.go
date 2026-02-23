// Package testfixtures provides centralized test data for output writer testing.
package testfixtures

import (
	"fmt"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/scoring"
)

// ============================================================================
// SAMPLE RESULT GENERATORS
// ============================================================================

// MakeTestResult creates a single test result with specified parameters.
// This is the canonical way to create test results in all output tests.
func MakeTestResult(id, category, severity, outcome string, statusCode int) *output.TestResult {
	return &output.TestResult{
		ID:         id,
		Category:   category,
		Severity:   severity,
		Outcome:    outcome,
		StatusCode: statusCode,
		LatencyMs:  42,
		Payload:    "test-payload-" + id,
		Timestamp:  time.Now().Format("15:04:05"),
		Method:     "GET",
		TargetPath: "/api/test/" + id,
		RiskScore:  scoring.Result{RiskScore: 5.0, FinalSeverity: severity},
	}
}

// MakeBlockedResult creates a result representing a WAF block.
func MakeBlockedResult(id, category, severity string) *output.TestResult {
	return &output.TestResult{
		ID:              id,
		Category:        category,
		Severity:        severity,
		Outcome:         "Blocked",
		StatusCode:      403,
		LatencyMs:       15,
		Payload:         "blocked-payload-" + id,
		Timestamp:       time.Now().Format("15:04:05"),
		Method:          "POST",
		TargetPath:      "/api/vulnerable/" + id,
		WAFRuleID:       "942100",
		BlockConfidence: 0.95,
		RiskScore:       scoring.Result{RiskScore: 8.0, FinalSeverity: severity},
	}
}

// MakeBypassResult creates a result representing a successful WAF bypass.
func MakeBypassResult(id, category, severity string, tampersUsed []string) *output.TestResult {
	return &output.TestResult{
		ID:              id,
		Category:        category,
		Severity:        severity,
		Outcome:         "Fail",
		StatusCode:      200,
		LatencyMs:       120,
		Payload:         "bypass-payload-" + id,
		Timestamp:       time.Now().Format("15:04:05"),
		Method:          "POST",
		TargetPath:      "/api/vulnerable/" + id,
		EncodingUsed:    "double_url",
		MutationType:    "unicode_normalize",
		OriginalPayload: "original-" + id,
		EvidenceMarkers: []string{"SQL syntax", "error in query"},
		CurlCommand:     fmt.Sprintf("curl -X POST 'https://target.com/api/vulnerable/%s' -d 'payload=...'", id),
		RiskScore:       scoring.Result{RiskScore: 9.5, FinalSeverity: severity},
	}
}

// MakeErrorResult creates a result representing a test error.
func MakeErrorResult(id, category string, errorMsg string) *output.TestResult {
	return &output.TestResult{
		ID:           id,
		Category:     category,
		Severity:     "Unknown",
		Outcome:      "Error",
		StatusCode:   0,
		LatencyMs:    0,
		ErrorMessage: errorMsg,
		Timestamp:    time.Now().Format("15:04:05"),
		Method:       "GET",
		TargetPath:   "/api/test/" + id,
		RiskScore:    scoring.Result{RiskScore: 0, FinalSeverity: "Unknown"},
	}
}

// ============================================================================
// BATCH GENERATORS
// ============================================================================

// MakeSampleResults generates n sample test results with variety.
func MakeSampleResults(n int) []*output.TestResult {
	results := make([]*output.TestResult, 0, n)
	categories := []string{"sqli", "xss", "traversal", "rce", "ssrf", "xxe"}
	severities := []string{"Critical", "High", "Medium", "Low"}
	outcomes := []string{"Blocked", "Fail", "Pass", "Error"}

	for i := 0; i < n; i++ {
		cat := categories[i%len(categories)]
		sev := severities[i%len(severities)]
		out := outcomes[i%len(outcomes)]
		status := 200
		if out == "Blocked" {
			status = 403
		} else if out == "Error" {
			status = 0
		}

		results = append(results, MakeTestResult(
			fmt.Sprintf("test-%03d", i+1),
			cat, sev, out, status,
		))
	}
	return results
}

// MakeRealisticScan generates results mimicking a real WAF scan.
// Returns: blocked (70%), bypassed (20%), errors (10%)
func MakeRealisticScan(totalPayloads int) []*output.TestResult {
	results := make([]*output.TestResult, 0, totalPayloads)

	blockedCount := int(float64(totalPayloads) * 0.70)
	bypassedCount := int(float64(totalPayloads) * 0.20)
	errorCount := totalPayloads - blockedCount - bypassedCount

	// Add blocked results
	for i := 0; i < blockedCount; i++ {
		cat := []string{"sqli", "xss", "rce"}[i%3]
		sev := []string{"Critical", "High", "Medium"}[i%3]
		results = append(results, MakeBlockedResult(
			fmt.Sprintf("blocked-%03d", i+1),
			cat, sev,
		))
	}

	// Add bypass results
	for i := 0; i < bypassedCount; i++ {
		cat := []string{"sqli", "xss"}[i%2]
		results = append(results, MakeBypassResult(
			fmt.Sprintf("bypass-%03d", i+1),
			cat, "Critical",
			[]string{"charunicodeencode", "space2comment"},
		))
	}

	// Add error results
	for i := 0; i < errorCount; i++ {
		results = append(results, MakeErrorResult(
			fmt.Sprintf("error-%03d", i+1),
			"connection",
			"connection timeout",
		))
	}

	return results
}

// ============================================================================
// ASSESSMENT FIXTURES
// ============================================================================

// AssessmentMetrics represents metrics for assessment testing.
type AssessmentMetrics struct {
	TruePositives  int
	FalsePositives int
	TrueNegatives  int
	FalseNegatives int
	DetectionRate  float64
	FPR            float64
	Precision      float64
	Recall         float64
	F1Score        float64
	MCC            float64
}

// MakeAssessmentData generates assessment metrics for testing.
func MakeAssessmentData() AssessmentMetrics {
	return AssessmentMetrics{
		TruePositives:  942,
		FalsePositives: 3,
		TrueNegatives:  1197,
		FalseNegatives: 58,
		DetectionRate:  0.942,
		FPR:            0.003,
		Precision:      0.997,
		Recall:         0.942,
		F1Score:        0.969,
		MCC:            0.942,
	}
}

// ============================================================================
// CATEGORY FIXTURES
// ============================================================================

// AllCategories returns all attack categories for comprehensive testing.
// Derived from the CategoryMapper — the single source of truth.
func AllCategories() []string {
	return payloadprovider.NewCategoryMapper().ShortNames()
}

// OWASPCategories returns OWASP-mapped categories for compliance testing.
// Uses the centralized defaults.OWASPCategoryMapping as the source of truth.
func OWASPCategories() map[string]string {
	result := make(map[string]string)
	for category, code := range defaults.OWASPCategoryMapping {
		if cat, ok := defaults.OWASPTop10[code]; ok {
			result[category] = cat.FullName
		}
	}
	return result
}

// ============================================================================
// WAF VENDOR FIXTURES
// ============================================================================

// WAFVendorFixture represents a WAF vendor for testing.
type WAFVendorFixture struct {
	Name               string
	Confidence         float64
	Evidence           []string
	RecommendedTampers []string
}

// MakeWAFVendors returns sample WAF vendor fixtures.
func MakeWAFVendors() []WAFVendorFixture {
	return []WAFVendorFixture{
		{
			Name:               "Cloudflare",
			Confidence:         0.98,
			Evidence:           []string{"cf-ray header", "__cfduid cookie", "1020 error page"},
			RecommendedTampers: []string{"charunicodeencode", "space2morecomment", "randomcase"},
		},
		{
			Name:               "AWS WAF",
			Confidence:         0.92,
			Evidence:           []string{"x-amzn-requestid header", "AWS error page"},
			RecommendedTampers: []string{"between", "charencode", "space2comment"},
		},
		{
			Name:               "Akamai",
			Confidence:         0.95,
			Evidence:           []string{"akamai-ghost-ip header", "Reference #"},
			RecommendedTampers: []string{"randomcase", "space2plus", "charencode"},
		},
	}
}
