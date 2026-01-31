package report

import (
	"testing"
)

func TestComplianceFrameworkConstants(t *testing.T) {
	frameworks := []ComplianceFramework{
		FrameworkPCIDSS,
		FrameworkOWASP,
		FrameworkSOC2,
		FrameworkISO27001,
		FrameworkHIPAA,
		FrameworkGDPR,
		FrameworkNIST,
	}

	// Ensure all frameworks are unique
	seen := make(map[ComplianceFramework]bool)
	for _, f := range frameworks {
		if seen[f] {
			t.Errorf("Duplicate framework: %s", f)
		}
		seen[f] = true
	}

	if len(frameworks) != 7 {
		t.Errorf("Expected 7 compliance frameworks, got %d", len(frameworks))
	}
}

func TestComplianceStatusConstants(t *testing.T) {
	statuses := []ComplianceStatus{
		StatusPass,
		StatusFail,
		StatusPartial,
		StatusNotApplicable,
	}

	if len(statuses) != 4 {
		t.Errorf("Expected 4 compliance statuses, got %d", len(statuses))
	}
}

func TestNewComplianceMapper(t *testing.T) {
	mapper := NewComplianceMapper(FrameworkPCIDSS)
	if mapper == nil {
		t.Fatal("NewComplianceMapper returned nil")
	}
	if mapper.framework != FrameworkPCIDSS {
		t.Errorf("Expected PCI DSS framework, got %s", mapper.framework)
	}
}

func TestComplianceMapperAllFrameworks(t *testing.T) {
	frameworks := []ComplianceFramework{
		FrameworkPCIDSS,
		FrameworkOWASP,
		FrameworkSOC2,
		FrameworkISO27001,
		FrameworkHIPAA,
		// Note: GDPR and NIST not yet implemented
	}

	for _, fw := range frameworks {
		mapper := NewComplianceMapper(fw)
		if mapper == nil {
			t.Errorf("NewComplianceMapper returned nil for %s", fw)
			continue
		}
		if len(mapper.mappings) == 0 {
			t.Errorf("Mapper for %s should have mappings", fw)
		}
	}
}

func TestComplianceMapperUnimplementedFrameworks(t *testing.T) {
	// These frameworks exist but don't have mappings yet
	unimplementedFrameworks := []ComplianceFramework{
		FrameworkGDPR,
		FrameworkNIST,
	}

	for _, fw := range unimplementedFrameworks {
		mapper := NewComplianceMapper(fw)
		if mapper == nil {
			t.Errorf("NewComplianceMapper returned nil for %s", fw)
			continue
		}
		// These don't have mappings yet - that's expected
		if len(mapper.mappings) != 0 {
			t.Logf("Framework %s now has mappings - update test", fw)
		}
	}
}

func TestComplianceMapperMapResults(t *testing.T) {
	mapper := NewComplianceMapper(FrameworkOWASP)

	stats := &Statistics{
		TotalRequests:   100,
		BlockedRequests: 80,
		PassedRequests:  20,
		TestsPerformed:  100,
		VulnsFound:      5,
		ByCategory: map[string]int{
			"xss":       10,
			"injection": 5,
			"auth":      3,
			"traversal": 2,
		},
	}

	controls := mapper.MapResults(stats)
	if len(controls) == 0 {
		t.Error("MapResults should return controls")
	}

	// Check that controls have required fields
	for _, ctrl := range controls {
		if ctrl.ControlID == "" {
			t.Error("Control should have ID")
		}
		if ctrl.ControlName == "" {
			t.Error("Control should have name")
		}
	}
}

func TestComplianceControlStruct(t *testing.T) {
	ctrl := ComplianceControl{
		Framework:   FrameworkOWASP,
		ControlID:   "A03:2021",
		ControlName: "Injection",
		Description: "Injection flaws",
		Status:      StatusFail,
		Evidence:    "5 SQL injection vulnerabilities found",
		Remediation: "Fix injections",
		References:  []string{"https://owasp.org/A03"},
	}

	if ctrl.ControlID != "A03:2021" {
		t.Errorf("Expected A03:2021, got %s", ctrl.ControlID)
	}
	if ctrl.Status != StatusFail {
		t.Errorf("Expected fail status")
	}
	if len(ctrl.References) != 1 {
		t.Errorf("Expected 1 reference, got %d", len(ctrl.References))
	}
}

func TestComplianceReportStruct(t *testing.T) {
	report := ComplianceReport{
		Framework:       FrameworkPCIDSS,
		OverallScore:    85.5,
		PassRate:        0.855,
		Controls:        []ComplianceControl{},
		Scope:           []string{"api.example.com"},
		Recommendations: []string{"Fix issues"},
	}

	if report.Framework != FrameworkPCIDSS {
		t.Errorf("Expected PCI DSS framework")
	}
	if report.OverallScore != 85.5 {
		t.Errorf("Expected 85.5%% score, got %f", report.OverallScore)
	}
}

func TestNewPDFEnhancer(t *testing.T) {
	enhancer := NewPDFEnhancer()
	if enhancer == nil {
		t.Fatal("NewPDFEnhancer returned nil")
	}
}

func TestPDFEnhancerChaining(t *testing.T) {
	enhancer := NewPDFEnhancer().
		WithLogo("logo.png").
		WithWatermark("CONFIDENTIAL").
		WithConfidential(true)

	if enhancer == nil {
		t.Fatal("Chained enhancer should not be nil")
	}
	if enhancer.Logo != "logo.png" {
		t.Errorf("Expected logo 'logo.png', got '%s'", enhancer.Logo)
	}
	if enhancer.Watermark != "CONFIDENTIAL" {
		t.Errorf("Expected watermark 'CONFIDENTIAL', got '%s'", enhancer.Watermark)
	}
	if !enhancer.Confidential {
		t.Error("Expected confidential to be true")
	}
}

func TestPDFEnhancerEnhanceHTML(t *testing.T) {
	enhancer := NewPDFEnhancer().
		WithWatermark("DRAFT").
		WithConfidential(true)

	input := []byte("<html><body><h1>Report</h1></body></html>")
	output := enhancer.EnhanceHTML(input)

	if len(output) == 0 {
		t.Error("Enhanced HTML should not be empty")
	}
	// Output should be at least as long as input (adds styling)
	if len(output) < len(input) {
		t.Error("Enhanced HTML should add content, not remove it")
	}
}

func TestComplianceMapperGetControlName(t *testing.T) {
	mapper := NewComplianceMapper(FrameworkOWASP)

	// Test known control
	name := mapper.getControlName("A01:2021")
	if name == "" {
		t.Error("Should return name for known OWASP control")
	}
}

func TestComplianceMapperGetControlDescription(t *testing.T) {
	mapper := NewComplianceMapper(FrameworkPCIDSS)

	// Test known control
	desc := mapper.getControlDescription("6.5.1")
	if desc == "" {
		t.Error("Should return description for known PCI DSS control")
	}
}

func TestComplianceMapperDetermineStatus(t *testing.T) {
	mapper := NewComplianceMapper(FrameworkOWASP)

	// High block rate (>= 95%) should pass
	highBlockStats := &Statistics{
		TotalRequests:   100,
		BlockedRequests: 95,
		PassedRequests:  5,
		BlockRate:       95.0,
	}
	status := mapper.determineStatus("xss", 0, highBlockStats)
	if status != StatusPass {
		t.Errorf("Expected pass status with 95%% block rate, got %s", status)
	}

	// Medium block rate (80-95%) should be partial
	mediumBlockStats := &Statistics{
		TotalRequests:   100,
		BlockedRequests: 85,
		PassedRequests:  15,
		BlockRate:       85.0,
	}
	status = mapper.determineStatus("xss", 5, mediumBlockStats)
	if status != StatusPartial {
		t.Errorf("Expected partial status with 85%% block rate, got %s", status)
	}

	// Low block rate (< 80%) should fail
	lowBlockStats := &Statistics{
		TotalRequests:   100,
		BlockedRequests: 50,
		PassedRequests:  50,
		BlockRate:       50.0,
	}
	status = mapper.determineStatus("xss", 10, lowBlockStats)
	if status != StatusFail {
		t.Errorf("Expected fail status with 50%% block rate, got %s", status)
	}
}
