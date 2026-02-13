package correlation

import (
	"context"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/finding"
)

func TestFindingTypes(t *testing.T) {
	types := []FindingType{
		FindingSQLi, FindingXSS, FindingLFI, FindingRCE, FindingSSRF,
		FindingXXE, FindingSSTI, FindingAuthBypass, FindingIDOR,
		FindingOpenRedirect, FindingInfoLeak, FindingMisconfiguration,
		FindingWeakCrypto, FindingBrokenAccess,
	}

	if len(types) != 14 {
		t.Errorf("Expected 14 finding types, got %d", len(types))
	}

	if string(FindingSQLi) != "sqli" {
		t.Error("FindingSQLi should be 'sqli'")
	}
}

func TestSeverityLevels(t *testing.T) {
	severities := []finding.Severity{
		finding.Critical, finding.High, finding.Medium,
		finding.Low, finding.Info,
	}

	if len(severities) != 5 {
		t.Errorf("Expected 5 severity levels, got %d", len(severities))
	}

	// Test ordering
	if severityOrder(finding.Critical) <= severityOrder(finding.High) {
		t.Error("Critical should be higher than High")
	}
}

func TestFinding_GenerateHash(t *testing.T) {
	f := &Finding{
		Type:      FindingSQLi,
		Target:    "https://example.com",
		Endpoint:  "/api/users",
		Method:    "GET",
		Parameter: "id",
	}

	hash := f.GenerateHash()
	if hash == "" {
		t.Error("Hash should not be empty")
	}
	if f.Hash != hash {
		t.Error("Hash should be stored in finding")
	}

	// Same input should produce same hash
	f2 := &Finding{
		Type:      FindingSQLi,
		Target:    "https://example.com",
		Endpoint:  "/api/users",
		Method:    "GET",
		Parameter: "id",
	}
	hash2 := f2.GenerateHash()
	if hash != hash2 {
		t.Error("Same input should produce same hash")
	}
}

func TestFinding_DifferentHash(t *testing.T) {
	f1 := &Finding{
		Type:     FindingSQLi,
		Target:   "https://example.com",
		Endpoint: "/api/users",
		Method:   "GET",
	}
	f2 := &Finding{
		Type:     FindingXSS, // Different type
		Target:   "https://example.com",
		Endpoint: "/api/users",
		Method:   "GET",
	}

	if f1.GenerateHash() == f2.GenerateHash() {
		t.Error("Different findings should have different hashes")
	}
}

func TestNewCorrelator(t *testing.T) {
	c := NewCorrelator()
	if c == nil {
		t.Fatal("NewCorrelator returned nil")
	}

	// Should have default rules
	rules := c.GetRules()
	if len(rules) == 0 {
		t.Error("Expected default rules to be loaded")
	}
}

func TestCorrelator_AddScanResult(t *testing.T) {
	c := NewCorrelator()

	result := &ScanResult{
		ScanID:    "scan-1",
		Target:    "https://example.com",
		Scanner:   "waf-tester",
		StartTime: time.Now(),
		EndTime:   time.Now().Add(1 * time.Minute),
		Findings: []*Finding{
			{
				ID:           "f1",
				Type:         FindingSQLi,
				Severity:     finding.High,
				Target:       "https://example.com",
				Endpoint:     "/api",
				DiscoveredAt: time.Now(),
			},
		},
	}

	err := c.AddScanResult(context.Background(), result)
	if err != nil {
		t.Errorf("AddScanResult failed: %v", err)
	}

	findings := c.GetAllFindings()
	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
}

func TestCorrelator_RecurringFindings(t *testing.T) {
	c := NewCorrelator()

	// First scan
	result1 := &ScanResult{
		ScanID:    "scan-1",
		Target:    "https://example.com",
		Scanner:   "waf-tester",
		StartTime: time.Now(),
		EndTime:   time.Now().Add(1 * time.Minute),
		Findings: []*Finding{
			{
				ID:           "f1",
				Type:         FindingSQLi,
				Severity:     finding.High,
				Target:       "https://example.com",
				Endpoint:     "/api",
				Method:       "GET",
				DiscoveredAt: time.Now(),
			},
		},
	}
	c.AddScanResult(context.Background(), result1)

	// Second scan with same finding
	result2 := &ScanResult{
		ScanID:    "scan-2",
		Target:    "https://example.com",
		Scanner:   "waf-tester",
		StartTime: time.Now().Add(1 * time.Hour),
		EndTime:   time.Now().Add(1*time.Hour + 1*time.Minute),
		Findings: []*Finding{
			{
				ID:           "f2",
				Type:         FindingSQLi,
				Severity:     finding.High,
				Target:       "https://example.com",
				Endpoint:     "/api",
				Method:       "GET",
				DiscoveredAt: time.Now().Add(1 * time.Hour),
			},
		},
	}
	c.AddScanResult(context.Background(), result2)

	// Should still be 1 unique finding
	findings := c.GetAllFindings()
	if len(findings) != 1 {
		t.Errorf("Expected 1 unique finding, got %d", len(findings))
	}

	// But should be marked as recurring
	recurring := c.GetRecurringFindings()
	if len(recurring) != 1 {
		t.Errorf("Expected 1 recurring finding, got %d", len(recurring))
	}

	if recurring[0].OccurrenceCount != 2 {
		t.Errorf("Expected 2 occurrences, got %d", recurring[0].OccurrenceCount)
	}
}

func TestCorrelator_GetFindingByHash(t *testing.T) {
	c := NewCorrelator()

	finding := &Finding{
		Type:     FindingSQLi,
		Target:   "https://example.com",
		Endpoint: "/api",
		Method:   "POST",
	}
	finding.GenerateHash()

	result := &ScanResult{
		ScanID:   "scan-1",
		Findings: []*Finding{finding},
	}
	c.AddScanResult(context.Background(), result)

	retrieved := c.GetFindingByHash(finding.Hash)
	if retrieved == nil {
		t.Fatal("Should find by hash")
	}
	if retrieved.Hash != finding.Hash {
		t.Error("Hash mismatch")
	}
}

func TestCorrelator_GetNewFindings(t *testing.T) {
	c := NewCorrelator()

	result := &ScanResult{
		ScanID: "scan-1",
		Findings: []*Finding{
			{Type: FindingSQLi, Target: "https://a.com", Endpoint: "/a", Method: "GET"},
			{Type: FindingXSS, Target: "https://a.com", Endpoint: "/b", Method: "GET"},
		},
	}
	c.AddScanResult(context.Background(), result)

	newFindings := c.GetNewFindings()
	if len(newFindings) != 2 {
		t.Errorf("Expected 2 new findings, got %d", len(newFindings))
	}
}

func TestCorrelator_GetFindingsBySeverity(t *testing.T) {
	c := NewCorrelator()

	result := &ScanResult{
		ScanID: "scan-1",
		Findings: []*Finding{
			{Type: FindingSQLi, Severity: finding.Critical, Target: "https://a.com", Endpoint: "/a", Method: "GET"},
			{Type: FindingXSS, Severity: finding.Medium, Target: "https://a.com", Endpoint: "/b", Method: "GET"},
			{Type: FindingInfoLeak, Severity: finding.Low, Target: "https://a.com", Endpoint: "/c", Method: "GET"},
		},
	}
	c.AddScanResult(context.Background(), result)

	critical := c.GetFindingsBySeverity(finding.Critical)
	if len(critical) != 1 {
		t.Errorf("Expected 1 critical finding, got %d", len(critical))
	}

	high := c.GetFindingsBySeverity(finding.High)
	if len(high) != 1 { // Only critical meets >= high
		t.Errorf("Expected 1 high+ finding, got %d", len(high))
	}

	low := c.GetFindingsBySeverity(finding.Low)
	if len(low) != 3 {
		t.Errorf("Expected 3 low+ findings, got %d", len(low))
	}
}

func TestCorrelator_GetFindingsByType(t *testing.T) {
	c := NewCorrelator()

	result := &ScanResult{
		ScanID: "scan-1",
		Findings: []*Finding{
			{Type: FindingSQLi, Target: "https://a.com", Endpoint: "/a", Method: "GET"},
			{Type: FindingSQLi, Target: "https://a.com", Endpoint: "/b", Method: "GET"},
			{Type: FindingXSS, Target: "https://a.com", Endpoint: "/c", Method: "GET"},
		},
	}
	c.AddScanResult(context.Background(), result)

	sqliFindings := c.GetFindingsByType(FindingSQLi)
	if len(sqliFindings) != 2 {
		t.Errorf("Expected 2 SQLi findings, got %d", len(sqliFindings))
	}

	xssFindings := c.GetFindingsByType(FindingXSS)
	if len(xssFindings) != 1 {
		t.Errorf("Expected 1 XSS finding, got %d", len(xssFindings))
	}
}

func TestCorrelator_UpdateFindingStatus(t *testing.T) {
	c := NewCorrelator()

	finding := &Finding{
		Type:     FindingSQLi,
		Target:   "https://a.com",
		Endpoint: "/api",
		Method:   "GET",
	}
	finding.GenerateHash()

	result := &ScanResult{
		ScanID:   "scan-1",
		Findings: []*Finding{finding},
	}
	c.AddScanResult(context.Background(), result)

	err := c.UpdateFindingStatus(finding.Hash, "false-positive", "Not exploitable")
	if err != nil {
		t.Errorf("UpdateFindingStatus failed: %v", err)
	}

	cf := c.GetFindingByHash(finding.Hash)
	if cf.Status != "false-positive" {
		t.Error("Status should be updated")
	}
	if cf.Notes != "Not exploitable" {
		t.Error("Notes should be set")
	}
}

func TestCorrelator_UpdateFindingStatus_NotFound(t *testing.T) {
	c := NewCorrelator()

	err := c.UpdateFindingStatus("nonexistent", "fixed", "")
	if err == nil {
		t.Error("Should error on nonexistent finding")
	}

	_, ok := err.(*NotFoundError)
	if !ok {
		t.Error("Should return NotFoundError")
	}
}

func TestCorrelator_FindRelatedFindings(t *testing.T) {
	c := NewCorrelator()

	result := &ScanResult{
		ScanID: "scan-1",
		Findings: []*Finding{
			{ID: "f1", Type: FindingSQLi, Target: "https://a.com", Endpoint: "/api", Method: "GET", CWE: "CWE-89"},
			{ID: "f2", Type: FindingSQLi, Target: "https://a.com", Endpoint: "/other", Method: "POST", CWE: "CWE-89"}, // Same CWE
			{ID: "f3", Type: FindingXSS, Target: "https://b.com", Endpoint: "/page", Method: "GET", CWE: "CWE-79"},
		},
	}
	c.AddScanResult(context.Background(), result)

	findings := c.GetAllFindings()
	if len(findings) < 3 {
		t.Skip("Need at least 3 findings")
	}

	// Find hash for f1
	var f1Hash string
	for _, cf := range findings {
		if len(cf.Findings) > 0 && cf.Findings[0].ID == "f1" {
			f1Hash = cf.Hash
			break
		}
	}

	related := c.FindRelatedFindings(f1Hash)
	// Should find f2 as related (same CWE, same target)
	if len(related) < 1 {
		t.Error("Expected at least 1 related finding")
	}
}

func TestCorrelator_GetScanHistory(t *testing.T) {
	c := NewCorrelator()

	c.AddScanResult(context.Background(), &ScanResult{ScanID: "scan-1"})
	c.AddScanResult(context.Background(), &ScanResult{ScanID: "scan-2"})
	c.AddScanResult(context.Background(), &ScanResult{ScanID: "scan-3"})

	history := c.GetScanHistory()
	if len(history) != 3 {
		t.Errorf("Expected 3 scans in history, got %d", len(history))
	}
}

func TestCorrelator_GetLatestScan(t *testing.T) {
	c := NewCorrelator()

	// Empty history
	if c.GetLatestScan() != nil {
		t.Error("Should return nil for empty history")
	}

	c.AddScanResult(context.Background(), &ScanResult{ScanID: "scan-1"})
	c.AddScanResult(context.Background(), &ScanResult{ScanID: "scan-2"})

	latest := c.GetLatestScan()
	if latest == nil {
		t.Fatal("Should return latest scan")
	}
	if latest.ScanID != "scan-2" {
		t.Error("Should return most recent scan")
	}
}

func TestCorrelator_DetectFixedFindings(t *testing.T) {
	c := NewCorrelator()

	// First scan with 2 findings
	result1 := &ScanResult{
		ScanID: "scan-1",
		Target: "https://a.com",
		Findings: []*Finding{
			{Type: FindingSQLi, Target: "https://a.com", Endpoint: "/a", Method: "GET"},
			{Type: FindingXSS, Target: "https://a.com", Endpoint: "/b", Method: "GET"},
		},
	}
	c.AddScanResult(context.Background(), result1)

	// Second scan tests same target and same categories but only 1 of the 2
	// original findings appears — the other was fixed.
	result2 := &ScanResult{
		ScanID: "scan-2",
		Target: "https://a.com",
		Findings: []*Finding{
			{Type: FindingSQLi, Target: "https://a.com", Endpoint: "/a", Method: "GET"},
			// XSS type IS tested (different endpoint) — so the missing XSS /b is truly fixed
			{Type: FindingXSS, Target: "https://a.com", Endpoint: "/c", Method: "GET"},
		},
	}
	c.AddScanResult(context.Background(), result2)

	fixed := c.DetectFixedFindings("scan-2")
	if len(fixed) != 1 {
		t.Errorf("Expected 1 fixed finding, got %d", len(fixed))
	}

	if fixed[0].Status != "fixed" {
		t.Error("Status should be 'fixed'")
	}
}

func TestCorrelator_AnalyzeTrends_Empty(t *testing.T) {
	c := NewCorrelator()

	analysis := c.AnalyzeTrends()
	if analysis.TotalScans != 0 {
		t.Error("Should have 0 scans for empty correlator")
	}
}

func TestCorrelator_AnalyzeTrends(t *testing.T) {
	c := NewCorrelator()

	now := time.Now()
	for i := 0; i < 5; i++ {
		result := &ScanResult{
			ScanID:    string(rune('1' + i)),
			StartTime: now.Add(time.Duration(i) * time.Hour),
			EndTime:   now.Add(time.Duration(i)*time.Hour + 30*time.Minute),
			Findings: []*Finding{
				{Type: FindingSQLi, Target: "https://a.com", Endpoint: "/api", Method: "GET"},
			},
		}
		c.AddScanResult(context.Background(), result)
	}

	analysis := c.AnalyzeTrends()

	if analysis.TotalScans != 5 {
		t.Errorf("Expected 5 scans, got %d", analysis.TotalScans)
	}

	if len(analysis.FindingTrend) != 5 {
		t.Errorf("Expected 5 trend points, got %d", len(analysis.FindingTrend))
	}

	if len(analysis.TopVulnTypes) == 0 {
		t.Error("Should have top vuln types")
	}
}

func TestCorrelator_AddRule(t *testing.T) {
	c := NewCorrelator()
	initialCount := len(c.GetRules())

	c.AddRule(CorrelationRule{
		Name:        "Custom Rule",
		Description: "Test rule",
		Condition: func(a, b *Finding) bool {
			return a.ID == b.ID
		},
		Weight: 0.5,
	})

	if len(c.GetRules()) != initialCount+1 {
		t.Error("Rule should be added")
	}
}

func TestCorrelator_Clear(t *testing.T) {
	c := NewCorrelator()

	result := &ScanResult{
		ScanID:   "scan-1",
		Findings: []*Finding{{Type: FindingSQLi}},
	}
	c.AddScanResult(context.Background(), result)

	c.Clear()

	if len(c.GetAllFindings()) != 0 {
		t.Error("Findings should be cleared")
	}
	if len(c.GetScanHistory()) != 0 {
		t.Error("History should be cleared")
	}
}

func TestCorrelator_GetStats(t *testing.T) {
	c := NewCorrelator()

	result := &ScanResult{
		ScanID: "scan-1",
		Findings: []*Finding{
			{Type: FindingSQLi, Target: "https://a.com", Endpoint: "/a", Method: "GET"},
			{Type: FindingXSS, Target: "https://a.com", Endpoint: "/b", Method: "GET"},
		},
	}
	c.AddScanResult(context.Background(), result)

	stats := c.GetStats()
	if stats.TotalFindings != 2 {
		t.Errorf("Expected 2 findings, got %d", stats.TotalFindings)
	}
	if stats.TotalScans != 1 {
		t.Errorf("Expected 1 scan, got %d", stats.TotalScans)
	}
	if stats.ByStatus["new"] != 2 {
		t.Error("Expected 2 new findings")
	}
}

func TestCorrelator_MultipleScanners(t *testing.T) {
	c := NewCorrelator()

	// Same finding from different scanners
	result1 := &ScanResult{
		ScanID:  "scan-1",
		Scanner: "scanner-a",
		Findings: []*Finding{
			{Type: FindingSQLi, Target: "https://a.com", Endpoint: "/api", Method: "GET", Scanner: "scanner-a"},
		},
	}
	c.AddScanResult(context.Background(), result1)

	result2 := &ScanResult{
		ScanID:  "scan-2",
		Scanner: "scanner-b",
		Findings: []*Finding{
			{Type: FindingSQLi, Target: "https://a.com", Endpoint: "/api", Method: "GET", Scanner: "scanner-b"},
		},
	}
	c.AddScanResult(context.Background(), result2)

	// Should correlate to same finding
	findings := c.GetAllFindings()
	if len(findings) != 1 {
		t.Errorf("Expected 1 correlated finding, got %d", len(findings))
	}

	// Should track both scanners
	if len(findings[0].Scanners) != 2 {
		t.Errorf("Expected 2 scanners, got %d", len(findings[0].Scanners))
	}
}

func TestNotFoundError(t *testing.T) {
	err := &NotFoundError{Hash: "abc123"}
	if !containsString(err.Error(), "abc123") {
		t.Error("Error message should contain hash")
	}
}

func TestSeverityOrder(t *testing.T) {
	tests := []struct {
		severity finding.Severity
		expected int
	}{
		{finding.Critical, 5},
		{finding.High, 4},
		{finding.Medium, 3},
		{finding.Low, 2},
		{finding.Info, 1},
		{finding.Severity("unknown"), 0},
	}

	for _, tc := range tests {
		result := severityOrder(tc.severity)
		if result != tc.expected {
			t.Errorf("severityOrder(%s) = %d, want %d", tc.severity, result, tc.expected)
		}
	}
}

func TestContainsScanner(t *testing.T) {
	scanners := []string{"a", "b", "c"}

	if !containsScanner(scanners, "a") {
		t.Error("Should contain 'a'")
	}
	if containsScanner(scanners, "d") {
		t.Error("Should not contain 'd'")
	}
}

func TestFinding_Struct(t *testing.T) {
	f := &Finding{
		ID:           "f1",
		Hash:         "abc123",
		Type:         FindingSQLi,
		Severity:     finding.High,
		Title:        "SQL Injection",
		Description:  "Found SQL injection",
		Target:       "https://example.com",
		Endpoint:     "/api",
		Method:       "GET",
		Parameter:    "id",
		Payload:      "' OR 1=1--",
		Evidence:     "SQL error",
		CWE:          "CWE-89",
		CVE:          "CVE-2021-1234",
		CVSS:         7.5,
		Confidence:   0.9,
		Scanner:      "waf-tester",
		ScanID:       "scan-1",
		Tags:         []string{"sqli", "critical"},
		Metadata:     map[string]string{"db": "mysql"},
		DiscoveredAt: time.Now(),
		Verified:     true,
	}

	if f.ID != "f1" {
		t.Error("ID mismatch")
	}
	if f.CWE != "CWE-89" {
		t.Error("CWE mismatch")
	}
	if f.CVSS != 7.5 {
		t.Error("CVSS mismatch")
	}
}

func TestCorrelatedFinding_Struct(t *testing.T) {
	cf := &CorrelatedFinding{
		Hash:            "abc123",
		Findings:        []*Finding{{ID: "f1"}},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
		OccurrenceCount: 5,
		Scanners:        []string{"a", "b"},
		IsRecurring:     true,
		Status:          "open",
		Notes:           "Important finding",
	}

	if cf.Hash != "abc123" {
		t.Error("Hash mismatch")
	}
	if cf.OccurrenceCount != 5 {
		t.Error("OccurrenceCount mismatch")
	}
}

func TestCorrelation_Struct(t *testing.T) {
	c := &Correlation{
		ID:         "corr-1",
		Type:       "same_vuln",
		Findings:   []string{"f1", "f2"},
		Reason:     "Same hash",
		Confidence: 0.95,
		CreatedAt:  time.Now(),
	}

	if c.ID != "corr-1" {
		t.Error("ID mismatch")
	}
	if c.Confidence != 0.95 {
		t.Error("Confidence mismatch")
	}
}

func TestScanResult_Struct(t *testing.T) {
	sr := &ScanResult{
		ScanID:    "scan-1",
		Target:    "https://example.com",
		Scanner:   "waf-tester",
		StartTime: time.Now(),
		EndTime:   time.Now().Add(1 * time.Minute),
		Findings:  []*Finding{},
		Summary: ScanSummary{
			TotalFindings: 10,
		},
	}

	if sr.ScanID != "scan-1" {
		t.Error("ScanID mismatch")
	}
	if sr.Summary.TotalFindings != 10 {
		t.Error("Summary mismatch")
	}
}

func TestTrendAnalysis_Struct(t *testing.T) {
	ta := &TrendAnalysis{
		TimeRange: TimeRange{
			Start: time.Now(),
			End:   time.Now().Add(1 * time.Hour),
		},
		TotalScans: 5,
		TopEndpoints: []EndpointStats{
			{Endpoint: "/api", Count: 10},
		},
	}

	if ta.TotalScans != 5 {
		t.Error("TotalScans mismatch")
	}
	if len(ta.TopEndpoints) != 1 {
		t.Error("TopEndpoints mismatch")
	}
}

func TestCorrelatorStats_Struct(t *testing.T) {
	cs := &CorrelatorStats{
		TotalFindings:     100,
		RecurringFindings: 25,
		TotalScans:        10,
		ByStatus:          map[string]int{"new": 50, "open": 30},
	}

	if cs.TotalFindings != 100 {
		t.Error("TotalFindings mismatch")
	}
	if cs.ByStatus["new"] != 50 {
		t.Error("ByStatus mismatch")
	}
}

// Helper function for string contains
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
