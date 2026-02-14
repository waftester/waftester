package main

import (
	"testing"

	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/sqli"
	"github.com/waftester/waftester/pkg/xss"
)

func TestParseScanFilters(t *testing.T) {
	t.Parallel()

	t.Run("empty flags produce no active filters", func(t *testing.T) {
		t.Parallel()
		f := parseScanFilters("", "", "", "", true, true)
		if f.hasFilters() {
			t.Fatal("expected no active filters")
		}
	})

	t.Run("match severity parsed correctly", func(t *testing.T) {
		t.Parallel()
		f := parseScanFilters("critical,high", "", "", "", true, true)
		if !f.includeSeverity(finding.Critical) {
			t.Error("critical should be included")
		}
		if !f.includeSeverity(finding.High) {
			t.Error("high should be included")
		}
		if f.includeSeverity(finding.Low) {
			t.Error("low should not be included when match=critical,high")
		}
	})

	t.Run("filter severity excludes", func(t *testing.T) {
		t.Parallel()
		f := parseScanFilters("", "info,low", "", "", true, true)
		if f.includeSeverity(finding.Info) {
			t.Error("info should be excluded")
		}
		if !f.includeSeverity(finding.High) {
			t.Error("high should still be included")
		}
	})

	t.Run("match category", func(t *testing.T) {
		t.Parallel()
		f := parseScanFilters("", "", "sqli,xss", "", true, true)
		if !f.includeCategory("sqli") {
			t.Error("sqli should be included")
		}
		if f.includeCategory("cmdi") {
			t.Error("cmdi should not be included")
		}
	})

	t.Run("filter category", func(t *testing.T) {
		t.Parallel()
		f := parseScanFilters("", "", "", "cors", true, true)
		if f.includeCategory("cors") {
			t.Error("cors should be excluded")
		}
		if !f.includeCategory("sqli") {
			t.Error("sqli should still be included")
		}
	})

	t.Run("strip evidence and remediation flags", func(t *testing.T) {
		t.Parallel()
		f := parseScanFilters("", "", "", "", false, false)
		if !f.stripEvidence {
			t.Error("evidence should be stripped")
		}
		if !f.stripRemediation {
			t.Error("remediation should be stripped")
		}
		if !f.hasFilters() {
			t.Error("strip flags should activate filters")
		}
	})
}

func TestApplyFilters_SeverityFilter(t *testing.T) {
	t.Parallel()

	result := &ScanResult{
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
		SQLi: &sqli.ScanResult{
			Vulnerabilities: []sqli.Vulnerability{
				{Vulnerability: finding.Vulnerability{Severity: finding.Critical, URL: "http://x", Evidence: "e1", Remediation: "r1"}},
				{Vulnerability: finding.Vulnerability{Severity: finding.Low, URL: "http://x", Evidence: "e2", Remediation: "r2"}},
				{Vulnerability: finding.Vulnerability{Severity: finding.High, URL: "http://x", Evidence: "e3", Remediation: "r3"}},
			},
		},
		TotalVulns: 3,
	}

	f := parseScanFilters("critical,high", "", "", "", true, true)
	applyFilters(result, f)

	if result.TotalVulns != 2 {
		t.Errorf("expected 2 vulns after filter, got %d", result.TotalVulns)
	}
	if len(result.SQLi.Vulnerabilities) != 2 {
		t.Errorf("expected 2 sqli vulns, got %d", len(result.SQLi.Vulnerabilities))
	}
	for _, v := range result.SQLi.Vulnerabilities {
		if v.Severity == finding.Low {
			t.Error("low severity vuln should have been filtered out")
		}
	}
}

func TestApplyFilters_CategoryFilter(t *testing.T) {
	t.Parallel()

	result := &ScanResult{
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
		SQLi: &sqli.ScanResult{
			Vulnerabilities: []sqli.Vulnerability{
				{Vulnerability: finding.Vulnerability{Severity: finding.High, URL: "http://x"}},
			},
		},
		XSS: &xss.ScanResult{
			Vulnerabilities: []xss.Vulnerability{
				{Vulnerability: finding.Vulnerability{Severity: finding.Medium, URL: "http://x"}},
			},
		},
		TotalVulns: 2,
	}

	// Match only sqli category
	f := parseScanFilters("", "", "sqli", "", true, true)
	applyFilters(result, f)

	if result.XSS != nil {
		t.Error("XSS should be nil after category match=sqli")
	}
	if result.SQLi == nil {
		t.Fatal("SQLi should still be present")
	}
	if result.TotalVulns != 1 {
		t.Errorf("expected 1 total vuln, got %d", result.TotalVulns)
	}
}

func TestApplyFilters_StripEvidence(t *testing.T) {
	t.Parallel()

	result := &ScanResult{
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
		SQLi: &sqli.ScanResult{
			Vulnerabilities: []sqli.Vulnerability{
				{Vulnerability: finding.Vulnerability{Severity: finding.High, URL: "http://x", Evidence: "secret", Remediation: "fix it"}},
			},
		},
		TotalVulns: 1,
	}

	f := parseScanFilters("", "", "", "", false, false)
	applyFilters(result, f)

	v := result.SQLi.Vulnerabilities[0]
	if v.Evidence != "" {
		t.Error("evidence should be stripped")
	}
	if v.Remediation != "" {
		t.Error("remediation should be stripped")
	}
	if result.TotalVulns != 1 {
		t.Error("total vulns should still be 1")
	}
}

func TestApplyFilters_NoFilters(t *testing.T) {
	t.Parallel()

	result := &ScanResult{
		BySeverity: map[string]int{"high": 1},
		ByCategory: map[string]int{"sqli": 1},
		SQLi: &sqli.ScanResult{
			Vulnerabilities: []sqli.Vulnerability{
				{Vulnerability: finding.Vulnerability{Severity: finding.High, URL: "http://x"}},
			},
		},
		TotalVulns: 1,
	}

	// No filters active
	f := parseScanFilters("", "", "", "", true, true)
	applyFilters(result, f)

	// Nothing should change
	if result.TotalVulns != 1 {
		t.Errorf("expected 1, got %d", result.TotalVulns)
	}
}

func TestSplitCSV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"a", 1},
		{"a,b,c", 3},
		{" A , B ", 2},
		{",,,", 0},
	}
	for _, tt := range tests {
		got := splitCSV(tt.input)
		if len(got) != tt.want {
			t.Errorf("splitCSV(%q) = %d items, want %d", tt.input, len(got), tt.want)
		}
	}
}
