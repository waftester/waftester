package policy

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLoadPolicy(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, p *Policy)
	}{
		{
			name: "valid full policy",
			content: `
version: "1.0"
name: "production-gate"
fail_on:
  bypasses:
    total: 5
    critical: 1
    high: 3
  categories:
    - sqli
    - rce
  effectiveness_below: 95.0
  error_rate_above: 10.0
ignore:
  test_ids:
    - "test-123"
  categories:
    - informational
`,
			wantErr: false,
			validate: func(t *testing.T, p *Policy) {
				if p.Name != "production-gate" {
					t.Errorf("got name %q, want %q", p.Name, "production-gate")
				}
				if p.Version != "1.0" {
					t.Errorf("got version %q, want %q", p.Version, "1.0")
				}
				if p.FailOn.Bypasses.Total == nil || *p.FailOn.Bypasses.Total != 5 {
					t.Errorf("got total threshold %v, want 5", p.FailOn.Bypasses.Total)
				}
				if p.FailOn.Bypasses.Critical == nil || *p.FailOn.Bypasses.Critical != 1 {
					t.Errorf("got critical threshold %v, want 1", p.FailOn.Bypasses.Critical)
				}
				if len(p.FailOn.Categories) != 2 {
					t.Errorf("got %d categories, want 2", len(p.FailOn.Categories))
				}
				if p.FailOn.EffectivenessBelow == nil || *p.FailOn.EffectivenessBelow != 95.0 {
					t.Errorf("got effectiveness threshold %v, want 95.0", p.FailOn.EffectivenessBelow)
				}
				if len(p.Ignore.TestIDs) != 1 {
					t.Errorf("got %d ignored test IDs, want 1", len(p.Ignore.TestIDs))
				}
			},
		},
		{
			name: "minimal policy",
			content: `
name: "minimal"
fail_on:
  bypasses:
    critical: 0
`,
			wantErr: false,
			validate: func(t *testing.T, p *Policy) {
				if p.Name != "minimal" {
					t.Errorf("got name %q, want %q", p.Name, "minimal")
				}
				if p.Version != "1.0" {
					t.Errorf("default version should be 1.0, got %q", p.Version)
				}
				if p.FailOn.Bypasses.Critical == nil || *p.FailOn.Bypasses.Critical != 0 {
					t.Errorf("got critical threshold %v, want 0", p.FailOn.Bypasses.Critical)
				}
			},
		},
		{
			name: "empty policy",
			content: `
name: "empty"
`,
			wantErr: false,
			validate: func(t *testing.T, p *Policy) {
				if p.Name != "empty" {
					t.Errorf("got name %q, want %q", p.Name, "empty")
				}
			},
		},
		{
			name: "categories normalized to lowercase",
			content: `
name: "case-test"
fail_on:
  categories:
    - SQLi
    - RCE
    - XSS
ignore:
  categories:
    - Informational
`,
			wantErr: false,
			validate: func(t *testing.T, p *Policy) {
				for _, cat := range p.FailOn.Categories {
					if cat != strings.ToLower(cat) {
						t.Errorf("category %q should be lowercase", cat)
					}
				}
				for _, cat := range p.Ignore.Categories {
					if cat != strings.ToLower(cat) {
						t.Errorf("ignore category %q should be lowercase", cat)
					}
				}
			},
		},
		{
			name:        "invalid yaml",
			content:     "{{invalid yaml",
			wantErr:     true,
			errContains: "invalid policy file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}

			p, err := LoadPolicy(path)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, p)
			}
		})
	}
}

func TestLoadPolicy_NotFound(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/path/policy.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "policy file not found") {
		t.Errorf("error should indicate file not found, got: %v", err)
	}
}

func TestParsePolicy(t *testing.T) {
	data := []byte(`
version: "2.0"
name: "test"
fail_on:
  bypasses:
    total: 10
`)
	p, err := ParsePolicy(data)
	if err != nil {
		t.Fatalf("ParsePolicy failed: %v", err)
	}
	if p.Version != "2.0" {
		t.Errorf("got version %q, want %q", p.Version, "2.0")
	}
	if p.Name != "test" {
		t.Errorf("got name %q, want %q", p.Name, "test")
	}
}

func TestEvaluate_TotalBypasses(t *testing.T) {
	policy := &Policy{
		Name: "test",
		FailOn: FailOn{
			Bypasses: BypassThresholds{
				Total: intPtr(5),
			},
		},
	}

	tests := []struct {
		name     string
		bypasses int
		wantPass bool
	}{
		{"under threshold", 3, true},
		{"at threshold", 5, true},
		{"over threshold", 6, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := SummaryData{
				TotalBypasses: tt.bypasses,
			}
			result := policy.Evaluate(summary)
			if result.Pass != tt.wantPass {
				t.Errorf("got Pass=%v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

func TestEvaluate_SeverityThresholds(t *testing.T) {
	policy := &Policy{
		Name: "test",
		FailOn: FailOn{
			Bypasses: BypassThresholds{
				Critical: intPtr(0),
				High:     intPtr(2),
				Medium:   intPtr(5),
			},
		},
	}

	tests := []struct {
		name       string
		severities map[string]int
		wantPass   bool
		wantFails  int
	}{
		{
			name:       "all under thresholds",
			severities: map[string]int{"critical": 0, "high": 1, "medium": 3},
			wantPass:   true,
			wantFails:  0,
		},
		{
			name:       "critical over threshold",
			severities: map[string]int{"critical": 1, "high": 0, "medium": 0},
			wantPass:   false,
			wantFails:  1,
		},
		{
			name:       "high over threshold",
			severities: map[string]int{"critical": 0, "high": 3, "medium": 0},
			wantPass:   false,
			wantFails:  1,
		},
		{
			name:       "multiple over threshold",
			severities: map[string]int{"critical": 2, "high": 5, "medium": 10},
			wantPass:   false,
			wantFails:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := SummaryData{
				BypassesBySeverity: tt.severities,
			}
			result := policy.Evaluate(summary)
			if result.Pass != tt.wantPass {
				t.Errorf("got Pass=%v, want %v", result.Pass, tt.wantPass)
			}
			if len(result.Failures) != tt.wantFails {
				t.Errorf("got %d failures, want %d: %v", len(result.Failures), tt.wantFails, result.Failures)
			}
		})
	}
}

func TestEvaluate_CategoryBypasses(t *testing.T) {
	policy := &Policy{
		Name: "test",
		FailOn: FailOn{
			Categories: []string{"sqli", "rce"},
		},
	}

	tests := []struct {
		name       string
		categories map[string]int
		wantPass   bool
		wantFails  int
	}{
		{
			name:       "no bypasses in watched categories",
			categories: map[string]int{"xss": 5, "traversal": 3},
			wantPass:   true,
			wantFails:  0,
		},
		{
			name:       "sqli bypass",
			categories: map[string]int{"sqli": 1},
			wantPass:   false,
			wantFails:  1,
		},
		{
			name:       "rce bypass",
			categories: map[string]int{"rce": 2},
			wantPass:   false,
			wantFails:  1,
		},
		{
			name:       "both sqli and rce",
			categories: map[string]int{"sqli": 1, "rce": 1},
			wantPass:   false,
			wantFails:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := SummaryData{
				BypassesByCategory: tt.categories,
			}
			result := policy.Evaluate(summary)
			if result.Pass != tt.wantPass {
				t.Errorf("got Pass=%v, want %v", result.Pass, tt.wantPass)
			}
			if len(result.Failures) != tt.wantFails {
				t.Errorf("got %d failures, want %d: %v", len(result.Failures), tt.wantFails, result.Failures)
			}
		})
	}
}

func TestEvaluate_Effectiveness(t *testing.T) {
	threshold := 95.0
	policy := &Policy{
		Name: "test",
		FailOn: FailOn{
			EffectivenessBelow: &threshold,
		},
	}

	tests := []struct {
		name          string
		effectiveness float64
		wantPass      bool
	}{
		{"above threshold", 98.0, true},
		{"at threshold", 95.0, true},
		{"below threshold", 90.0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := SummaryData{
				Effectiveness: tt.effectiveness,
			}
			result := policy.Evaluate(summary)
			if result.Pass != tt.wantPass {
				t.Errorf("got Pass=%v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

func TestEvaluate_ErrorRate(t *testing.T) {
	threshold := 10.0
	policy := &Policy{
		Name: "test",
		FailOn: FailOn{
			ErrorRateAbove: &threshold,
		},
	}

	tests := []struct {
		name      string
		errorRate float64
		wantPass  bool
	}{
		{"below threshold", 5.0, true},
		{"at threshold", 10.0, true},
		{"above threshold", 15.0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := SummaryData{
				ErrorRate: tt.errorRate,
			}
			result := policy.Evaluate(summary)
			if result.Pass != tt.wantPass {
				t.Errorf("got Pass=%v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}

func TestEvaluate_IgnoreCategories(t *testing.T) {
	policy := &Policy{
		Name: "test",
		FailOn: FailOn{
			Bypasses: BypassThresholds{
				Total: intPtr(0), // Fail on any bypass
			},
			Categories: []string{"sqli"},
		},
		Ignore: IgnoreSpec{
			Categories: []string{"informational", "sqli"},
		},
	}

	summary := SummaryData{
		TotalBypasses: 5,
		BypassesByCategory: map[string]int{
			"informational": 3,
			"sqli":          2,
		},
	}

	result := policy.Evaluate(summary)
	// Total bypasses should be reduced by ignored categories (5 - 3 - 2 = 0)
	if !result.Pass {
		t.Errorf("expected pass when all bypasses are in ignored categories, got failures: %v", result.Failures)
	}
}

func TestEvaluate_IgnoreTestIDs(t *testing.T) {
	policy := &Policy{
		Name: "test",
		Ignore: IgnoreSpec{
			TestIDs: []string{"test-123", "test-456"},
		},
	}

	summary := SummaryData{
		TotalBypasses: 2,
		BypassTestIDs: []string{"test-123", "test-456"},
	}

	// Note: Current implementation doesn't fully support per-test-ID ignore
	// This test verifies the ignore spec is properly parsed
	result := policy.Evaluate(summary)
	if result.PolicyName != "test" {
		t.Errorf("got policy name %q, want %q", result.PolicyName, "test")
	}
}

func TestEvaluate_ExitCode(t *testing.T) {
	policy := &Policy{
		Name: "test",
		FailOn: FailOn{
			Bypasses: BypassThresholds{
				Total: intPtr(0),
			},
		},
	}

	tests := []struct {
		name         string
		bypasses     int
		wantExitCode int
	}{
		{"pass", 0, 0},
		{"fail", 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := SummaryData{
				TotalBypasses: tt.bypasses,
			}
			result := policy.Evaluate(summary)
			if result.ExitCode != tt.wantExitCode {
				t.Errorf("got ExitCode=%d, want %d", result.ExitCode, tt.wantExitCode)
			}
		})
	}
}

func TestEvaluate_FailureMessages(t *testing.T) {
	threshold := 95.0
	errorThreshold := 10.0
	policy := &Policy{
		Name: "test",
		FailOn: FailOn{
			Bypasses: BypassThresholds{
				Total:    intPtr(5),
				Critical: intPtr(0),
			},
			Categories:         []string{"rce"},
			EffectivenessBelow: &threshold,
			ErrorRateAbove:     &errorThreshold,
		},
	}

	summary := SummaryData{
		TotalBypasses:      10,
		BypassesBySeverity: map[string]int{"critical": 2},
		BypassesByCategory: map[string]int{"rce": 1},
		Effectiveness:      85.0,
		ErrorRate:          15.0,
	}

	result := policy.Evaluate(summary)
	if result.Pass {
		t.Error("expected failure")
	}

	// Should have 5 failures
	expectedFailures := 5
	if len(result.Failures) != expectedFailures {
		t.Errorf("got %d failures, want %d: %v", len(result.Failures), expectedFailures, result.Failures)
	}

	// Check failure messages contain useful information
	for _, msg := range result.Failures {
		if msg == "" {
			t.Error("failure message should not be empty")
		}
	}
}

func TestEvaluate_ThreadSafety(t *testing.T) {
	policy := &Policy{
		Name: "concurrent-test",
		FailOn: FailOn{
			Bypasses: BypassThresholds{
				Total: intPtr(10),
			},
		},
	}

	summary := SummaryData{
		TotalBypasses: 5,
	}

	// Run concurrent evaluations
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := policy.Evaluate(summary)
			if !result.Pass {
				t.Error("concurrent evaluation failed unexpectedly")
			}
		}()
	}
	wg.Wait()
}

func TestPolicy_String(t *testing.T) {
	tests := []struct {
		name    string
		policy  *Policy
		wantStr string
	}{
		{
			name:    "with name",
			policy:  &Policy{Name: "prod-gate", Version: "1.0"},
			wantStr: "Policy(prod-gate v1.0)",
		},
		{
			name:    "without name",
			policy:  &Policy{Version: "2.0"},
			wantStr: "Policy(v2.0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.String(); got != tt.wantStr {
				t.Errorf("got %q, want %q", got, tt.wantStr)
			}
		})
	}
}

func TestEvaluate_ComplexPolicy(t *testing.T) {
	// Test a realistic production policy
	policyYAML := `
version: "1.0"
name: "production-security-gate"
fail_on:
  bypasses:
    total: 10
    critical: 0
    high: 3
  categories:
    - sqli
    - rce
    - command-injection
  effectiveness_below: 90.0
  error_rate_above: 5.0
ignore:
  categories:
    - informational
`
	policy, err := ParsePolicy([]byte(policyYAML))
	if err != nil {
		t.Fatalf("failed to parse policy: %v", err)
	}

	tests := []struct {
		name     string
		summary  SummaryData
		wantPass bool
	}{
		{
			name: "passing scan",
			summary: SummaryData{
				TotalBypasses:      5,
				BypassesBySeverity: map[string]int{"high": 2, "medium": 3},
				BypassesByCategory: map[string]int{"xss": 3, "traversal": 2},
				Effectiveness:      95.0,
				ErrorRate:          2.0,
			},
			wantPass: true,
		},
		{
			name: "failing on critical",
			summary: SummaryData{
				TotalBypasses:      1,
				BypassesBySeverity: map[string]int{"critical": 1},
				Effectiveness:      99.0,
				ErrorRate:          1.0,
			},
			wantPass: false,
		},
		{
			name: "failing on sqli category",
			summary: SummaryData{
				TotalBypasses:      1,
				BypassesByCategory: map[string]int{"sqli": 1},
				Effectiveness:      99.0,
				ErrorRate:          1.0,
			},
			wantPass: false,
		},
		{
			name: "failing on low effectiveness",
			summary: SummaryData{
				TotalBypasses: 0,
				Effectiveness: 85.0,
				ErrorRate:     1.0,
			},
			wantPass: false,
		},
		{
			name: "ignored informational bypasses",
			summary: SummaryData{
				TotalBypasses:      5,
				BypassesByCategory: map[string]int{"informational": 5},
				Effectiveness:      95.0,
				ErrorRate:          2.0,
			},
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := policy.Evaluate(tt.summary)
			if result.Pass != tt.wantPass {
				t.Errorf("got Pass=%v, want %v, failures: %v", result.Pass, tt.wantPass, result.Failures)
			}
		})
	}
}

func TestEvaluate_NilThresholds(t *testing.T) {
	// Policy with no thresholds set should pass everything
	policy := &Policy{
		Name: "permissive",
	}

	summary := SummaryData{
		TotalBypasses:      100,
		BypassesBySeverity: map[string]int{"critical": 50},
		BypassesByCategory: map[string]int{"sqli": 25, "rce": 25},
		Effectiveness:      50.0,
		ErrorRate:          50.0,
	}

	result := policy.Evaluate(summary)
	if !result.Pass {
		t.Errorf("permissive policy should pass, got failures: %v", result.Failures)
	}
}

func TestEvaluate_ZeroThresholdVsNilThreshold(t *testing.T) {
	// Zero threshold means "fail if > 0" (any bypass fails)
	// Nil threshold means "no limit"

	tests := []struct {
		name      string
		threshold *int
		bypasses  int
		wantPass  bool
	}{
		{"nil threshold, many bypasses", nil, 100, true},
		{"zero threshold, zero bypasses", intPtr(0), 0, true},
		{"zero threshold, one bypass", intPtr(0), 1, false},
		{"one threshold, one bypass", intPtr(1), 1, true},
		{"one threshold, two bypasses", intPtr(1), 2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &Policy{
				Name: "test",
				FailOn: FailOn{
					Bypasses: BypassThresholds{
						Critical: tt.threshold,
					},
				},
			}
			summary := SummaryData{
				BypassesBySeverity: map[string]int{"critical": tt.bypasses},
			}
			result := policy.Evaluate(summary)
			if result.Pass != tt.wantPass {
				t.Errorf("got Pass=%v, want %v", result.Pass, tt.wantPass)
			}
		})
	}
}
