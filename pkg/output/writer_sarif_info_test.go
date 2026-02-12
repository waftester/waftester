// Regression test for Bug #8: SARIF writer missing "Info" severity mapping.
//
// Before the fix, severityMap and securityScore had no "Info" entry, causing
// Info-severity findings to get empty strings for SARIF level and score.
package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestSARIFWriter_InfoSeverity verifies that Info-severity findings produce
// valid SARIF output with level "note" and a security score.
//
// Regression: The severityMap had Critical/High/Medium/Low but not Info,
// so Info findings produced empty level and score fields.
func TestSARIFWriter_InfoSeverity(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "info-test.sarif")

	w, err := NewWriter(path, "sarif")
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	// Write findings at every severity level including Info.
	w.Write(makeTestResult("test-info", "recon", "Info", "Fail", 200))
	w.Write(makeTestResult("test-low", "xss", "Low", "Fail", 200))
	w.Write(makeTestResult("test-critical", "sqli", "Critical", "Fail", 200))
	w.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var sarif struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
						} `json:"properties"`
						DefaultConfig struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("failed to parse SARIF: %v", err)
	}

	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}

	results := sarif.Runs[0].Results
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Verify the Info-severity result has level "note" in the result.
	foundResult := false
	for _, r := range results {
		if r.RuleID == "test-info" {
			foundResult = true
			if r.Level != "note" {
				t.Errorf("Info severity result level = %q, want \"note\"", r.Level)
			}
		}
	}
	if !foundResult {
		t.Error("Info-severity result not found in SARIF output")
	}

	// Verify the Info-severity rule has security-severity "1.0".
	rules := sarif.Runs[0].Tool.Driver.Rules
	foundRule := false
	for _, rule := range rules {
		if rule.ID == "test-info" {
			foundRule = true
			if rule.Properties.SecuritySeverity != "1.0" {
				t.Errorf("Info rule security-severity = %q, want \"1.0\"", rule.Properties.SecuritySeverity)
			}
			if rule.DefaultConfig.Level != "note" {
				t.Errorf("Info rule defaultConfiguration.level = %q, want \"note\"", rule.DefaultConfig.Level)
			}
		}
	}
	if !foundRule {
		t.Error("Info-severity rule not found in SARIF output")
	}
}
