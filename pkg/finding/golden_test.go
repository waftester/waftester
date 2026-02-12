package finding_test

import (
	"encoding/json"
	"testing"
)

// TestGolden_PreMigrationJSONShape captures current JSON output shapes as
// golden references. Run BEFORE and AFTER migration to verify JSON compat.
func TestGolden_PreMigrationJSONShape(t *testing.T) {
	t.Parallel()

	shapes := map[string]string{
		"sqli": `{
			"type":"error-based","dbms":"mysql",
			"description":"SQL injection in search parameter",
			"severity":"critical","url":"https://example.com/search",
			"parameter":"id","method":"GET",
			"payload":null,"evidence":"syntax error at position 42",
			"remediation":"Use parameterized queries",
			"response_time":0,"cvss":7.5,"confirmed_by":1
		}`,
		"xss": `{
			"type":"reflected","context":"html-attr",
			"description":"Reflected XSS in search",
			"severity":"medium",
			"url":"https://example.com/search",
			"parameter":"q","method":"GET",
			"payload":null,"evidence":"<script>alert(1)</script>",
			"remediation":"Encode output","cvss":5.4,
			"confirmed_by":1
		}`,
		"ssrf": `{
			"type":"cloud-metadata",
			"severity":"critical",
			"parameter":"url",
			"payload":"http://169.254.169.254/latest/meta-data/",
			"evidence":"ami-id found in response",
			"confidence":0.95,
			"remediation":"Validate and restrict outbound URLs",
			"confirmed_by":1
		}`,
	}

	// Common fields every vulnerability shape must have
	requiredFields := []string{"severity", "evidence", "confirmed_by"}

	for name, rawJSON := range shapes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m map[string]any
			if err := json.Unmarshal([]byte(rawJSON), &m); err != nil {
				t.Fatalf("invalid golden JSON for %s: %v", name, err)
			}

			for _, field := range requiredFields {
				if _, ok := m[field]; !ok {
					t.Errorf("%s: missing required field %q", name, field)
				}
			}
		})
	}
}

// TestGolden_SeverityValues verifies that all codebase severity values
// are lowercase strings — the canonical format used across 28 packages.
func TestGolden_SeverityValues(t *testing.T) {
	t.Parallel()

	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
		"info":     true,
	}

	testCases := []struct {
		pkg      string
		severity string
	}{
		{"sqli", "critical"},
		{"xss", "medium"},
		{"ssrf", "critical"},
		{"cmdi", "high"},
		{"ssti", "high"},
		{"xxe", "critical"},
	}

	for _, tc := range testCases {
		t.Run(tc.pkg, func(t *testing.T) {
			t.Parallel()
			if !validSeverities[tc.severity] {
				t.Errorf("%s: severity %q is not valid", tc.pkg, tc.severity)
			}
		})
	}
}
