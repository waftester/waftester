package detection

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestRequiredFieldsExist verifies the contract constants are defined
func TestRequiredFieldsExist(t *testing.T) {
	if len(RequiredStatsFields) == 0 {
		t.Fatal("RequiredStatsFields must not be empty")
	}
	if len(RequiredJSONKeys) == 0 {
		t.Fatal("RequiredJSONKeys must not be empty")
	}
	if len(RequiredConsoleLabels) == 0 {
		t.Fatal("RequiredConsoleLabels must not be empty")
	}
}

// TestAllFormatsContainRequiredFields is the MASTER CONTRACT TEST.
// If this test fails, a required field is missing from an output format.
func TestAllFormatsContainRequiredFields(t *testing.T) {
	// Create stats with all fields populated
	stats := Stats{
		DropsDetected: 5,
		BansDetected:  3,
		HostsSkipped:  2,
	}

	formats := []struct {
		format Format
		name   string
	}{
		{FormatConsole, "Console"},
		{FormatJSON, "JSON"},
		{FormatMarkdown, "Markdown"},
	}

	for _, tc := range formats {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := stats.WriteTo(&buf, tc.format)
			if err != nil {
				t.Fatalf("WriteTo failed: %v", err)
			}
			output := buf.String()

			// For JSON, parse and check keys
			if tc.format == FormatJSON {
				var parsed map[string]interface{}
				if err := json.Unmarshal([]byte(output), &parsed); err != nil {
					t.Fatalf("Invalid JSON output: %v", err)
				}
				for _, key := range RequiredJSONKeys {
					if _, ok := parsed[key]; !ok {
						t.Errorf("JSON output missing required key: %s", key)
					}
				}
				return
			}

			// For text formats, check labels appear
			if tc.format == FormatConsole {
				for _, label := range RequiredConsoleLabels {
					if !strings.Contains(output, label) {
						t.Errorf("Console output missing required label: %s\nOutput: %s", label, output)
					}
				}
				return
			}

			// For Markdown, check labels appear
			if tc.format == FormatMarkdown {
				for _, label := range RequiredMarkdownLabels {
					if !strings.Contains(output, label) {
						t.Errorf("Markdown output missing required label: %s\nOutput: %s", label, output)
					}
				}
				return
			}
		})
	}
}

// TestJSONOutputStructure verifies JSON output is valid and complete
func TestJSONOutputStructure(t *testing.T) {
	stats := Stats{
		DropsDetected: 10,
		BansDetected:  5,
		HostsSkipped:  3,
		Details: map[string]int{
			"extra_stat": 42,
		},
	}

	var buf bytes.Buffer
	err := stats.WriteTo(&buf, FormatJSON)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	// Check values match
	if int(parsed["drops_detected"].(float64)) != 10 {
		t.Errorf("drops_detected mismatch: got %v, want 10", parsed["drops_detected"])
	}
	if int(parsed["bans_detected"].(float64)) != 5 {
		t.Errorf("bans_detected mismatch: got %v, want 5", parsed["bans_detected"])
	}
	if int(parsed["hosts_skipped"].(float64)) != 3 {
		t.Errorf("hosts_skipped mismatch: got %v, want 3", parsed["hosts_skipped"])
	}
}

// TestConsoleOutputHasColors verifies console output includes ANSI colors
func TestConsoleOutputHasColors(t *testing.T) {
	stats := Stats{
		DropsDetected: 5,
		BansDetected:  3,
		HostsSkipped:  2,
	}

	var buf bytes.Buffer
	err := stats.WriteTo(&buf, FormatConsole)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	output := buf.String()

	// Should contain ANSI escape codes or emoji indicators
	hasIndicators := strings.Contains(output, "⚠") ||
		strings.Contains(output, "🚫") ||
		strings.Contains(output, "⏭") ||
		strings.Contains(output, "\033[")

	if !hasIndicators {
		t.Errorf("Console output should have visual indicators (emoji or ANSI)\nOutput: %s", output)
	}
}

// TestEmptyStatsProducesNoOutput verifies HasData works correctly
func TestEmptyStatsProducesNoOutput(t *testing.T) {
	stats := Stats{}

	if stats.HasData() {
		t.Error("Empty stats should return HasData() = false")
	}
}

// TestNonEmptyStatsHasData verifies HasData detects populated stats
func TestNonEmptyStatsHasData(t *testing.T) {
	tests := []struct {
		name  string
		stats Stats
		want  bool
	}{
		{"drops only", Stats{DropsDetected: 1}, true},
		{"bans only", Stats{BansDetected: 1}, true},
		{"skipped only", Stats{HostsSkipped: 1}, true},
		{"all zeros", Stats{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.stats.HasData(); got != tc.want {
				t.Errorf("HasData() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSeverityLevels verifies severity classification
func TestSeverityLevels(t *testing.T) {
	tests := []struct {
		name  string
		stats Stats
		want  string
	}{
		{"none", Stats{}, "none"},
		{"info - skipped only", Stats{HostsSkipped: 1}, "info"},
		{"warning - drops", Stats{DropsDetected: 1}, "warning"},
		{"error - bans", Stats{BansDetected: 1}, "error"},
		{"error - bans override drops", Stats{DropsDetected: 5, BansDetected: 1}, "error"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.stats.Severity(); got != tc.want {
				t.Errorf("Severity() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestExitCodeContribution verifies exit code mapping
func TestExitCodeContribution(t *testing.T) {
	tests := []struct {
		name  string
		stats Stats
		want  int
	}{
		{"none", Stats{}, 0},
		{"info", Stats{HostsSkipped: 1}, 0},
		{"warning", Stats{DropsDetected: 1}, 1},
		{"error", Stats{BansDetected: 1}, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.stats.ExitCodeContribution(); got != tc.want {
				t.Errorf("ExitCodeContribution() = %v, want %v", got, tc.want)
			}
		})
	}
}
