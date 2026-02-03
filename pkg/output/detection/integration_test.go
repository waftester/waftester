package detection

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestIntegrationFullPipeline tests the complete flow from provider to output
func TestIntegrationFullPipeline(t *testing.T) {
	// Simulate what the detector would return
	mockStats := map[string]int{
		"connmon_total_drops":    15,
		"silentban_total_bans":   8,
		"hosts_skipped":          4,
		"connmon_reset_count":    3,
		"connmon_timeout_count":  5,
		"silentban_403_count":    2,
		"silentban_captcha_count": 1,
	}

	mock := &mockProvider{stats: mockStats}

	// Extract stats
	stats := FromProvider(mock)

	// Verify extraction
	if stats.DropsDetected != 15 {
		t.Errorf("DropsDetected = %d, want 15", stats.DropsDetected)
	}
	if stats.BansDetected != 8 {
		t.Errorf("BansDetected = %d, want 8", stats.BansDetected)
	}
	if stats.HostsSkipped != 4 {
		t.Errorf("HostsSkipped = %d, want 4", stats.HostsSkipped)
	}

	// Verify HasData
	if !stats.HasData() {
		t.Error("Stats with data should return HasData() = true")
	}

	// Verify severity (bans = error)
	if sev := stats.Severity(); sev != "error" {
		t.Errorf("Severity = %s, want error", sev)
	}

	// Verify exit code
	if code := stats.ExitCodeContribution(); code != 2 {
		t.Errorf("ExitCodeContribution = %d, want 2", code)
	}

	// Verify recommendations exist
	recs := stats.Recommendations()
	if len(recs) == 0 {
		t.Error("Should have recommendations")
	}

	// Verify all output formats work
	formats := []Format{FormatConsole, FormatJSON, FormatMarkdown}
	for _, format := range formats {
		var buf bytes.Buffer
		if err := stats.WriteTo(&buf, format); err != nil {
			t.Errorf("Format %d failed: %v", format, err)
		}
		if buf.Len() == 0 {
			t.Errorf("Format %d produced empty output", format)
		}
	}

	// Verify ToJSON
	jsonMap := stats.ToJSON()
	if len(jsonMap) == 0 {
		t.Error("ToJSON should return non-empty map")
	}

	// Verify JSON is serializable
	jsonBytes, err := json.Marshal(jsonMap)
	if err != nil {
		t.Errorf("JSON marshaling failed: %v", err)
	}
	if len(jsonBytes) < 10 {
		t.Error("JSON output too short")
	}
}

// TestIntegrationEmptyPipeline tests empty stats don't cause errors
func TestIntegrationEmptyPipeline(t *testing.T) {
	mock := &mockProvider{stats: map[string]int{}}

	stats := FromProvider(mock)

	// Should not have data
	if stats.HasData() {
		t.Error("Empty stats should return HasData() = false")
	}

	// Severity should be none
	if sev := stats.Severity(); sev != "none" {
		t.Errorf("Empty stats Severity = %s, want none", sev)
	}

	// No recommendations
	if recs := stats.Recommendations(); len(recs) != 0 {
		t.Errorf("Empty stats should have no recommendations: %v", recs)
	}

	// All formats should still work (may produce minimal output)
	formats := []Format{FormatConsole, FormatJSON, FormatMarkdown}
	for _, format := range formats {
		var buf bytes.Buffer
		if err := stats.WriteTo(&buf, format); err != nil {
			t.Errorf("Format %d failed on empty stats: %v", format, err)
		}
	}
}

// TestIntegrationDetailsPreserved verifies extra stats are preserved in Details
func TestIntegrationDetailsPreserved(t *testing.T) {
	mockStats := map[string]int{
		"connmon_total_drops":   5,
		"connmon_reset_count":   2,
		"connmon_timeout_count": 3,
		"custom_metric":         99,
	}

	stats := FromMap(mockStats)

	// Core fields extracted
	if stats.DropsDetected != 5 {
		t.Errorf("DropsDetected = %d, want 5", stats.DropsDetected)
	}

	// Details should have the breakdown
	if stats.Details["connmon_reset_count"] != 2 {
		t.Errorf("Details[connmon_reset_count] = %d, want 2", stats.Details["connmon_reset_count"])
	}
	if stats.Details["custom_metric"] != 99 {
		t.Errorf("Details[custom_metric] = %d, want 99", stats.Details["custom_metric"])
	}
}
