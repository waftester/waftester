package detection

import (
	"bytes"
	"strings"
	"testing"
)

// TestFromMapExtractsCorrectFields verifies FromMap extracts the right keys
func TestFromMapExtractsCorrectFields(t *testing.T) {
	m := map[string]int{
		"connmon_total_drops":  10,
		"silentban_total_bans": 5,
		"hosts_skipped":        3,
		"other_stat":           99,
	}

	stats := FromMap(m)

	if stats.DropsDetected != 10 {
		t.Errorf("DropsDetected = %d, want 10", stats.DropsDetected)
	}
	if stats.BansDetected != 5 {
		t.Errorf("BansDetected = %d, want 5", stats.BansDetected)
	}
	if stats.HostsSkipped != 3 {
		t.Errorf("HostsSkipped = %d, want 3", stats.HostsSkipped)
	}
	// Details should contain remaining stats
	if stats.Details["other_stat"] != 99 {
		t.Errorf("Details[other_stat] = %d, want 99", stats.Details["other_stat"])
	}
}

// TestFromProviderInterface verifies provider interface works
func TestFromProviderInterface(t *testing.T) {
	mock := &mockProvider{
		stats: map[string]int{
			"connmon_total_drops":  7,
			"silentban_total_bans": 2,
			"hosts_skipped":        1,
		},
	}

	stats := FromProvider(mock)

	if stats.DropsDetected != 7 {
		t.Errorf("DropsDetected = %d, want 7", stats.DropsDetected)
	}
	if stats.BansDetected != 2 {
		t.Errorf("BansDetected = %d, want 2", stats.BansDetected)
	}
	if stats.HostsSkipped != 1 {
		t.Errorf("HostsSkipped = %d, want 1", stats.HostsSkipped)
	}
}

type mockProvider struct {
	stats map[string]int
}

func (m *mockProvider) Stats() map[string]int {
	return m.stats
}

// TestToJSONProducesValidOutput verifies ToJSON returns proper map
func TestToJSONProducesValidOutput(t *testing.T) {
	stats := Stats{
		DropsDetected: 5,
		BansDetected:  3,
		HostsSkipped:  2,
	}

	jsonMap := stats.ToJSON()

	if jsonMap["drops_detected"] != 5 {
		t.Errorf("drops_detected = %v, want 5", jsonMap["drops_detected"])
	}
	if jsonMap["bans_detected"] != 3 {
		t.Errorf("bans_detected = %v, want 3", jsonMap["bans_detected"])
	}
	if jsonMap["hosts_skipped"] != 2 {
		t.Errorf("hosts_skipped = %v, want 2", jsonMap["hosts_skipped"])
	}
}

// TestMarkdownFormat verifies markdown output structure
func TestMarkdownFormat(t *testing.T) {
	stats := Stats{
		DropsDetected: 5,
		BansDetected:  3,
		HostsSkipped:  2,
	}

	var buf bytes.Buffer
	err := stats.WriteTo(&buf, FormatMarkdown)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	output := buf.String()

	// Should have markdown structure
	if !strings.Contains(output, "#") && !strings.Contains(output, "|") {
		t.Errorf("Markdown output should have headers or tables\nOutput: %s", output)
	}

	// Should contain values
	if !strings.Contains(output, "5") || !strings.Contains(output, "3") || !strings.Contains(output, "2") {
		t.Errorf("Markdown should contain stat values\nOutput: %s", output)
	}
}

// TestWriteToUnknownFormat verifies error handling for unknown format
func TestWriteToUnknownFormat(t *testing.T) {
	stats := Stats{DropsDetected: 1}

	var buf bytes.Buffer
	err := stats.WriteTo(&buf, Format(999))

	if err == nil {
		t.Error("WriteTo with unknown format should return error")
	}
}
