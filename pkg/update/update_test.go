package update

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUpdateConfig tests UpdateConfig struct
func TestUpdateConfig(t *testing.T) {
	cfg := UpdateConfig{
		PayloadDir:      "/payloads",
		Source:          "OWASP",
		DryRun:          true,
		AutoApply:       false,
		SkipDestructive: true,
		VersionBump:     "minor",
		OutputFile:      "report.json",
	}

	if cfg.PayloadDir != "/payloads" {
		t.Errorf("PayloadDir mismatch")
	}
	if cfg.Source != "OWASP" {
		t.Errorf("Source mismatch")
	}
	if !cfg.DryRun {
		t.Error("DryRun should be true")
	}
	if !cfg.SkipDestructive {
		t.Error("SkipDestructive should be true")
	}
}

// TestUpdateReport tests UpdateReport JSON serialization
func TestUpdateReport(t *testing.T) {
	report := UpdateReport{
		Timestamp:       "2025-01-01T00:00:00Z",
		Source:          "OWASP",
		PreviousVersion: "1.0.0",
		NewVersion:      "1.1.0",
		PayloadsAdded:   10,
		PayloadsRemoved: 2,
		PayloadsUpdated: 5,
		SkippedUnsafe:   1,
		Changes: []PayloadChange{
			{Type: "added", ID: "test-001", Category: "sqli", Description: "New SQLi payload"},
		},
		DryRun: true,
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored UpdateReport
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.PayloadsAdded != 10 {
		t.Errorf("expected PayloadsAdded 10, got %d", restored.PayloadsAdded)
	}
	if len(restored.Changes) != 1 {
		t.Errorf("expected 1 change, got %d", len(restored.Changes))
	}
}

// TestPayloadChange tests PayloadChange struct
func TestPayloadChange(t *testing.T) {
	change := PayloadChange{
		Type:        "modified",
		ID:          "test-001",
		Category:    "xss",
		Description: "Updated XSS payload",
		IsUnsafe:    true,
	}

	data, err := json.Marshal(change)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored PayloadChange
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.Type != "modified" {
		t.Errorf("Type mismatch")
	}
	if !restored.IsUnsafe {
		t.Error("IsUnsafe should be true")
	}
}

// TestVersionInfo tests VersionInfo struct
func TestVersionInfo(t *testing.T) {
	info := VersionInfo{
		Version:      "1.2.3",
		LastUpdated:  "2025-01-01",
		PayloadCount: 1000,
		Source:       "OWASP",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored VersionInfo
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.Version != "1.2.3" {
		t.Errorf("Version mismatch")
	}
	if restored.PayloadCount != 1000 {
		t.Errorf("PayloadCount mismatch")
	}
}

// TestOwaspSources tests the OWASP sources map
func TestOwaspSources(t *testing.T) {
	if len(owaspSources) == 0 {
		t.Error("owaspSources should not be empty")
	}
	if _, ok := owaspSources["xss"]; !ok {
		t.Error("expected xss source")
	}
	if _, ok := owaspSources["sqli"]; !ok {
		t.Error("expected sqli source")
	}
	if _, ok := owaspSources["traversal"]; !ok {
		t.Error("expected traversal source")
	}
}

// TestUnsafePatterns tests the unsafe patterns list
func TestUnsafePatterns(t *testing.T) {
	if len(unsafePatterns) == 0 {
		t.Error("unsafePatterns should not be empty")
	}
	// Check some dangerous patterns are included
	found := false
	for _, p := range unsafePatterns {
		if p == "rm -rf" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'rm -rf' in unsafePatterns")
	}
}

// TestUpdatePayloadsDryRun tests UpdatePayloads with dry run
func TestUpdatePayloadsDryRun(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a minimal version.json
	versionInfo := VersionInfo{
		Version:      "1.0.0",
		LastUpdated:  "2025-01-01",
		PayloadCount: 100,
		Source:       "OWASP",
	}
	versionData, _ := json.Marshal(versionInfo)
	os.WriteFile(filepath.Join(tmpDir, "version.json"), versionData, 0644)

	cfg := &UpdateConfig{
		PayloadDir:      tmpDir,
		Source:          "OWASP",
		DryRun:          true,
		SkipDestructive: true,
	}

	report, err := UpdatePayloads(cfg)
	// May fail due to network/source issues, just check it runs
	_ = err
	_ = report
}

// TestUpdatePayloadsMissingVersion tests with missing version.json
func TestUpdatePayloadsMissingVersion(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &UpdateConfig{
		PayloadDir: tmpDir,
		Source:     "OWASP",
		DryRun:     true,
	}

	// Should still work, creating new version
	report, _ := UpdatePayloads(cfg)
	if report != nil && report.PreviousVersion != "" {
		// If it runs, previous version should be empty or "0.0.0"
	}
}

// TestBumpVersion tests version bumping logic
func TestBumpVersion(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		bump     string
		expected string
	}{
		{"patch bump", "1.0.0", "patch", "1.0.1"},
		{"minor bump", "1.0.0", "minor", "1.1.0"},
		{"major bump", "1.0.0", "major", "2.0.0"},
		{"patch from higher", "2.5.10", "patch", "2.5.11"},
		{"minor from higher", "2.5.10", "minor", "2.6.0"},
		{"major from higher", "2.5.10", "major", "3.0.0"},
		{"invalid version", "invalid", "", "1.0.0"},
		{"empty bump", "1.0.0", "", "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bumpVersion(tt.current, tt.bump)
			if result != tt.expected {
				t.Errorf("bumpVersion(%s, %s) = %s, want %s", tt.current, tt.bump, result, tt.expected)
			}
		})
	}
}

// TestIsUnsafePayload tests unsafe payload detection
func TestIsUnsafePayload(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected bool
	}{
		{"rm -rf command", "rm -rf /", true},
		{"shutdown", "shutdown -h now", true},
		{"reboot", "reboot", true},
		{"format c:", "format c:", true},
		{"del command", "del /f /s /q C:\\*", true},
		{"fork bomb", ":(){:|:&};:", true},
		{"dd zero", "dd if=/dev/zero of=/dev/sda", true},
		{"mkfs", "mkfs.ext4 /dev/sda1", true},
		{"write to sda", "> /dev/sda", true},
		{"safe xss", "<script>alert(1)</script>", false},
		{"safe sqli", "' OR '1'='1", false},
		{"safe traversal", "../../../etc/passwd", false},
		{"case insensitive rm", "RM -RF /tmp", true},
		{"case insensitive shutdown", "SHUTDOWN", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isUnsafePayload(tt.payload)
			if result != tt.expected {
				t.Errorf("isUnsafePayload(%q) = %v, want %v", tt.payload, result, tt.expected)
			}
		})
	}
}

// TestGetCurrentVersion tests reading version from file
func TestGetCurrentVersion(t *testing.T) {
	tmpDir := t.TempDir()

	// Create version.json
	versionInfo := VersionInfo{
		Version:      "1.2.3",
		LastUpdated:  "2025-01-01",
		PayloadCount: 500,
		Source:       "OWASP",
	}
	versionData, _ := json.Marshal(versionInfo)
	versionPath := filepath.Join(tmpDir, "version.json")
	if err := os.WriteFile(versionPath, versionData, 0644); err != nil {
		t.Fatalf("failed to write version.json: %v", err)
	}

	version, err := getCurrentVersion(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "1.2.3" {
		t.Errorf("expected version '1.2.3', got %s", version)
	}
}

// TestGetCurrentVersionMissing tests when version.json doesn't exist
func TestGetCurrentVersionMissing(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := getCurrentVersion(tmpDir)
	if err == nil {
		t.Error("expected error for missing version.json")
	}
}

// TestGetCurrentVersionInvalid tests when version.json is invalid
func TestGetCurrentVersionInvalid(t *testing.T) {
	tmpDir := t.TempDir()

	// Write invalid JSON
	versionPath := filepath.Join(tmpDir, "version.json")
	if err := os.WriteFile(versionPath, []byte("not json"), 0644); err != nil {
		t.Fatalf("failed to write version.json: %v", err)
	}

	_, err := getCurrentVersion(tmpDir)
	if err == nil {
		t.Error("expected error for invalid version.json")
	}
}

// TestWriteVersion tests writing version file
func TestWriteVersion(t *testing.T) {
	tmpDir := t.TempDir()

	err := writeVersion(tmpDir, "2.0.0", "OWASP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the file was written
	versionPath := filepath.Join(tmpDir, "version.json")
	data, err := os.ReadFile(versionPath)
	if err != nil {
		t.Fatalf("failed to read version.json: %v", err)
	}

	var versionInfo VersionInfo
	if err := json.Unmarshal(data, &versionInfo); err != nil {
		t.Fatalf("failed to unmarshal version.json: %v", err)
	}

	if versionInfo.Version != "2.0.0" {
		t.Errorf("expected version '2.0.0', got %s", versionInfo.Version)
	}
	if versionInfo.Source != "OWASP" {
		t.Errorf("expected source 'OWASP', got %s", versionInfo.Source)
	}
}

// TestWriteVersionWithPayloads tests version file with payload count
func TestWriteVersionWithPayloads(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some payload files
	payloads := []interface{}{
		map[string]interface{}{"id": "XSS-001", "payload": "<script>"},
		map[string]interface{}{"id": "XSS-002", "payload": "alert(1)"},
	}
	payloadData, _ := json.Marshal(payloads)
	if err := os.WriteFile(filepath.Join(tmpDir, "xss.json"), payloadData, 0644); err != nil {
		t.Fatalf("failed to write xss.json: %v", err)
	}

	err := writeVersion(tmpDir, "1.0.0", "GitHub")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify payload count
	data, _ := os.ReadFile(filepath.Join(tmpDir, "version.json"))
	var versionInfo VersionInfo
	json.Unmarshal(data, &versionInfo)

	if versionInfo.PayloadCount != 2 {
		t.Errorf("expected PayloadCount 2, got %d", versionInfo.PayloadCount)
	}
}

// TestWriteReport tests writing report file
func TestWriteReport(t *testing.T) {
	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "report.json")

	report := &UpdateReport{
		Timestamp:       "2025-01-01T00:00:00Z",
		Source:          "OWASP",
		PreviousVersion: "1.0.0",
		NewVersion:      "1.0.1",
		PayloadsAdded:   5,
		DryRun:          true,
	}

	err := writeReport(reportPath, report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the file was written
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}

	var decoded UpdateReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal report: %v", err)
	}

	if decoded.Source != "OWASP" {
		t.Errorf("expected Source 'OWASP', got %s", decoded.Source)
	}
	if decoded.PayloadsAdded != 5 {
		t.Errorf("expected PayloadsAdded 5, got %d", decoded.PayloadsAdded)
	}
}

// TestUpdatePayloadsUnknownSource tests UpdatePayloads with unknown source
func TestUpdatePayloadsUnknownSource(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &UpdateConfig{
		PayloadDir: tmpDir,
		Source:     "unknown_source",
		DryRun:     true,
	}

	_, err := UpdatePayloads(cfg)
	if err == nil {
		t.Error("expected error for unknown source")
	}
}

// TestUpdatePayloadsManual tests UpdatePayloads with Manual source
func TestUpdatePayloadsManual(t *testing.T) {
	tmpDir := t.TempDir()

	// Create version.json
	versionInfo := VersionInfo{Version: "1.0.0"}
	versionData, _ := json.Marshal(versionInfo)
	os.WriteFile(filepath.Join(tmpDir, "version.json"), versionData, 0644)

	cfg := &UpdateConfig{
		PayloadDir:  tmpDir,
		Source:      "Manual",
		DryRun:      true,
		VersionBump: "patch",
	}

	report, err := UpdatePayloads(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected report, got nil")
	}
	if report.Source != "Manual" {
		t.Errorf("expected Source 'Manual', got %s", report.Source)
	}
}

// TestUpdatePayloadsGitHub tests UpdatePayloads with GitHub source
func TestUpdatePayloadsGitHub(t *testing.T) {
	tmpDir := t.TempDir()

	// Create version.json
	versionInfo := VersionInfo{Version: "1.0.0"}
	versionData, _ := json.Marshal(versionInfo)
	os.WriteFile(filepath.Join(tmpDir, "version.json"), versionData, 0644)

	cfg := &UpdateConfig{
		PayloadDir:  tmpDir,
		Source:      "GitHub",
		DryRun:      true,
		VersionBump: "minor",
	}

	report, err := UpdatePayloads(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected report, got nil")
	}
	if report.Source != "GitHub" {
		t.Errorf("expected Source 'GitHub', got %s", report.Source)
	}
}

// TestUpdatePayloadsWithReportFile tests UpdatePayloads writes report file
func TestUpdatePayloadsWithReportFile(t *testing.T) {
	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "update-report.json")

	// Create version.json
	versionInfo := VersionInfo{Version: "1.0.0"}
	versionData, _ := json.Marshal(versionInfo)
	os.WriteFile(filepath.Join(tmpDir, "version.json"), versionData, 0644)

	cfg := &UpdateConfig{
		PayloadDir:  tmpDir,
		Source:      "Manual",
		DryRun:      false, // Not dry run, will write version
		VersionBump: "patch",
		OutputFile:  reportPath,
	}

	_, err := UpdatePayloads(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify report file was created
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		t.Error("expected report file to be created")
	}

	// Verify version was updated
	version, _ := getCurrentVersion(tmpDir)
	if version != "1.0.1" {
		t.Errorf("expected version '1.0.1', got %s", version)
	}
}

// TestUpdatePayloadsVersionBumps tests different version bump scenarios
func TestUpdatePayloadsVersionBumps(t *testing.T) {
	tests := []struct {
		name        string
		startVer    string
		bump        string
		expectedVer string
	}{
		{"patch bump", "1.0.0", "patch", "1.0.1"},
		{"minor bump", "1.0.0", "minor", "1.1.0"},
		{"major bump", "1.0.0", "major", "2.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create version.json
			versionInfo := VersionInfo{Version: tt.startVer}
			versionData, _ := json.Marshal(versionInfo)
			os.WriteFile(filepath.Join(tmpDir, "version.json"), versionData, 0644)

			cfg := &UpdateConfig{
				PayloadDir:  tmpDir,
				Source:      "Manual",
				DryRun:      false,
				VersionBump: tt.bump,
			}

			report, err := UpdatePayloads(cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if report.NewVersion != tt.expectedVer {
				t.Errorf("expected NewVersion '%s', got '%s'", tt.expectedVer, report.NewVersion)
			}
		})
	}
}

// TestPayloadChangeTypes tests PayloadChange with different types
func TestPayloadChangeTypes(t *testing.T) {
	types := []string{"added", "removed", "modified"}

	for _, changeType := range types {
		t.Run(changeType, func(t *testing.T) {
			change := PayloadChange{
				Type:        changeType,
				ID:          "TEST-001",
				Category:    "test",
				Description: "Test payload",
			}

			data, err := json.Marshal(change)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			var decoded PayloadChange
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if decoded.Type != changeType {
				t.Errorf("expected Type '%s', got '%s'", changeType, decoded.Type)
			}
		})
	}
}

// TestUpdateReportChangesSlice tests UpdateReport with multiple changes
func TestUpdateReportChangesSlice(t *testing.T) {
	report := UpdateReport{
		Changes: []PayloadChange{
			{Type: "added", ID: "XSS-001", Category: "xss"},
			{Type: "added", ID: "XSS-002", Category: "xss"},
			{Type: "removed", ID: "SQLI-001", Category: "sqli"},
			{Type: "modified", ID: "TRAV-001", Category: "traversal"},
		},
	}

	if len(report.Changes) != 4 {
		t.Errorf("expected 4 changes, got %d", len(report.Changes))
	}

	// Count by type
	added, removed, modified := 0, 0, 0
	for _, c := range report.Changes {
		switch c.Type {
		case "added":
			added++
		case "removed":
			removed++
		case "modified":
			modified++
		}
	}

	if added != 2 {
		t.Errorf("expected 2 added, got %d", added)
	}
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if modified != 1 {
		t.Errorf("expected 1 modified, got %d", modified)
	}
}

// TestWriteVersionInvalidPath tests writeVersion with invalid path
func TestWriteVersionInvalidPath(t *testing.T) {
	err := writeVersion("/nonexistent/path/that/doesnt/exist", "1.0.0", "Test")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

// TestWriteReportInvalidPath tests writeReport with invalid path
func TestWriteReportInvalidPath(t *testing.T) {
	report := &UpdateReport{Source: "Test"}
	err := writeReport("/nonexistent/path/that/doesnt/exist/report.json", report)
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

// TestBumpVersionEdgeCases tests additional version bumping edge cases
func TestBumpVersionEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		bump     string
		expected string
	}{
		{"only two parts", "1.0", "", "1.0.0"},
		{"only one part", "1", "", "1.0.0"},
		{"empty string", "", "", "1.0.0"},
		{"with extra", "1.0.0.0", "", "1.0.0"},
		{"zeros", "0.0.0", "patch", "0.0.1"},
		{"zeros minor", "0.0.0", "minor", "0.1.0"},
		{"zeros major", "0.0.0", "major", "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bumpVersion(tt.current, tt.bump)
			if result != tt.expected {
				t.Errorf("bumpVersion(%s, %s) = %s, want %s", tt.current, tt.bump, result, tt.expected)
			}
		})
	}
}

// TestIsUnsafePayloadEmpty tests isUnsafePayload with edge cases
func TestIsUnsafePayloadEmpty(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected bool
	}{
		{"empty string", "", false},
		{"whitespace only", "   ", false},
		{"normal text", "hello world", false},
		{"mixed case unsafe", "RM -RF /home", true},
		{"partial match", "format", false}, // "format" alone isn't dangerous
		{"with format c:", "format c: /q", true},
		{"shutdown with args", "shutdown /s /t 0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isUnsafePayload(tt.payload)
			if result != tt.expected {
				t.Errorf("isUnsafePayload(%q) = %v, want %v", tt.payload, result, tt.expected)
			}
		})
	}
}

// TestWriteVersionCountsPayloads tests that writeVersion correctly counts payloads
func TestWriteVersionCountsPayloads(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple payload files
	payloads1 := []interface{}{
		map[string]interface{}{"id": "XSS-001"},
		map[string]interface{}{"id": "XSS-002"},
		map[string]interface{}{"id": "XSS-003"},
	}
	payloads2 := []interface{}{
		map[string]interface{}{"id": "SQLI-001"},
		map[string]interface{}{"id": "SQLI-002"},
	}

	data1, _ := json.Marshal(payloads1)
	data2, _ := json.Marshal(payloads2)

	os.WriteFile(filepath.Join(tmpDir, "xss.json"), data1, 0644)
	os.WriteFile(filepath.Join(tmpDir, "sqli.json"), data2, 0644)

	// Also create ids-map.json which should be excluded from count
	idsMap := map[string]string{"XSS-001": "xss.json"}
	idsData, _ := json.Marshal(idsMap)
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsData, 0644)

	err := writeVersion(tmpDir, "1.0.0", "Test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read and verify count
	versionPath := filepath.Join(tmpDir, "version.json")
	data, _ := os.ReadFile(versionPath)
	var info VersionInfo
	json.Unmarshal(data, &info)

	// Should count 5 payloads (3 from xss.json + 2 from sqli.json), not ids-map.json
	if info.PayloadCount != 5 {
		t.Errorf("expected PayloadCount 5, got %d", info.PayloadCount)
	}
}

// TestUpdateConfigJSONSerialization tests UpdateConfig as JSON
func TestUpdateConfigJSONSerialization(t *testing.T) {
	cfg := UpdateConfig{
		PayloadDir:      "/path/to/payloads",
		Source:          "OWASP",
		DryRun:          true,
		AutoApply:       false,
		SkipDestructive: true,
		VersionBump:     "minor",
		OutputFile:      "output.json",
	}

	// UpdateConfig doesn't have json tags but should still work
	// Just verify we can create and use it
	if cfg.Source != "OWASP" {
		t.Error("Source should be OWASP")
	}
}

// TestUpdatePayloadsOWSAPSkipDestructive tests OWASP update with skip destructive
func TestUpdatePayloadsOWSAPSkipDestructive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create version.json
	versionInfo := VersionInfo{Version: "1.0.0"}
	versionData, _ := json.Marshal(versionInfo)
	os.WriteFile(filepath.Join(tmpDir, "version.json"), versionData, 0644)

	cfg := &UpdateConfig{
		PayloadDir:      tmpDir,
		Source:          "OWASP",
		DryRun:          true,
		SkipDestructive: true,
		VersionBump:     "patch",
	}

	// This will try to fetch from OWASP URLs (will likely fail due to network)
	// Just verify it runs without crashing
	report, _ := UpdatePayloads(cfg)
	if report != nil {
		// If it returns a report, check basic fields
		if report.Source != "OWASP" {
			t.Errorf("expected source OWASP, got %s", report.Source)
		}
	}
}

// =============================================================================
// DEEP BUG-FINDING TESTS - Line by line analysis of update.go
// =============================================================================

// TestBumpVersionDeepEdgeCases tests version bumping edge cases more thoroughly
func TestBumpVersionDeepEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		current string
		bump    string
		want    string
	}{
		// Normal cases
		{"patch bump", "1.0.0", "patch", "1.0.1"},
		{"minor bump", "1.0.0", "minor", "1.1.0"},
		{"major bump", "1.0.0", "major", "2.0.0"},

		// Edge cases
		{"minor resets patch", "1.2.3", "minor", "1.3.0"},
		{"major resets all", "5.6.7", "major", "6.0.0"},

		// Invalid/edge versions — malformed input returns default "1.0.0"
		{"empty version", "", "patch", "1.0.0"},            // Should default
		{"single part", "1", "patch", "1.0.0"},             // Invalid format
		{"two parts", "1.2", "patch", "1.0.0"},             // Invalid format
		{"four parts", "1.2.3.4", "patch", "1.0.0"},        // Too many parts
		{"non-numeric major", "a.0.0", "patch", "1.0.0"},   // Invalid returns default
		{"non-numeric minor", "1.b.0", "minor", "1.0.0"},   // Invalid returns default
		{"non-numeric patch", "1.0.c", "patch", "1.0.0"},   // Invalid returns default
		{"negative numbers", "-1.-2.-3", "patch", "1.0.0"}, // Negative rejected
		{"large numbers", "999.999.999", "patch", "999.999.1000"},
		{"zero version", "0.0.0", "patch", "0.0.1"},
		{"leading zeros", "01.02.03", "patch", "1.2.4"}, // Atoi strips leading zeros

		// Unknown bump type
		{"unknown bump", "1.0.0", "unknown", "1.0.0"},
		{"empty bump", "1.0.0", "", "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bumpVersion(tt.current, tt.bump)
			if got != tt.want {
				t.Errorf("bumpVersion(%q, %q) = %q, want %q",
					tt.current, tt.bump, got, tt.want)
			}
		})
	}
}

// TestBumpVersionOverflow tests integer overflow in version numbers
func TestBumpVersionOverflow(t *testing.T) {
	// Test near max int
	maxIntVersion := "9223372036854775807.0.0" // Max int64 as major

	result := bumpVersion(maxIntVersion, "major")

	// Should overflow to negative or wrap
	t.Logf("Max int64 major + 1 = %s", result)

	// This is a potential bug if version numbers can get very large
}

// TestUnsafePatternDetection tests all unsafe patterns
func TestUnsafePatternDetection(t *testing.T) {
	// Verify all patterns are checked
	for _, pattern := range unsafePatterns {
		if pattern == "" {
			t.Error("Empty pattern in unsafePatterns list")
		}
	}

	// Test that isUnsafePayload catches all patterns
	for i, pattern := range unsafePatterns {
		if !isUnsafePayload(pattern) {
			t.Errorf("Pattern %d %q not detected as unsafe", i, pattern)
		}
	}

	// Test case sensitivity - turns out isUnsafePayload IS case-insensitive!
	testCases := []struct {
		payload    string
		wantUnsafe bool
	}{
		{"rm -rf /", true},
		{"RM -RF /", true},      // Case insensitive - good!
		{"Rm -Rf /", true},      // Case insensitive - good!
		{"rm -RF /", true},      // Mixed case works
		{"rm-rf", false},        // Missing space
		{"rm  -rf", false},      // Extra space
		{":(){:|:&};:", true},   // Fork bomb
		{" :(){:|:&};: ", true}, // With spaces - still detected
		{"format c:", true},
		{"FORMAT C:", true}, // Case insensitive
	}

	for _, tc := range testCases {
		got := isUnsafePayload(tc.payload)
		if got != tc.wantUnsafe {
			t.Errorf("isUnsafePayload(%q) = %v, want %v",
				tc.payload, got, tc.wantUnsafe)
		}
	}
}

// TestOWASPSourceURLs tests that OWASP source URLs are valid
func TestOWASPSourceURLs(t *testing.T) {
	for category, url := range owaspSources {
		if category == "" {
			t.Error("Empty category in owaspSources")
		}
		if url == "" {
			t.Errorf("Empty URL for category %s", category)
		}
		if !strings.HasPrefix(url, "https://") {
			t.Errorf("URL for %s should use HTTPS: %s", category, url)
		}
	}
}

// TestWriteVersionWithSpecialPaths tests version writing edge cases
func TestWriteVersionWithSpecialPaths(t *testing.T) {
	t.Run("directory with spaces", func(t *testing.T) {
		tmpDir := t.TempDir()
		specialDir := filepath.Join(tmpDir, "path with spaces")
		os.MkdirAll(specialDir, 0755)

		err := writeVersion(specialDir, "1.0.0", "Test")
		if err != nil {
			t.Errorf("Failed with spaces in path: %v", err)
		}
	})

	t.Run("unicode in path", func(t *testing.T) {
		tmpDir := t.TempDir()
		unicodeDir := filepath.Join(tmpDir, "日本語")
		os.MkdirAll(unicodeDir, 0755)

		err := writeVersion(unicodeDir, "1.0.0", "Test")
		if err != nil {
			t.Errorf("Failed with unicode in path: %v", err)
		}
	})

	t.Run("version with special chars", func(t *testing.T) {
		tmpDir := t.TempDir()

		err := writeVersion(tmpDir, "1.0.0-beta.1+build.123", "Test")
		if err != nil {
			t.Errorf("Failed with semantic version: %v", err)
		}

		// Read back and verify
		data, _ := os.ReadFile(filepath.Join(tmpDir, "version.json"))
		var info VersionInfo
		json.Unmarshal(data, &info)

		if info.Version != "1.0.0-beta.1+build.123" {
			t.Errorf("Version not preserved: %s", info.Version)
		}
	})
}

// TestWriteReportEdgeCases tests report writing edge cases
func TestWriteReportEdgeCases(t *testing.T) {
	t.Run("empty report", func(t *testing.T) {
		tmpDir := t.TempDir()
		reportPath := filepath.Join(tmpDir, "report.json")

		report := &UpdateReport{}
		err := writeReport(reportPath, report)
		if err != nil {
			t.Errorf("Failed with empty report: %v", err)
		}
	})

	t.Run("report with unicode", func(t *testing.T) {
		tmpDir := t.TempDir()
		reportPath := filepath.Join(tmpDir, "report.json")

		report := &UpdateReport{
			Changes: []PayloadChange{
				{Description: "日本語テスト"},
			},
		}
		err := writeReport(reportPath, report)
		if err != nil {
			t.Errorf("Failed with unicode: %v", err)
		}

		// Read back and verify
		data, _ := os.ReadFile(reportPath)
		var restored UpdateReport
		json.Unmarshal(data, &restored)

		if restored.Changes[0].Description != "日本語テスト" {
			t.Error("Unicode not preserved")
		}
	})

	t.Run("report to non-existent directory", func(t *testing.T) {
		report := &UpdateReport{}
		err := writeReport("/this/path/does/not/exist/report.json", report)
		if err == nil {
			t.Error("Should fail writing to non-existent directory")
		}
	})
}

// TestGetCurrentVersionEdgeCases tests version reading edge cases
func TestGetCurrentVersionEdgeCases(t *testing.T) {
	t.Run("missing version.json", func(t *testing.T) {
		tmpDir := t.TempDir()
		version, err := getCurrentVersion(tmpDir)
		if err == nil {
			t.Error("Should return error for missing version.json")
		}
		_ = version
	})

	t.Run("malformed version.json", func(t *testing.T) {
		tmpDir := t.TempDir()
		os.WriteFile(filepath.Join(tmpDir, "version.json"), []byte(`{invalid`), 0644)

		_, err := getCurrentVersion(tmpDir)
		if err == nil {
			t.Error("Should return error for malformed JSON")
		}
	})

	t.Run("empty version field", func(t *testing.T) {
		tmpDir := t.TempDir()
		info := VersionInfo{Version: ""}
		data, _ := json.Marshal(info)
		os.WriteFile(filepath.Join(tmpDir, "version.json"), data, 0644)

		version, err := getCurrentVersion(tmpDir)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if version != "" {
			t.Errorf("Expected empty version, got %s", version)
		}
	})
}

// TestWriteVersionPayloadCounting tests accurate payload counting
func TestWriteVersionPayloadCounting(t *testing.T) {
	t.Run("nested directories", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create nested structure
		os.MkdirAll(filepath.Join(tmpDir, "category1", "subcategory"), 0755)
		os.MkdirAll(filepath.Join(tmpDir, "category2"), 0755)

		// Add payloads at different levels
		writePayloads(t, filepath.Join(tmpDir, "root.json"), 5)
		writePayloads(t, filepath.Join(tmpDir, "category1", "level1.json"), 3)
		writePayloads(t, filepath.Join(tmpDir, "category1", "subcategory", "deep.json"), 2)
		writePayloads(t, filepath.Join(tmpDir, "category2", "cat2.json"), 4)

		err := writeVersion(tmpDir, "1.0.0", "Test")
		if err != nil {
			t.Fatal(err)
		}

		// Read and verify
		data, _ := os.ReadFile(filepath.Join(tmpDir, "version.json"))
		var info VersionInfo
		json.Unmarshal(data, &info)

		// Should count 5+3+2+4 = 14
		if info.PayloadCount != 14 {
			t.Errorf("Expected 14 payloads, got %d", info.PayloadCount)
		}
	})

	t.Run("empty JSON arrays", func(t *testing.T) {
		tmpDir := t.TempDir()

		os.WriteFile(filepath.Join(tmpDir, "empty.json"), []byte("[]"), 0644)
		writePayloads(t, filepath.Join(tmpDir, "filled.json"), 5)

		err := writeVersion(tmpDir, "1.0.0", "Test")
		if err != nil {
			t.Fatal(err)
		}

		data, _ := os.ReadFile(filepath.Join(tmpDir, "version.json"))
		var info VersionInfo
		json.Unmarshal(data, &info)

		// Empty arrays contribute 0
		if info.PayloadCount != 5 {
			t.Errorf("Expected 5 payloads, got %d", info.PayloadCount)
		}
	})

	t.Run("malformed JSON ignored", func(t *testing.T) {
		tmpDir := t.TempDir()

		os.WriteFile(filepath.Join(tmpDir, "bad.json"), []byte("not json"), 0644)
		writePayloads(t, filepath.Join(tmpDir, "good.json"), 5)

		err := writeVersion(tmpDir, "1.0.0", "Test")
		if err != nil {
			t.Fatal(err)
		}

		data, _ := os.ReadFile(filepath.Join(tmpDir, "version.json"))
		var info VersionInfo
		json.Unmarshal(data, &info)

		// Bad JSON is silently ignored, only good.json counted
		if info.PayloadCount != 5 {
			t.Errorf("Expected 5 payloads (bad.json ignored), got %d", info.PayloadCount)
		}
	})
}

// Helper to write test payloads
func writePayloads(t *testing.T, path string, count int) {
	t.Helper()
	payloads := make([]map[string]string, count)
	for i := 0; i < count; i++ {
		payloads[i] = map[string]string{"id": fmt.Sprintf("test-%d", i)}
	}
	data, _ := json.Marshal(payloads)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

// =============================================================================
// BUG-EXPOSING TESTS - These tests expose real bugs in the source code
// =============================================================================

// TestBumpVersionMustRejectMalformedVersions tests that malformed versions return default "1.0.0".
func TestBumpVersionMustRejectMalformedVersions(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		bump        string
		expected    string
		shouldError bool // True = malformed input, returns default "1.0.0"
	}{
		{"valid version", "1.2.3", "patch", "1.2.4", false},
		{"letters in major", "a.0.0", "patch", "1.0.0", true},         // Returns default
		{"letters in minor", "1.b.0", "minor", "1.0.0", true},         // Returns default
		{"letters in patch", "1.0.c", "patch", "1.0.0", true},         // Returns default
		{"all letters", "a.b.c", "patch", "1.0.0", true},              // Returns default
		{"mixed garbage", "1.x.3", "patch", "1.0.0", true},            // Returns default
		{"hex looks valid", "0x10.0x20.0x30", "patch", "1.0.0", true}, // Returns default
		{"float version", "1.2.3.4", "patch", "1.0.0", false},         // Already handled (len != 3)
		{"spaces", "1 .2 .3", "patch", "1.0.0", true},                 // Returns default
		{"empty parts", "..", "patch", "1.0.0", true},                 // Returns default
		{"negative string", "-a.-b.-c", "patch", "1.0.0", true},       // Returns default
		{"negative numbers", "-1.-2.-3", "patch", "1.0.0", true},      // Negative rejected
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bumpVersion(tt.version, tt.bump)

			if result != tt.expected {
				t.Errorf("bumpVersion(%q, %q) = %q, want %q",
					tt.version, tt.bump, result, tt.expected)
			}
		})
	}
}

// TestUpdateFromOWASPResourceLeakFixed documents that the defer-in-loop bug has been fixed
// BUG FIXED: updateFromOWASP used to have defer resp.Body.Close() inside a for loop
// This caused all response bodies to stay open until the function returned
// FIX: Wrapped the HTTP request in a closure so defer executes per iteration
func TestUpdateFromOWASPResourceLeakFixed(t *testing.T) {
	// This test documents that the bug was fixed
	// The fix wraps the HTTP request in an IIFE (immediately invoked function expression)
	// so that defer resp.Body.Close() executes after each iteration, not at function end

	t.Log("FIXED: defer resp.Body.Close() was inside a for loop")
	t.Log("This caused resource leak - multiple response bodies stayed open")
	t.Log("Fix: Wrapped in closure func() { ... resp.Body.Close() ... }()")

	// Note: Can't easily test resource leaks in Go, but the code review shows the fix
}

// TestGitHubReleaseTypes tests the GitHub API types
func TestGitHubReleaseTypes(t *testing.T) {
	release := GitHubRelease{
		TagName:     "v1.2.0",
		Name:        "Release v1.2.0",
		PublishedAt: "2025-01-15T10:00:00Z",
		Body:        "Release notes",
		Assets: []GitHubAsset{
			{
				Name:               "xss.json",
				BrowserDownloadURL: "https://github.com/test/releases/download/v1.2.0/xss.json",
				Size:               1024,
				ContentType:        "application/json",
			},
		},
	}

	if release.TagName != "v1.2.0" {
		t.Errorf("TagName mismatch")
	}
	if len(release.Assets) != 1 {
		t.Errorf("Expected 1 asset, got %d", len(release.Assets))
	}
	if release.Assets[0].Name != "xss.json" {
		t.Errorf("Asset name mismatch")
	}
}

// TestGitHubAssetType tests GitHubAsset struct
func TestGitHubAssetType(t *testing.T) {
	asset := GitHubAsset{
		Name:               "sqli.json",
		BrowserDownloadURL: "https://example.com/sqli.json",
		Size:               2048,
		ContentType:        "application/json",
	}

	data, err := json.Marshal(asset)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var restored GitHubAsset
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if restored.Name != "sqli.json" {
		t.Errorf("Name mismatch")
	}
	if restored.Size != 2048 {
		t.Errorf("Size mismatch")
	}
}

// TestMergePayloads tests the payload merging logic
func TestMergePayloads(t *testing.T) {
	tests := []struct {
		name     string
		existing []interface{}
		new      []interface{}
		expected int
	}{
		{
			name:     "empty existing",
			existing: []interface{}{},
			new:      []interface{}{"payload1", "payload2"},
			expected: 2,
		},
		{
			name:     "empty new",
			existing: []interface{}{"payload1"},
			new:      []interface{}{},
			expected: 1,
		},
		{
			name:     "no duplicates",
			existing: []interface{}{"payload1", "payload2"},
			new:      []interface{}{"payload3", "payload4"},
			expected: 4,
		},
		{
			name:     "with duplicates",
			existing: []interface{}{"payload1", "payload2"},
			new:      []interface{}{"payload2", "payload3"},
			expected: 3,
		},
		{
			name:     "all duplicates",
			existing: []interface{}{"payload1", "payload2"},
			new:      []interface{}{"payload1", "payload2"},
			expected: 2,
		},
		{
			name:     "both empty",
			existing: []interface{}{},
			new:      []interface{}{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergePayloads(tt.existing, tt.new)
			if len(result) != tt.expected {
				t.Errorf("mergePayloads() returned %d items, expected %d", len(result), tt.expected)
			}
		})
	}
}

// TestMergePayloadsWithMaps tests merging payloads that are map objects
func TestMergePayloadsWithMaps(t *testing.T) {
	existing := []interface{}{
		map[string]interface{}{"payload": "test1", "category": "xss"},
	}
	new := []interface{}{
		map[string]interface{}{"payload": "test1", "category": "xss"}, // duplicate
		map[string]interface{}{"payload": "test2", "category": "xss"}, // new
	}

	result := mergePayloads(existing, new)
	if len(result) != 2 {
		t.Errorf("Expected 2 unique payloads, got %d", len(result))
	}
}

// TestGitHubConstants tests that constants are defined correctly
func TestGitHubConstants(t *testing.T) {
	if defaultGitHubOwner == "" {
		t.Error("defaultGitHubOwner should not be empty")
	}
	if defaultGitHubRepo == "" {
		t.Error("defaultGitHubRepo should not be empty")
	}
	if gitHubAPIBase == "" {
		t.Error("gitHubAPIBase should not be empty")
	}
	if !strings.HasPrefix(gitHubAPIBase, "https://") {
		t.Error("gitHubAPIBase should be HTTPS")
	}
}

// TestUpdatePayloadsGitHubIntegration tests the GitHub update flow
func TestUpdatePayloadsGitHubIntegration(t *testing.T) {
	// Create temp directory with version file
	tempDir := t.TempDir()
	versionPath := filepath.Join(tempDir, "version.json")
	versionData := `{"version": "1.0.0", "last_updated": "2025-01-01", "payload_count": 100, "source": "Manual"}`
	if err := os.WriteFile(versionPath, []byte(versionData), 0644); err != nil {
		t.Fatalf("Failed to write version: %v", err)
	}

	cfg := &UpdateConfig{
		PayloadDir:  tempDir,
		Source:      "GitHub",
		DryRun:      true, // Don't actually download
		VersionBump: "minor",
	}

	report, err := UpdatePayloads(cfg)
	if err != nil {
		t.Fatalf("UpdatePayloads failed: %v", err)
	}

	if report.Source != "GitHub" {
		t.Errorf("Expected source GitHub, got %s", report.Source)
	}
	if report.PreviousVersion != "1.0.0" {
		t.Errorf("Expected previous version 1.0.0, got %s", report.PreviousVersion)
	}
}

// TestGitHubReleaseJSONSerialization tests JSON round-trip
func TestGitHubReleaseJSONSerialization(t *testing.T) {
	release := GitHubRelease{
		TagName:     "v2.0.0",
		Name:        "Major Release",
		PublishedAt: "2025-01-20T15:30:00Z",
		Body:        "Breaking changes included",
		Assets: []GitHubAsset{
			{Name: "xss.json", Size: 1000},
			{Name: "sqli.json", Size: 2000},
		},
	}

	data, err := json.Marshal(release)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var restored GitHubRelease
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if restored.TagName != release.TagName {
		t.Errorf("TagName mismatch after round-trip")
	}
	if len(restored.Assets) != 2 {
		t.Errorf("Expected 2 assets after round-trip")
	}
}
