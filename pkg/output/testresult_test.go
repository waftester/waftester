package output

import (
	"encoding/json"
	"testing"
)

// TestTestResultRoundTrip ensures all fields serialize and deserialize correctly
func TestTestResultRoundTrip(t *testing.T) {
	original := &TestResult{
		ID:          "test-001",
		Category:    "sqli",
		Severity:    "High",
		Outcome:     "Blocked",
		StatusCode:  403,
		LatencyMs:   42,
		Payload:     "' OR '1'='1",
		Timestamp:   "10:30:45",
		Method:      "POST",
		TargetPath:  "/api/login",
		ContentType: "application/json",
	}

	// Serialize
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal TestResult: %v", err)
	}

	// Deserialize
	var restored TestResult
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Failed to unmarshal TestResult: %v", err)
	}

	// Verify all fields
	if restored.ID != original.ID {
		t.Errorf("ID mismatch: got %q, want %q", restored.ID, original.ID)
	}
	if restored.Category != original.Category {
		t.Errorf("Category mismatch: got %q, want %q", restored.Category, original.Category)
	}
	if restored.Severity != original.Severity {
		t.Errorf("Severity mismatch: got %q, want %q", restored.Severity, original.Severity)
	}
	if restored.Outcome != original.Outcome {
		t.Errorf("Outcome mismatch: got %q, want %q", restored.Outcome, original.Outcome)
	}
	if restored.StatusCode != original.StatusCode {
		t.Errorf("StatusCode mismatch: got %d, want %d", restored.StatusCode, original.StatusCode)
	}
	if restored.LatencyMs != original.LatencyMs {
		t.Errorf("LatencyMs mismatch: got %d, want %d", restored.LatencyMs, original.LatencyMs)
	}
	if restored.Payload != original.Payload {
		t.Errorf("Payload mismatch: got %q, want %q", restored.Payload, original.Payload)
	}
	if restored.Timestamp != original.Timestamp {
		t.Errorf("Timestamp mismatch: got %q, want %q", restored.Timestamp, original.Timestamp)
	}
	if restored.Method != original.Method {
		t.Errorf("Method mismatch: got %q, want %q", restored.Method, original.Method)
	}
	if restored.TargetPath != original.TargetPath {
		t.Errorf("TargetPath mismatch: got %q, want %q", restored.TargetPath, original.TargetPath)
	}
	if restored.ContentType != original.ContentType {
		t.Errorf("ContentType mismatch: got %q, want %q", restored.ContentType, original.ContentType)
	}
}

// TestTestResultJSONFieldNames verifies JSON field names are correct
func TestTestResultJSONFieldNames(t *testing.T) {
	result := &TestResult{
		ID:          "test-001",
		Category:    "xss",
		Method:      "POST",
		TargetPath:  "/api/test",
		ContentType: "application/json",
	}

	data, _ := json.Marshal(result)
	jsonStr := string(data)

	// Check that JSON uses correct field names (snake_case)
	expectedFields := []string{
		`"id"`,
		`"category"`,
		`"method"`,
		`"target_path"`,
		`"content_type"`,
		`"status_code"`,
		`"latency_ms"`,
	}

	for _, field := range expectedFields {
		if !contains(jsonStr, field) {
			t.Errorf("Missing JSON field %s in output: %s", field, jsonStr)
		}
	}
}

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
