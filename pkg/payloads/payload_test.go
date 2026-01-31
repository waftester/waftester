package payloads

import (
	"encoding/json"
	"testing"
)

// TestPayloadRoundTrip ensures payloads can be serialized and deserialized correctly.
// This catches issues where:
// - JSON field names don't match between generation and loading
// - Fields are missing from the struct
// - Field types are incompatible
func TestPayloadRoundTrip(t *testing.T) {
	// Create a payload with ALL fields populated
	original := Payload{
		ID:            "TEST-001",
		Payload:       "' OR '1'='1",
		Tags:          []string{"sqli", "learned"},
		ExpectedBlock: true,
		SeverityHint:  "Critical",
		Notes:         "Test payload",
		Category:      "injection",
		Method:        "POST",
		ContentType:   "application/json",
		TargetPath:    "/api/test",
	}

	// Serialize to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	// Deserialize from JSON
	var loaded Payload
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	// Verify all fields match
	if loaded.ID != original.ID {
		t.Errorf("ID mismatch: got %q, want %q", loaded.ID, original.ID)
	}
	if loaded.Payload != original.Payload {
		t.Errorf("Payload mismatch: got %q, want %q", loaded.Payload, original.Payload)
	}
	if loaded.Category != original.Category {
		t.Errorf("Category mismatch: got %q, want %q", loaded.Category, original.Category)
	}
	if loaded.Method != original.Method {
		t.Errorf("Method mismatch: got %q, want %q", loaded.Method, original.Method)
	}
	if loaded.ContentType != original.ContentType {
		t.Errorf("ContentType mismatch: got %q, want %q", loaded.ContentType, original.ContentType)
	}
	if loaded.TargetPath != original.TargetPath {
		t.Errorf("TargetPath mismatch: got %q, want %q", loaded.TargetPath, original.TargetPath)
	}
	if loaded.SeverityHint != original.SeverityHint {
		t.Errorf("SeverityHint mismatch: got %q, want %q", loaded.SeverityHint, original.SeverityHint)
	}
	if loaded.ExpectedBlock != original.ExpectedBlock {
		t.Errorf("ExpectedBlock mismatch: got %v, want %v", loaded.ExpectedBlock, original.ExpectedBlock)
	}
}

// TestPayloadJSONFields ensures JSON field names are correct.
// This catches the attack_category vs category mismatch issue.
func TestPayloadJSONFields(t *testing.T) {
	// This JSON mimics what the learn command generates
	jsonData := `{
		"id": "LEARN-001",
		"payload": "test",
		"method": "POST",
		"content_type": "application/json",
		"target_path": "/api/test",
		"expected_block": true,
		"severity_hint": "Critical",
		"category": "injection",
		"tags": ["sqli"],
		"notes": "Test"
	}`

	var p Payload
	if err := json.Unmarshal([]byte(jsonData), &p); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify critical fields are loaded
	if p.Category == "" {
		t.Error("Category should be loaded from 'category' JSON field")
	}
	if p.Method == "" {
		t.Error("Method should be loaded from 'method' JSON field")
	}
	if p.TargetPath == "" {
		t.Error("TargetPath should be loaded from 'target_path' JSON field")
	}
	if p.ContentType == "" {
		t.Error("ContentType should be loaded from 'content_type' JSON field")
	}
}

// TestPayloadRequiredFields ensures essential fields are defined in the struct.
// This is a compile-time check to prevent fields from being accidentally removed.
func TestPayloadRequiredFields(t *testing.T) {
	p := Payload{}

	// These assignments will fail to compile if fields are removed
	_ = p.ID
	_ = p.Payload
	_ = p.Category
	_ = p.Method
	_ = p.ContentType
	_ = p.TargetPath
	_ = p.ExpectedBlock
	_ = p.SeverityHint
	_ = p.Tags
	_ = p.Notes
}
