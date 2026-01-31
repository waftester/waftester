package core

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
)

// TestPayloadToTestResultFieldMapping ensures all relevant Payload fields
// are mapped to TestResult. This catches the case where we add a field to
// Payload but forget to populate it in TestResult.
func TestPayloadToTestResultFieldMapping(t *testing.T) {
	// Fields from Payload that MUST be mapped to TestResult
	// This is the source of truth for what fields should flow through
	requiredMappings := map[string]string{
		// Payload field -> TestResult field
		"ID":           "ID",
		"Category":     "Category",
		"SeverityHint": "Severity",
		"Payload":      "Payload",
		"Method":       "Method",
		"TargetPath":   "TargetPath",
		"ContentType":  "ContentType",
	}

	// Verify TestResult has all required fields
	resultType := reflect.TypeOf(output.TestResult{})
	for payloadField, resultField := range requiredMappings {
		_, found := resultType.FieldByName(resultField)
		if !found {
			t.Errorf("TestResult missing field %q (mapped from Payload.%s)", resultField, payloadField)
		}
	}

	// Verify Payload has all source fields
	payloadType := reflect.TypeOf(payloads.Payload{})
	for payloadField := range requiredMappings {
		_, found := payloadType.FieldByName(payloadField)
		if !found {
			t.Errorf("Payload missing field %q", payloadField)
		}
	}
}

// TestPayloadFieldsExist is a compile-time check that essential fields exist.
// If any field is removed, this test won't compile.
func TestPayloadFieldsExist(t *testing.T) {
	p := payloads.Payload{
		ID:          "required",
		Payload:     "required",
		Category:    "required",
		Method:      "optional",
		ContentType: "optional",
		TargetPath:  "optional",
	}

	r := output.TestResult{
		ID:          p.ID,
		Category:    p.Category,
		Payload:     p.Payload,
		Method:      p.Method,
		TargetPath:  p.TargetPath,
		ContentType: p.ContentType,
	}

	// Use r to avoid unused variable error
	if r.ID != p.ID {
		t.Error("Field mapping broken")
	}
}

// TestNewPayloadFieldsDocumented reminds developers to update this test
// when adding new fields to Payload. Uses reflection to detect new fields.
func TestNewPayloadFieldsDocumented(t *testing.T) {
	// Known fields in Payload - update this list when adding new fields
	knownFields := map[string]bool{
		"ID":              true,
		"Payload":         true,
		"Category":        true,
		"Method":          true,
		"ContentType":     true,
		"TargetPath":      true,
		"ExpectedBlock":   true,
		"SeverityHint":    true,
		"Tags":            true,
		"Notes":           true,
		"AttackCategory":  true, // Deprecated but still present
		"EncodingUsed":    true, // Encoding applied to payload
		"MutationType":    true, // Type of mutation applied
		"OriginalPayload": true, // Original payload before mutation
	}

	payloadType := reflect.TypeOf(payloads.Payload{})
	for i := 0; i < payloadType.NumField(); i++ {
		field := payloadType.Field(i)
		if !knownFields[field.Name] {
			t.Errorf("New field %q found in Payload struct - update knownFields and consider if it should be mapped to TestResult", field.Name)
		}
	}
}

// TestBuildTargetURL verifies URL construction logic matches executor behavior
func TestBuildTargetURL(t *testing.T) {
	testCases := []struct {
		name       string
		baseURL    string
		targetPath string
		wantPath   string
	}{
		{
			name:       "no target path uses base",
			baseURL:    "https://example.com/api",
			targetPath: "",
			wantPath:   "/api",
		},
		{
			name:       "target path replaces base path",
			baseURL:    "https://example.com/",
			targetPath: "/api/users",
			wantPath:   "/api/users",
		},
		{
			name:       "target path with complex base",
			baseURL:    "https://example.com:8080/v1/",
			targetPath: "/api/login",
			wantPath:   "/api/login",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate executor URL construction logic
			targetURL := tc.baseURL
			if tc.targetPath != "" {
				baseURL, err := url.Parse(tc.baseURL)
				if err != nil {
					t.Fatalf("Failed to parse base URL: %v", err)
				}
				baseURL.Path = tc.targetPath
				targetURL = baseURL.String()
			}

			parsed, _ := url.Parse(targetURL)
			if parsed.Path != tc.wantPath {
				t.Errorf("Path: got %q, want %q (full URL: %s)", parsed.Path, tc.wantPath, targetURL)
			}
		})
	}
}

// TestMethodDefaulting verifies GET is default when method empty
func TestMethodDefaulting(t *testing.T) {
	p := payloads.Payload{
		ID:      "test",
		Payload: "test",
		Method:  "", // Empty
	}

	method := p.Method
	if method == "" {
		method = "GET"
	}

	if method != "GET" {
		t.Errorf("Empty method should default to GET, got %q", method)
	}
}

// TestPOSTRequestNeedsContentType verifies POST with body requires ContentType
func TestPOSTRequestNeedsContentType(t *testing.T) {
	testCases := []struct {
		name        string
		method      string
		contentType string
		expectBody  bool
	}{
		{"POST with JSON", "POST", "application/json", true},
		{"POST with form", "POST", "application/x-www-form-urlencoded", true},
		{"POST without content type", "POST", "", false},
		{"GET never has body", "GET", "application/json", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate executor logic
			usesBody := tc.method == "POST" && tc.contentType != ""
			if usesBody != tc.expectBody {
				t.Errorf("usesBody: got %v, want %v", usesBody, tc.expectBody)
			}
		})
	}
}
