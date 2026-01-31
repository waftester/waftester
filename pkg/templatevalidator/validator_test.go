package templatevalidator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateFile(t *testing.T) {
	// Create a valid template
	validTemplate := `id: test-template

info:
  name: Test Template
  author: waf-tester
  severity: high
  description: A test template for validation
  reference:
    - https://example.com
  tags: test,validation

http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: word
        words:
          - "test"
      - type: status
        status:
          - 200
`

	// Create temp file
	tmpDir := t.TempDir()
	validFile := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validFile, []byte(validTemplate), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	validator := NewValidator(false)
	result := validator.ValidateFile(validFile)

	if !result.Valid {
		t.Errorf("Expected valid template, got errors: %v", result.Errors)
	}

	if len(result.Errors) > 0 {
		t.Errorf("Expected no errors, got: %v", result.Errors)
	}
}

func TestValidateFile_MissingID(t *testing.T) {
	invalidTemplate := `info:
  name: Test Template
  author: waf-tester
  severity: high
`

	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte(invalidTemplate), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	validator := NewValidator(false)
	result := validator.ValidateFile(invalidFile)

	if result.Valid {
		t.Error("Expected invalid template due to missing id")
	}

	found := false
	for _, err := range result.Errors {
		if err == "missing required field: id" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected error about missing id, got: %v", result.Errors)
	}
}

func TestValidateFile_InvalidSeverity(t *testing.T) {
	invalidTemplate := `id: test-template

info:
  name: Test Template
  author: waf-tester
  severity: super-critical
`

	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte(invalidTemplate), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	validator := NewValidator(false)
	result := validator.ValidateFile(invalidFile)

	if result.Valid {
		t.Error("Expected invalid template due to invalid severity")
	}

	found := false
	for _, err := range result.Errors {
		if contains(err, "invalid severity") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected error about invalid severity, got: %v", result.Errors)
	}
}

func TestValidateFile_CVEFormat(t *testing.T) {
	validCVE := `id: CVE-2021-44228

info:
  name: Log4Shell
  author: waf-tester
  severity: critical

http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: status
        status:
          - 200
`

	tmpDir := t.TempDir()
	cveFile := filepath.Join(tmpDir, "cve.yaml")
	if err := os.WriteFile(cveFile, []byte(validCVE), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	validator := NewValidator(false)
	result := validator.ValidateFile(cveFile)

	if !result.Valid {
		t.Errorf("Expected valid CVE template, got errors: %v", result.Errors)
	}
}

func TestValidateDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid template
	validTemplate := `id: valid-template

info:
  name: Valid Template
  author: waf-tester
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: status
        status:
          - 200
`

	// Create invalid template
	invalidTemplate := `info:
  name: Invalid Template
  severity: wrong
`

	if err := os.WriteFile(filepath.Join(tmpDir, "valid.yaml"), []byte(validTemplate), 0644); err != nil {
		t.Fatalf("Failed to create valid file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "invalid.yaml"), []byte(invalidTemplate), 0644); err != nil {
		t.Fatalf("Failed to create invalid file: %v", err)
	}

	validator := NewValidator(false)
	summary, err := validator.ValidateDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ValidateDirectory failed: %v", err)
	}

	if summary.TotalFiles != 2 {
		t.Errorf("Expected 2 files, got %d", summary.TotalFiles)
	}

	if summary.ValidFiles != 1 {
		t.Errorf("Expected 1 valid file, got %d", summary.ValidFiles)
	}

	if summary.InvalidFiles != 1 {
		t.Errorf("Expected 1 invalid file, got %d", summary.InvalidFiles)
	}
}

func TestIsValidID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"test-template", true},
		{"sqli-error-based", true},
		{"CVE-2021-44228", true},
		{"CVE-2020-5902", true},
		{"a", true},
		{"", false},
		{"-invalid", false},
		{"invalid-", false},
		{"INVALID", false},
		{"Test_Template", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := isValidID(tt.id); got != tt.valid {
				t.Errorf("isValidID(%q) = %v, want %v", tt.id, got, tt.valid)
			}
		})
	}
}

func TestIsValidSeverity(t *testing.T) {
	tests := []struct {
		severity string
		valid    bool
	}{
		{"critical", true},
		{"high", true},
		{"medium", true},
		{"low", true},
		{"info", true},
		{"unknown", true},
		{"Critical", true}, // case insensitive
		{"HIGH", true},
		{"super", false},
		{"", false},
		{"urgent", false},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			if got := isValidSeverity(tt.severity); got != tt.valid {
				t.Errorf("isValidSeverity(%q) = %v, want %v", tt.severity, got, tt.valid)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
