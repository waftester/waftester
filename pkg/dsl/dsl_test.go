package dsl

import (
	"strings"
	"testing"
	"time"
)

func TestNew_BasicTemplate(t *testing.T) {
	f, err := New("{{.URL}} [{{.StatusCode}}]")
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}

	result := &Result{
		URL:        "https://example.com",
		StatusCode: 200,
	}

	output, err := f.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	expected := "https://example.com [200]"
	if output != expected {
		t.Errorf("Expected %q, got %q", expected, output)
	}
}

func TestNew_Presets(t *testing.T) {
	tests := []struct {
		preset   string
		result   *Result
		expected string
	}{
		{
			preset:   "url",
			result:   &Result{URL: "https://example.com"},
			expected: "https://example.com",
		},
		{
			preset:   "host",
			result:   &Result{Host: "example.com"},
			expected: "example.com",
		},
		{
			preset:   "status",
			result:   &Result{URL: "https://example.com", StatusCode: 404},
			expected: "https://example.com [404]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.preset, func(t *testing.T) {
			f, err := New(tt.preset)
			if err != nil {
				t.Fatalf("Failed to create formatter: %v", err)
			}

			output, err := f.Format(tt.result)
			if err != nil {
				t.Fatalf("Failed to format: %v", err)
			}

			if output != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, output)
			}
		})
	}
}

func TestFormat_JSON(t *testing.T) {
	f, err := New("json")
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}

	result := &Result{
		URL:        "https://example.com",
		StatusCode: 200,
		Title:      "Example Domain",
	}

	output, err := f.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if !strings.Contains(output, `"url": "https://example.com"`) {
		t.Errorf("JSON output missing url field")
	}
	if !strings.Contains(output, `"status_code": 200`) {
		t.Errorf("JSON output missing status_code field")
	}
}

func TestFormat_JSONL(t *testing.T) {
	f, err := New("jsonl")
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}

	result := &Result{
		URL:        "https://example.com",
		StatusCode: 200,
	}

	output, err := f.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// JSONL should be single line
	if strings.Contains(output, "\n") {
		t.Errorf("JSONL output should not contain newlines")
	}

	if !strings.Contains(output, `"url":"https://example.com"`) {
		t.Errorf("JSONL output missing url field")
	}
}

func TestFormat_TemplateFunctions(t *testing.T) {
	tests := []struct {
		name     string
		template string
		result   *Result
		expected string
	}{
		{
			name:     "lower",
			template: "{{lower .URL}}",
			result:   &Result{URL: "HTTPS://EXAMPLE.COM"},
			expected: "https://example.com",
		},
		{
			name:     "upper",
			template: "{{upper .Host}}",
			result:   &Result{Host: "example.com"},
			expected: "EXAMPLE.COM",
		},
		{
			name:     "default",
			template: "{{default \"unknown\" .Title}}",
			result:   &Result{Title: ""},
			expected: "unknown",
		},
		{
			name:     "ternary",
			template: "{{ternary (isSuccess .StatusCode) \"OK\" \"FAIL\"}}",
			result:   &Result{StatusCode: 200},
			expected: "OK",
		},
		{
			name:     "contains",
			template: "{{if contains .URL \"example\"}}MATCHED{{else}}NO{{end}}",
			result:   &Result{URL: "https://example.com"},
			expected: "MATCHED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.template)
			if err != nil {
				t.Fatalf("Failed to create formatter: %v", err)
			}

			output, err := f.Format(tt.result)
			if err != nil {
				t.Fatalf("Failed to format: %v", err)
			}

			if output != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, output)
			}
		})
	}
}

func TestFormat_StatusHelpers(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		helper     string
		expected   bool
	}{
		{"isSuccess 200", 200, "isSuccess", true},
		{"isSuccess 201", 201, "isSuccess", true},
		{"isSuccess 404", 404, "isSuccess", false},
		{"isRedirect 301", 301, "isRedirect", true},
		{"isRedirect 302", 302, "isRedirect", true},
		{"isRedirect 200", 200, "isRedirect", false},
		{"isClientError 400", 400, "isClientError", true},
		{"isClientError 404", 404, "isClientError", true},
		{"isClientError 500", 500, "isClientError", false},
		{"isServerError 500", 500, "isServerError", true},
		{"isServerError 503", 503, "isServerError", true},
		{"isServerError 404", 404, "isServerError", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := "{{if " + tt.helper + " .StatusCode}}true{{else}}false{{end}}"
			f, err := New(template)
			if err != nil {
				t.Fatalf("Failed to create formatter: %v", err)
			}

			result := &Result{StatusCode: tt.statusCode}
			output, err := f.Format(result)
			if err != nil {
				t.Fatalf("Failed to format: %v", err)
			}

			expectedStr := "false"
			if tt.expected {
				expectedStr = "true"
			}
			if output != expectedStr {
				t.Errorf("Expected %q, got %q", expectedStr, output)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	// Valid templates
	valid := []string{
		"{{.URL}}",
		"{{.URL}} [{{.StatusCode}}]",
		"{{if .Alive}}UP{{else}}DOWN{{end}}",
		"json",
		"jsonl",
		"status",
	}

	for _, tmpl := range valid {
		if err := Validate(tmpl); err != nil {
			t.Errorf("Template %q should be valid: %v", tmpl, err)
		}
	}

	// Invalid templates
	invalid := []string{
		"{{.URL",
		"{{if}}{{end}}",
		"{{unknownFunc .URL}}",
	}

	for _, tmpl := range invalid {
		if err := Validate(tmpl); err == nil {
			t.Errorf("Template %q should be invalid", tmpl)
		}
	}
}

func TestListPresets(t *testing.T) {
	presets := ListPresets()
	if len(presets) == 0 {
		t.Error("Expected at least one preset")
	}

	// Check expected presets exist
	expected := []string{"url", "host", "status", "json", "jsonl"}
	for _, e := range expected {
		found := false
		for _, p := range presets {
			if p == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected preset %q not found", e)
		}
	}
}

func TestFormatMap(t *testing.T) {
	f, err := New("{{.name}}: {{.value}}")
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}

	data := map[string]interface{}{
		"name":  "test",
		"value": 123,
	}

	output, err := f.FormatMap(data)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	expected := "test: 123"
	if output != expected {
		t.Errorf("Expected %q, got %q", expected, output)
	}
}

func TestDSLExpression_StatusCode(t *testing.T) {
	tests := []struct {
		expr     string
		code     int
		expected bool
	}{
		{"status_code == 200", 200, true},
		{"status_code == 200", 404, false},
		{"status_code >= 400", 500, true},
		{"status_code >= 400", 200, false},
		{"status_code < 300", 200, true},
		{"status_code < 300", 400, false},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			e, err := ParseExpression(tt.expr)
			if err != nil {
				t.Fatalf("Failed to parse: %v", err)
			}

			result := &Result{StatusCode: tt.code}
			if got := e.Match(result); got != tt.expected {
				t.Errorf("Match() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDSLExpression_Contains(t *testing.T) {
	tests := []struct {
		expr     string
		result   *Result
		expected bool
	}{
		{
			expr:     `contains(title, "admin")`,
			result:   &Result{Title: "Admin Panel"},
			expected: true,
		},
		{
			expr:     `contains(title, "admin")`,
			result:   &Result{Title: "User Panel"},
			expected: false,
		},
		{
			expr:     `contains(url, "login")`,
			result:   &Result{URL: "https://example.com/login"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			e, err := ParseExpression(tt.expr)
			if err != nil {
				t.Fatalf("Failed to parse: %v", err)
			}

			if got := e.Match(tt.result); got != tt.expected {
				t.Errorf("Match() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDSLExpression_Regex(t *testing.T) {
	e, err := ParseExpression(`regex:https?://.*\.com`)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com", true},
		{"http://test.com/path", true},
		{"ftp://example.com", false},
		{"https://example.org", false},
	}

	for _, tt := range tests {
		result := &Result{URL: tt.url}
		if got := e.Match(result); got != tt.expected {
			t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.expected)
		}
	}
}

func TestFormat_Duration(t *testing.T) {
	f, err := New("{{duration .ResponseTime}}")
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}

	result := &Result{
		ResponseTime: 150 * time.Millisecond,
	}

	output, err := f.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if output != "150ms" {
		t.Errorf("Expected '150ms', got %q", output)
	}
}

func TestFormat_ColorFunctions(t *testing.T) {
	f, err := New("{{red \"error\"}}")
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}

	result := &Result{}
	output, err := f.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	// Should contain ANSI codes
	if !strings.Contains(output, "\033[31m") {
		t.Errorf("Expected red ANSI code in output")
	}
}
