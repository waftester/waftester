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

func TestCoalesce(t *testing.T) {
	tests := []struct {
		name     string
		template string
		result   *Result
		expected string
	}{
		{
			name:     "returns first non-empty value",
			template: `{{coalesce .Title .Host "fallback"}}`,
			result:   &Result{Title: "My Page", Host: "example.com"},
			expected: "My Page",
		},
		{
			name:     "skips empty returns second",
			template: `{{coalesce .Title .Host "fallback"}}`,
			result:   &Result{Title: "", Host: "example.com"},
			expected: "example.com",
		},
		{
			name:     "all empty returns fallback",
			template: `{{coalesce .Title .Host "fallback"}}`,
			result:   &Result{Title: "", Host: ""},
			expected: "fallback",
		},
		{
			name:     "all nil returns empty string",
			template: `{{coalesce .Title .Host}}`,
			result:   &Result{},
			expected: "",
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

func TestToJSON(t *testing.T) {
	f, err := New(`{{toJson .Headers}}`)
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}
	result := &Result{
		Headers: map[string]string{"Content-Type": "text/html", "Server": "nginx"},
	}
	output, err := f.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}
	if !strings.Contains(output, `"Content-Type":"text/html"`) {
		t.Errorf("Expected JSON with Content-Type, got %q", output)
	}
	if !strings.Contains(output, `"Server":"nginx"`) {
		t.Errorf("Expected JSON with Server, got %q", output)
	}
}

func TestToJSON_NilMap(t *testing.T) {
	f, err := New(`{{toJson .Headers}}`)
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}
	result := &Result{}
	output, err := f.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}
	if output != "null" {
		t.Errorf("Expected \"null\" for nil map, got %q", output)
	}
}

func TestToPrettyJSON(t *testing.T) {
	f, err := New(`{{toPrettyJson .Custom}}`)
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}
	result := &Result{
		Custom: map[string]interface{}{"key": "value"},
	}
	output, err := f.Format(result)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}
	if !strings.Contains(output, "  ") {
		t.Errorf("Expected indented JSON, got %q", output)
	}
	if !strings.Contains(output, `"key": "value"`) {
		t.Errorf("Expected key field in pretty JSON, got %q", output)
	}
}

func TestFormatTime(t *testing.T) {
	tests := []struct {
		name     string
		template string
		ts       time.Time
		expected string
	}{
		{
			name:     "date format",
			template: `{{formatTime .Timestamp "2006-01-02"}}`,
			ts:       time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
			expected: "2025-06-15",
		},
		{
			name:     "datetime format",
			template: `{{formatTime .Timestamp "2006-01-02 15:04:05"}}`,
			ts:       time.Date(2025, 6, 15, 10, 30, 45, 0, time.UTC),
			expected: "2025-06-15 10:30:45",
		},
		{
			name:     "time only",
			template: `{{formatTime .Timestamp "15:04"}}`,
			ts:       time.Date(2025, 1, 1, 14, 5, 0, 0, time.UTC),
			expected: "14:05",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.template)
			if err != nil {
				t.Fatalf("Failed to create formatter: %v", err)
			}
			result := &Result{Timestamp: tt.ts}
			output, err := f.Format(result)
			if err != nil {
				t.Fatalf("Failed to format: %v", err)
			}
			if output != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, output)
			}
		})
	}
}

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		name      string
		severity  string
		ansiCode  string
		wantPlain bool
	}{
		{"critical", "critical", "\033[1;31m", false},
		{"high", "high", "\033[31m", false},
		{"medium", "medium", "\033[33m", false},
		{"low", "low", "\033[34m", false},
		{"info", "info", "\033[36m", false},
		{"unknown returns plain", "unknown", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(`{{severityColor .Severity}}`)
			if err != nil {
				t.Fatalf("Failed to create formatter: %v", err)
			}
			result := &Result{Severity: tt.severity}
			output, err := f.Format(result)
			if err != nil {
				t.Fatalf("Failed to format: %v", err)
			}
			if tt.wantPlain {
				if output != tt.severity {
					t.Errorf("Expected plain %q, got %q", tt.severity, output)
				}
			} else {
				if !strings.Contains(output, tt.ansiCode) {
					t.Errorf("Expected ANSI code %q in output %q", tt.ansiCode, output)
				}
				if !strings.Contains(output, tt.severity) {
					t.Errorf("Expected severity text %q in output %q", tt.severity, output)
				}
				if !strings.Contains(output, "\033[0m") {
					t.Errorf("Expected ANSI reset code in output %q", output)
				}
			}
		})
	}
}

func TestFormatMap_JSON(t *testing.T) {
	f, err := New("json")
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}
	data := map[string]interface{}{"url": "https://example.com", "status": 200}
	output, err := f.FormatMap(data)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}
	if !strings.Contains(output, `"url": "https://example.com"`) {
		t.Errorf("Expected JSON url field, got %q", output)
	}
	// Should be indented (pretty JSON)
	if !strings.Contains(output, "\n") {
		t.Errorf("JSON output should be multi-line")
	}
}

func TestFormatMap_JSONL(t *testing.T) {
	f, err := New("jsonl")
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}
	data := map[string]interface{}{"url": "https://example.com"}
	output, err := f.FormatMap(data)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}
	if strings.Contains(output, "\n") {
		t.Errorf("JSONL output should be single line, got %q", output)
	}
	if !strings.Contains(output, `"url":"https://example.com"`) {
		t.Errorf("Expected JSONL url field, got %q", output)
	}
}

func TestFormatMap_StrictModeError(t *testing.T) {
	// Accessing a sub-field on a string value triggers a template execution error
	f, err := New("{{.name.subfield}}")
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}
	f.StrictMode = true
	data := map[string]interface{}{"name": "test"}
	_, err = f.FormatMap(data)
	if err == nil {
		t.Error("Expected error in strict mode for invalid field access")
	}
}

func TestEvaluateContains_Fields(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		result   *Result
		expected bool
	}{
		{
			name:     "body contains match",
			expr:     `contains(body, "forbidden")`,
			result:   &Result{BodyPreview: "403 Forbidden"},
			expected: true,
		},
		{
			name:     "body_preview contains match",
			expr:     `contains(body_preview, "error")`,
			result:   &Result{BodyPreview: "Internal Server Error"},
			expected: true,
		},
		{
			name:     "server contains match",
			expr:     `contains(server, "nginx")`,
			result:   &Result{Server: "nginx/1.24.0"},
			expected: true,
		},
		{
			name:     "server no match",
			expr:     `contains(server, "apache")`,
			result:   &Result{Server: "nginx/1.24.0"},
			expected: false,
		},
		{
			name:     "tech contains match",
			expr:     `contains(tech, "php")`,
			result:   &Result{Tech: "PHP, MySQL"},
			expected: true,
		},
		{
			name:     "content_type match",
			expr:     `contains(content_type, "json")`,
			result:   &Result{ContentType: "application/json"},
			expected: true,
		},
		{
			name:     "content_type no match",
			expr:     `contains(content_type, "xml")`,
			result:   &Result{ContentType: "application/json"},
			expected: false,
		},
		{
			name:     "unknown field returns false",
			expr:     `contains(unknown_field, "test")`,
			result:   &Result{Title: "test"},
			expected: false,
		},
		{
			name:     "malformed expression returns false",
			expr:     `contains(broken`,
			result:   &Result{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestEvaluateStatusCode_Operators(t *testing.T) {
	tests := []struct {
		expr     string
		code     int
		expected bool
	}{
		{"status_code <= 299", 200, true},
		{"status_code <= 299", 299, true},
		{"status_code <= 299", 300, false},
		{"status_code > 399", 400, true},
		{"status_code > 399", 500, true},
		{"status_code > 399", 399, false},
		{"status_code > 399", 200, false},
		{"status_code == invalid", 200, false},
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

func TestFormatDuration_Ranges(t *testing.T) {
	tests := []struct {
		name     string
		template string
		dur      time.Duration
		expected string
	}{
		{
			name:     "microseconds",
			template: "{{duration .ResponseTime}}",
			dur:      500 * time.Microsecond,
			expected: "500µs",
		},
		{
			name:     "milliseconds",
			template: "{{duration .ResponseTime}}",
			dur:      250 * time.Millisecond,
			expected: "250ms",
		},
		{
			name:     "seconds",
			template: "{{duration .ResponseTime}}",
			dur:      2500 * time.Millisecond,
			expected: "2.50s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.template)
			if err != nil {
				t.Fatalf("Failed to create formatter: %v", err)
			}
			result := &Result{ResponseTime: tt.dur}
			output, err := f.Format(result)
			if err != nil {
				t.Fatalf("Failed to format: %v", err)
			}
			if output != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, output)
			}
		})
	}
}

func TestFormat_StrictModeError(t *testing.T) {
	f, err := New("{{.NonExistentField}}")
	if err != nil {
		t.Fatalf("Failed to create formatter: %v", err)
	}
	f.StrictMode = true
	result := &Result{}
	_, err = f.Format(result)
	// NonExistentField doesn't exist on the struct, strict mode should error
	if err == nil {
		t.Error("Expected error in strict mode for non-existent field")
	}
}

func TestRepeat_ClampedToMax(t *testing.T) {
	// strings.Repeat must be clamped to 10000 to prevent memory exhaustion.
	// An unclamped repeat(s, 1000000) would allocate ~1GB.
	f, err := New(`{{repeat "A" 50000}}`)
	if err != nil {
		t.Fatalf("failed to create formatter: %v", err)
	}

	output, err := f.Format(&Result{})
	if err != nil {
		t.Fatalf("format error: %v", err)
	}
	if len(output) != 10000 {
		t.Errorf("repeat should clamp to 10000, got length %d", len(output))
	}
}

func TestRepeat_ExactBoundary(t *testing.T) {
	// Exactly at the clamp limit should NOT be truncated.
	f, err := New(`{{repeat "Z" 10000}}`)
	if err != nil {
		t.Fatalf("failed to create formatter: %v", err)
	}
	output, err := f.Format(&Result{})
	if err != nil {
		t.Fatalf("format error: %v", err)
	}
	if len(output) != 10000 {
		t.Errorf("repeat at exact boundary should produce 10000 chars, got %d", len(output))
	}
}

func TestRepeat_OnePastBoundary(t *testing.T) {
	// One past the clamp limit should be clamped to 10000.
	f, err := New(`{{repeat "Z" 10001}}`)
	if err != nil {
		t.Fatalf("failed to create formatter: %v", err)
	}
	output, err := f.Format(&Result{})
	if err != nil {
		t.Fatalf("format error: %v", err)
	}
	if len(output) != 10000 {
		t.Errorf("repeat at 10001 should clamp to 10000, got %d", len(output))
	}
}

func TestRepeat_NegativeCount(t *testing.T) {
	f, err := New(`{{repeat "B" -5}}`)
	if err != nil {
		t.Fatalf("failed to create formatter: %v", err)
	}

	output, err := f.Format(&Result{})
	if err != nil {
		t.Fatalf("format error: %v", err)
	}
	if output != "" {
		t.Errorf("repeat with negative count should produce empty string, got %q", output)
	}
}

func TestRepeat_NormalCount(t *testing.T) {
	f, err := New(`{{repeat "x" 5}}`)
	if err != nil {
		t.Fatalf("failed to create formatter: %v", err)
	}

	output, err := f.Format(&Result{})
	if err != nil {
		t.Fatalf("format error: %v", err)
	}
	if output != "xxxxx" {
		t.Errorf("expected %q, got %q", "xxxxx", output)
	}
}
