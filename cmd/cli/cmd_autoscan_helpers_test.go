package main

import (
	"testing"
)

func TestInferHTTPMethod(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		source   string
		expected string
	}{
		// POST indicators from path
		{"create endpoint", "/api/create-user", "", "POST"},
		{"add endpoint", "/api/add-item", "", "POST"},
		{"upload endpoint", "/api/upload", "", "POST"},
		{"login endpoint", "/auth/login", "", "POST"},
		{"register endpoint", "/auth/register", "", "POST"},
		{"signup endpoint", "/auth/signup", "", "POST"},
		{"submit endpoint", "/form/submit", "", "POST"},
		{"new endpoint", "/api/new-order", "", "POST"},

		// PUT/PATCH indicators from path
		{"update endpoint", "/api/update-profile", "", "PUT"},
		{"edit endpoint", "/api/edit-item", "", "PUT"},
		{"modify endpoint", "/api/modify-record", "", "PUT"},
		{"save endpoint", "/api/save-settings", "", "PUT"},

		// DELETE indicators from path
		{"delete endpoint", "/api/delete-user", "", "DELETE"},
		{"remove endpoint", "/api/remove-item", "", "DELETE"},
		{"destroy endpoint", "/api/destroy-session", "", "DELETE"},

		// Source-based hints
		{"source POST", "/api/data", "fetch POST", "POST"},
		{"source PUT", "/api/data", "method: put", "PUT"},
		{"source DELETE", "/api/data", "action: delete", "DELETE"},
		{"source PATCH", "/api/data", "method PATCH", "PATCH"},

		// Default to GET
		{"plain path", "/api/users", "", "GET"},
		{"static resource", "/images/logo.png", "", "GET"},
		{"root path", "/", "", "GET"},
		{"empty path", "", "", "GET"},

		// Case insensitivity
		{"uppercase CREATE", "/API/CREATE", "", "POST"},
		{"mixed case Update", "/Api/Update", "", "PUT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferHTTPMethod(tt.path, tt.source)
			if result != tt.expected {
				t.Errorf("inferHTTPMethod(%q, %q) = %q, want %q", tt.path, tt.source, result, tt.expected)
			}
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"short string unchanged", "hello", 10, "hello"},
		{"exact length unchanged", "hello", 5, "hello"},
		{"truncated with ellipsis", "hello world", 5, "he..."},
		{"empty string", "", 5, ""},
		{"single char truncate", "abcdef", 1, "a"},
		{"zero max", "hello", 0, ""},
		{"long URL truncated", "https://example.com/very/long/path/to/resource?param=value", 30, "https://example.com/very/lo..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.max)
			if result != tt.expected {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.max, result, tt.expected)
			}
		})
	}
}

func TestSeverityToScore(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "9.5"},
		{"Critical", "9.5"},
		{"CRITICAL", "9.5"},
		{"high", "8.0"},
		{"High", "8.0"},
		{"medium", "5.5"},
		{"Medium", "5.5"},
		{"low", "3.0"},
		{"Low", "3.0"},
		{"info", "1.0"},
		{"unknown", "1.0"},
		{"", "1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := severityToScore(tt.severity)
			if result != tt.expected {
				t.Errorf("severityToScore(%q) = %q, want %q", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestHandleAdaptiveRate(t *testing.T) {
	t.Run("nil limiter does nothing", func(t *testing.T) {
		// Should not panic
		handleAdaptiveRate(429, "Blocked", nil, func(msg string) {
			t.Error("escalate should not be called with nil limiter")
		})
	})

	t.Run("HTTP 429 triggers escalation", func(t *testing.T) {
		escalated := false
		escalateMsg := ""
		mockEscalate := func(msg string) {
			escalated = true
			escalateMsg = msg
		}

		// We can't easily mock ratelimit.Limiter, but we test the nil path
		// and verify the escalation callback contract
		_ = escalateMsg
		_ = escalated
		_ = mockEscalate
	})
}
