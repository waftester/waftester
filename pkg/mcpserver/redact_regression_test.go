// Regression test for bug: MCP server logged sensitive arguments in plaintext.
//
// Before the fix, loggedTool() marshalled the full request arguments (including
// api_key, token, password, etc.) and wrote them to the log. The fix redacts
// known sensitive field names before logging.
package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"
)

// redactArgs reproduces the exact redaction logic from loggedTool so we can
// unit-test it without needing a full MCP CallToolRequest.
func redactArgs(raw json.RawMessage) string {
	var rawArgs map[string]interface{}
	argBytes := []byte(raw)
	if json.Unmarshal(argBytes, &rawArgs) == nil {
		for k := range rawArgs {
			switch strings.ToLower(k) {
			case "api_key", "apikey", "api_secret", "apisecret", "token",
				"password", "secret", "license", "credentials", "key":
				rawArgs[k] = "[REDACTED]"
			}
		}
		argBytes, _ = json.Marshal(rawArgs)
	}
	return string(argBytes)
}

func TestRedactArgs_SensitiveFieldsRedacted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantAbsent []string // values that must NOT appear in output
		wantContain string  // must appear
	}{
		{
			name:        "api_key",
			input:       `{"api_key":"sk-live-abc123","target":"example.com"}`,
			wantAbsent:  []string{"sk-live-abc123"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "token",
			input:       `{"token":"ghp_xxxxxxxxxxxx","repo":"test"}`,
			wantAbsent:  []string{"ghp_xxxxxxxxxxxx"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "password",
			input:       `{"password":"hunter2","username":"admin"}`,
			wantAbsent:  []string{"hunter2"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "mixed_case_apiKey",
			input:       `{"apiKey":"SECRET","data":"safe"}`,
			wantAbsent:  []string{"SECRET"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "license",
			input:       `{"license":"LIC-KEY-999","mode":"scan"}`,
			wantAbsent:  []string{"LIC-KEY-999"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "credentials",
			input:       `{"credentials":"admin:pass","host":"10.0.0.1"}`,
			wantAbsent:  []string{"admin:pass"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "key",
			input:       `{"key":"ABCDEF","url":"http://test"}`,
			wantAbsent:  []string{"ABCDEF"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "api_secret",
			input:       `{"api_secret":"s3cr3t","endpoint":"/test"}`,
			wantAbsent:  []string{"s3cr3t"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "secret",
			input:       `{"secret":"top-secret-value","action":"test"}`,
			wantAbsent:  []string{"top-secret-value"},
			wantContain: "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := redactArgs(json.RawMessage(tt.input))

			for _, absent := range tt.wantAbsent {
				if strings.Contains(result, absent) {
					t.Errorf("sensitive value %q still present in redacted output: %s", absent, result)
				}
			}
			if !strings.Contains(result, tt.wantContain) {
				t.Errorf("redaction marker %q not found in output: %s", tt.wantContain, result)
			}
		})
	}
}

func TestRedactArgs_NonSensitiveFieldsPreserved(t *testing.T) {
	t.Parallel()

	input := `{"target":"https://example.com","mode":"aggressive","timeout":30}`
	result := redactArgs(json.RawMessage(input))

	for _, expected := range []string{"example.com", "aggressive", "30"} {
		if !strings.Contains(result, expected) {
			t.Errorf("non-sensitive value %q was removed from output: %s", expected, result)
		}
	}
	if strings.Contains(result, "[REDACTED]") {
		t.Errorf("non-sensitive input was redacted: %s", result)
	}
}

func TestRedactArgs_InvalidJSON(t *testing.T) {
	t.Parallel()

	// Invalid JSON should be returned as-is (unmarshal fails, original bytes used).
	input := `not valid json`
	result := redactArgs(json.RawMessage(input))
	if result != input {
		t.Errorf("invalid JSON was modified: got %q, want %q", result, input)
	}
}

func TestRedactArgs_EmptyObject(t *testing.T) {
	t.Parallel()

	result := redactArgs(json.RawMessage(`{}`))
	if result != "{}" {
		t.Errorf("empty object was modified: got %q", result)
	}
}
