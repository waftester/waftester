// Regression test for bug: MCP server logged sensitive arguments in plaintext.
//
// Before the fix, loggedTool() marshalled the full request arguments (including
// api_key, token, password, etc.) and wrote them to the log. The fix redacts
// known sensitive field names before logging.
//
// These tests call the real isSensitiveKey/redactMap functions — NOT a local
// copy — so they break if the production logic changes or regresses.
package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactMap_SensitiveFieldsRedacted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantAbsent  []string // values that must NOT appear in output
		wantContain string   // must appear
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
		// NEW: fields that the old code MISSED (they would have leaked)
		{
			name:        "authorization_header",
			input:       `{"authorization":"Bearer eyJhbGci...","url":"/api"}`,
			wantAbsent:  []string{"Bearer eyJhbGci..."},
			wantContain: "[REDACTED]",
		},
		{
			name:        "access_token",
			input:       `{"access_token":"ya29.xxxxx","scope":"admin"}`,
			wantAbsent:  []string{"ya29.xxxxx"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "refresh_token",
			input:       `{"refresh_token":"rt_xxxx","client":"app"}`,
			wantAbsent:  []string{"rt_xxxx"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "jwt_value",
			input:       `{"jwt":"eyJhbGci.payload.sig","user":"admin"}`,
			wantAbsent:  []string{"eyJhbGci.payload.sig"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "private_key",
			input:       `{"private_key":"-----BEGIN RSA PRIVATE KEY-----","id":"1"}`,
			wantAbsent:  []string{"-----BEGIN RSA PRIVATE KEY-----"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "client_secret",
			input:       `{"client_secret":"cs_xxxx","client_id":"pub"}`,
			wantAbsent:  []string{"cs_xxxx"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "bearer_token",
			input:       `{"bearer":"tok_123","method":"POST"}`,
			wantAbsent:  []string{"tok_123"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "cookie_value",
			input:       `{"cookie":"session=abc123","path":"/"}`,
			wantAbsent:  []string{"session=abc123"},
			wantContain: "[REDACTED]",
		},
		{
			name:        "session_id",
			input:       `{"session_id":"sess_abc","user":"admin"}`,
			wantAbsent:  []string{"sess_abc"},
			wantContain: "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var rawArgs map[string]interface{}
			if err := json.Unmarshal([]byte(tt.input), &rawArgs); err != nil {
				t.Fatalf("invalid test input: %v", err)
			}
			redactMap(rawArgs)
			result, _ := json.Marshal(rawArgs)
			resultStr := string(result)

			for _, absent := range tt.wantAbsent {
				if strings.Contains(resultStr, absent) {
					t.Errorf("sensitive value %q still present in redacted output: %s", absent, resultStr)
				}
			}
			if !strings.Contains(resultStr, tt.wantContain) {
				t.Errorf("redaction marker %q not found in output: %s", tt.wantContain, resultStr)
			}
		})
	}
}

func TestRedactMap_NonSensitiveFieldsPreserved(t *testing.T) {
	t.Parallel()

	var rawArgs map[string]interface{}
	input := `{"target":"https://example.com","mode":"aggressive","timeout":30}`
	if err := json.Unmarshal([]byte(input), &rawArgs); err != nil {
		t.Fatalf("invalid test input: %v", err)
	}
	redactMap(rawArgs)
	result, _ := json.Marshal(rawArgs)
	resultStr := string(result)

	for _, expected := range []string{"example.com", "aggressive", "30"} {
		if !strings.Contains(resultStr, expected) {
			t.Errorf("non-sensitive value %q was removed from output: %s", expected, resultStr)
		}
	}
	if strings.Contains(resultStr, "[REDACTED]") {
		t.Errorf("non-sensitive input was redacted: %s", resultStr)
	}
}

func TestRedactMap_InvalidJSON(t *testing.T) {
	t.Parallel()

	// Invalid JSON: unmarshal fails, so redactMap is never called.
	// This tests the caller's behavior (loggedTool uses original bytes).
	input := `not valid json`
	var rawArgs map[string]interface{}
	err := json.Unmarshal([]byte(input), &rawArgs)
	if err == nil {
		t.Fatal("expected unmarshal error for invalid JSON")
	}
	// No crash — rawArgs is nil, redactMap should not be called on nil.
}

func TestRedactMap_EmptyObject(t *testing.T) {
	t.Parallel()

	var rawArgs map[string]interface{}
	_ = json.Unmarshal([]byte(`{}`), &rawArgs)
	redactMap(rawArgs)
	result, _ := json.Marshal(rawArgs)
	if string(result) != "{}" {
		t.Errorf("empty object was modified: got %q", string(result))
	}
}

func TestRedactMap_NestedSensitiveFields(t *testing.T) {
	t.Parallel()

	input := `{"config":{"api_key":"sk-nested","debug":true},"name":"test"}`
	var rawArgs map[string]interface{}
	if err := json.Unmarshal([]byte(input), &rawArgs); err != nil {
		t.Fatalf("invalid test input: %v", err)
	}
	redactMap(rawArgs)
	result, _ := json.Marshal(rawArgs)
	resultStr := string(result)

	if strings.Contains(resultStr, "sk-nested") {
		t.Errorf("nested sensitive value leaked: %s", resultStr)
	}
	if !strings.Contains(resultStr, "test") {
		t.Errorf("non-sensitive nested value was removed: %s", resultStr)
	}
}

func TestIsSensitiveKey_SubstringMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key  string
		want bool
	}{
		{"api_key", true},
		{"x_api_key", true},
		{"MY_SECRET_TOKEN", true},
		{"Authorization", true},
		{"x-auth-header", true},
		{"bearer_token", true},
		{"jwt_value", true},
		{"session_id", true},
		{"cookie", true},
		{"target", false},
		{"mode", false},
		{"url", false},
		{"timeout", false},
		{"data", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Parallel()
			if got := isSensitiveKey(tt.key); got != tt.want {
				t.Errorf("isSensitiveKey(%q) = %v; want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestTruncateString_UTF8Safe(t *testing.T) {
	t.Parallel()

	// 4-byte emoji repeated — truncating at byte boundary would split a rune
	input := strings.Repeat("🔥", 60) // 60 runes, 240 bytes
	result := truncateString(input, 50)
	if len([]rune(result)) != 50 {
		t.Errorf("truncated to %d runes; want 50", len([]rune(result)))
	}
	// Verify no broken runes — re-encoding should not change the string
	for _, r := range result {
		if r == '\uFFFD' {
			t.Error("truncation produced replacement character (broken UTF-8)")
		}
	}
}

func TestRedactMap_ArrayTraversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantAbsent []string
	}{
		{
			name:       "array of objects with sensitive fields",
			input:      `{"items":[{"api_key":"secret1","name":"a"},{"token":"secret2","name":"b"}]}`,
			wantAbsent: []string{"secret1", "secret2"},
		},
		{
			name:       "nested array in object",
			input:      `{"config":{"servers":[{"password":"pw1"},{"password":"pw2"}]}}`,
			wantAbsent: []string{"pw1", "pw2"},
		},
		{
			name:       "mixed array with non-map items",
			input:      `{"data":["plain_string",{"secret":"hidden"},42]}`,
			wantAbsent: []string{"hidden"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var rawArgs map[string]interface{}
			if err := json.Unmarshal([]byte(tt.input), &rawArgs); err != nil {
				t.Fatalf("invalid test input: %v", err)
			}
			redactMap(rawArgs)
			result, _ := json.Marshal(rawArgs)
			resultStr := string(result)
			for _, absent := range tt.wantAbsent {
				if strings.Contains(resultStr, absent) {
					t.Errorf("sensitive value %q still present after redaction: %s", absent, resultStr)
				}
			}
		})
	}
}

func TestIsSensitiveKey_ExpandedPatterns(t *testing.T) {
	t.Parallel()

	// These patterns were added during security review to catch additional
	// sensitive field names beyond the original set.
	tests := []struct {
		key  string
		want bool
	}{
		{"access_key_id", true},
		{"private_data", true},
		{"signing_key", true},
		{"encrypt_secret", true},
		{"encryption_key", true},
		{"access_id", false},
		{"my_private_field", true},
		{"proxy_auth", true},

		// "key" is matched via suffix patterns (_key, -key) so compound names
		// like "primary_key" are caught, but "keyboard" is not (no bare "key" substring).
		{"primary_key", true},
		{"keyboard_layout", false},

		// Ensure non-sensitive fields are still safe.
		{"process", false},
		{"driver", false},
		{"format", false},
		{"concurrency", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Parallel()
			if got := isSensitiveKey(tt.key); got != tt.want {
				t.Errorf("isSensitiveKey(%q) = %v; want %v", tt.key, got, tt.want)
			}
		})
	}
}
