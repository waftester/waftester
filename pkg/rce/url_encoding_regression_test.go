// Regression test for bug: buildFormData used manual string concatenation
// for URL-encoded form data, allowing parameter injection via special chars.
// The fix uses url.Values.Encode() for proper percent-encoding.
package rce

import (
	"net/url"
	"strings"
	"testing"
)

func TestBuildFormData_SpecialCharsEncoded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params map[string]string
		check  func(t *testing.T, result string)
	}{
		{
			name:   "ampersand_injection_prevented",
			params: map[string]string{"cmd": "ls&rm -rf /"},
			check: func(t *testing.T, result string) {
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("cmd"); got != "ls&rm -rf /" {
					t.Errorf("cmd = %q; want %q", got, "ls&rm -rf /")
				}
				// Must not have "rm" as a separate parameter.
				if vals.Get("rm -rf /") != "" {
					t.Error("parameter injection detected")
				}
			},
		},
		{
			name:   "equals_in_value",
			params: map[string]string{"data": "key=value"},
			check: func(t *testing.T, result string) {
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("data"); got != "key=value" {
					t.Errorf("data = %q; want %q", got, "key=value")
				}
			},
		},
		{
			name:   "space_encoded",
			params: map[string]string{"arg": "hello world"},
			check: func(t *testing.T, result string) {
				if strings.Contains(result, " ") {
					t.Error("literal space found in encoded form data")
				}
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("arg"); got != "hello world" {
					t.Errorf("arg = %q; want %q", got, "hello world")
				}
			},
		},
		{
			name:   "special_chars_in_key",
			params: map[string]string{"x&y=z": "value"},
			check: func(t *testing.T, result string) {
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("x&y=z"); got != "value" {
					t.Errorf("key with special chars: got %q; want %q", got, "value")
				}
				if vals.Get("y") != "" {
					t.Error("key injection: 'y' parsed as separate param from key")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := buildFormData(tt.params)
			tt.check(t, result)
		})
	}
}
