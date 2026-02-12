// Regression test for bug: buildQuery used manual concatenation, not url.Values.
package responsesplit

import (
	"net/url"
	"strings"
	"testing"
)

func TestBuildQuery_SpecialCharsEncoded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params map[string]string
		check  func(t *testing.T, result string)
	}{
		{
			name:   "crlf_injection_encoded",
			params: map[string]string{"header": "value\r\nInjected: true"},
			check: func(t *testing.T, result string) {
				// The \r\n must be percent-encoded, not passed raw.
				if strings.Contains(result, "\r\n") {
					t.Error("raw CRLF found in encoded query — response splitting possible")
				}
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("header"); got != "value\r\nInjected: true" {
					t.Errorf("header = %q; want %q", got, "value\r\nInjected: true")
				}
			},
		},
		{
			name:   "ampersand_injection",
			params: map[string]string{"x": "a&y=evil"},
			check: func(t *testing.T, result string) {
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if vals.Get("y") != "" {
					t.Error("parameter injection: 'y' parsed as separate param")
				}
				if got := vals.Get("x"); got != "a&y=evil" {
					t.Errorf("x = %q; want %q", got, "a&y=evil")
				}
			},
		},
		{
			name:   "space_encoded",
			params: map[string]string{"q": "hello world"},
			check: func(t *testing.T, result string) {
				if strings.Contains(result, " ") {
					t.Error("literal space found in query string")
				}
			},
		},
		{
			name:   "special_chars_in_key",
			params: map[string]string{"a&b=c": "safe"},
			check: func(t *testing.T, result string) {
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("a&b=c"); got != "safe" {
					t.Errorf("key with special chars: got %q; want %q", got, "safe")
				}
				if vals.Get("b") != "" {
					t.Error("key injection: 'b' parsed as separate param from key")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := buildQuery(tt.params)
			tt.check(t, result)
		})
	}
}
