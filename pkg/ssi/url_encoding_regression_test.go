// Regression test for bug: buildQuery/buildFormData used manual string
// concatenation for URL-encoded form data.
//
// Before the fix, the functions built query strings as k+"="+v joined with "&",
// which did NOT encode special characters like &, =, +, spaces, or unicode.
// An attacker-controlled parameter value containing "&extra=injected" would
// inject additional form fields. The fix uses url.Values.Encode() which
// properly percent-encodes all reserved characters.
package ssi

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
			name:   "ampersand_in_value",
			params: map[string]string{"q": "a&b=c"},
			check: func(t *testing.T, result string) {
				// The encoded result must NOT contain a bare "&b=c"
				// that would be interpreted as a second parameter.
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("q"); got != "a&b=c" {
					t.Errorf("q = %q; want %q", got, "a&b=c")
				}
				if vals.Get("b") != "" {
					t.Error("parameter injection: 'b' was parsed as a separate param")
				}
			},
		},
		{
			name:   "equals_in_value",
			params: map[string]string{"expr": "1+1=2"},
			check: func(t *testing.T, result string) {
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("expr"); got != "1+1=2" {
					t.Errorf("expr = %q; want %q", got, "1+1=2")
				}
			},
		},
		{
			name:   "plus_in_value",
			params: map[string]string{"term": "foo+bar"},
			check: func(t *testing.T, result string) {
				// "+" must be encoded as %2B, not left as literal "+"
				// (which url.ParseQuery decodes as space).
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("term"); got != "foo+bar" {
					t.Errorf("term = %q; want %q", got, "foo+bar")
				}
			},
		},
		{
			name:   "space_in_value",
			params: map[string]string{"name": "John Doe"},
			check: func(t *testing.T, result string) {
				// Space must be encoded, not left as literal space.
				if strings.Contains(result, " ") {
					t.Error("space was not encoded in query string")
				}
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("name"); got != "John Doe" {
					t.Errorf("name = %q; want %q", got, "John Doe")
				}
			},
		},
		{
			name:   "unicode_chars",
			params: map[string]string{"emoji": "🔥"},
			check: func(t *testing.T, result string) {
				vals, err := url.ParseQuery(result)
				if err != nil {
					t.Fatalf("ParseQuery failed: %v", err)
				}
				if got := vals.Get("emoji"); got != "🔥" {
					t.Errorf("emoji = %q; want %q", got, "🔥")
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
				// Must not split into separate params
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
