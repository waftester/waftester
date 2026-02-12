// Regression tests for SanitizePrototypePollution and detectPollution bugs.
//
// Bug #7: SanitizePrototypePollution used single-pass replacement, allowing
//         nested payloads like "__pro__proto__to__" to survive as "__proto__".
//
// Bug #9: detectPollution had a dead branch — the general ppmarker check at
//         line 320 returned before the specific (test: + ppmarker) check.
package prototype

import (
	"testing"
)

// TestSanitizePrototypePollution_NestedBypass verifies that nested/overlapping
// dangerous patterns are fully removed via iterative replacement.
//
// Regression: A single pass of strings.ReplaceAll removed only the innermost
// match — e.g. "__pro__proto__to__" → "__proto__" survived.
func TestSanitizePrototypePollution_NestedBypass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "nested __proto__",
			input: "__pro__proto__to__",
			want:  "",
		},
		{
			name:  "nested constructor",
			input: "conconstructorstructor",
			want:  "",
		},
		{
			name:  "nested prototype",
			input: "protoprototypetype",
			want:  "",
		},
		{
			name:  "double nested __proto__",
			input: "__pr__pro__proto__to__oto__",
			want:  "",
		},
		{
			name:  "mixed nested",
			input: "__proto__constructorprototype__pro__proto__to__",
			want:  "",
		},
		{
			name:  "triple nesting",
			input: "__pr__pr__pro__proto__to__oto__oto__",
			want:  "",
		},
		{
			name:  "safe input unchanged",
			input: "normal safe input",
			want:  "normal safe input",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SanitizePrototypePollution(tt.input)
			if got != tt.want {
				t.Errorf("SanitizePrototypePollution(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestDetectPollution_SpecificBeforeGeneral verifies that a response containing
// both "test": and "ppmarker" returns the specific detection message, not the
// generic marker message.
//
// Regression: The general "ppmarker" check at line 320 returned early for ALL
// ppmarker-containing bodies, making the more specific (test: + ppmarker) check
// unreachable dead code.
func TestDetectPollution_SpecificBeforeGeneral(t *testing.T) {
	t.Parallel()

	tester := NewTester(nil)

	tests := []struct {
		name     string
		body     string
		wantMsg  string
		wantHit  bool
	}{
		{
			name:    "specific: test key + ppmarker",
			body:    `{"test": "ppmarker", "other": "data"}`,
			wantMsg: "Polluted property appeared in response",
			wantHit: true,
		},
		{
			name:    "general: ppmarker only",
			body:    `{"result": "ppmarker"}`,
			wantMsg: "Marker found in response - pollution successful",
			wantHit: true,
		},
		{
			name:    "no ppmarker",
			body:    `{"status": "ok"}`,
			wantMsg: "",
			wantHit: false,
		},
		{
			name:    "test key without ppmarker",
			body:    `{"test": "hello"}`,
			wantMsg: "",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tester.detectPollution(tt.body, nil)

			if tt.wantHit && result == "" {
				t.Error("expected detection, got empty string")
			}
			if !tt.wantHit && result != "" {
				t.Errorf("expected no detection, got: %s", result)
			}
			if tt.wantMsg != "" && result != tt.wantMsg {
				t.Errorf("got %q, want %q", result, tt.wantMsg)
			}
		})
	}
}
