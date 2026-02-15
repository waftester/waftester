package nuclei

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Regression: R9 — expandVariables must sort longest-first ---
// When one variable name is a prefix of another (e.g., "api" and "api_key"),
// the longer key must be replaced first to prevent corruption.

func TestExpandVariables_LongestFirst(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		vars   map[string]string
		expect string
	}{
		{
			name:  "prefix collision — api vs api_key",
			input: "url={{api_key}}/resource",
			vars: map[string]string{
				"api":     "https://example.com",
				"api_key": "secret123",
			},
			expect: "url=secret123/resource",
		},
		{
			name:  "prefix collision — Base vs BaseURL",
			input: "{{BaseURL}}/login",
			vars: map[string]string{
				"Base":    "base_value",
				"BaseURL": "https://example.com",
			},
			expect: "https://example.com/login",
		},
		{
			name:  "prefix collision — host vs hostname",
			input: "connect to {{hostname}}:8080",
			vars: map[string]string{
				"host":     "h",
				"hostname": "example.com",
			},
			expect: "connect to example.com:8080",
		},
		{
			name:  "no collision — independent keys",
			input: "{{a}} and {{b}}",
			vars: map[string]string{
				"a": "alpha",
				"b": "beta",
			},
			expect: "alpha and beta",
		},
		{
			name:  "dot-prefixed vars",
			input: "{{.api_key}}/{{.api}}",
			vars: map[string]string{
				"api":     "base",
				"api_key": "key123",
			},
			expect: "key123/base",
		},
		{
			name:   "empty vars map",
			input:  "{{untouched}}",
			vars:   map[string]string{},
			expect: "{{untouched}}",
		},
		{
			name:   "nil vars map",
			input:  "{{untouched}}",
			vars:   nil,
			expect: "{{untouched}}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandVariables(tt.input, tt.vars)
			assert.Equal(t, tt.expect, got)
		})
	}
}

// --- Regression: R6 — matchStatus must handle "and" condition ---
// With condition="and", ALL listed statuses must match (they're all the same code).

func TestMatchStatus_AndCondition(t *testing.T) {
	tests := []struct {
		name      string
		statuses  []int
		code      int
		condition string
		expect    bool
	}{
		{
			"OR: one matches",
			[]int{200, 301, 404}, 200, "",
			true,
		},
		{
			"OR: none match",
			[]int{200, 301}, 404, "",
			false,
		},
		{
			"AND: code matches all entries (same code listed twice)",
			[]int{200, 200}, 200, "and",
			true,
		},
		{
			"AND: code does not match one entry",
			[]int{200, 301}, 200, "and",
			false,
		},
		{
			"AND: empty list",
			[]int{}, 200, "and",
			true,
		},
		{
			"OR: empty list",
			[]int{}, 404, "",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchStatus(tt.statuses, tt.code, tt.condition)
			assert.Equal(t, tt.expect, got, "matchStatus(%v, %d, %q)", tt.statuses, tt.code, tt.condition)
		})
	}
}

// --- Regression: R6 — matchSize must handle "and" condition ---

func TestMatchSize_AndCondition(t *testing.T) {
	tests := []struct {
		name      string
		sizes     []int
		size      int
		condition string
		expect    bool
	}{
		{
			"OR: one matches",
			[]int{100, 200, 300}, 200, "",
			true,
		},
		{
			"OR: none match",
			[]int{100, 200}, 500, "",
			false,
		},
		{
			"AND: size matches all entries",
			[]int{100, 100}, 100, "and",
			true,
		},
		{
			"AND: size does not match one entry",
			[]int{100, 200}, 100, "and",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchSize(tt.sizes, tt.size, tt.condition)
			assert.Equal(t, tt.expect, got)
		})
	}
}

// --- Regression: R10 — runExtractor must guard against negative Group index ---
// A template with group: -1 must not panic. Before the fix, accessing m[-1]
// would panic with index out of range.

func TestRunExtractor_NegativeGroupNoPanic(t *testing.T) {
	e := Extractor{
		Type:  "regex",
		Regex: []string{`(\w+)=(\w+)`},
		Group: -1, // malformed template
	}

	resp := &ResponseData{
		StatusCode: 200,
		Headers:    http.Header{},
		Body:       []byte("key=value foo=bar"),
	}

	// Must not panic — guard `e.Group >= 0` falls through to m[0]
	results := runExtractor(&e, resp)
	require.NotEmpty(t, results, "should extract via fallback m[0]")
	assert.Equal(t, "key=value", results[0],
		"with group=-1, should fall back to m[0] (full match)")
}

func TestRunExtractor_ValidGroup(t *testing.T) {
	e := Extractor{
		Type:  "regex",
		Regex: []string{`(\w+)=(\w+)`},
		Group: 2,
	}

	resp := &ResponseData{
		StatusCode: 200,
		Headers:    http.Header{},
		Body:       []byte("key=value"),
	}

	results := runExtractor(&e, resp)
	require.NotEmpty(t, results)
	assert.Equal(t, "value", results[0],
		"group=2 should capture the second submatch")
}

func TestRunExtractor_GroupExceedsMatchCount(t *testing.T) {
	e := Extractor{
		Type:  "regex",
		Regex: []string{`(\w+)`},
		Group: 5, // only 2 groups: [full, capture]
	}

	resp := &ResponseData{
		StatusCode: 200,
		Headers:    http.Header{},
		Body:       []byte("hello"),
	}

	results := runExtractor(&e, resp)
	// Falls through to m[0] since Group >= len(m)
	require.NotEmpty(t, results)
	assert.Equal(t, "hello", results[0],
		"out-of-bounds group should fall back to m[0]")
}

// Verify the guard logic handles the full range of edge cases.
func TestRunExtractor_GroupBoundary(t *testing.T) {
	tests := []struct {
		name  string
		group int
		want  string
	}{
		{"group=-100", -100, "key=value"}, // falls back to m[0]
		{"group=0", 0, "key=value"},       // m[0] = full match
		{"group=1", 1, "key"},             // m[1] = first capture
		{"group=2", 2, "value"},           // m[2] = second capture
		{"group=3", 3, "key=value"},       // out of range → m[0]
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Extractor{
				Type:  "regex",
				Regex: []string{`(\w+)=(\w+)`},
				Group: tt.group,
			}
			resp := &ResponseData{
				StatusCode: 200,
				Headers:    http.Header{},
				Body:       []byte("key=value"),
			}
			results := runExtractor(&e, resp)
			require.NotEmpty(t, results)
			assert.Equal(t, tt.want, results[0])
		})
	}
}
