package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- Regression: R11 — Double URL-decode prevention ---
// FindLinksInJS decodes content once. ExtractJSURLsEnhanced also decodes once
// before calling findLinksInJSDecoded. Content with %25 must survive correctly.

func TestFindLinksInJS_NoDoubleDecoding(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string // expected URL substring in results
		reject  string // must NOT appear in any result
	}{
		{
			name:    "percent-encoded space (%2520) stays as %20 after single decode",
			content: `const url = "/api/search?q=%2520term";`,
			want:    "/api/search?q=%20term",
			reject:  "/api/search?q= term",
		},
		{
			name:    "simple path survives",
			content: `fetch("/api/users/list");`,
			want:    "/api/users/list",
		},
		{
			name:    "unicode escaped path survives",
			content: `const u = "\u002Fapi\u002Fdata";`,
			want:    "/api/data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := FindLinksInJS(tt.content)

			if tt.want != "" {
				found := false
				for _, link := range links {
					if link == tt.want {
						found = true
						break
					}
				}
				assert.True(t, found, "expected %q to be found in %v", tt.want, links)
			}

			if tt.reject != "" {
				for _, link := range links {
					assert.NotEqual(t, tt.reject, link,
						"double-decoded URL %q must not appear in results", tt.reject)
				}
			}
		})
	}
}

// ExtractJSURLsEnhanced should not double-decode when calling findLinksInJSDecoded.

func TestExtractJSURLsEnhanced_NoDoubleDecoding(t *testing.T) {
	// Content with a percent-encoded percent sign: %2520 → single decode → %20
	content := `
		const apiUrl = "/api/v1/search?q=%2520test";
		fetch("/api/v2/items");
	`
	matches := ExtractJSURLsEnhanced(content)

	// Check that %2520 was decoded once to %20, not twice to a space
	for _, m := range matches {
		assert.NotContains(t, m.URL, "q= test",
			"URL should not be double-decoded: %q", m.URL)
	}
}

// --- Regression: R5 — IsSimilar handles zero-value responses ---

func TestIsSimilar_BothZeroValues(t *testing.T) {
	a := ResponseFingerprint{
		StatusCode:    200,
		ContentLength: 0,
		WordCount:     0,
		LineCount:     0,
		ContentType:   "text/html",
	}
	b := ResponseFingerprint{
		StatusCode:    200,
		ContentLength: 0,
		WordCount:     0,
		LineCount:     0,
		ContentType:   "text/html",
	}

	// Two zero-value responses with same status should be considered similar
	assert.True(t, a.IsSimilar(b, 0.7), "two zero-value responses should be similar")
}

func TestIsSimilar_OneZeroOneNonZero(t *testing.T) {
	a := ResponseFingerprint{
		StatusCode:    200,
		ContentLength: 1000,
		WordCount:     50,
		LineCount:     10,
		ContentType:   "text/html",
	}
	b := ResponseFingerprint{
		StatusCode:    200,
		ContentLength: 0,
		WordCount:     0,
		LineCount:     0,
		ContentType:   "text/html",
	}

	assert.False(t, a.IsSimilar(b, 0.7), "zero vs non-zero should not be similar")
}

func TestIsSimilar_DifferentStatus(t *testing.T) {
	a := ResponseFingerprint{
		StatusCode:    200,
		ContentLength: 1000,
		WordCount:     50,
		LineCount:     10,
		ContentType:   "text/html",
	}
	b := ResponseFingerprint{
		StatusCode:    403,
		ContentLength: 1000,
		WordCount:     50,
		LineCount:     10,
		ContentType:   "text/html",
	}

	assert.False(t, a.IsSimilar(b, 0.7), "different status codes should not be similar")
}
