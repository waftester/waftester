package discovery

import (
	"strings"
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

// ExtractJSURLsEnhanced must decode JS content exactly once.
// The R11 fix calls findLinksInJSDecoded (skip decode) instead of
// FindLinksInJS (which decodes again). Without the fix, %2520 becomes
// a space (double decoded) instead of %20 (single decoded).

func TestExtractJSURLsEnhanced_NoDoubleDecoding(t *testing.T) {
	// %2520 = percent-encoded "%20". Single decode → %20. Double decode → space.
	content := `const apiUrl = "/api/v1/search?q=%2520test";`
	matches := ExtractJSURLsEnhanced(content)

	found := false
	for _, m := range matches {
		if strings.Contains(m.URL, "search") {
			found = true
			// Must contain %20 (single decode of %2520)
			assert.Contains(t, m.URL, "q=%20test",
				"single decode should produce %%20, got %q", m.URL)
			// Must NOT contain a literal space (that would mean double decode)
			assert.NotContains(t, m.URL, "q= test",
				"double decode would produce a space, got %q", m.URL)
		}
	}
	assert.True(t, found, "expected to find the search URL in %v", matches)
}

// --- Regression: R5 — IsSimilar handles zero-value responses ---
// The R5 fix added explicit zero-value branches:
//   if f.ContentLength == 0 && other.ContentLength == 0 { score += 0.4 }
// Without these, two empty responses would score 0 (below any threshold).

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

	// Without the fix: score = 0.0, below threshold → false (BUG)
	// With the fix: score = 0.4 + 0.3 + 0.2 = ~0.9 → true
	assert.True(t, a.IsSimilar(b, 0.7), "two zero-value responses must be similar")
	assert.True(t, a.IsSimilar(b, 0.89), "two zero-value responses score ~0.9")
	// Without the fix these would all fail: score would be 0.0
	assert.True(t, a.IsSimilar(b, 0.5), "zero-zero must pass 0.5 threshold")
}

func TestIsSimilar_BothZeroContentLength_DifferentWordCount(t *testing.T) {
	a := ResponseFingerprint{
		StatusCode:    200,
		ContentLength: 0,
		WordCount:     50,
		LineCount:     10,
		ContentType:   "text/html",
	}
	b := ResponseFingerprint{
		StatusCode:    200,
		ContentLength: 0,
		WordCount:     500,
		LineCount:     100,
		ContentType:   "text/html",
	}

	// ContentLength both 0 → +0.4, but word/line counts differ by >10% → no bonus
	// Score = 0.4, below 0.7 threshold
	assert.False(t, a.IsSimilar(b, 0.7),
		"zero content-length but very different word/line counts should not be similar")
}

func TestIsSimilar_ScoreArithmetic(t *testing.T) {
	// Both have matching content-length (+0.4), word count (+0.3),
	// line count (+0.2), but no title hash (+0). Score = 0.9.
	a := ResponseFingerprint{
		StatusCode:    200,
		ContentLength: 1000,
		WordCount:     100,
		LineCount:     20,
		ContentType:   "text/html",
	}
	b := ResponseFingerprint{
		StatusCode:    200,
		ContentLength: 1050, // within 10% of 1000
		WordCount:     105,  // within 10% of 100
		LineCount:     21,   // within 10% of 20
		ContentType:   "text/html",
	}

	assert.True(t, a.IsSimilar(b, 0.7), "score ~0.9 should pass 0.7 threshold")
	assert.True(t, a.IsSimilar(b, 0.89), "score ~0.9 should pass 0.89 threshold")
	assert.False(t, a.IsSimilar(b, 0.95), "score ~0.9 should fail 0.95 threshold")
}

func TestIsSimilar_DifferentStatusAlwaysFalse(t *testing.T) {
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

	assert.False(t, a.IsSimilar(b, 0.0),
		"different status codes must fail even at threshold 0")
}
