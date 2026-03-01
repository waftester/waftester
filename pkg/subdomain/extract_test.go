package subdomain

import (
	"sort"
	"strings"
	"testing"
)

func TestExtract_WithScope(t *testing.T) {
	content := `
		https://api.target.com/v1
		https://cdn.target.com/assets
		https://analytics.google.com/track
		https://ads.facebook.com/pixel
		https://sub.deep.target.com/api
	`

	got := Extract(content, "target.com")
	for _, s := range got {
		if !strings.HasSuffix(s, ".target.com") && s != "target.com" {
			t.Errorf("unexpected domain in scoped result: %q", s)
		}
	}
	if len(got) < 2 {
		t.Errorf("expected at least 2 scoped subdomains, got %d: %v", len(got), got)
	}
}

func TestExtract_WithoutScope(t *testing.T) {
	content := `
		https://api.target.com/v1
		https://analytics.google.com/track
	`

	scoped := Extract(content, "target.com")
	unscoped := Extract(content, "")

	if len(unscoped) <= len(scoped) {
		t.Errorf("unscoped (%d) should find more domains than scoped (%d)", len(unscoped), len(scoped))
	}
}

func TestExtract_Empty(t *testing.T) {
	if got := Extract("", "example.com"); len(got) != 0 {
		t.Errorf("expected nil/empty, got %v", got)
	}
}

func TestExtract_Sorted(t *testing.T) {
	content := `https://z.example.com https://a.example.com https://m.example.com`
	got := Extract(content, "example.com")
	if !sort.StringsAreSorted(got) {
		t.Errorf("results not sorted: %v", got)
	}
}

func TestExtract_Dedup(t *testing.T) {
	content := `https://api.example.com https://api.example.com https://API.Example.Com`
	got := Extract(content, "example.com")
	if len(got) != 1 {
		t.Errorf("expected 1 deduped result, got %d: %v", len(got), got)
	}
}

func TestExtractStrict_ReturnsSubdomainsOnly(t *testing.T) {
	content := `
		<a href="https://api.example.com/v1">API</a>
		<a href="https://staging.example.com">Staging</a>
		<a href="https://example.com">Home</a>
		<a href="https://not-example.com">Other</a>
	`

	got := ExtractStrict(content, "example.com")

	want := map[string]bool{
		"api.example.com":     true,
		"staging.example.com": true,
	}
	for _, s := range got {
		delete(want, s)
	}
	for missing := range want {
		t.Errorf("missing subdomain: %s", missing)
	}

	// Must NOT include base domain
	for _, s := range got {
		if s == "example.com" {
			t.Error("should not include base domain itself")
		}
	}

	// Must NOT include unrelated domains
	for _, s := range got {
		if !strings.HasSuffix(s, ".example.com") {
			t.Errorf("unexpected domain: %s", s)
		}
	}
}

func TestExtractStrict_EmptyBaseDomain(t *testing.T) {
	if got := ExtractStrict("some content", ""); got != nil {
		t.Errorf("expected nil for empty baseDomain, got %v", got)
	}
}

func TestExtractStrict_NoMatches(t *testing.T) {
	got := ExtractStrict("no subdomains here", "example.com")
	if len(got) != 0 {
		t.Errorf("expected 0, got %d: %v", len(got), got)
	}
}
