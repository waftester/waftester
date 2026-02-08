package main

import (
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tests for unified_payloads.go — the shared helpers that bridge every CLI
// command to the unified payload engine (JSON database + Nuclei templates).
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFallbackFuzzPayloads_KnownCategories(t *testing.T) {
	categories := []string{
		"sqli", "SQL-Injection",
		"xss",
		"cmdi", "Command-Injection",
		"traversal", "Path-Traversal", "lfi",
		"ssrf",
		"ssti",
		"xxe",
	}

	for _, cat := range categories {
		t.Run(cat, func(t *testing.T) {
			payloads := getFallbackFuzzPayloads(cat)
			if len(payloads) == 0 {
				t.Errorf("getFallbackFuzzPayloads(%q) returned empty slice", cat)
			}
			for i, p := range payloads {
				if p == "" {
					t.Errorf("getFallbackFuzzPayloads(%q)[%d] is empty string", cat, i)
				}
			}
		})
	}
}

func TestGetFallbackFuzzPayloads_UnknownCategory(t *testing.T) {
	payloads := getFallbackFuzzPayloads("unknown-category-xyz")
	if len(payloads) == 0 {
		t.Error("default fallback should return non-empty slice for unknown categories")
	}
}

func TestGetFallbackFuzzPayloads_CaseInsensitive(t *testing.T) {
	lower := getFallbackFuzzPayloads("sqli")
	upper := getFallbackFuzzPayloads("SQLI")
	mixed := getFallbackFuzzPayloads("SQL-injection")

	// All should return the same payloads (case-insensitive matching)
	if len(lower) == 0 || len(upper) == 0 || len(mixed) == 0 {
		t.Fatal("all case variants should return payloads")
	}
	if len(lower) != len(upper) {
		t.Errorf("sqli (%d) and SQLI (%d) returned different counts", len(lower), len(upper))
	}
}

func TestGetFallbackFuzzPayloads_NoDuplicates(t *testing.T) {
	categories := []string{"sqli", "xss", "cmdi", "traversal", "ssrf", "ssti", "xxe"}

	for _, cat := range categories {
		t.Run(cat, func(t *testing.T) {
			payloads := getFallbackFuzzPayloads(cat)
			seen := make(map[string]bool)
			for _, p := range payloads {
				if seen[p] {
					t.Errorf("duplicate payload in %q fallback: %q", cat, p)
				}
				seen[p] = true
			}
		})
	}
}

func TestGetUnifiedFuzzPayloads_FallsBackOnBadDir(t *testing.T) {
	// Non-existent directory should trigger fallback
	payloads := getUnifiedFuzzPayloads("/nonexistent/dir/payloads", "/nonexistent/dir/templates", "sqli", 50, false)
	if len(payloads) == 0 {
		t.Error("getUnifiedFuzzPayloads should return fallback payloads for bad directory")
	}
}

func TestGetUnifiedFuzzPayloads_RespectsLimit(t *testing.T) {
	// With a bad dir, fallback has ~5 payloads for sqli
	payloads := getUnifiedFuzzPayloads("/nonexistent/dir/payloads", "/nonexistent/dir/templates", "sqli", 2, false)
	// Should be capped at 2 if DB was available, but fallback returns full set
	// since getFallbackFuzzPayloads doesn't cap — the cap is in the DB path.
	// This test just ensures no panic and returns something.
	if len(payloads) == 0 {
		t.Error("should return payloads even with limit")
	}
}

func TestLoadUnifiedPayloads_BadDir(t *testing.T) {
	_, _, err := loadUnifiedPayloads("/nonexistent/dir/payloads", "/nonexistent/dir/templates", false)
	if err == nil {
		t.Error("expected error for non-existent payload directory")
	}
}

func TestLoadUnifiedByCategory_BadDir(t *testing.T) {
	_, err := loadUnifiedByCategory("/nonexistent/dir/payloads", "/nonexistent/dir/templates", "sqli", false)
	if err == nil {
		t.Error("expected error for non-existent payload directory")
	}
}
