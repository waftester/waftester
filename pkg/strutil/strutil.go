// Package strutil provides shared string utilities for the WAFtester codebase.
package strutil

import (
	"strings"
	"unicode/utf8"
)

// Truncate returns s cut to maxLen runes. If truncated, a "..." suffix
// is appended (included in maxLen). Returns s unchanged if
// utf8.RuneCountInString(s) <= maxLen.
// Safe for maxLen <= 0 (returns empty string).
// This function is rune-aware and never produces invalid UTF-8.
func Truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runeCount := utf8.RuneCountInString(s)
	if runeCount <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string([]rune(s)[:maxLen])
	}
	return string([]rune(s)[:maxLen-3]) + "..."
}

// SplitTrimmed splits s by sep, trims whitespace from each element,
// and returns only non-empty results. Useful for parsing comma-separated
// lists from CLI flags and config values.
func SplitTrimmed(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
