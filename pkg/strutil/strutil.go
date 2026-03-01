// Package strutil provides shared string utilities for the WAFtester codebase.
package strutil

import (
	"sort"
	"strconv"
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

// Unique returns a new slice with duplicate elements removed, preserving
// order of first appearance. Works with any comparable type.
func Unique[T comparable](s []T) []T {
	if len(s) == 0 {
		return nil
	}
	seen := make(map[T]bool, len(s))
	result := make([]T, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
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

// Atoi converts a string to int, returning 0 if parsing fails.
// Useful for best-effort numeric parsing in CLI and config values.
func Atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// SanitizeFilename replaces characters unsafe for filenames with underscores
// and limits the result to maxLen runes. If maxLen <= 0, defaults to 100.
func SanitizeFilename(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 100
	}
	replacer := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "?", "_",
		"&", "_", "=", "_", "#", "_", " ", "_",
		"<", "_", ">", "_", "|", "_", "\"", "_",
		"*", "_",
	)
	s = replacer.Replace(s)
	if len([]rune(s)) > maxLen {
		s = string([]rune(s)[:maxLen])
	}
	return s
}

// SortedMapKeys returns the keys of a map sorted in ascending order.
// Uses generics to accept maps with any value type, including named map types
// like http.Header and url.Values.
func SortedMapKeys[M ~map[string]V, V any](m M) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
