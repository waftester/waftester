// Package strutil provides shared string utilities for the WAFtester codebase.
package strutil

// Truncate returns s cut to maxLen characters. If truncated, a "..." suffix
// is appended (included in maxLen). Returns s unchanged if len(s) <= maxLen.
// Safe for maxLen <= 0 (returns empty string).
func Truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
