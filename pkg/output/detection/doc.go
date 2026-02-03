// Package detection provides unified detection statistics output formatting.
//
// This package centralizes all detection stats display logic, ensuring consistent
// output across console, JSON, Markdown, and SARIF formats. It includes contract
// tests that catch missing implementations when new stats fields are added.
//
// Basic usage:
//
//	stats := detection.FromDetector()
//	if stats.HasData() {
//	    stats.PrintConsole()
//	}
//
// For JSON output:
//
//	jsonMap := stats.ToJSON()
//
// For custom output:
//
//	var buf bytes.Buffer
//	stats.WriteTo(&buf, detection.FormatMarkdown)
//
// Testing with mock data:
//
//	stats := detection.FromMap(map[string]int{
//	    "connmon_total_drops": 5,
//	    "silentban_total_bans": 2,
//	})
package detection
