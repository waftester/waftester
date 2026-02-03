package detection

// RequiredStatsFields lists all fields that MUST appear in every output format.
// Contract tests use this to verify completeness - if a field is added here,
// tests will fail until all output formats include it.
var RequiredStatsFields = []string{
	"drops_detected",
	"bans_detected",
	"hosts_skipped",
}

// RequiredJSONKeys lists the exact JSON keys that must appear in JSON output.
var RequiredJSONKeys = []string{
	"drops_detected",
	"bans_detected",
	"hosts_skipped",
}

// RequiredConsoleLabels lists labels that must appear in console output.
var RequiredConsoleLabels = []string{
	"Connection Drops",
	"Silent Bans",
	"Hosts Skipped",
}

// RequiredMarkdownLabels lists labels that must appear in markdown output.
// These may differ from console labels due to formatting.
var RequiredMarkdownLabels = []string{
	"Connection Drops",
	"Silent Bans",
	"Hosts Skipped",
}
