// Package logcorrelation provides WAF log parsing and correlation capabilities.
// It supports ModSecurity audit logs and correlates test requests with triggered rules.
package logcorrelation

import (
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// LogEntry represents a parsed WAF log entry
type LogEntry struct {
	Timestamp      time.Time // When the log entry was recorded
	Marker         string    // Correlation marker from request
	TriggeredRules []uint    // Rule IDs that fired
	Messages       []string  // Rule messages
	Severity       string    // Highest severity
	RawContent     string    // Original log content
	ClientIP       string    // Client IP address
	RequestURI     string    // Request URI
	RuleFile       string    // Rule file that matched
}

// LogParser defines the interface for WAF log parsers
type LogParser interface {
	// FindByMarker finds log entries matching the correlation marker
	FindByMarker(marker string) ([]LogEntry, error)
	// FindByTimeRange finds entries in a time window
	FindByTimeRange(start, end time.Time) ([]LogEntry, error)
	// Tail watches for new entries
	Tail() <-chan LogEntry
	// Close releases resources
	Close() error
}

// GenerateMarker creates a unique correlation marker
func GenerateMarker() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

// MarkerHeader is the default header name for correlation markers
const MarkerHeader = "X-WAF-Test-Marker"

// ruleIDRegex matches [id "NNNNNN"] in ModSecurity logs
var ruleIDRegex = regexp.MustCompile(`\[id\s*"?(\d+)"?\]`)

// msgRegex matches [msg "..."] in ModSecurity logs
var msgRegex = regexp.MustCompile(`\[msg\s*"([^"]+)"\]`)

// fileRegex matches [file "..."] in ModSecurity logs
var fileRegex = regexp.MustCompile(`\[file\s*"([^"]+)"\]`)

// severityRegex matches [severity "..."] in ModSecurity logs
var severityRegex = regexp.MustCompile(`\[severity\s*"([^"]+)"\]`)
