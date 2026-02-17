// Package writers provides output writers for various formats.
package writers

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*SonarQubeWriter)(nil)

// SonarQubeWriter writes events in SonarQube Generic Issue Import format.
// This format is used for importing external security findings into SonarQube.
// Results are buffered and written as a complete document on Close.
// See: https://docs.sonarqube.org/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/
type SonarQubeWriter struct {
	w      io.Writer
	mu     sync.Mutex
	opts   SonarQubeOptions
	issues []sonarQubeIssue
}

// SonarQubeOptions configures the SonarQube writer.
type SonarQubeOptions struct {
	// ToolName is the engine ID (default: waftester).
	ToolName string

	// ToolVersion is the version of the tool.
	ToolVersion string
}

// SonarQube Generic Issue Import structures.

type sonarQubeDocument struct {
	Issues []sonarQubeIssue `json:"issues"`
}

type sonarQubeIssue struct {
	EngineID        string                   `json:"engineId"`
	RuleID          string                   `json:"ruleId"`
	Severity        string                   `json:"severity"`
	Type            string                   `json:"type"`
	PrimaryLocation sonarQubePrimaryLocation `json:"primaryLocation"`
	EffortMinutes   int                      `json:"effortMinutes"`
}

type sonarQubePrimaryLocation struct {
	Message   string             `json:"message"`
	FilePath  string             `json:"filePath"`
	TextRange sonarQubeTextRange `json:"textRange"`
}

type sonarQubeTextRange struct {
	StartLine int `json:"startLine"`
}

// NewSonarQubeWriter creates a new SonarQube Generic Issue Import writer.
// The writer buffers all results and writes a complete document on Close.
// The writer is safe for concurrent use.
func NewSonarQubeWriter(w io.Writer, opts SonarQubeOptions) *SonarQubeWriter {
	if opts.ToolName == "" {
		opts.ToolName = defaults.ToolName
	}
	return &SonarQubeWriter{
		w:      w,
		opts:   opts,
		issues: make([]sonarQubeIssue, 0),
	}
}

// severityToSonarQube maps WAFtester severity to SonarQube severity.
// Delegates to finding.Severity.ToSonarQube for canonical mapping.
func severityToSonarQube(severity events.Severity) string {
	return severity.ToSonarQube()
}

// Write converts a result event to SonarQube issue format.
// Only bypass and error outcomes are included in the output.
func (sw *SonarQubeWriter) Write(event events.Event) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	re, ok := event.(*events.ResultEvent)
	if !ok {
		return nil // Skip non-result events
	}

	// Only include bypass/error outcomes
	if re.Result.Outcome != events.OutcomeBypass && re.Result.Outcome != events.OutcomeError {
		return nil
	}

	ruleID := re.Test.Category + "-" + re.Test.ID

	issue := sonarQubeIssue{
		EngineID: sw.opts.ToolName,
		RuleID:   ruleID,
		Severity: severityToSonarQube(re.Test.Severity),
		Type:     "VULNERABILITY",
		PrimaryLocation: sonarQubePrimaryLocation{
			Message:  re.Test.Category + " WAF bypass detected",
			FilePath: re.Target.URL,
			TextRange: sonarQubeTextRange{
				StartLine: 1,
			},
		},
		EffortMinutes: 30,
	}

	sw.issues = append(sw.issues, issue)
	return nil
}

// Flush is a no-op for SonarQube writer.
// All results are written as a single document on Close.
func (sw *SonarQubeWriter) Flush() error { return nil }

// Close writes all buffered issues as a complete SonarQube document.
// If the underlying writer implements io.Closer, it will be closed.
func (sw *SonarQubeWriter) Close() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	doc := sonarQubeDocument{
		Issues: sw.issues,
	}

	encoder := json.NewEncoder(sw.w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("sonarqube: encode: %w", err)
	}

	// Close underlying writer if it implements io.Closer
	if closer, ok := sw.w.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// SupportsEvent returns true for result and bypass events.
func (sw *SonarQubeWriter) SupportsEvent(eventType events.EventType) bool {
	switch eventType {
	case events.EventTypeResult, events.EventTypeBypass:
		return true
	default:
		return false
	}
}
