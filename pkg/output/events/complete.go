package events

// CompleteEvent is emitted when a scan finishes.
// It indicates the final status and exit code of the scan,
// with an optional reference to the summary for detailed results.
type CompleteEvent struct {
	BaseEvent
	Success    bool          `json:"success"`
	ExitCode   int           `json:"exit_code"`
	ExitReason string        `json:"exit_reason"`
	Summary    *SummaryEvent `json:"summary,omitempty"`
}
