package logcorrelation

import (
	"fmt"
)

// VerificationResult holds the result of rule verification
type VerificationResult struct {
	Marker                     string // Correlation marker used
	TriggeredRules             []uint // All rules that triggered
	ExpectedRules              []uint // Rules expected to trigger
	UnexpectedRules            []uint // Rules expected NOT to trigger
	MissingExpectedRules       []uint // Expected rules that didn't trigger
	UnexpectedRulesTriggered   []uint // Unexpected rules that did trigger
	ExpectedRulesMatched       bool   // All expected rules triggered
	NoUnexpectedRulesTriggered bool   // No unexpected rules triggered
	Success                    bool   // Overall verification success
	Messages                   []string
}

// Correlator correlates HTTP requests with WAF log entries
type Correlator struct {
	parser       LogParser
	markerHeader string
}

// NewCorrelator creates a new correlator
func NewCorrelator(logFile, markerHeader string) (*Correlator, error) {
	parser, err := NewModSecParser(logFile)
	if err != nil {
		return nil, err
	}

	if markerHeader == "" {
		markerHeader = MarkerHeader
	}

	return &Correlator{
		parser:       parser,
		markerHeader: markerHeader,
	}, nil
}

// NewCorrelatorWithParser creates a correlator with a custom parser
func NewCorrelatorWithParser(parser LogParser, markerHeader string) *Correlator {
	if markerHeader == "" {
		markerHeader = MarkerHeader
	}
	return &Correlator{
		parser:       parser,
		markerHeader: markerHeader,
	}
}

// Verify checks if expected rules triggered and unexpected rules didn't
func (c *Correlator) Verify(marker string, expectRules, noExpectRules []uint) (*VerificationResult, error) {
	entries, err := c.parser.FindByMarker(marker)
	if err != nil {
		return nil, fmt.Errorf("finding log entries: %w", err)
	}

	// Collect all triggered rules across entries
	triggeredMap := make(map[uint]bool)
	var messages []string
	for _, entry := range entries {
		for _, ruleID := range entry.TriggeredRules {
			triggeredMap[ruleID] = true
		}
		messages = append(messages, entry.Messages...)
	}

	triggered := make([]uint, 0, len(triggeredMap))
	for id := range triggeredMap {
		triggered = append(triggered, id)
	}

	result := &VerificationResult{
		Marker:          marker,
		TriggeredRules:  triggered,
		ExpectedRules:   expectRules,
		UnexpectedRules: noExpectRules,
		Messages:        messages,
	}

	// Check expected rules
	result.ExpectedRulesMatched = true
	for _, expected := range expectRules {
		if !triggeredMap[expected] {
			result.MissingExpectedRules = append(result.MissingExpectedRules, expected)
			result.ExpectedRulesMatched = false
		}
	}

	// Check unexpected rules
	result.NoUnexpectedRulesTriggered = true
	for _, unexpected := range noExpectRules {
		if triggeredMap[unexpected] {
			result.UnexpectedRulesTriggered = append(result.UnexpectedRulesTriggered, unexpected)
			result.NoUnexpectedRulesTriggered = false
		}
	}

	// Overall success
	result.Success = result.ExpectedRulesMatched && result.NoUnexpectedRulesTriggered

	return result, nil
}

// VerifyBlocked checks if the request was blocked (any rule triggered)
func (c *Correlator) VerifyBlocked(marker string) (*VerificationResult, error) {
	entries, err := c.parser.FindByMarker(marker)
	if err != nil {
		return nil, fmt.Errorf("finding log entries: %w", err)
	}

	// Collect all triggered rules
	triggeredMap := make(map[uint]bool)
	var messages []string
	for _, entry := range entries {
		for _, ruleID := range entry.TriggeredRules {
			triggeredMap[ruleID] = true
		}
		messages = append(messages, entry.Messages...)
	}

	triggered := make([]uint, 0, len(triggeredMap))
	for id := range triggeredMap {
		triggered = append(triggered, id)
	}

	result := &VerificationResult{
		Marker:         marker,
		TriggeredRules: triggered,
		Messages:       messages,
		Success:        len(triggered) > 0,
	}

	return result, nil
}

// GetMarkerHeader returns the header name used for correlation
func (c *Correlator) GetMarkerHeader() string {
	return c.markerHeader
}

// Close releases resources
func (c *Correlator) Close() error {
	return c.parser.Close()
}

// TestResult represents the result of a correlated test
type TestResult struct {
	TestID         string
	Marker         string
	Blocked        bool
	StatusCode     int
	TriggeredRules []uint
	ExpectedRules  []uint
	Passed         bool
	Error          error
}

// BatchVerify verifies multiple markers at once
func (c *Correlator) BatchVerify(tests []struct {
	Marker      string
	ExpectRules []uint
}) ([]*VerificationResult, error) {
	results := make([]*VerificationResult, len(tests))
	for i, test := range tests {
		result, err := c.Verify(test.Marker, test.ExpectRules, nil)
		if err != nil {
			return nil, fmt.Errorf("verifying test %d: %w", i, err)
		}
		results[i] = result
	}
	return results, nil
}
