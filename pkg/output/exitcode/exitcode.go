// Package exitcode provides semantic exit codes for CI/CD integration.
// Exit codes communicate scan outcomes to automation pipelines.
//
// Exit codes:
//   - 0: Success (no bypasses detected)
//   - 1: Bypasses detected (configurable)
//   - 2: Too many errors
//   - 3: Invalid configuration
//   - 4: Target unreachable
//   - 5: Scan interrupted
//   - 6: License error (Enterprise)
package exitcode

import (
	"fmt"
	"sync"

	"github.com/waftester/waftester/pkg/output/events"
)

// Code represents a semantic exit code for CI/CD pipelines.
type Code int

const (
	// Success indicates the scan completed with no bypasses detected.
	Success Code = 0
	// Bypasses indicates one or more WAF bypasses were detected.
	Bypasses Code = 1
	// Errors indicates too many errors occurred during scanning.
	Errors Code = 2
	// Configuration indicates invalid configuration was provided.
	Configuration Code = 3
	// Target indicates the target URL was unreachable.
	Target Code = 4
	// Interrupted indicates the scan was interrupted (e.g., SIGINT).
	Interrupted Code = 5
	// License indicates a license error (Enterprise feature).
	License Code = 6
)

// codeStrings maps exit codes to human-readable descriptions.
var codeStrings = map[Code]string{
	Success:       "success",
	Bypasses:      "bypasses_detected",
	Errors:        "too_many_errors",
	Configuration: "invalid_configuration",
	Target:        "target_unreachable",
	Interrupted:   "scan_interrupted",
	License:       "license_error",
}

// codeDescriptions provides detailed descriptions for exit codes.
var codeDescriptions = map[Code]string{
	Success:       "Scan completed successfully with no bypasses detected",
	Bypasses:      "One or more WAF bypasses were detected",
	Errors:        "Scan terminated due to too many errors",
	Configuration: "Invalid configuration provided",
	Target:        "Target URL is unreachable",
	Interrupted:   "Scan was interrupted by user or signal",
	License:       "License validation failed (Enterprise feature)",
}

// Config holds configuration for the exit code manager.
type Config struct {
	// BypassCode is the exit code to return when bypasses are detected.
	// Default: 1
	BypassCode int

	// ExitOnError determines whether to exit with error code on too many errors.
	ExitOnError bool

	// ErrorThreshold is the number of errors that triggers an error exit.
	// Default: 10
	ErrorThreshold int
}

// DefaultConfig returns the default exit code configuration.
func DefaultConfig() Config {
	return Config{
		BypassCode:     1,
		ExitOnError:    true,
		ErrorThreshold: 10,
	}
}

// Manager tracks scan outcomes and determines the appropriate exit code.
type Manager struct {
	cfg      Config
	bypasses int
	errors   int
	mu       sync.Mutex

	// Special state flags
	configError bool
	targetError bool
	interrupted bool
	licenseErr  bool
}

// New creates a new exit code manager with the given configuration.
func New(cfg Config) *Manager {
	// Apply defaults for zero values
	if cfg.BypassCode == 0 {
		cfg.BypassCode = 1
	}
	if cfg.ErrorThreshold == 0 {
		cfg.ErrorThreshold = 10
	}

	return &Manager{
		cfg: cfg,
	}
}

// Record records an outcome from a test result.
func (m *Manager) Record(outcome events.Outcome) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch outcome {
	case events.OutcomeBypass:
		m.bypasses++
	case events.OutcomeError:
		m.errors++
	case events.OutcomeTimeout:
		// Timeouts count as errors for threshold purposes
		m.errors++
	}
}

// RecordBypass increments the bypass counter.
func (m *Manager) RecordBypass() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bypasses++
}

// RecordError increments the error counter.
func (m *Manager) RecordError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors++
}

// SetConfigError marks that a configuration error occurred.
func (m *Manager) SetConfigError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configError = true
}

// SetTargetError marks that the target was unreachable.
func (m *Manager) SetTargetError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.targetError = true
}

// SetInterrupted marks that the scan was interrupted.
func (m *Manager) SetInterrupted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interrupted = true
}

// SetLicenseError marks that a license error occurred.
func (m *Manager) SetLicenseError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.licenseErr = true
}

// ExitCode returns the appropriate exit code based on recorded outcomes.
// The returned string provides a human-readable reason for the code.
//
// Priority order (highest to lowest):
//  1. License error
//  2. Interrupted
//  3. Configuration error
//  4. Target unreachable
//  5. Too many errors (if ExitOnError enabled)
//  6. Bypasses detected
//  7. Success
func (m *Manager) ExitCode() (Code, string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check special states in priority order
	if m.licenseErr {
		return License, codeDescriptions[License]
	}

	if m.interrupted {
		return Interrupted, codeDescriptions[Interrupted]
	}

	if m.configError {
		return Configuration, codeDescriptions[Configuration]
	}

	if m.targetError {
		return Target, codeDescriptions[Target]
	}

	// Check error threshold
	if m.cfg.ExitOnError && m.errors >= m.cfg.ErrorThreshold {
		return Errors, fmt.Sprintf("%s (threshold: %d, actual: %d)",
			codeDescriptions[Errors], m.cfg.ErrorThreshold, m.errors)
	}

	// Check bypasses
	if m.bypasses > 0 {
		return Code(m.cfg.BypassCode), fmt.Sprintf("%s (count: %d)",
			codeDescriptions[Bypasses], m.bypasses)
	}

	return Success, codeDescriptions[Success]
}

// String returns the string representation of an exit code.
func (m *Manager) String(code Code) string {
	if s, ok := codeStrings[code]; ok {
		return s
	}
	return fmt.Sprintf("unknown_code_%d", code)
}

// Stats returns the current bypass and error counts.
func (m *Manager) Stats() (bypasses, errors int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bypasses, m.errors
}

// Reset clears all recorded outcomes and state flags.
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bypasses = 0
	m.errors = 0
	m.configError = false
	m.targetError = false
	m.interrupted = false
	m.licenseErr = false
}

// CodeString returns the string representation of any exit code.
// This is a package-level function for convenience.
func CodeString(code Code) string {
	if s, ok := codeStrings[code]; ok {
		return s
	}
	return fmt.Sprintf("unknown_code_%d", code)
}

// CodeDescription returns a detailed description of an exit code.
func CodeDescription(code Code) string {
	if s, ok := codeDescriptions[code]; ok {
		return s
	}
	return fmt.Sprintf("Unknown exit code: %d", code)
}
