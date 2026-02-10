package config

import "errors"

// Sentinel errors for configuration failure modes.
// Callers should use errors.Is() to check for these.
var (
	// ErrInvalidConfig indicates the configuration is syntactically
	// or semantically invalid (bad YAML, conflicting options, etc.).
	ErrInvalidConfig = errors.New("config: invalid configuration")

	// ErrMissingRequired indicates a required configuration field
	// was not provided.
	ErrMissingRequired = errors.New("config: missing required field")
)
