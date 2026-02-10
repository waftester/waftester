package attackconfig

import (
	"net/http"
	"time"
)

// Base contains configuration fields shared across all
// attack and testing packages. Embed it in package-specific
// Config structs to inherit common functionality.
type Base struct {
	Timeout     time.Duration `json:"timeout,omitempty"`
	UserAgent   string        `json:"user_agent,omitempty"`
	Client      *http.Client  `json:"-"`
	MaxPayloads int           `json:"max_payloads,omitempty"`
	MaxParams   int           `json:"max_params,omitempty"`
	Concurrency int           `json:"concurrency,omitempty"`
}

// DefaultBase returns a Base with production defaults.
func DefaultBase() Base {
	return Base{
		Timeout:     15 * time.Second,
		Concurrency: 10,
	}
}

// Validate fills zero-value fields with defaults.
// Call this in NewTester constructors to ensure sane values.
func (b *Base) Validate() {
	if b.Timeout <= 0 {
		b.Timeout = 15 * time.Second
	}
	if b.Concurrency <= 0 {
		b.Concurrency = 10
	}
}
