// Package scanner defines interfaces for pluggable vulnerability scanners.
//
// The Scanner interface abstracts over the 39+ attack packages (sqli, xss,
// cmdi, etc.) so the CLI dispatch layer doesn't need to import each one
// directly. Each attack package can implement ScannerFactory to register
// itself with a Dispatcher.
//
// This package is the consumer-side interface layer — it defines contracts
// that the CLI and orchestration code depend on, while concrete implementations
// live in their respective packages.
package scanner

import (
	"context"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/finding"
)

// Vulnerability is an alias for finding.Vulnerability, the canonical
// representation of a security finding. Scanner implementations convert
// their package-specific vulnerability types into this common format.
type Vulnerability = finding.Vulnerability

// Result holds the output of a single scanner execution.
type Result struct {
	// Category is the scanner name (e.g., "sqli", "xss", "cmdi").
	Category string `json:"category"`

	// Vulnerabilities found by this scanner.
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`

	// RawResult holds the package-specific result for serialization.
	// This preserves the full typed result for JSON output while
	// allowing the dispatcher to work with the unified Vulnerability slice.
	RawResult any `json:"raw_result,omitempty"`

	// Error is non-nil if the scanner failed.
	Error error `json:"-"`
}

// ScanFunc is the signature for a scanner execution function.
// Each attack package provides a ScanFunc that creates its tester,
// runs the scan, and converts results to the unified format.
type ScanFunc func(ctx context.Context, target string, cfg *attackconfig.Base) *Result

// Dispatcher manages scanner registration and concurrent execution.
type Dispatcher struct {
	scanners map[string]ScanFunc
	order    []string // preserves registration order for deterministic execution
}

// NewDispatcher creates a new scanner dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		scanners: make(map[string]ScanFunc),
	}
}

// Register adds a named scanner to the dispatcher.
// Scanners are executed in registration order.
func (d *Dispatcher) Register(name string, fn ScanFunc) {
	if _, exists := d.scanners[name]; !exists {
		d.order = append(d.order, name)
	}
	d.scanners[name] = fn
}

// Names returns all registered scanner names in registration order.
func (d *Dispatcher) Names() []string {
	out := make([]string, len(d.order))
	copy(out, d.order)
	return out
}

// Get returns the ScanFunc for the given scanner name, or nil if not registered.
func (d *Dispatcher) Get(name string) ScanFunc {
	return d.scanners[name]
}

// Count returns the number of registered scanners.
func (d *Dispatcher) Count() int {
	return len(d.scanners)
}

// Has returns true if a scanner with the given name is registered.
func (d *Dispatcher) Has(name string) bool {
	_, ok := d.scanners[name]
	return ok
}
