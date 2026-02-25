// Package mutation provides a plugin-based mutation pipeline for WAF testing.
// This architecture matches nuclei-templates / SecLists for maximum coverage.
package mutation

import (
	"fmt"
	"sync"
)

// MutatedPayload represents a payload after transformation
type MutatedPayload struct {
	Original    string   `json:"original"`
	Mutated     string   `json:"mutated"`
	MutatorName string   `json:"mutator_name"`
	Category    string   `json:"category"`
	Chain       []string `json:"chain,omitempty"` // For chained mutations
}

// Mutator is the interface all mutation plugins implement
type Mutator interface {
	// Name returns the unique identifier for this mutator
	Name() string

	// Category returns the type: "encoder", "location", "evasion", "protocol"
	Category() string

	// Description returns human-readable description
	Description() string

	// Mutate transforms a payload into one or more variants
	Mutate(payload string) []MutatedPayload
}

// Registry holds all registered mutators
type Registry struct {
	mu       sync.RWMutex
	mutators map[string]Mutator
	byType   map[string][]Mutator
}

// NewRegistry creates a new mutator registry
func NewRegistry() *Registry {
	return &Registry{
		mutators: make(map[string]Mutator),
		byType:   make(map[string][]Mutator),
	}
}

// Register adds a mutator to the registry
func (r *Registry) Register(m Mutator) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.mutators[m.Name()]; exists {
		return fmt.Errorf("mutator %q already registered", m.Name())
	}

	r.mutators[m.Name()] = m
	r.byType[m.Category()] = append(r.byType[m.Category()], m)
	return nil
}

// Get retrieves a mutator by name
func (r *Registry) Get(name string) (Mutator, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.mutators[name]
	return m, ok
}

// GetByCategory returns all mutators of a specific category
func (r *Registry) GetByCategory(category string) []Mutator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byType[category]
}

// All returns all registered mutators
func (r *Registry) All() []Mutator {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Mutator, 0, len(r.mutators))
	for _, m := range r.mutators {
		result = append(result, m)
	}
	return result
}

// Names returns all registered mutator names
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.mutators))
	for name := range r.mutators {
		names = append(names, name)
	}
	return names
}

// Categories returns all registered categories
func (r *Registry) Categories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	categories := make([]string, 0, len(r.byType))
	for cat := range r.byType {
		categories = append(categories, cat)
	}
	return categories
}

// NamesForCategory returns the names of all mutators in a category.
func (r *Registry) NamesForCategory(category string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	mutators := r.byType[category]
	names := make([]string, len(mutators))
	for i, m := range mutators {
		names[i] = m.Name()
	}
	return names
}

// MutateWithAll applies all mutators to a payload
func (r *Registry) MutateWithAll(payload string) []MutatedPayload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []MutatedPayload
	for _, m := range r.mutators {
		results = append(results, m.Mutate(payload)...)
	}
	return results
}

// MutateWithCategory applies all mutators of a category
func (r *Registry) MutateWithCategory(payload, category string) []MutatedPayload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []MutatedPayload
	for _, m := range r.byType[category] {
		results = append(results, m.Mutate(payload)...)
	}
	return results
}

// MutateWithNames applies specific mutators by name
func (r *Registry) MutateWithNames(payload string, names []string) []MutatedPayload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []MutatedPayload
	for _, name := range names {
		if m, ok := r.mutators[name]; ok {
			results = append(results, m.Mutate(payload)...)
		}
	}
	return results
}

// ChainMutate applies mutators in sequence, each output feeding the next
func (r *Registry) ChainMutate(payload string, names []string) []MutatedPayload {
	if len(names) == 0 {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Start with original payload
	current := []MutatedPayload{{
		Original:    payload,
		Mutated:     payload,
		MutatorName: "raw",
		Category:    "none",
		Chain:       []string{},
	}}

	// Apply each mutator in sequence
	for _, name := range names {
		m, ok := r.mutators[name]
		if !ok {
			continue
		}

		var next []MutatedPayload
		for _, mp := range current {
			mutated := m.Mutate(mp.Mutated)
			for _, result := range mutated {
				result.Original = payload
				result.Chain = append(mp.Chain, m.Name())
				next = append(next, result)
			}
		}
		current = next
	}

	return current
}

// DefaultRegistry is the global registry instance
var DefaultRegistry = NewRegistry()

// Register adds a mutator to the default registry
func Register(m Mutator) error {
	return DefaultRegistry.Register(m)
}

// Pipeline configuration for mutation testing
type PipelineConfig struct {
	// Encoders to apply (empty = all)
	Encoders []string `json:"encoders,omitempty"`

	// Locations to inject payloads (empty = all)
	Locations []string `json:"locations,omitempty"`

	// Evasions to apply (empty = none for speed, "all" for full)
	Evasions []string `json:"evasions,omitempty"`

	// ChainEncodings if true, chains encodings (url then double_url, etc.)
	ChainEncodings bool `json:"chain_encodings,omitempty"`

	// MaxChainDepth limits chaining depth (default 2)
	MaxChainDepth int `json:"max_chain_depth,omitempty"`

	// IncludeRaw includes original unmodified payload
	IncludeRaw bool `json:"include_raw,omitempty"`
}

// DefaultPipelineConfig returns sensible defaults for standard scanning.
// Uses all registered encoders, common locations, no evasions.
func DefaultPipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		Encoders:       DefaultRegistry.NamesForCategory("encoder"),
		Locations:      DefaultRegistry.NamesForCategory("location"),
		Evasions:       []string{}, // None by default for speed
		ChainEncodings: false,
		MaxChainDepth:  2,
		IncludeRaw:     true,
	}
}

// QuickPipelineConfig returns a minimal config for fast scanning.
// URL encoding variants only, single location.
func QuickPipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		Encoders:       []string{"raw", "url", "double_url"},
		Locations:      []string{"query_param"},
		Evasions:       []string{},
		ChainEncodings: false,
		IncludeRaw:     true,
	}
}

// StandardPipelineConfig returns a balanced config for typical scanning.
// Common encoders and locations, no evasions.
func StandardPipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		Encoders:       []string{"raw", "url", "double_url", "html_hex", "unicode"},
		Locations:      []string{"query_param", "post_form", "post_json"},
		Evasions:       []string{},
		ChainEncodings: false,
		IncludeRaw:     true,
	}
}

// BypassPipelineConfig returns a config optimized for WAF bypass testing.
// Includes encoding tricks, multiple injection locations, and evasion techniques.
func BypassPipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		Encoders: []string{
			"raw", "url", "double_url", "triple_url",
			"overlong_utf8", "wide_gbk", "utf7",
			"html_decimal", "html_hex", "mixed",
		},
		Locations: []string{
			"query_param", "post_form", "post_json",
			"header_xforward", "cookie", "path_segment",
		},
		Evasions: []string{
			"case_swap", "sql_comment", "whitespace_alt",
			"null_byte", "hpp", "unicode_normalize",
		},
		ChainEncodings: true,
		MaxChainDepth:  2,
		IncludeRaw:     true,
	}
}

// FullCoveragePipelineConfig returns config for maximum coverage.
// All registered encoders, locations, and evasions with chaining enabled.
func FullCoveragePipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		Encoders:       DefaultRegistry.NamesForCategory("encoder"),
		Locations:      DefaultRegistry.NamesForCategory("location"),
		Evasions:       DefaultRegistry.NamesForCategory("evasion"),
		ChainEncodings: true,
		MaxChainDepth:  3,
		IncludeRaw:     true,
	}
}
