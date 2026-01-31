// Package placeholders provides payload injection points for WAF testing.
// It supports 15+ injection locations including URL, headers, body, and more.
package placeholders

import (
	"fmt"
	"net/http"
	"strings"
)

// PlaceholderConfig holds optional configuration for placeholder
type PlaceholderConfig struct {
	ParamName   string            // Custom parameter name
	HeaderName  string            // Custom header name
	CookieName  string            // Custom cookie name
	FieldName   string            // Custom field name for body
	ContentType string            // Custom content type
	Method      string            // HTTP method override
	Extra       map[string]string // Additional config
}

// Placeholder defines where to inject the payload in HTTP request
type Placeholder interface {
	// Name returns the placeholder identifier
	Name() string
	// Description returns human-readable description
	Description() string
	// Apply creates an HTTP request with payload injected
	Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error)
}

// Registry of available placeholders
var registry = make(map[string]Placeholder)

// Register adds a placeholder to the registry
func Register(p Placeholder) {
	registry[strings.ToLower(p.Name())] = p
}

// Get retrieves a placeholder by name
func Get(name string) Placeholder {
	return registry[strings.ToLower(name)]
}

// List returns all registered placeholder names
func List() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// All returns all registered placeholders
func All() []Placeholder {
	placeholders := make([]Placeholder, 0, len(registry))
	for _, p := range registry {
		placeholders = append(placeholders, p)
	}
	return placeholders
}

// DefaultConfig returns a default configuration
func DefaultConfig() *PlaceholderConfig {
	return &PlaceholderConfig{
		ParamName:  "param",
		HeaderName: "X-Test-Payload",
		CookieName: "test",
		FieldName:  "data",
	}
}

// MergeConfig merges custom config with defaults
func MergeConfig(custom *PlaceholderConfig) *PlaceholderConfig {
	if custom == nil {
		return DefaultConfig()
	}
	result := DefaultConfig()
	if custom.ParamName != "" {
		result.ParamName = custom.ParamName
	}
	if custom.HeaderName != "" {
		result.HeaderName = custom.HeaderName
	}
	if custom.CookieName != "" {
		result.CookieName = custom.CookieName
	}
	if custom.FieldName != "" {
		result.FieldName = custom.FieldName
	}
	if custom.ContentType != "" {
		result.ContentType = custom.ContentType
	}
	if custom.Method != "" {
		result.Method = custom.Method
	}
	if custom.Extra != nil {
		result.Extra = custom.Extra
	}
	return result
}

// ApplyAll applies payload using all placeholders
func ApplyAll(targetURL, payload string, config *PlaceholderConfig) ([]*http.Request, error) {
	var requests []*http.Request
	for _, p := range registry {
		req, err := p.Apply(targetURL, payload, config)
		if err != nil {
			return nil, fmt.Errorf("placeholder %s: %w", p.Name(), err)
		}
		requests = append(requests, req)
	}
	return requests, nil
}
