// Package placeholder provides template placeholder processing for WAF testing.
package placeholder

import (
	"regexp"
	"strings"
)

// Value represents a placeholder value.
type Value struct {
	Name    string `json:"name" yaml:"name"`
	Value   string `json:"value" yaml:"value"`
	Default string `json:"default,omitempty" yaml:"default,omitempty"`
}

// Placeholder represents a placeholder definition.
type Placeholder struct {
	Name        string `json:"name" yaml:"name"`
	Pattern     string `json:"pattern" yaml:"pattern"`
	Description string `json:"description" yaml:"description"`
	Default     string `json:"default,omitempty" yaml:"default,omitempty"`
	Required    bool   `json:"required" yaml:"required"`
}

// Config holds placeholder engine configuration.
type Config struct {
	Prefix     string `json:"prefix" yaml:"prefix"`
	Suffix     string `json:"suffix" yaml:"suffix"`
	PayloadKey string `json:"payload_key" yaml:"payload_key"`
}

// DefaultConfig returns default configuration.
func DefaultConfig() *Config {
	return &Config{
		Prefix:     "{{",
		Suffix:     "}}",
		PayloadKey: "PAYLOAD",
	}
}

// Engine processes placeholder templates.
type Engine struct {
	config       *Config
	placeholders map[string]*Placeholder
	regex        *regexp.Regexp
}

// NewEngine creates a new placeholder engine.
func NewEngine(config *Config) *Engine {
	if config == nil {
		config = DefaultConfig()
	}

	pattern := regexp.QuoteMeta(config.Prefix) + `([A-Z_][A-Z0-9_]*)` + regexp.QuoteMeta(config.Suffix)
	re := regexp.MustCompile(pattern)

	e := &Engine{
		config:       config,
		placeholders: make(map[string]*Placeholder),
		regex:        re,
	}

	e.registerBuiltins()
	return e
}

// registerBuiltins registers built-in placeholders.
func (e *Engine) registerBuiltins() {
	builtins := []*Placeholder{
		{Name: "PAYLOAD", Description: "Main attack payload", Required: true},
		{Name: "TARGET", Description: "Target URL", Required: true},
		{Name: "HOST", Description: "Target hostname"},
		{Name: "PORT", Description: "Target port", Default: "80"},
		{Name: "PATH", Description: "Request path", Default: "/"},
		{Name: "METHOD", Description: "HTTP method", Default: "GET"},
		{Name: "RANDOM", Description: "Random string"},
		{Name: "TIMESTAMP", Description: "Current timestamp"},
		{Name: "USER", Description: "Username for auth"},
		{Name: "PASS", Description: "Password for auth"},
		{Name: "TOKEN", Description: "Auth token"},
		{Name: "SESSION", Description: "Session ID"},
		{Name: "COOKIE", Description: "Cookie value"},
		{Name: "HEADER", Description: "Custom header value"},
		{Name: "BODY", Description: "Request body"},
		{Name: "QUERY", Description: "Query string"},
		{Name: "PARAM", Description: "Parameter name"},
		{Name: "VALUE", Description: "Parameter value"},
	}

	for _, p := range builtins {
		e.placeholders[p.Name] = p
	}
}

// Register adds a custom placeholder.
func (e *Engine) Register(p *Placeholder) {
	e.placeholders[p.Name] = p
}

// Get returns a placeholder by name.
func (e *Engine) Get(name string) (*Placeholder, bool) {
	p, ok := e.placeholders[name]
	return p, ok
}

// List returns all registered placeholders.
func (e *Engine) List() []*Placeholder {
	var result []*Placeholder
	for _, p := range e.placeholders {
		result = append(result, p)
	}
	return result
}

// Process replaces placeholders in template with values.
func (e *Engine) Process(template string, values []Value) string {
	result := template

	valueMap := make(map[string]string)
	for _, v := range values {
		valueMap[v.Name] = v.Value
	}

	result = e.regex.ReplaceAllStringFunc(result, func(match string) string {
		name := e.regex.FindStringSubmatch(match)[1]
		if val, ok := valueMap[name]; ok {
			return val
		}
		if p, ok := e.placeholders[name]; ok && p.Default != "" {
			return p.Default
		}
		return match
	})

	return result
}

// Inject injects a payload into template's PAYLOAD placeholder.
func (e *Engine) Inject(template, payload string) string {
	return e.Process(template, []Value{{Name: e.config.PayloadKey, Value: payload}})
}

// Extract extracts placeholder names from template.
func (e *Engine) Extract(template string) []string {
	matches := e.regex.FindAllStringSubmatch(template, -1)
	var names []string
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] {
			names = append(names, match[1])
			seen[match[1]] = true
		}
	}

	return names
}

// Validate checks if template has all required placeholders filled.
func (e *Engine) Validate(template string, values []Value) []string {
	extracted := e.Extract(template)
	valueMap := make(map[string]bool)
	for _, v := range values {
		valueMap[v.Name] = true
	}

	var missing []string
	for _, name := range extracted {
		if p, ok := e.placeholders[name]; ok && p.Required {
			if !valueMap[name] {
				missing = append(missing, name)
			}
		}
	}

	return missing
}

// HasPlaceholders checks if string contains placeholders.
func (e *Engine) HasPlaceholders(s string) bool {
	return e.regex.MatchString(s)
}

// Count returns number of placeholders in string.
func (e *Engine) Count(s string) int {
	return len(e.regex.FindAllString(s, -1))
}

// Builder builds templates with placeholders.
type Builder struct {
	engine *Engine
	parts  []string
}

// NewBuilder creates a new template builder.
func NewBuilder(engine *Engine) *Builder {
	if engine == nil {
		engine = NewEngine(nil)
	}
	return &Builder{engine: engine}
}

// Text adds literal text.
func (b *Builder) Text(s string) *Builder {
	b.parts = append(b.parts, s)
	return b
}

// Placeholder adds a placeholder.
func (b *Builder) Placeholder(name string) *Builder {
	ph := b.engine.config.Prefix + name + b.engine.config.Suffix
	b.parts = append(b.parts, ph)
	return b
}

// Payload adds the payload placeholder.
func (b *Builder) Payload() *Builder {
	return b.Placeholder(b.engine.config.PayloadKey)
}

// Build returns the completed template.
func (b *Builder) Build() string {
	return strings.Join(b.parts, "")
}

// Reset clears the builder.
func (b *Builder) Reset() *Builder {
	b.parts = nil
	return b
}
