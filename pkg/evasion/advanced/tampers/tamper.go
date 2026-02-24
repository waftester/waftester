// Package tampers provides sqlmap-compatible tamper scripts for WAF bypass.
// Ported from https://github.com/sqlmapproject/sqlmap/tree/master/tamper
// with enhancements for HTTP-level modifications.
//
// Tampers are organized by category:
//   - encoding: Character/string encoding transformations
//   - space: Space replacement techniques
//   - sql: SQL syntax transformations
//   - mysql: MySQL-specific bypasses
//   - mssql: MSSQL-specific bypasses
//   - waf: WAF-specific bypasses (Cloudflare, ModSecurity, etc.)
//   - http: HTTP-level modifications (headers, parameters)
//   - obfuscation: General obfuscation techniques
package tampers

import (
	"net/http"
	"sort"
	"sync"
)

// Category represents the tamper category
type Category string

const (
	CategoryEncoding    Category = "encoding"    // Character/string encoding
	CategorySpace       Category = "space"       // Space replacement techniques
	CategorySQL         Category = "sql"         // SQL syntax transformations
	CategoryMySQL       Category = "mysql"       // MySQL-specific
	CategoryMSSQL       Category = "mssql"       // MSSQL-specific
	CategoryWAF         Category = "waf"         // WAF-specific bypasses
	CategoryHTTP        Category = "http"        // HTTP-level modifications
	CategoryObfuscation Category = "obfuscation" // General obfuscation
)

// Priority represents tamper execution priority (higher = runs first)
type Priority int

const (
	PriorityLowest  Priority = 0
	PriorityLow     Priority = 25
	PriorityNormal  Priority = 50
	PriorityHigh    Priority = 75
	PriorityHighest Priority = 100
)

// Tamper represents a payload/request transformation technique
type Tamper interface {
	// Name returns the tamper identifier (e.g., "space2comment")
	Name() string

	// Description returns human-readable description
	Description() string

	// Category returns the tamper category
	Category() Category

	// Priority returns execution priority (higher = runs first)
	Priority() Priority

	// Tags returns applicable contexts (e.g., ["mysql", "modsecurity"])
	Tags() []string

	// Transform modifies the payload string
	Transform(payload string) string

	// TransformRequest optionally modifies the HTTP request
	// Returns nil if this tamper doesn't modify requests
	TransformRequest(req *http.Request) *http.Request
}

// BaseTamper provides common implementation for tampers
type BaseTamper struct {
	name        string
	description string
	category    Category
	priority    Priority
	tags        []string
}

// NewBaseTamper creates a new base tamper
func NewBaseTamper(name, description string, category Category, priority Priority, tags ...string) BaseTamper {
	return BaseTamper{
		name:        name,
		description: description,
		category:    category,
		priority:    priority,
		tags:        tags,
	}
}

// Name returns the tamper identifier
func (b *BaseTamper) Name() string { return b.name }

// Description returns human-readable description
func (b *BaseTamper) Description() string { return b.description }

// Category returns the tamper category
func (b *BaseTamper) Category() Category { return b.category }

// Priority returns execution priority
func (b *BaseTamper) Priority() Priority { return b.priority }

// Tags returns applicable contexts
func (b *BaseTamper) Tags() []string { return b.tags }

// TransformRequest default implementation returns nil (no HTTP modification)
func (b *BaseTamper) TransformRequest(req *http.Request) *http.Request { return nil }

// registry holds all registered tampers
var (
	registry = make(map[string]Tamper)
	mu       sync.RWMutex
)

// Register adds a tamper to the registry
func Register(t Tamper) {
	mu.Lock()
	defer mu.Unlock()
	registry[t.Name()] = t
}

// Get returns a tamper by name
func Get(name string) Tamper {
	mu.RLock()
	defer mu.RUnlock()
	return registry[name]
}

// List returns all registered tamper names sorted alphabetically
func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All returns all registered tampers
func All() []Tamper {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Tamper, 0, len(registry))
	for _, t := range registry {
		result = append(result, t)
	}
	return result
}

// ByCategory returns tampers filtered by category
func ByCategory(cat Category) []Tamper {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Tamper, 0)
	for _, t := range registry {
		if t.Category() == cat {
			result = append(result, t)
		}
	}
	return result
}

// ByTag returns tampers that have the given tag
func ByTag(tag string) []Tamper {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Tamper, 0)
	for _, t := range registry {
		for _, ttag := range t.Tags() {
			if ttag == tag {
				result = append(result, t)
				break
			}
		}
	}
	return result
}

// Count returns the number of registered tampers
func Count() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(registry)
}

// GetMultiple returns multiple tampers with a single lock acquisition
func GetMultiple(names ...string) []Tamper {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Tamper, 0, len(names))
	for _, name := range names {
		if t, ok := registry[name]; ok {
			result = append(result, t)
		}
	}
	return result
}

// Chain applies multiple tampers in sequence to a payload
// Uses single lock acquisition for all lookups
func Chain(payload string, tamperNames ...string) string {
	tampers := GetMultiple(tamperNames...)
	result := payload
	for _, t := range tampers {
		result = t.Transform(result)
	}
	return result
}

// ChainByPriority applies tampers sorted by priority (highest first)
// Uses single lock acquisition for all lookups
func ChainByPriority(payload string, tamperNames ...string) string {
	tampers := GetMultiple(tamperNames...)
	if len(tampers) == 0 {
		return payload
	}

	// Sort by priority (highest first)
	sort.Slice(tampers, func(i, j int) bool {
		return tampers[i].Priority() > tampers[j].Priority()
	})

	// Apply in order
	result := payload
	for _, t := range tampers {
		result = t.Transform(result)
	}
	return result
}

// ChainRequest applies multiple tampers to an HTTP request
// Uses single lock acquisition for all lookups
func ChainRequest(req *http.Request, tamperNames ...string) *http.Request {
	tampers := GetMultiple(tamperNames...)
	result := req
	for _, t := range tampers {
		if modified := t.TransformRequest(result); modified != nil {
			result = modified
		}
	}
	return result
}

// Categories returns all available categories
func Categories() []Category {
	return []Category{
		CategoryEncoding,
		CategorySpace,
		CategorySQL,
		CategoryMySQL,
		CategoryMSSQL,
		CategoryWAF,
		CategoryHTTP,
		CategoryObfuscation,
	}
}

// CategoryStrings returns all category names as strings, suitable for enum schemas.
func CategoryStrings() []string {
	cats := Categories()
	out := make([]string, len(cats))
	for i, c := range cats {
		out[i] = string(c)
	}
	return out
}
