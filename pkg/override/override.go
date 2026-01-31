// Package override provides test override management for WAF testing.
package override

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Action represents an override action.
type Action string

const (
	ActionSkip     Action = "skip"
	ActionModify   Action = "modify"
	ActionEnable   Action = "enable"
	ActionDisable  Action = "disable"
	ActionPriority Action = "priority"
)

// Override represents a test override.
type Override struct {
	TestID      string            `json:"test_id" yaml:"test_id"`
	RuleID      string            `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
	Action      Action            `json:"action" yaml:"action"`
	Reason      string            `json:"reason" yaml:"reason"`
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	CreatedBy   string            `json:"created_by,omitempty" yaml:"created_by,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Conditions  []Condition       `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	Replacement *Replacement      `json:"replacement,omitempty" yaml:"replacement,omitempty"`
}

// IsExpired checks if override has expired.
func (o *Override) IsExpired() bool {
	if o.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*o.ExpiresAt)
}

// Condition represents an override condition.
type Condition struct {
	Field    string `json:"field" yaml:"field"`
	Operator string `json:"operator" yaml:"operator"`
	Value    string `json:"value" yaml:"value"`
}

// Matches checks if condition matches a value.
func (c *Condition) Matches(fieldValue string) bool {
	switch c.Operator {
	case "eq", "==", "equals":
		return fieldValue == c.Value
	case "ne", "!=", "not_equals":
		return fieldValue != c.Value
	case "contains":
		return contains(fieldValue, c.Value)
	case "prefix", "starts_with":
		return len(fieldValue) >= len(c.Value) && fieldValue[:len(c.Value)] == c.Value
	case "suffix", "ends_with":
		return len(fieldValue) >= len(c.Value) && fieldValue[len(fieldValue)-len(c.Value):] == c.Value
	default:
		return false
	}
}

// Replacement holds replacement values for modify action.
type Replacement struct {
	Payload     string            `json:"payload,omitempty" yaml:"payload,omitempty"`
	ExpectBlock *bool             `json:"expect_block,omitempty" yaml:"expect_block,omitempty"`
	Headers     map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Method      string            `json:"method,omitempty" yaml:"method,omitempty"`
}

// Test represents a test that can be overridden.
type Test struct {
	ID          string            `json:"id" yaml:"id"`
	RuleID      string            `json:"rule_id" yaml:"rule_id"`
	Category    string            `json:"category" yaml:"category"`
	Payload     string            `json:"payload" yaml:"payload"`
	ExpectBlock bool              `json:"expect_block" yaml:"expect_block"`
	Method      string            `json:"method" yaml:"method"`
	Headers     map[string]string `json:"headers" yaml:"headers"`
	Tags        []string          `json:"tags" yaml:"tags"`
}

// Result represents the result of applying an override.
type Result struct {
	Applied  bool      `json:"applied"`
	Override *Override `json:"override,omitempty"`
	Action   Action    `json:"action"`
	SkipTest bool      `json:"skip_test"`
	Modified *Test     `json:"modified,omitempty"`
}

// Config holds manager configuration.
type Config struct {
	AllowExpired bool `json:"allow_expired" yaml:"allow_expired"`
}

// DefaultConfig returns default configuration.
func DefaultConfig() *Config {
	return &Config{
		AllowExpired: false,
	}
}

// Manager manages test overrides.
type Manager struct {
	overrides map[string]*Override
	config    *Config
	mu        sync.RWMutex
}

// NewManager creates a new override manager.
func NewManager(config *Config) *Manager {
	if config == nil {
		config = DefaultConfig()
	}
	return &Manager{
		overrides: make(map[string]*Override),
		config:    config,
	}
}

// Add adds an override.
func (m *Manager) Add(o *Override) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.overrides[o.TestID] = o
}

// Remove removes an override.
func (m *Manager) Remove(testID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.overrides[testID]; ok {
		delete(m.overrides, testID)
		return true
	}
	return false
}

// Get returns an override by test ID.
func (m *Manager) Get(testID string) (*Override, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.overrides[testID]
	return o, ok
}

// List returns all overrides.
func (m *Manager) List() []*Override {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*Override
	for _, o := range m.overrides {
		result = append(result, o)
	}
	return result
}

// ListActive returns non-expired overrides.
func (m *Manager) ListActive() []*Override {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*Override
	for _, o := range m.overrides {
		if !o.IsExpired() {
			result = append(result, o)
		}
	}
	return result
}

// Apply applies overrides to a test.
func (m *Manager) Apply(test *Test) *Result {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := &Result{Applied: false}

	o, ok := m.overrides[test.ID]
	if !ok {
		return result
	}

	if !m.config.AllowExpired && o.IsExpired() {
		return result
	}

	// Check conditions
	if len(o.Conditions) > 0 {
		match := true
		for _, c := range o.Conditions {
			var fieldValue string
			switch c.Field {
			case "category":
				fieldValue = test.Category
			case "rule_id":
				fieldValue = test.RuleID
			case "method":
				fieldValue = test.Method
			}
			if !c.Matches(fieldValue) {
				match = false
				break
			}
		}
		if !match {
			return result
		}
	}

	result.Applied = true
	result.Override = o
	result.Action = o.Action

	switch o.Action {
	case ActionSkip, ActionDisable:
		result.SkipTest = true

	case ActionModify:
		if o.Replacement != nil {
			modified := *test
			if o.Replacement.Payload != "" {
				modified.Payload = o.Replacement.Payload
			}
			if o.Replacement.ExpectBlock != nil {
				modified.ExpectBlock = *o.Replacement.ExpectBlock
			}
			if o.Replacement.Method != "" {
				modified.Method = o.Replacement.Method
			}
			if len(o.Replacement.Headers) > 0 {
				if modified.Headers == nil {
					modified.Headers = make(map[string]string)
				}
				for k, v := range o.Replacement.Headers {
					modified.Headers[k] = v
				}
			}
			result.Modified = &modified
		}

	case ActionEnable:
		result.SkipTest = false
	}

	return result
}

// Count returns number of overrides.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.overrides)
}

// Clear removes all overrides.
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.overrides = make(map[string]*Override)
}

// LoadFromFile loads overrides from file.
func (m *Manager) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var overrides []*Override
	if err := json.Unmarshal(data, &overrides); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range overrides {
		m.overrides[o.TestID] = o
	}

	return nil
}

// SaveToFile saves overrides to file.
func (m *Manager) SaveToFile(path string) error {
	m.mu.RLock()
	overrides := make([]*Override, 0, len(m.overrides))
	for _, o := range m.overrides {
		overrides = append(overrides, o)
	}
	m.mu.RUnlock()

	data, err := json.MarshalIndent(overrides, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
