// Package overrides provides test configuration override capabilities
package overrides

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Override represents a test override configuration
type Override struct {
	// ID is the unique identifier for the override
	ID string `json:"id" yaml:"id"`
	// Description explains why this override exists
	Description string `json:"description" yaml:"description"`
	// Matcher defines which tests this override applies to
	Matcher *Matcher `json:"match" yaml:"match"`
	// Action defines what to do with matched tests
	Action Action `json:"action" yaml:"action"`
	// Modifications to apply if action is Modify
	Modifications *Modifications `json:"modifications,omitempty" yaml:"modifications,omitempty"`
	// Priority determines order of application (higher = first)
	Priority int `json:"priority,omitempty" yaml:"priority,omitempty"`
	// Enabled allows disabling an override without removing it
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// Action defines what to do with matched tests
type Action string

const (
	// Skip marks the test to be skipped
	Skip Action = "skip"
	// Modify changes test properties
	Modify Action = "modify"
	// Invert inverts the expected result
	Invert Action = "invert"
	// Force forces the test to run even if filtered
	Force Action = "force"
)

// Valid returns true if the action is valid
func (a Action) Valid() bool {
	switch a {
	case Skip, Modify, Invert, Force:
		return true
	default:
		return false
	}
}

// Matcher defines criteria for matching tests
type Matcher struct {
	// TestID matches specific test IDs (exact match)
	TestID []string `json:"test_id,omitempty" yaml:"test_id,omitempty"`
	// TestIDPattern matches test IDs using regex
	TestIDPattern string `json:"test_id_pattern,omitempty" yaml:"test_id_pattern,omitempty"`
	// Category matches tests by category
	Category []string `json:"category,omitempty" yaml:"category,omitempty"`
	// Tags matches tests that have any of these tags
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	// Payload matches tests containing this payload substring
	Payload string `json:"payload,omitempty" yaml:"payload,omitempty"`
	// PayloadPattern matches payloads using regex
	PayloadPattern string `json:"payload_pattern,omitempty" yaml:"payload_pattern,omitempty"`
	// Method matches tests with specific HTTP methods
	Method []string `json:"method,omitempty" yaml:"method,omitempty"`
	// Path matches tests targeting specific paths
	Path []string `json:"path,omitempty" yaml:"path,omitempty"`
	// PathPattern matches paths using regex
	PathPattern string `json:"path_pattern,omitempty" yaml:"path_pattern,omitempty"`

	// Compiled patterns (not serialized)
	testIDRegex  *regexp.Regexp
	payloadRegex *regexp.Regexp
	pathRegex    *regexp.Regexp
}

// Compile compiles regex patterns
func (m *Matcher) Compile() error {
	if m.TestIDPattern != "" {
		re, err := regexp.Compile(m.TestIDPattern)
		if err != nil {
			return fmt.Errorf("invalid test_id_pattern: %w", err)
		}
		m.testIDRegex = re
	}

	if m.PayloadPattern != "" {
		re, err := regexp.Compile(m.PayloadPattern)
		if err != nil {
			return fmt.Errorf("invalid payload_pattern: %w", err)
		}
		m.payloadRegex = re
	}

	if m.PathPattern != "" {
		re, err := regexp.Compile(m.PathPattern)
		if err != nil {
			return fmt.Errorf("invalid path_pattern: %w", err)
		}
		m.pathRegex = re
	}

	return nil
}

// Test represents a test case to be matched
type Test struct {
	ID       string
	Category string
	Tags     []string
	Payload  string
	Method   string
	Path     string
}

// Matches returns true if the test matches this matcher
func (m *Matcher) Matches(t *Test) bool {
	if t == nil {
		return false
	}

	// Empty matcher matches nothing
	if m.isEmpty() {
		return false
	}

	// Test ID matching
	if len(m.TestID) > 0 {
		found := false
		for _, id := range m.TestID {
			if id == t.ID {
				found = true
				break
			}
		}
		if !found && m.testIDRegex == nil {
			return false
		}
		if found {
			return true
		}
	}

	if m.testIDRegex != nil && m.testIDRegex.MatchString(t.ID) {
		return true
	}

	// Category matching
	if len(m.Category) > 0 {
		found := false
		for _, cat := range m.Category {
			if cat == t.Category {
				found = true
				break
			}
		}
		if found {
			return true
		}
	}

	// Tag matching
	if len(m.Tags) > 0 {
		for _, matchTag := range m.Tags {
			for _, testTag := range t.Tags {
				if matchTag == testTag {
					return true
				}
			}
		}
	}

	// Payload matching
	if m.Payload != "" && strings.Contains(t.Payload, m.Payload) {
		return true
	}
	if m.payloadRegex != nil && m.payloadRegex.MatchString(t.Payload) {
		return true
	}

	// Method matching
	if len(m.Method) > 0 {
		for _, method := range m.Method {
			if strings.EqualFold(method, t.Method) {
				return true
			}
		}
	}

	// Path matching
	if len(m.Path) > 0 {
		for _, path := range m.Path {
			if path == t.Path {
				return true
			}
		}
	}
	if m.pathRegex != nil && m.pathRegex.MatchString(t.Path) {
		return true
	}

	return false
}

func (m *Matcher) isEmpty() bool {
	return len(m.TestID) == 0 &&
		m.TestIDPattern == "" &&
		len(m.Category) == 0 &&
		len(m.Tags) == 0 &&
		m.Payload == "" &&
		m.PayloadPattern == "" &&
		len(m.Method) == 0 &&
		len(m.Path) == 0 &&
		m.PathPattern == ""
}

// Modifications defines how to modify matched tests
type Modifications struct {
	// ExpectBlock overrides the expected block status
	ExpectBlock *bool `json:"expect_block,omitempty" yaml:"expect_block,omitempty"`
	// Payload replaces the payload
	Payload *string `json:"payload,omitempty" yaml:"payload,omitempty"`
	// Method replaces the HTTP method
	Method *string `json:"method,omitempty" yaml:"method,omitempty"`
	// Path replaces the target path
	Path *string `json:"path,omitempty" yaml:"path,omitempty"`
	// Headers to add or replace
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	// AddTags adds tags to the test
	AddTags []string `json:"add_tags,omitempty" yaml:"add_tags,omitempty"`
	// RemoveTags removes tags from the test
	RemoveTags []string `json:"remove_tags,omitempty" yaml:"remove_tags,omitempty"`
}

// Config holds all override configurations
type Config struct {
	// Version is the config schema version
	Version string `json:"version" yaml:"version"`
	// Overrides is the list of overrides
	Overrides []*Override `json:"overrides" yaml:"overrides"`
}

// NewConfig creates a new empty configuration
func NewConfig() *Config {
	return &Config{
		Version:   "1.0",
		Overrides: []*Override{},
	}
}

// Add adds an override to the configuration
func (c *Config) Add(o *Override) {
	c.Overrides = append(c.Overrides, o)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	for i, o := range c.Overrides {
		if o.ID == "" {
			return fmt.Errorf("override at index %d has no ID", i)
		}
		if !o.Action.Valid() {
			return fmt.Errorf("override %s has invalid action: %s", o.ID, o.Action)
		}
		if o.Matcher == nil {
			return fmt.Errorf("override %s has no matcher", o.ID)
		}
		if err := o.Matcher.Compile(); err != nil {
			return fmt.Errorf("override %s: %w", o.ID, err)
		}
		if o.Action == Modify && o.Modifications == nil {
			return fmt.Errorf("override %s has action 'modify' but no modifications", o.ID)
		}
	}
	return nil
}

// Compile compiles all regex patterns in the configuration
func (c *Config) Compile() error {
	for _, o := range c.Overrides {
		if o.Matcher != nil {
			if err := o.Matcher.Compile(); err != nil {
				return fmt.Errorf("override %s: %w", o.ID, err)
			}
		}
	}
	return nil
}

// EnabledOverrides returns only enabled overrides
func (c *Config) EnabledOverrides() []*Override {
	var enabled []*Override
	for _, o := range c.Overrides {
		if o.Enabled {
			enabled = append(enabled, o)
		}
	}
	return enabled
}

// LoadFromFile loads configuration from a YAML or JSON file
func LoadFromFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	return Load(f, path)
}

// Load loads configuration from a reader
func Load(r io.Reader, filename string) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	cfg := NewConfig()

	if strings.HasSuffix(filename, ".json") {
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	}

	if err := cfg.Compile(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// SaveToFile saves configuration to a file
func (c *Config) SaveToFile(path string) error {
	var data []byte
	var err error

	if strings.HasSuffix(path, ".json") {
		data, err = json.MarshalIndent(c, "", "  ")
	} else {
		data, err = yaml.Marshal(c)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// Engine applies overrides to tests
type Engine struct {
	config *Config
}

// NewEngine creates a new override engine
func NewEngine(config *Config) *Engine {
	return &Engine{config: config}
}

// Result represents the result of applying overrides to a test
type Result struct {
	// Test is the original test
	Test *Test
	// Skipped is true if the test should be skipped
	Skipped bool
	// SkipReason explains why the test was skipped
	SkipReason string
	// Modified is true if the test was modified
	Modified bool
	// Inverted is true if the expected result was inverted
	Inverted bool
	// Forced is true if the test is forced to run
	Forced bool
	// AppliedOverrides lists which overrides were applied
	AppliedOverrides []string
}

// Apply applies all matching overrides to a test
func (e *Engine) Apply(t *Test) *Result {
	result := &Result{
		Test: t,
	}

	// Get enabled overrides sorted by priority
	overrides := e.config.EnabledOverrides()
	sortByPriority(overrides)

	for _, o := range overrides {
		if o.Matcher.Matches(t) {
			result.AppliedOverrides = append(result.AppliedOverrides, o.ID)

			switch o.Action {
			case Skip:
				result.Skipped = true
				result.SkipReason = o.Description
			case Modify:
				result.Modified = true
				e.applyModifications(t, o.Modifications)
			case Invert:
				result.Inverted = true
			case Force:
				result.Forced = true
			}
		}
	}

	return result
}

func (e *Engine) applyModifications(t *Test, m *Modifications) {
	if m == nil {
		return
	}

	if m.Payload != nil {
		t.Payload = *m.Payload
	}
	if m.Method != nil {
		t.Method = *m.Method
	}
	if m.Path != nil {
		t.Path = *m.Path
	}

	// Handle tags
	for _, tag := range m.AddTags {
		if !containsString(t.Tags, tag) {
			t.Tags = append(t.Tags, tag)
		}
	}
	for _, tag := range m.RemoveTags {
		t.Tags = removeString(t.Tags, tag)
	}
}

func sortByPriority(overrides []*Override) {
	// Sort by priority descending using efficient O(n log n) sort
	sort.Slice(overrides, func(i, j int) bool {
		return overrides[i].Priority > overrides[j].Priority
	})
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) []string {
	var result []string
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}

// ApplyToAll applies overrides to all tests and returns results
func (e *Engine) ApplyToAll(tests []*Test) []*Result {
	var results []*Result
	for _, t := range tests {
		results = append(results, e.Apply(t))
	}
	return results
}

// Filter returns tests that should be run (not skipped)
func (e *Engine) Filter(tests []*Test) []*Test {
	var filtered []*Test
	for _, t := range tests {
		result := e.Apply(t)
		if !result.Skipped || result.Forced {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// Stats returns statistics about override applications
type Stats struct {
	TotalTests      int
	SkippedTests    int
	ModifiedTests   int
	InvertedTests   int
	ForcedTests     int
	OverrideMatches map[string]int
}

// GetStats returns statistics from applying overrides to tests
func (e *Engine) GetStats(tests []*Test) *Stats {
	stats := &Stats{
		TotalTests:      len(tests),
		OverrideMatches: make(map[string]int),
	}

	for _, t := range tests {
		result := e.Apply(t)
		if result.Skipped {
			stats.SkippedTests++
		}
		if result.Modified {
			stats.ModifiedTests++
		}
		if result.Inverted {
			stats.InvertedTests++
		}
		if result.Forced {
			stats.ForcedTests++
		}
		for _, id := range result.AppliedOverrides {
			stats.OverrideMatches[id]++
		}
	}

	return stats
}
