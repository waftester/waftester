// Package paranoia provides WAF paranoia level testing and configuration
package paranoia

// Level represents a WAF paranoia level (1-4)
type Level int

const (
	// PL1 is the default paranoia level - catches obvious attacks
	PL1 Level = 1
	// PL2 provides more coverage with few false positives
	PL2 Level = 2
	// PL3 provides high security with some false positives
	PL3 Level = 3
	// PL4 is maximum security with expected false positives
	PL4 Level = 4
)

// String returns the string representation of a paranoia level
func (l Level) String() string {
	switch l {
	case PL1:
		return "PL1"
	case PL2:
		return "PL2"
	case PL3:
		return "PL3"
	case PL4:
		return "PL4"
	default:
		return "Unknown"
	}
}

// Valid returns true if the level is a valid paranoia level (1-4)
func (l Level) Valid() bool {
	return l >= PL1 && l <= PL4
}

// Description returns a human-readable description of the paranoia level
func (l Level) Description() string {
	switch l {
	case PL1:
		return "Default - catches obvious attacks with minimal false positives"
	case PL2:
		return "Enhanced - catches more attacks with few false positives"
	case PL3:
		return "High Security - comprehensive protection with some false positives"
	case PL4:
		return "Maximum Security - strictest rules, expect false positives"
	default:
		return "Unknown paranoia level"
	}
}

// RuleCategories returns the attack categories active at this level
func (l Level) RuleCategories() []string {
	base := []string{
		"sqli",
		"xss",
		"rce",
		"lfi",
		"rfi",
	}

	if l >= PL2 {
		base = append(base, "session-fixation", "http-splitting")
	}
	if l >= PL3 {
		base = append(base, "ssrf", "xxe", "ssti")
	}
	if l >= PL4 {
		base = append(base, "nosql", "ldap", "graphql")
	}

	return base
}

// Config holds paranoia level configuration for testing
type Config struct {
	Level                 Level
	ThresholdAnomalyScore int
	BlockingMode          bool
	ExcludedRules         []int
}

// DefaultConfig returns the default configuration for a paranoia level
func DefaultConfig(level Level) *Config {
	cfg := &Config{
		Level:        level,
		BlockingMode: true,
	}

	// Set default anomaly score thresholds based on CRS recommendations
	switch level {
	case PL1:
		cfg.ThresholdAnomalyScore = 5
	case PL2:
		cfg.ThresholdAnomalyScore = 4
	case PL3:
		cfg.ThresholdAnomalyScore = 3
	case PL4:
		cfg.ThresholdAnomalyScore = 2
	}

	return cfg
}

// NewConfig creates a new paranoia configuration
func NewConfig(level Level, opts ...ConfigOption) *Config {
	cfg := DefaultConfig(level)
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// ConfigOption modifies a Config
type ConfigOption func(*Config)

// WithAnomalyThreshold sets the anomaly score threshold
func WithAnomalyThreshold(threshold int) ConfigOption {
	return func(c *Config) {
		c.ThresholdAnomalyScore = threshold
	}
}

// WithBlockingMode sets whether to use blocking mode
func WithBlockingMode(blocking bool) ConfigOption {
	return func(c *Config) {
		c.BlockingMode = blocking
	}
}

// WithExcludedRules sets rules to exclude
func WithExcludedRules(rules []int) ConfigOption {
	return func(c *Config) {
		c.ExcludedRules = rules
	}
}

// TestSuite represents a set of tests for a specific paranoia level
type TestSuite struct {
	Level    Level
	Name     string
	Tests    []TestCase
	Payloads []string
}

// TestCase represents a single test case for paranoia level testing
type TestCase struct {
	ID            string
	Description   string
	Payload       string
	MinLevel      Level // Minimum paranoia level where this should be blocked
	Category      string
	ExpectedAtPL1 bool // Expected to be blocked at PL1
	ExpectedAtPL2 bool // Expected to be blocked at PL2
	ExpectedAtPL3 bool // Expected to be blocked at PL3
	ExpectedAtPL4 bool // Expected to be blocked at PL4
}

// ExpectedBlock returns whether the test case should be blocked at the given level
func (tc *TestCase) ExpectedBlock(level Level) bool {
	switch level {
	case PL1:
		return tc.ExpectedAtPL1
	case PL2:
		return tc.ExpectedAtPL2
	case PL3:
		return tc.ExpectedAtPL3
	case PL4:
		return tc.ExpectedAtPL4
	default:
		return false
	}
}

// Result represents the result of running a test at a specific paranoia level
type Result struct {
	TestCase *TestCase
	Level    Level
	Blocked  bool
	Expected bool
	Passed   bool
	Message  string
}

// Summary represents a summary of test results for a paranoia level
type Summary struct {
	Level          Level
	TotalTests     int
	Passed         int
	Failed         int
	FalsePositives int
	FalseNegatives int
}

// PassRate returns the pass rate as a percentage
func (s *Summary) PassRate() float64 {
	if s.TotalTests == 0 {
		return 0
	}
	return float64(s.Passed) / float64(s.TotalTests) * 100
}

// Generator creates test cases for each paranoia level
type Generator struct {
	payloads map[string][]string
}

// NewGenerator creates a new test case generator
func NewGenerator() *Generator {
	return &Generator{
		payloads: make(map[string][]string),
	}
}

// AddPayloads adds payloads for a category
func (g *Generator) AddPayloads(category string, payloads []string) {
	g.payloads[category] = append(g.payloads[category], payloads...)
}

// GenerateForLevel creates test cases for a specific paranoia level
func (g *Generator) GenerateForLevel(level Level) []TestCase {
	var tests []TestCase
	categories := level.RuleCategories()

	id := 1
	for _, category := range categories {
		payloads, ok := g.payloads[category]
		if !ok {
			continue
		}

		for _, payload := range payloads {
			tc := TestCase{
				ID:          generateID(category, id),
				Description: generateDescription(category, payload),
				Payload:     payload,
				MinLevel:    determineMinLevel(category),
				Category:    category,
			}

			// Set expectations based on category and level
			setExpectations(&tc)

			tests = append(tests, tc)
			id++
		}
	}

	return tests
}

// GenerateSuite creates a full test suite for a paranoia level
func (g *Generator) GenerateSuite(level Level) *TestSuite {
	return &TestSuite{
		Level:    level,
		Name:     "Paranoia Level " + level.String() + " Test Suite",
		Tests:    g.GenerateForLevel(level),
		Payloads: g.getAllPayloads(),
	}
}

func (g *Generator) getAllPayloads() []string {
	var all []string
	for _, payloads := range g.payloads {
		all = append(all, payloads...)
	}
	return all
}

func generateID(category string, n int) string {
	return category + "-" + padInt(n, 3)
}

func padInt(n, width int) string {
	result := ""
	for i := 0; i < width-len(intToString(n)); i++ {
		result += "0"
	}
	return result + intToString(n)
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

func generateDescription(category, payload string) string {
	if len([]rune(payload)) > 50 {
		payload = string([]rune(payload)[:50]) + "..."
	}
	return category + " attack: " + payload
}

func determineMinLevel(category string) Level {
	switch category {
	case "sqli", "xss", "rce", "lfi", "rfi":
		return PL1
	case "session-fixation", "http-splitting":
		return PL2
	case "ssrf", "xxe", "ssti":
		return PL3
	case "nosql", "ldap", "graphql":
		return PL4
	default:
		return PL1
	}
}

func setExpectations(tc *TestCase) {
	// All tests should be blocked at or above their minimum level
	tc.ExpectedAtPL1 = tc.MinLevel <= PL1
	tc.ExpectedAtPL2 = tc.MinLevel <= PL2
	tc.ExpectedAtPL3 = tc.MinLevel <= PL3
	tc.ExpectedAtPL4 = tc.MinLevel <= PL4
}

// Validator validates WAF behavior across paranoia levels
type Validator struct {
	results map[Level][]Result
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{
		results: make(map[Level][]Result),
	}
}

// AddResult adds a test result
func (v *Validator) AddResult(level Level, result Result) {
	v.results[level] = append(v.results[level], result)
}

// GetSummary returns a summary for a paranoia level
func (v *Validator) GetSummary(level Level) *Summary {
	results := v.results[level]
	summary := &Summary{
		Level:      level,
		TotalTests: len(results),
	}

	for _, r := range results {
		if r.Passed {
			summary.Passed++
		} else {
			summary.Failed++
			if r.Blocked && !r.Expected {
				summary.FalsePositives++
			}
			if !r.Blocked && r.Expected {
				summary.FalseNegatives++
			}
		}
	}

	return summary
}

// GetResults returns all results for a level
func (v *Validator) GetResults(level Level) []Result {
	return v.results[level]
}

// AllSummaries returns summaries for all tested levels
func (v *Validator) AllSummaries() []*Summary {
	var summaries []*Summary
	for level := PL1; level <= PL4; level++ {
		if len(v.results[level]) > 0 {
			summaries = append(summaries, v.GetSummary(level))
		}
	}
	return summaries
}

// Compare compares results across paranoia levels
func (v *Validator) Compare() *Comparison {
	comparison := &Comparison{
		Levels:   make(map[Level]*Summary),
		Coverage: make(map[Level]float64),
	}

	for level := PL1; level <= PL4; level++ {
		if len(v.results[level]) > 0 {
			summary := v.GetSummary(level)
			comparison.Levels[level] = summary
			comparison.Coverage[level] = summary.PassRate()
		}
	}

	return comparison
}

// Comparison represents a comparison across paranoia levels
type Comparison struct {
	Levels   map[Level]*Summary
	Coverage map[Level]float64
}

// HighestCoverage returns the level with highest coverage
func (c *Comparison) HighestCoverage() Level {
	var best Level
	var bestCoverage float64 = -1

	for level, coverage := range c.Coverage {
		if coverage > bestCoverage {
			bestCoverage = coverage
			best = level
		}
	}

	return best
}

// RecommendedLevel returns the recommended paranoia level based on results
func (c *Comparison) RecommendedLevel() Level {
	// Prefer higher security with acceptable false positive rate
	for level := PL4; level >= PL1; level-- {
		if summary, ok := c.Levels[level]; ok {
			// Accept if false positive rate is < 5%
			if summary.TotalTests > 0 {
				fpRate := float64(summary.FalsePositives) / float64(summary.TotalTests) * 100
				if fpRate < 5 && summary.PassRate() > 90 {
					return level
				}
			}
		}
	}
	return PL1
}
