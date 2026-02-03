package policy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// ErrPolicyNotFound is returned when a policy file does not exist.
var ErrPolicyNotFound = errors.New("policy file not found")

// ErrInvalidPolicy is returned when a policy file is malformed.
var ErrInvalidPolicy = errors.New("invalid policy file")

// Policy represents a parsed policy configuration.
type Policy struct {
	Version string     `yaml:"version"`
	Name    string     `yaml:"name"`
	FailOn  FailOn     `yaml:"fail_on"`
	Ignore  IgnoreSpec `yaml:"ignore"`

	mu sync.RWMutex // protects evaluation
}

// FailOn defines conditions that cause a scan to fail.
type FailOn struct {
	Bypasses           BypassThresholds `yaml:"bypasses"`
	Categories         []string         `yaml:"categories"`
	EffectivenessBelow *float64         `yaml:"effectiveness_below"`
	ErrorRateAbove     *float64         `yaml:"error_rate_above"`
}

// BypassThresholds defines maximum allowed bypasses by severity.
// A value of 0 means no threshold (unlimited).
// A value of N means fail if bypasses > N.
type BypassThresholds struct {
	Total    *int `yaml:"total"`
	Critical *int `yaml:"critical"`
	High     *int `yaml:"high"`
	Medium   *int `yaml:"medium"`
	Low      *int `yaml:"low"`
	Info     *int `yaml:"info"`
}

// IgnoreSpec defines patterns to ignore during evaluation.
type IgnoreSpec struct {
	TestIDs    []string `yaml:"test_ids"`
	Categories []string `yaml:"categories"`
}

// SummaryData holds the scan summary metrics for policy evaluation.
type SummaryData struct {
	// TotalBypasses is the total number of bypasses detected.
	TotalBypasses int

	// BypassesBySeverity maps severity (critical, high, medium, low, info) to bypass count.
	BypassesBySeverity map[string]int

	// BypassesByCategory maps category name to bypass count.
	BypassesByCategory map[string]int

	// BypassTestIDs contains the test IDs of all bypasses (for ignore matching).
	BypassTestIDs []string

	// Effectiveness is the WAF block rate percentage (0-100).
	Effectiveness float64

	// ErrorRate is the percentage of tests that resulted in errors (0-100).
	ErrorRate float64

	// TotalTests is the total number of tests run.
	TotalTests int

	// TotalErrors is the total number of errors.
	TotalErrors int
}

// PolicyResult contains the outcome of a policy evaluation.
type PolicyResult struct {
	// Pass is true if the policy passed (no failures).
	Pass bool

	// Failures contains human-readable failure messages.
	Failures []string

	// ExitCode is the recommended exit code based on the policy result.
	// 0 = pass, 1 = policy failure (bypasses detected).
	ExitCode int

	// PolicyName is the name of the evaluated policy.
	PolicyName string
}

// LoadPolicy loads and parses a policy file from the given path.
// Returns ErrPolicyNotFound if the file doesn't exist.
// Returns ErrInvalidPolicy if the file is malformed.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrPolicyNotFound, path)
		}
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	return ParsePolicy(data)
}

// ParsePolicy parses policy YAML data.
// Returns ErrInvalidPolicy if the data is malformed.
func ParsePolicy(data []byte) (*Policy, error) {
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}

	// Validate version
	if policy.Version == "" {
		policy.Version = "1.0"
	}

	// Normalize categories to lowercase
	for i := range policy.FailOn.Categories {
		policy.FailOn.Categories[i] = strings.ToLower(policy.FailOn.Categories[i])
	}
	for i := range policy.Ignore.Categories {
		policy.Ignore.Categories[i] = strings.ToLower(policy.Ignore.Categories[i])
	}

	return &policy, nil
}

// Evaluate evaluates the policy against the given scan summary.
// This method is thread-safe.
func (p *Policy) Evaluate(summary SummaryData) PolicyResult {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := PolicyResult{
		Pass:       true,
		Failures:   make([]string, 0),
		ExitCode:   0,
		PolicyName: p.Name,
	}

	// Build ignore sets for efficient lookup
	ignoreTestIDs := make(map[string]bool)
	for _, id := range p.Ignore.TestIDs {
		ignoreTestIDs[id] = true
	}
	ignoreCategories := make(map[string]bool)
	for _, cat := range p.Ignore.Categories {
		ignoreCategories[strings.ToLower(cat)] = true
	}

	// Adjust summary data based on ignore rules
	adjustedSummary := p.applyIgnoreRules(summary, ignoreTestIDs, ignoreCategories)

	// Check bypass thresholds
	p.checkBypassThresholds(&result, adjustedSummary)

	// Check category-specific bypasses
	p.checkCategoryBypasses(&result, adjustedSummary, ignoreCategories)

	// Check effectiveness threshold
	p.checkEffectiveness(&result, adjustedSummary)

	// Check error rate threshold
	p.checkErrorRate(&result, adjustedSummary)

	// Set exit code if any failures
	if len(result.Failures) > 0 {
		result.Pass = false
		result.ExitCode = 1
	}

	return result
}

// applyIgnoreRules adjusts the summary data based on ignore rules.
func (p *Policy) applyIgnoreRules(summary SummaryData, ignoreTestIDs, ignoreCategories map[string]bool) SummaryData {
	adjusted := SummaryData{
		TotalBypasses:      summary.TotalBypasses,
		BypassesBySeverity: make(map[string]int),
		BypassesByCategory: make(map[string]int),
		BypassTestIDs:      summary.BypassTestIDs,
		Effectiveness:      summary.Effectiveness,
		ErrorRate:          summary.ErrorRate,
		TotalTests:         summary.TotalTests,
		TotalErrors:        summary.TotalErrors,
	}

	// Copy severity map
	for k, v := range summary.BypassesBySeverity {
		adjusted.BypassesBySeverity[k] = v
	}

	// Copy category map, excluding ignored categories
	ignoredCount := 0
	for cat, count := range summary.BypassesByCategory {
		if ignoreCategories[strings.ToLower(cat)] {
			ignoredCount += count
			continue
		}
		adjusted.BypassesByCategory[cat] = count
	}

	// Reduce total bypasses by ignored category count
	adjusted.TotalBypasses -= ignoredCount

	// Note: We can't accurately adjust by test ID without more detailed data,
	// so we skip that adjustment (would need per-bypass category/severity info)

	return adjusted
}

// checkBypassThresholds checks bypass count thresholds.
func (p *Policy) checkBypassThresholds(result *PolicyResult, summary SummaryData) {
	thresholds := p.FailOn.Bypasses

	// Total bypass threshold
	if thresholds.Total != nil {
		if summary.TotalBypasses > *thresholds.Total {
			result.Failures = append(result.Failures,
				fmt.Sprintf("total bypasses (%d) exceeds threshold (%d)",
					summary.TotalBypasses, *thresholds.Total))
		}
	}

	// Critical severity threshold
	if thresholds.Critical != nil {
		count := summary.BypassesBySeverity["critical"]
		if count > *thresholds.Critical {
			result.Failures = append(result.Failures,
				fmt.Sprintf("critical bypasses (%d) exceeds threshold (%d)",
					count, *thresholds.Critical))
		}
	}

	// High severity threshold
	if thresholds.High != nil {
		count := summary.BypassesBySeverity["high"]
		if count > *thresholds.High {
			result.Failures = append(result.Failures,
				fmt.Sprintf("high severity bypasses (%d) exceeds threshold (%d)",
					count, *thresholds.High))
		}
	}

	// Medium severity threshold
	if thresholds.Medium != nil {
		count := summary.BypassesBySeverity["medium"]
		if count > *thresholds.Medium {
			result.Failures = append(result.Failures,
				fmt.Sprintf("medium severity bypasses (%d) exceeds threshold (%d)",
					count, *thresholds.Medium))
		}
	}

	// Low severity threshold
	if thresholds.Low != nil {
		count := summary.BypassesBySeverity["low"]
		if count > *thresholds.Low {
			result.Failures = append(result.Failures,
				fmt.Sprintf("low severity bypasses (%d) exceeds threshold (%d)",
					count, *thresholds.Low))
		}
	}

	// Info severity threshold
	if thresholds.Info != nil {
		count := summary.BypassesBySeverity["info"]
		if count > *thresholds.Info {
			result.Failures = append(result.Failures,
				fmt.Sprintf("info severity bypasses (%d) exceeds threshold (%d)",
					count, *thresholds.Info))
		}
	}
}

// checkCategoryBypasses checks for bypasses in specified categories.
func (p *Policy) checkCategoryBypasses(result *PolicyResult, summary SummaryData, ignoreCategories map[string]bool) {
	for _, category := range p.FailOn.Categories {
		cat := strings.ToLower(category)

		// Skip if this category is ignored
		if ignoreCategories[cat] {
			continue
		}

		count := summary.BypassesByCategory[cat]
		if count > 0 {
			result.Failures = append(result.Failures,
				fmt.Sprintf("bypasses detected in category '%s' (%d found)",
					category, count))
		}
	}
}

// checkEffectiveness checks the WAF effectiveness threshold.
func (p *Policy) checkEffectiveness(result *PolicyResult, summary SummaryData) {
	if p.FailOn.EffectivenessBelow == nil {
		return
	}

	threshold := *p.FailOn.EffectivenessBelow
	if summary.Effectiveness < threshold {
		result.Failures = append(result.Failures,
			fmt.Sprintf("WAF effectiveness (%.1f%%) is below threshold (%.1f%%)",
				summary.Effectiveness, threshold))
	}
}

// checkErrorRate checks the error rate threshold.
func (p *Policy) checkErrorRate(result *PolicyResult, summary SummaryData) {
	if p.FailOn.ErrorRateAbove == nil {
		return
	}

	threshold := *p.FailOn.ErrorRateAbove
	if summary.ErrorRate > threshold {
		result.Failures = append(result.Failures,
			fmt.Sprintf("error rate (%.1f%%) exceeds threshold (%.1f%%)",
				summary.ErrorRate, threshold))
	}
}

// String returns a human-readable representation of the policy.
func (p *Policy) String() string {
	if p.Name != "" {
		return fmt.Sprintf("Policy(%s v%s)", p.Name, p.Version)
	}
	return fmt.Sprintf("Policy(v%s)", p.Version)
}

// intPtr is a helper to create a pointer to an int.
func intPtr(i int) *int {
	return &i
}

// floatPtr is a helper to create a pointer to a float64.
func floatPtr(f float64) *float64 {
	return &f
}
