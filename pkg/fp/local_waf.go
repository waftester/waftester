// Package fp provides local WAF testing using embedded Coraza.
// This allows testing payloads against CRS rules without network requests.
package fp

import (
	"fmt"
	"regexp"
	"strings"
)

// LocalWAF provides local WAF rule testing using pattern matching
// Note: For full Coraza integration, add github.com/corazawaf/coraza/v3 dependency
// This implementation uses pattern matching for CRS rule simulation
type LocalWAF struct {
	paranoiaLevel int
	rules         []LocalRule
}

// LocalRule represents a simplified WAF rule for local testing
type LocalRule struct {
	ID            int
	Description   string
	Pattern       *regexp.Regexp
	ParanoiaLevel int // Minimum PL required to activate
	Category      string
}

// LocalTestResult contains the result of a local WAF test
type LocalTestResult struct {
	Blocked       bool     `json:"blocked"`
	MatchedRules  []int    `json:"matched_rules"`
	RuleMessages  []string `json:"rule_messages"`
	ParanoiaLevel int      `json:"paranoia_level"`
}

// NewLocalWAF creates a new local WAF instance
func NewLocalWAF(paranoiaLevel int) *LocalWAF {
	if paranoiaLevel < 1 {
		paranoiaLevel = 1
	}
	if paranoiaLevel > 4 {
		paranoiaLevel = 4
	}

	waf := &LocalWAF{
		paranoiaLevel: paranoiaLevel,
		rules:         make([]LocalRule, 0),
	}

	waf.loadCRSRules()
	return waf
}

// Test runs a payload against local WAF rules
func (w *LocalWAF) Test(payload string) *LocalTestResult {
	result := &LocalTestResult{
		Blocked:       false,
		MatchedRules:  make([]int, 0),
		RuleMessages:  make([]string, 0),
		ParanoiaLevel: w.paranoiaLevel,
	}

	for _, rule := range w.rules {
		if rule.ParanoiaLevel > w.paranoiaLevel {
			continue // Skip rules above current paranoia level
		}

		if rule.Pattern.MatchString(payload) {
			result.Blocked = true
			result.MatchedRules = append(result.MatchedRules, rule.ID)
			result.RuleMessages = append(result.RuleMessages, rule.Description)
		}
	}

	return result
}

// loadCRSRules loads simplified CRS rule patterns
// These patterns simulate common CRS rules for FP testing
func (w *LocalWAF) loadCRSRules() {
	// SQL Injection rules (920xxx, 942xxx)
	w.addRule(942100, "SQL Injection Attack Detected via libinjection", 1, "sqli",
		`(?i)([\s\(\)])(select|insert|update|delete|drop|union|exec|execute)[\s\(]`)
	w.addRule(942110, "SQL Injection Attack: Common Injection Testing Detected", 1, "sqli",
		`(?i)'[\s]*or[\s]*'?\d*'?[\s]*=[\s]*'?\d*`)
	w.addRule(942120, "SQL Injection Attack: SQL Operator Detected", 1, "sqli",
		`(?i)([\s\(\)])(and|or)[\s]+[\d\w]+=[\d\w]+`)
	w.addRule(942130, "SQL Injection Attack: SQL Tautology Detected", 2, "sqli",
		`(?i)'\s*(or|and)\s*'\d+'\s*=\s*'\d+`)
	w.addRule(942140, "SQL Injection Attack: Common DB Names Detected", 2, "sqli",
		`(?i)(information_schema|mysql|sysobjects|syscolumns|msysaces)`)
	w.addRule(942150, "SQL Injection Attack: SQL Function Names", 2, "sqli",
		`(?i)(concat|char|chr|substring|ascii|hex|unhex|load_file|benchmark|sleep)\s*\(`)
	w.addRule(942160, "SQL Injection Attack: Blind SQLi Tests", 3, "sqli",
		`(?i)(sleep|benchmark|waitfor|delay)\s*\(`)

	// XSS rules (941xxx)
	w.addRule(941100, "XSS Attack Detected via libinjection", 1, "xss",
		`(?i)<script[^>]*>`)
	w.addRule(941110, "XSS Filter - Category 1: Script Tag Vector", 1, "xss",
		`(?i)<script[\s\S]*?>`)
	w.addRule(941120, "XSS Filter - Category 2: Event Handler Vector", 1, "xss",
		`(?i)\bon\w+\s*=`)
	w.addRule(941130, "XSS Filter - Category 3: Attribute Vector", 2, "xss",
		`(?i)javascript\s*:`)
	w.addRule(941140, "XSS Filter - Category 4: JS URI Vector", 2, "xss",
		`(?i)vbscript\s*:`)
	w.addRule(941150, "XSS Filter - Category 5: Disallowed HTML Attributes", 3, "xss",
		`(?i)(expression|behavior|binding)\s*\(`)
	w.addRule(941160, "XSS Filter - IE Filters", 3, "xss",
		`(?i)<\s*(iframe|object|embed|applet|form)`)

	// Path Traversal rules (930xxx)
	w.addRule(930100, "Path Traversal Attack (/../)", 1, "lfi",
		`(?i)(\.\.\/|\.\.\\)`)
	w.addRule(930110, "Path Traversal Attack (..;)", 2, "lfi",
		`(?i)\.\.;`)
	w.addRule(930120, "Path Traversal Attack: OS File Access", 2, "lfi",
		`(?i)(\/etc\/passwd|\/etc\/shadow|c:\\windows\\system32)`)

	// Remote Command Execution (932xxx)
	w.addRule(932100, "Remote Command Execution: Unix Command Injection", 1, "rce",
		`(?i)(;|\||&&)\s*(cat|ls|id|whoami|wget|curl|nc|netcat|bash|sh|perl|python|php|ruby)\s`)
	w.addRule(932105, "Remote Command Execution: Windows Command Injection", 1, "rce",
		`(?i)(;|\||&&)\s*(cmd|powershell|net\s|ping\s|nslookup|type\s)`)
	w.addRule(932110, "Remote Command Execution: Command Chaining", 2, "rce",
		`(?i)\$\([\s\S]+\)|\x60[\s\S]+\x60`)

	// Protocol Attack (921xxx)
	w.addRule(921100, "HTTP Request Smuggling Attack", 1, "protocol",
		`(?i)(transfer-encoding|content-length)[\s]*:.*\n.*(transfer-encoding|content-length)`)
	w.addRule(921110, "HTTP Response Splitting Attack", 1, "protocol",
		`(?i)[\r\n](set-cookie|location)\s*:`)

	// PHP Injection (933xxx)
	w.addRule(933100, "PHP Injection Attack", 2, "php",
		`(?i)<\?php|<\?=`)
	w.addRule(933110, "PHP Injection Attack: High-Risk PHP Function Call", 2, "php",
		`(?i)(eval|exec|system|shell_exec|passthru|proc_open|popen)\s*\(`)

	// Paranoia Level 3-4 Rules (more aggressive)
	w.addRule(942200, "SQL Comment Sequence Detected", 3, "sqli",
		`(?i)(--|#|\/\*|\*\/)`)
	w.addRule(942210, "SQL Comment Injection", 4, "sqli",
		`(?i)\/\*.*\*\/`)
	w.addRule(941200, "XSS using style tag", 3, "xss",
		`(?i)<style`)
	w.addRule(941210, "XSS using meta tag", 4, "xss",
		`(?i)<meta`)
	w.addRule(930200, "Directory listing pattern", 4, "lfi",
		`(?i)index\s+of\s+\/`)
}

// addRule adds a rule to the WAF
func (w *LocalWAF) addRule(id int, desc string, pl int, category, pattern string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return // Skip invalid patterns
	}

	w.rules = append(w.rules, LocalRule{
		ID:            id,
		Description:   desc,
		Pattern:       re,
		ParanoiaLevel: pl,
		Category:      category,
	})
}

// SetParanoiaLevel changes the paranoia level
func (w *LocalWAF) SetParanoiaLevel(pl int) {
	if pl >= 1 && pl <= 4 {
		w.paranoiaLevel = pl
	}
}

// GetRuleCount returns the number of active rules at current paranoia level
func (w *LocalWAF) GetRuleCount() int {
	count := 0
	for _, rule := range w.rules {
		if rule.ParanoiaLevel <= w.paranoiaLevel {
			count++
		}
	}
	return count
}

// TestCorpus runs FP testing against all corpus payloads
// This is a convenience method that wraps RunLocalFPTest for single paranoia level
func (w *LocalWAF) TestCorpus(verbose bool) map[int]*LocalFPStats {
	corpus := NewCorpus()
	// Load all corpus sources
	corpus.Load([]string{"leipzig", "edgecases", "forms", "api", "technical", "international"})

	if verbose {
		fmt.Printf("Tested %d payloads against %d rules\n",
			len(corpus.All()), w.GetRuleCount())
	}

	results := RunLocalFPTest(corpus, []int{w.paranoiaLevel})
	return results
}

// LocalFPStats tracks false positive statistics by rule
type LocalFPStats struct {
	TotalTests      int64            `json:"total_tests"`
	FalsePositives  int64            `json:"false_positives"`
	TrueNegatives   int64            `json:"true_negatives"`
	FPRatio         float64          `json:"fp_ratio"`
	ByRule          map[int]int64    `json:"by_rule"`
	ByParanoiaLevel map[int]int64    `json:"by_paranoia_level"`
	ByCategory      map[string]int64 `json:"by_category"`
	TopFPRules      []RuleFPInfo     `json:"top_fp_rules"`
}

// RuleFPInfo contains FP info for a specific rule
type RuleFPInfo struct {
	RuleID      int    `json:"rule_id"`
	Description string `json:"description"`
	FPCount     int64  `json:"fp_count"`
	Category    string `json:"category"`
}

// NewLocalFPStats creates new stats tracker
func NewLocalFPStats() *LocalFPStats {
	return &LocalFPStats{
		ByRule:          make(map[int]int64),
		ByParanoiaLevel: make(map[int]int64),
		ByCategory:      make(map[string]int64),
		TopFPRules:      make([]RuleFPInfo, 0),
	}
}

// RunLocalFPTest runs comprehensive FP testing using local WAF
func RunLocalFPTest(corpus *Corpus, paranoiaLevels []int) map[int]*LocalFPStats {
	results := make(map[int]*LocalFPStats)

	for _, pl := range paranoiaLevels {
		waf := NewLocalWAF(pl)
		stats := NewLocalFPStats()

		payloads := corpus.All()
		for _, payload := range payloads {
			stats.TotalTests++
			result := waf.Test(payload)

			if result.Blocked {
				stats.FalsePositives++
				for _, ruleID := range result.MatchedRules {
					stats.ByRule[ruleID]++
				}
				stats.ByParanoiaLevel[pl]++
			} else {
				stats.TrueNegatives++
			}
		}

		if stats.TotalTests > 0 {
			stats.FPRatio = float64(stats.FalsePositives) / float64(stats.TotalTests)
		}

		// Build top FP rules
		for ruleID, count := range stats.ByRule {
			for _, rule := range waf.rules {
				if rule.ID == ruleID {
					stats.TopFPRules = append(stats.TopFPRules, RuleFPInfo{
						RuleID:      ruleID,
						Description: rule.Description,
						FPCount:     count,
						Category:    rule.Category,
					})
					stats.ByCategory[rule.Category] += count
					break
				}
			}
		}

		results[pl] = stats
	}

	return results
}

// FormatLocalFPReport formats the local FP test results
func FormatLocalFPReport(stats map[int]*LocalFPStats) string {
	var sb strings.Builder

	sb.WriteString("=== Local WAF False Positive Analysis ===\n\n")

	for pl := 1; pl <= 4; pl++ {
		if s, ok := stats[pl]; ok {
			sb.WriteString(fmt.Sprintf("Paranoia Level %d:\n", pl))
			sb.WriteString(fmt.Sprintf("  Total Tests:     %d\n", s.TotalTests))
			sb.WriteString(fmt.Sprintf("  False Positives: %d\n", s.FalsePositives))
			sb.WriteString(fmt.Sprintf("  True Negatives:  %d\n", s.TrueNegatives))
			sb.WriteString(fmt.Sprintf("  FP Ratio:        %.2f%%\n", s.FPRatio))

			if len(s.TopFPRules) > 0 {
				sb.WriteString("\n  Top Triggering Rules:\n")
				for i, rule := range s.TopFPRules {
					if i >= 5 {
						break
					}
					sb.WriteString(fmt.Sprintf("    [%d] %s: %d FPs\n",
						rule.RuleID, rule.Description, rule.FPCount))
				}
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}
