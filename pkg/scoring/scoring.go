package scoring

import (
	"strings"

	"github.com/waftester/waftester/pkg/defaults"
)

// Input contains all data needed for risk calculation
type Input struct {
	Severity   string
	Outcome    string
	StatusCode int
	LatencyMs  int64
	Category   string
	// Optional evidence fields for escalation
	ResponseContains string
	Reflected        bool
}

// Result contains the calculated risk score and metadata
type Result struct {
	RiskScore        float64
	FinalSeverity    string
	EscalationReason string
}

// Base severity scores (matching PowerShell logic)
var severityScores = map[string]float64{
	"critical": 10.0,
	"high":     7.0,
	"medium":   5.0,
	"low":      3.0,
}

// Sensitive patterns for escalation (ported from PowerShell)
var sensitivePatterns = map[string]struct {
	Impact float64
	Reason string
}{
	"root:x:0:0":        {Impact: 3.0, Reason: "/etc/passwd contents detected"},
	"AWS_ACCESS_KEY_ID": {Impact: 4.0, Reason: "AWS credentials exposed"},
	"DATABASE_URL":      {Impact: 3.5, Reason: "Database connection string leaked"},
	"SECRET_KEY":        {Impact: 3.0, Reason: "Application secret key exposed"},
	"-----BEGIN":        {Impact: 4.0, Reason: "Private key exposed"},
	"SQL syntax":        {Impact: 2.5, Reason: "SQL error indicates injection success"},
}

// Calculate computes the risk score using multi-factor algorithm
// Ported from PowerShell Scoring.ps1
func Calculate(input Input) Result {
	result := Result{
		FinalSeverity: input.Severity,
	}

	// Get base severity score (case-insensitive)
	severity := strings.ToLower(input.Severity)
	baseSeverity, ok := severityScores[severity]
	if !ok {
		baseSeverity = 5.0 // Default to Medium
	}

	// Initialize modifiers
	impactWeight := 1.0
	exploitabilityMod := 0.0
	detectionMod := 0.0

	// 1. Outcome-based impact adjustment (case-insensitive)
	outcome := strings.ToLower(input.Outcome)
	switch outcome {
	case "fail":
		impactWeight = 1.5 // Vulnerability confirmed
	case "blocked":
		impactWeight = 0.3 // WAF working
		detectionMod = -2.0
	case "pass":
		impactWeight = 0.1 // Safe
		detectionMod = -3.0
	case "error":
		impactWeight = 0.5 // Uncertain
		detectionMod = -1.0
	}

	// 2. Check for sensitive patterns (if response provided)
	if input.ResponseContains != "" {
		var bestImpact float64
		var bestReason string
		for pattern, info := range sensitivePatterns {
			if containsSecurityPattern(input.ResponseContains, pattern) {
				if info.Impact > bestImpact {
					bestImpact = info.Impact
					bestReason = info.Reason
				}
			}
		}
		if bestImpact > 0 {
			exploitabilityMod += bestImpact
			result.EscalationReason = bestReason
			if bestImpact >= 4.0 && strings.ToLower(result.FinalSeverity) != "critical" {
				result.FinalSeverity = "Critical"
				baseSeverity = severityScores["critical"]
			}
		}
	}

	// 3. XSS reflection check
	if input.Reflected {
		exploitabilityMod += 2.0
		if result.EscalationReason == "" {
			result.EscalationReason = "XSS payload reflected"
		}
	}

	// 4. Timing attack detection (blind SQLi, etc.)
	if input.LatencyMs > defaults.TimingThresholdMs && outcome == "fail" {
		exploitabilityMod += 1.5
		if result.EscalationReason == "" {
			result.EscalationReason = "Timing differential suggests blind injection"
		}
	}

	// 5. Category-based escalation reasons (if no specific reason yet)
	if result.EscalationReason == "" && outcome == "fail" {
		result.EscalationReason = getCategoryEscalationReason(input.Category, input.StatusCode)
	}

	// 6. Blocked tests get a reason too
	if result.EscalationReason == "" && outcome == "blocked" {
		result.EscalationReason = "WAF blocked attack attempt"
	}

	// 7. Pass/Error get generic reasons
	if result.EscalationReason == "" {
		switch outcome {
		case "pass":
			result.EscalationReason = "Test passed - no vulnerability detected"
		case "error":
			result.EscalationReason = "Test error - inconclusive result"
		default:
			// Catch-all for any uncategorized outcome
			result.EscalationReason = "Test completed with outcome: " + input.Outcome
		}
	}

	// Calculate final score: (impact * base + mods) / normalization
	// Normalize to 0-100 scale
	rawScore := (impactWeight*baseSeverity + exploitabilityMod + detectionMod)
	result.RiskScore = normalize(rawScore)

	return result
}

// normalize scales the score to 0-100
func normalize(raw float64) float64 {
	// Max possible: 1.5 * 10 + 4 + 0 = 19
	// Min possible: 0.1 * 3 + 0 - 3 = -2.7
	// Scale to 0-100
	normalized := ((raw + 3) / 22) * defaults.NormalizationScale
	if normalized < 0 {
		return 0
	}
	if normalized > defaults.NormalizationScale {
		return 100
	}
	return normalized
}

// containsSecurityPattern checks for pattern with word boundary awareness
// to avoid false positives like "notroot:x:0:0" matching "root:x:0:0"
func containsSecurityPattern(text, pattern string) bool {
	if len(text) == 0 || len(pattern) == 0 {
		return false
	}

	for i := 0; i <= len(text)-len(pattern); i++ {
		if text[i:i+len(pattern)] == pattern {
			// Check for word boundary at start (not preceded by alphanumeric)
			if i > 0 {
				prevChar := text[i-1]
				if isAlphanumeric(prevChar) {
					continue // Not a word boundary, skip this match
				}
			}
			return true
		}
	}
	return false
}

// isAlphanumeric checks if a byte is a letter or digit
func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// getCategoryEscalationReason returns a reason based on attack category for failed tests
func getCategoryEscalationReason(category string, statusCode int) string {
	cat := strings.ToLower(category)

	// Status code hints
	statusHint := ""
	switch statusCode {
	case 200:
		statusHint = " (200 OK response)"
	case 500:
		statusHint = " (server error triggered)"
	case 302, 301:
		statusHint = " (redirect behavior)"
	}

	switch cat {
	case "sqli", "injection":
		return "SQL/Command injection payload not blocked" + statusHint
	case "xss":
		return "XSS payload reached application" + statusHint
	case "xxe":
		return "XXE payload processed by server" + statusHint
	case "ssrf":
		return "SSRF payload may have reached internal resources" + statusHint
	case "traversal", "lfi":
		return "Path traversal payload not filtered" + statusHint
	case "auth":
		return "Authentication bypass attempt not blocked" + statusHint
	case "rce", "cmd":
		return "Remote code execution payload not blocked" + statusHint
	case "upload", "media":
		return "Malicious file upload not prevented" + statusHint
	case "template":
		return "Template injection payload processed" + statusHint
	case "deserialize":
		return "Deserialization payload not blocked" + statusHint
	case "graphql":
		return "GraphQL attack payload accepted" + statusHint
	case "nosql":
		return "NoSQL injection payload not blocked" + statusHint
	case "ldap":
		return "LDAP injection payload not blocked" + statusHint
	case "protocol":
		return "HTTP protocol attack not prevented" + statusHint
	case "waf-bypass":
		return "WAF evasion technique succeeded" + statusHint
	case "waf-validation":
		return "WAF validation test failed" + statusHint
	default:
		return "Attack payload bypassed security controls" + statusHint
	}
}
