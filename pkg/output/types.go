package output

import (
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/scoring"
)

// TestResult represents a single test execution result
// Matches the schema from PowerShell Core.psm1
type TestResult struct {
	ID           string         `json:"id"`
	Category     string         `json:"category"`
	Severity     string         `json:"severity"`
	Outcome      string         `json:"outcome"` // Pass, Blocked, Fail, Error
	StatusCode   int            `json:"status_code"`
	LatencyMs    int64          `json:"latency_ms"`
	Payload      string         `json:"payload,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	RiskScore    scoring.Result `json:"risk_score"`
	Timestamp    string         `json:"timestamp,omitempty"`

	// Request details (populated from payload)
	Method      string `json:"method,omitempty"`       // HTTP method used
	TargetPath  string `json:"target_path,omitempty"`  // Endpoint path tested
	ContentType string `json:"content_type,omitempty"` // Request content type
	RequestURL  string `json:"request_url,omitempty"`  // Full URL tested

	// Response details (for filtering - ffuf-style)
	ContentLength   int               `json:"content_length,omitempty"`   // Response body size
	WordCount       int               `json:"word_count,omitempty"`       // Words in response
	LineCount       int               `json:"line_count,omitempty"`       // Lines in response
	Filtered        bool              `json:"-"`                          // True if filtered out (not shown)
	ResponseHeaders map[string]string `json:"response_headers,omitempty"` // Key response headers
	WAFRuleID       string            `json:"waf_rule_id,omitempty"`      // WAF rule that blocked (if detected)
	BlockConfidence float64           `json:"block_confidence,omitempty"` // Detection confidence 0-1

	// Reproducibility (for bypass analysis)
	CurlCommand string `json:"curl_command,omitempty"` // curl command to reproduce

	// Response evidence (for bypass verification)
	ResponseBodySnippet string   `json:"response_body_snippet,omitempty"` // First 300 chars of response
	ResponseBodyHash    string   `json:"response_body_hash,omitempty"`    // SHA256 prefix for dedup
	EvidenceMarkers     []string `json:"evidence_markers,omitempty"`      // Detected vuln patterns

	// Detection information (v2.5.2)
	DropDetected  bool    `json:"drop_detected,omitempty"`  // Connection drop detected
	DropType      string  `json:"drop_type,omitempty"`      // Type of drop (tcp_reset, tls_abort, timeout, eof, tarpit)
	BanDetected   bool    `json:"ban_detected,omitempty"`   // Silent ban detected
	BanType       string  `json:"ban_type,omitempty"`       // Type of ban (rate_limit, ip_block, behavioral, honeypot)
	BanConfidence float64 `json:"ban_confidence,omitempty"` // Ban detection confidence 0-1
	LatencyDrift  float64 `json:"latency_drift,omitempty"`  // Latency change ratio vs baseline

	// Encoding/mutation tracking
	EncodingUsed    string `json:"encoding_used,omitempty"`    // url, double_url, base64, etc.
	MutationType    string `json:"mutation_type,omitempty"`    // encoder type applied
	OriginalPayload string `json:"original_payload,omitempty"` // Pre-mutation payload
}

// OWASPMapping maps attack categories to OWASP Top 10 2021 and CWE IDs.
// OWASP codes are derived from defaults.OWASPCategoryMapping at runtime.
var OWASPMapping = func() map[string]struct {
	OWASP string
	CWE   []string
} {
	// CWE mappings for each category
	cwes := map[string][]string{
		"sqli":            {"CWE-89"},
		"injection":       {"CWE-89", "CWE-77", "CWE-78"},
		"xss":             {"CWE-79"},
		"xxe":             {"CWE-611"},
		"ssrf":            {"CWE-918"},
		"traversal":       {"CWE-22"},
		"auth":            {"CWE-287"},
		"idor":            {"CWE-639"},
		"deserialize":     {"CWE-502"},
		"crypto":          {"CWE-327"},
		"rce":             {"CWE-78", "CWE-94"},
		"lfi":             {"CWE-22", "CWE-98"},
		"rfi":             {"CWE-98"},
		"cmd":             {"CWE-78"},
		"template":        {"CWE-94"},
		"nosql":           {"CWE-943"},
		"ldap":            {"CWE-90"},
		"generic-attacks": {"CWE-74"},
	}

	result := make(map[string]struct {
		OWASP string
		CWE   []string
	})

	// Build from centralized OWASPCategoryMapping
	for category := range cwes {
		cat := defaults.GetOWASPForCategory(category)
		result[category] = struct {
			OWASP string
			CWE   []string
		}{
			OWASP: cat.FullName,
			CWE:   cwes[category],
		}
	}

	return result
}()

// ErrorCategory categorizes test errors for better analysis
type ErrorCategory string

const (
	ErrorTimeout    ErrorCategory = "timeout"
	ErrorDNS        ErrorCategory = "dns_failure"
	ErrorTLS        ErrorCategory = "tls_error"
	ErrorConnection ErrorCategory = "connection_refused"
	ErrorHTTPStatus   ErrorCategory = "unexpected_status"
	ErrorInvalidReq   ErrorCategory = "invalid_request"
	ErrorRateLimit    ErrorCategory = "rate_limited"
	ErrorDropDetected ErrorCategory = "connection_drop"
	ErrorSilentBan    ErrorCategory = "silent_ban"
	ErrorTarpit       ErrorCategory = "tarpit"
	ErrorUnknown      ErrorCategory = "unknown"
)

// ResultWriter is the legacy interface for writing TestResult values.
// For event-based output, use dispatcher.Writer instead.
type ResultWriter interface {
	Write(result *TestResult) error
	Close() error
}
