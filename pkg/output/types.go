package output

import (
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

	// Encoding/mutation tracking
	EncodingUsed    string `json:"encoding_used,omitempty"`    // url, double_url, base64, etc.
	MutationType    string `json:"mutation_type,omitempty"`    // encoder type applied
	OriginalPayload string `json:"original_payload,omitempty"` // Pre-mutation payload
}

// OWASPMapping maps attack categories to OWASP Top 10 2021
var OWASPMapping = map[string]struct {
	OWASP string
	CWE   []string
}{
	"sqli":            {"A03:2021-Injection", []string{"CWE-89"}},
	"injection":       {"A03:2021-Injection", []string{"CWE-89", "CWE-77", "CWE-78"}},
	"xss":             {"A03:2021-Injection", []string{"CWE-79"}},
	"xxe":             {"A05:2021-Security Misconfiguration", []string{"CWE-611"}},
	"ssrf":            {"A10:2021-SSRF", []string{"CWE-918"}},
	"traversal":       {"A01:2021-Broken Access Control", []string{"CWE-22"}},
	"auth":            {"A07:2021-Identification and Authentication Failures", []string{"CWE-287"}},
	"idor":            {"A01:2021-Broken Access Control", []string{"CWE-639"}},
	"deserialize":     {"A08:2021-Software and Data Integrity Failures", []string{"CWE-502"}},
	"crypto":          {"A02:2021-Cryptographic Failures", []string{"CWE-327"}},
	"rce":             {"A03:2021-Injection", []string{"CWE-78", "CWE-94"}},
	"lfi":             {"A01:2021-Broken Access Control", []string{"CWE-22", "CWE-98"}},
	"rfi":             {"A03:2021-Injection", []string{"CWE-98"}},
	"cmd":             {"A03:2021-Injection", []string{"CWE-78"}},
	"template":        {"A03:2021-Injection", []string{"CWE-94"}},
	"nosql":           {"A03:2021-Injection", []string{"CWE-943"}},
	"ldap":            {"A03:2021-Injection", []string{"CWE-90"}},
	"generic-attacks": {"A03:2021-Injection", []string{"CWE-74"}},
}

// ErrorCategory categorizes test errors for better analysis
type ErrorCategory string

const (
	ErrorTimeout    ErrorCategory = "timeout"
	ErrorDNS        ErrorCategory = "dns_failure"
	ErrorTLS        ErrorCategory = "tls_error"
	ErrorConnection ErrorCategory = "connection_refused"
	ErrorHTTPStatus ErrorCategory = "unexpected_status"
	ErrorInvalidReq ErrorCategory = "invalid_request"
	ErrorRateLimit  ErrorCategory = "rate_limited"
	ErrorUnknown    ErrorCategory = "unknown"
)

// Writer interface for different output formats
type Writer interface {
	Write(result *TestResult) error
	Close() error
}
