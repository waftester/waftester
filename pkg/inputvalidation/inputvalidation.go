// Package inputvalidation provides testing for Input Validation vulnerabilities
package inputvalidation

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VulnerabilityType represents input validation vulnerability types
type VulnerabilityType string

const (
	TypeJuggling           VulnerabilityType = "type_juggling"
	IntegerOverflow        VulnerabilityType = "integer_overflow"
	BufferOverflow         VulnerabilityType = "buffer_overflow"
	FormatStringVuln       VulnerabilityType = "format_string"
	UnicodeBypass          VulnerabilityType = "unicode_bypass"
	NullByteInjection      VulnerabilityType = "null_byte_injection"
	ArrayIndexManipulation VulnerabilityType = "array_index_manipulation"
	RegexDoS               VulnerabilityType = "regex_dos"
	EncodingBypass         VulnerabilityType = "encoding_bypass"
	BoundaryCondition      VulnerabilityType = "boundary_condition"
)

// TestResult represents an input validation test result
type TestResult struct {
	VulnType    VulnerabilityType `json:"vuln_type"`
	Endpoint    string            `json:"endpoint"`
	Parameter   string            `json:"parameter"`
	Payload     string            `json:"payload"`
	Vulnerable  bool              `json:"vulnerable"`
	Description string            `json:"description"`
	StatusCode  int               `json:"status_code"`
	Response    string            `json:"response,omitempty"`
	Severity    string            `json:"severity"`
	Remediation string            `json:"remediation"`
}

// Tester performs input validation testing
type Tester struct {
	client  *http.Client
	target  string
	timeout time.Duration
}

// NewTester creates a new input validation tester
func NewTester(target string, timeout time.Duration) *Tester {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Tester{
		client: &http.Client{
			Timeout: timeout,
		},
		target:  target,
		timeout: timeout,
	}
}

// TypeJugglingPayloads returns payloads for type juggling attacks (PHP-style)
func TypeJugglingPayloads() []struct {
	Value    string
	Expected string
} {
	return []struct {
		Value    string
		Expected string
	}{
		{"0", "Zero as string"},
		{"0e123", "Scientific notation zero"},
		{"0e215962017", "MD5 magic hash"},
		{"[]", "Empty array"},
		{"[0]", "Array with zero"},
		{"true", "Boolean true"},
		{"false", "Boolean false"},
		{"null", "Null value"},
		{"0x0", "Hex zero"},
		{"0b0", "Binary zero"},
		{"", "Empty string"},
		{`{"0": 0}`, "Object with zero key"},
		{"0.0", "Float zero"},
		{"-0", "Negative zero"},
		{"00", "Octal-like zero"},
	}
}

// IntegerOverflowPayloads returns integer overflow test values
func IntegerOverflowPayloads() []struct {
	Value       string
	Description string
} {
	return []struct {
		Value       string
		Description string
	}{
		{"2147483647", "Max int32"},
		{"2147483648", "Max int32 + 1"},
		{"-2147483648", "Min int32"},
		{"-2147483649", "Min int32 - 1"},
		{"9223372036854775807", "Max int64"},
		{"9223372036854775808", "Max int64 + 1"},
		{"18446744073709551615", "Max uint64"},
		{"18446744073709551616", "Max uint64 + 1"},
		{"-1", "Negative one (uint underflow)"},
		{"0xFFFFFFFF", "Hex max uint32"},
		{"0xFFFFFFFFFFFFFFFF", "Hex max uint64"},
		{"999999999999999999999999999", "Very large number"},
		{"1e308", "Near max float64"},
		{"1e309", "Overflow float64"},
	}
}

// BufferOverflowPayloads returns buffer overflow test payloads
func BufferOverflowPayloads() []struct {
	Size        int
	Description string
} {
	return []struct {
		Size        int
		Description string
	}{
		{256, "256 bytes"},
		{512, "512 bytes"},
		{1024, "1KB"},
		{4096, "4KB"},
		{8192, "8KB"},
		{65536, "64KB"},
		{1048576, "1MB"},
	}
}

// FormatStringPayloads returns format string vulnerability payloads
func FormatStringPayloads() []string {
	return []string{
		"%s",
		"%x",
		"%n",
		"%p",
		"%.1024d",
		"%s%s%s%s%s",
		"%x%x%x%x%x",
		"%n%n%n%n%n",
		"%p%p%p%p%p",
		"AAAA%08x.%08x.%08x.%08x",
		"%1$s",
		"%1$n",
		"${7*7}",
		"{{7*7}}",
		"<%= 7*7 %>",
	}
}

// UnicodeBypassPayloads returns unicode normalization bypass payloads
func UnicodeBypassPayloads() []struct {
	Payload     string
	Description string
} {
	return []struct {
		Payload     string
		Description string
	}{
		{"\uff41\uff44\uff4d\uff49\uff4e", "Fullwidth 'admin'"},
		{"\u0041\u0044\u004d\u0049\u004e", "Unicode 'ADMIN'"},
		{"a\u0000dmin", "Null byte in string"},
		{"adm\u200bin", "Zero-width space"},
		{"adm\uFEFFin", "BOM in string"},
		{"\u0391\u0394\u039c\u0399\u039d", "Greek lookalike"},
		{"аdmin", "Cyrillic 'a'"},
		{"ɑdmin", "Latin alpha"},
		{"adm\u0131n", "Dotless i"},
		{"ad\u1d50in", "Modifier letter m"},
		{"\u212b", "Angstrom sign (normalizes to A)"},
		{"scr\u0131pt", "Dotless i in 'script'"},
		{"\uff1cscript\uff1e", "Fullwidth angle brackets"},
	}
}

// NullBytePayloads returns null byte injection payloads
func NullBytePayloads() []string {
	return []string{
		"test%00.txt",
		"test\x00.txt",
		"%00",
		"\x00",
		"file.php%00.jpg",
		"../../etc/passwd%00",
		"admin%00ignored",
		"%00%00%00",
		"test%00test",
		"name=%00value",
		"test\x00\x00\x00",
	}
}

// ArrayManipulationPayloads returns array index manipulation payloads
func ArrayManipulationPayloads() []string {
	return []string{
		"param[]",
		"param[0]",
		"param[-1]",
		"param[999999]",
		"param[__proto__]",
		"param[constructor]",
		"param[prototype]",
		"param[length]",
		"param[][0]",
		"param[0][0]",
		"param['test']",
		`param["test"]`,
	}
}

// RegexDoSPayloads returns ReDoS payloads
func RegexDoSPayloads() []string {
	return []string{
		strings.Repeat("a", 30) + "!",
		strings.Repeat("a", 50) + "X",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
		strings.Repeat("0", 50) + "x",
		"<" + strings.Repeat(" ", 1000) + ">",
		strings.Repeat("=", 100),
		"a]" + strings.Repeat("[", 30),
		strings.Repeat("(a+)+", 5) + "!",
		strings.Repeat("\\d+", 20) + "x",
	}
}

// EncodingBypassPayloads returns encoding bypass payloads
func EncodingBypassPayloads() []struct {
	Payload     string
	Description string
} {
	return []struct {
		Payload     string
		Description string
	}{
		{"%3Cscript%3E", "URL encoded <script>"},
		{"%253Cscript%253E", "Double URL encoded"},
		{"&#60;script&#62;", "HTML entity encoded"},
		{"&#x3c;script&#x3e;", "Hex HTML entity"},
		{"\u003cscript\u003e", "Unicode escaped"},
		{"PHNjcmlwdD4=", "Base64 encoded <script>"},
		{"%u003cscript%u003e", "IIS Unicode"},
		{"%%33%63script%%33%65", "Mixed encoding"},
		{"<scr%00ipt>", "Null byte in tag"},
		{"<scr\tipt>", "Tab in tag"},
		{"<scr\nipt>", "Newline in tag"},
	}
}

// BoundaryPayloads returns boundary condition test values
func BoundaryPayloads() []struct {
	Value       string
	Description string
} {
	return []struct {
		Value       string
		Description string
	}{
		{"0", "Zero"},
		{"-1", "Negative one"},
		{"1", "One"},
		{"", "Empty"},
		{" ", "Single space"},
		{"\t", "Tab"},
		{"\n", "Newline"},
		{"\r\n", "CRLF"},
		{"\\", "Backslash"},
		{"/", "Forward slash"},
		{".", "Dot"},
		{"..", "Double dot"},
		{"...", "Triple dot"},
		{"NaN", "Not a number"},
		{"Infinity", "Infinity"},
		{"-Infinity", "Negative infinity"},
		{"undefined", "Undefined"},
	}
}

// TestTypeJuggling tests for type juggling vulnerabilities
func (t *Tester) TestTypeJuggling(ctx context.Context, endpoint, param string) ([]TestResult, error) {
	var results []TestResult

	payloads := TypeJugglingPayloads()

	for _, p := range payloads {
		fullURL := t.target + endpoint + "?" + url.QueryEscape(param) + "=" + url.QueryEscape(p.Value)

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		result := TestResult{
			VulnType:   TypeJuggling,
			Endpoint:   endpoint,
			Parameter:  param,
			Payload:    p.Value,
			StatusCode: resp.StatusCode,
			Severity:   "High",
		}

		// Check for unexpected success
		if resp.StatusCode == 200 && len(body) > 0 {
			// Check if the payload caused unexpected behavior
			bodyStr := strings.ToLower(string(body))
			if strings.Contains(bodyStr, "success") ||
				strings.Contains(bodyStr, "welcome") ||
				strings.Contains(bodyStr, "admin") {
				result.Vulnerable = true
				result.Description = fmt.Sprintf("Type juggling with '%s' may have bypassed validation", p.Expected)
				result.Response = string(body[:min(100, len(body))])
				result.Remediation = "Use strict type comparison (=== in PHP/JS)"
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// TestIntegerOverflow tests for integer overflow vulnerabilities
func (t *Tester) TestIntegerOverflow(ctx context.Context, endpoint, param string) ([]TestResult, error) {
	var results []TestResult

	payloads := IntegerOverflowPayloads()

	for _, p := range payloads {
		fullURL := t.target + endpoint + "?" + url.QueryEscape(param) + "=" + url.QueryEscape(p.Value)

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		result := TestResult{
			VulnType:   IntegerOverflow,
			Endpoint:   endpoint,
			Parameter:  param,
			Payload:    p.Value,
			StatusCode: resp.StatusCode,
			Severity:   "High",
		}

		// Check for error messages indicating overflow
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "overflow") ||
			strings.Contains(bodyStr, "out of range") ||
			strings.Contains(bodyStr, "too large") ||
			resp.StatusCode == 500 {
			result.Vulnerable = true
			result.Description = fmt.Sprintf("Integer overflow detected with %s", p.Description)
			result.Response = string(body[:min(200, len(body))])
			result.Remediation = "Validate integer ranges before processing"
		}

		results = append(results, result)
	}

	return results, nil
}

// TestFormatString tests for format string vulnerabilities
func (t *Tester) TestFormatString(ctx context.Context, endpoint, param string) ([]TestResult, error) {
	var results []TestResult

	payloads := FormatStringPayloads()

	for _, payload := range payloads {
		fullURL := t.target + endpoint + "?" + url.QueryEscape(param) + "=" + url.QueryEscape(payload)

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		result := TestResult{
			VulnType:   FormatStringVuln,
			Endpoint:   endpoint,
			Parameter:  param,
			Payload:    payload,
			StatusCode: resp.StatusCode,
			Severity:   "Critical",
		}

		// Check if format string was interpreted
		bodyStr := string(body)
		// If we sent %x and see hex in response, or payload not reflected as-is
		if strings.Contains(payload, "%") && !strings.Contains(bodyStr, payload) && len(bodyStr) > 0 {
			// Format specifiers may have been interpreted
			if strings.Contains(bodyStr, "0x") || strings.Contains(bodyStr, "(nil)") {
				result.Vulnerable = true
				result.Description = "Format string payload appears to be interpreted"
				result.Response = string(body[:min(200, len(body))])
				result.Remediation = "Never pass user input directly to format functions"
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// TestNullByte tests for null byte injection vulnerabilities
func (t *Tester) TestNullByte(ctx context.Context, endpoint, param string) ([]TestResult, error) {
	var results []TestResult

	payloads := NullBytePayloads()

	for _, payload := range payloads {
		fullURL := t.target + endpoint + "?" + param + "=" + url.QueryEscape(payload)

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		result := TestResult{
			VulnType:   NullByteInjection,
			Endpoint:   endpoint,
			Parameter:  param,
			Payload:    payload,
			StatusCode: resp.StatusCode,
			Severity:   "High",
		}

		// Successful 200 with null byte in path could indicate vulnerability
		if resp.StatusCode == 200 && strings.Contains(payload, "passwd") {
			bodyStr := string(body)
			if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "/bin/") {
				result.Vulnerable = true
				result.Description = "Null byte injection may have bypassed extension check"
				result.Response = string(body[:min(200, len(body))])
				result.Remediation = "Reject input containing null bytes"
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// TestUnicodeBypass tests for unicode normalization bypass
func (t *Tester) TestUnicodeBypass(ctx context.Context, endpoint, param string) ([]TestResult, error) {
	var results []TestResult

	payloads := UnicodeBypassPayloads()

	for _, p := range payloads {
		fullURL := t.target + endpoint + "?" + param + "=" + url.QueryEscape(p.Payload)

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		result := TestResult{
			VulnType:   UnicodeBypass,
			Endpoint:   endpoint,
			Parameter:  param,
			Payload:    p.Payload,
			StatusCode: resp.StatusCode,
			Severity:   "Medium",
		}

		// Check if unicode characters bypassed filter
		if resp.StatusCode == 200 {
			bodyStr := strings.ToLower(string(body))
			if strings.Contains(bodyStr, "admin") || strings.Contains(bodyStr, "success") {
				result.Vulnerable = true
				result.Description = fmt.Sprintf("Unicode bypass (%s) may have succeeded", p.Description)
				result.Response = string(body[:min(200, len(body))])
				result.Remediation = "Normalize unicode before validation, reject unexpected characters"
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// TestEncodingBypass tests for encoding bypass vulnerabilities
func (t *Tester) TestEncodingBypass(ctx context.Context, endpoint, param string) ([]TestResult, error) {
	var results []TestResult

	payloads := EncodingBypassPayloads()

	for _, p := range payloads {
		fullURL := t.target + endpoint + "?" + param + "=" + url.QueryEscape(p.Payload)

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		result := TestResult{
			VulnType:   EncodingBypass,
			Endpoint:   endpoint,
			Parameter:  param,
			Payload:    p.Payload,
			StatusCode: resp.StatusCode,
			Severity:   "High",
		}

		// Check if encoded payload was reflected (XSS) or executed
		bodyStr := string(body)
		// If the decoded form appears in response
		if strings.Contains(strings.ToLower(bodyStr), "<script>") ||
			strings.Contains(strings.ToLower(bodyStr), "script") {
			result.Vulnerable = true
			result.Description = fmt.Sprintf("Encoding bypass (%s) may have succeeded", p.Description)
			result.Response = string(body[:min(200, len(body))])
			result.Remediation = "Decode all layers before validation, use output encoding"
		}

		results = append(results, result)
	}

	return results, nil
}

// AllPayloadCategories returns all payload categories
func AllPayloadCategories() []string {
	return []string{
		"type_juggling",
		"integer_overflow",
		"buffer_overflow",
		"format_string",
		"unicode_bypass",
		"null_byte",
		"array_manipulation",
		"regex_dos",
		"encoding_bypass",
		"boundary",
	}
}

// GenerateBufferPayload generates a buffer overflow payload of specified size
func GenerateBufferPayload(size int, char byte) string {
	return strings.Repeat(string(char), size)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
