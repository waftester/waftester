package plugin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// HTTPClient is the HTTP client used by built-in scanners
var HTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// HeaderScanner checks for security headers
type HeaderScanner struct{}

// NewHeaderScanner creates a new security header scanner
func NewHeaderScanner() *HeaderScanner {
	return &HeaderScanner{}
}

func (s *HeaderScanner) Name() string        { return "headers" }
func (s *HeaderScanner) Description() string { return "Checks for security headers" }
func (s *HeaderScanner) Version() string     { return "1.0.0" }

func (s *HeaderScanner) Init(config map[string]interface{}) error { return nil }
func (s *HeaderScanner) Cleanup() error                           { return nil }

func (s *HeaderScanner) Scan(ctx context.Context, target *Target) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{Scanner: s.Name()}

	req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for security headers
	securityHeaders := map[string]struct {
		expected string
		severity string
		cwe      string
		desc     string
	}{
		"X-Frame-Options": {
			expected: "DENY|SAMEORIGIN",
			severity: "medium",
			cwe:      "CWE-1021",
			desc:     "Missing X-Frame-Options header allows clickjacking attacks",
		},
		"X-Content-Type-Options": {
			expected: "nosniff",
			severity: "low",
			cwe:      "CWE-16",
			desc:     "Missing X-Content-Type-Options allows MIME-sniffing attacks",
		},
		"Strict-Transport-Security": {
			expected: "max-age=",
			severity: "medium",
			cwe:      "CWE-319",
			desc:     "Missing HSTS header allows protocol downgrade attacks",
		},
		"Content-Security-Policy": {
			expected: "default-src",
			severity: "medium",
			cwe:      "CWE-79",
			desc:     "Missing CSP header increases XSS risk",
		},
		"X-XSS-Protection": {
			expected: "1",
			severity: "info",
			cwe:      "CWE-79",
			desc:     "Missing X-XSS-Protection header (deprecated but still useful)",
		},
		"Referrer-Policy": {
			expected: "no-referrer|strict-origin|same-origin",
			severity: "low",
			cwe:      "CWE-200",
			desc:     "Missing Referrer-Policy header may leak sensitive URLs",
		},
		"Permissions-Policy": {
			expected: "",
			severity: "low",
			cwe:      "CWE-16",
			desc:     "Missing Permissions-Policy header doesn't restrict browser features",
		},
	}

	for header, check := range securityHeaders {
		value := resp.Header.Get(header)
		if value == "" {
			result.Findings = append(result.Findings, Finding{
				Title:       fmt.Sprintf("Missing %s Header", header),
				Description: check.desc,
				Severity:    check.severity,
				Type:        "missing-header",
				CWE:         check.cwe,
				MatchedAt:   target.URL,
				Remediation: fmt.Sprintf("Add the %s header to responses", header),
			})
		} else if check.expected != "" {
			matched := false
			for _, exp := range strings.Split(check.expected, "|") {
				if strings.Contains(strings.ToLower(value), strings.ToLower(exp)) {
					matched = true
					break
				}
			}
			if !matched {
				result.Info = append(result.Info, InfoItem{
					Title: header,
					Value: value,
					Type:  "header",
				})
			}
		}
	}

	// Record all security headers present
	for header := range securityHeaders {
		if v := resp.Header.Get(header); v != "" {
			result.Info = append(result.Info, InfoItem{
				Title: header,
				Value: v,
				Type:  "present-header",
			})
		}
	}

	result.DurationMs = time.Since(start).Milliseconds()
	return result, nil
}

// TechScanner detects technologies
type TechScanner struct {
	patterns map[string]*regexp.Regexp
}

// NewTechScanner creates a new technology detection scanner
func NewTechScanner() *TechScanner {
	s := &TechScanner{
		patterns: make(map[string]*regexp.Regexp),
	}

	// Common technology detection patterns
	techs := map[string]string{
		"WordPress":    `(?i)wp-content|wp-includes|wordpress`,
		"Drupal":       `(?i)drupal|/sites/default/files`,
		"Joomla":       `(?i)joomla|/components/|/templates/`,
		"React":        `(?i)react|_next/|__NEXT_DATA__`,
		"Angular":      `(?i)ng-version|angular`,
		"Vue.js":       `(?i)vue\.js|__vue__`,
		"jQuery":       `(?i)jquery|jQuery`,
		"Bootstrap":    `(?i)bootstrap\.css|bootstrap\.min\.css`,
		"PHP":          `(?i)\.php|PHPSESSID`,
		"ASP.NET":      `(?i)\.aspx|__VIEWSTATE|ASP\.NET`,
		"Java":         `(?i)jsessionid|\.jsp|\.do`,
		"Ruby":         `(?i)_rails|Ruby|\.erb`,
		"Python":       `(?i)django|flask|\.py`,
		"nginx":        `(?i)nginx`,
		"Apache":       `(?i)apache|httpd`,
		"Cloudflare":   `(?i)cloudflare|cf-ray`,
		"AWS":          `(?i)x-amz-|aws`,
		"Google Cloud": `(?i)x-goog-|google-cloud`,
	}

	for name, pattern := range techs {
		s.patterns[name] = regexp.MustCompile(pattern)
	}

	return s
}

func (s *TechScanner) Name() string        { return "tech" }
func (s *TechScanner) Description() string { return "Detects web technologies" }
func (s *TechScanner) Version() string     { return "1.0.0" }

func (s *TechScanner) Init(config map[string]interface{}) error { return nil }
func (s *TechScanner) Cleanup() error                           { return nil }

func (s *TechScanner) Scan(ctx context.Context, target *Target) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{Scanner: s.Name()}

	req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, err
	}

	// Combine headers and body for searching
	content := string(body)
	for k, v := range resp.Header {
		content += " " + k + ": " + strings.Join(v, " ")
	}

	// Detect technologies
	detected := make(map[string]bool)
	for name, pattern := range s.patterns {
		if pattern.MatchString(content) {
			detected[name] = true
		}
	}

	for tech := range detected {
		result.Info = append(result.Info, InfoItem{
			Title: "Technology",
			Value: tech,
			Type:  "tech",
		})
	}

	// Server header
	if server := resp.Header.Get("Server"); server != "" {
		result.Info = append(result.Info, InfoItem{
			Title: "Server",
			Value: server,
			Type:  "server",
		})
	}

	// X-Powered-By header
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		result.Info = append(result.Info, InfoItem{
			Title: "X-Powered-By",
			Value: powered,
			Type:  "powered-by",
		})

		// Information disclosure finding
		result.Findings = append(result.Findings, Finding{
			Title:       "Information Disclosure: X-Powered-By Header",
			Description: fmt.Sprintf("Server exposes technology version: %s", powered),
			Severity:    "low",
			Type:        "info-disclosure",
			CWE:         "CWE-200",
			Evidence:    powered,
			MatchedAt:   target.URL,
			Remediation: "Remove the X-Powered-By header",
		})
	}

	result.DurationMs = time.Since(start).Milliseconds()
	return result, nil
}

// CORSScanner checks for CORS misconfigurations
type CORSScanner struct{}

// NewCORSScanner creates a new CORS misconfiguration scanner
func NewCORSScanner() *CORSScanner {
	return &CORSScanner{}
}

func (s *CORSScanner) Name() string        { return "cors" }
func (s *CORSScanner) Description() string { return "Checks for CORS misconfigurations" }
func (s *CORSScanner) Version() string     { return "1.0.0" }

func (s *CORSScanner) Init(config map[string]interface{}) error { return nil }
func (s *CORSScanner) Cleanup() error                           { return nil }

func (s *CORSScanner) Scan(ctx context.Context, target *Target) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{Scanner: s.Name()}

	// Test origins
	testOrigins := []string{
		"https://evil.com",
		"null",
		"https://" + target.Host + ".evil.com",
		"https://evil" + target.Host,
	}

	for _, origin := range testOrigins {
		req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Origin", origin)
		for k, v := range target.Headers {
			req.Header.Set(k, v)
		}

		resp, err := HTTPClient.Do(req)
		if err != nil {
			continue
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		resp.Body.Close()

		if acao == "*" {
			result.Findings = append(result.Findings, Finding{
				Title:       "CORS Wildcard Origin",
				Description: "Server allows requests from any origin",
				Severity:    "medium",
				Type:        "cors-misconfiguration",
				CWE:         "CWE-942",
				Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s", acao),
				MatchedAt:   target.URL,
				Remediation: "Configure CORS to only allow trusted origins",
			})
			break
		}

		if acao == origin && origin != "null" {
			severity := "medium"
			if acac == "true" {
				severity = "high"
			}

			result.Findings = append(result.Findings, Finding{
				Title:       "CORS Origin Reflection",
				Description: fmt.Sprintf("Server reflects arbitrary origin: %s", origin),
				Severity:    severity,
				Type:        "cors-misconfiguration",
				CWE:         "CWE-942",
				Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %s", acao, acac),
				MatchedAt:   target.URL,
				Remediation: "Validate origins against a whitelist",
			})
			break
		}

		if acao == "null" && origin == "null" {
			result.Findings = append(result.Findings, Finding{
				Title:       "CORS Null Origin Allowed",
				Description: "Server allows null origin which can be exploited",
				Severity:    "high",
				Type:        "cors-misconfiguration",
				CWE:         "CWE-942",
				Evidence:    "Access-Control-Allow-Origin: null",
				MatchedAt:   target.URL,
				Remediation: "Never allow null origin",
			})
			break
		}
	}

	result.DurationMs = time.Since(start).Milliseconds()
	return result, nil
}

// RegisterBuiltins registers all built-in scanners
func (m *Manager) RegisterBuiltins() {
	m.Register(NewHeaderScanner())
	m.Register(NewTechScanner())
	m.Register(NewCORSScanner())
}
