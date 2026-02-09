// Package bizlogic provides business logic vulnerability testing.
// Tests for authentication bypasses, authorization flaws, IDOR, race conditions,
// and other logic vulnerabilities that cannot be detected by signature-based WAFs.
package bizlogic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

// VulnerabilityType represents the type of business logic vulnerability.
type VulnerabilityType string

const (
	// VulnIDOR represents Insecure Direct Object Reference.
	VulnIDOR VulnerabilityType = "idor"
	// VulnAuthBypass represents authentication bypass.
	VulnAuthBypass VulnerabilityType = "auth-bypass"
	// VulnPrivEsc represents privilege escalation.
	VulnPrivEsc VulnerabilityType = "privilege-escalation"
	// VulnMassAssign represents mass assignment vulnerability.
	VulnMassAssign VulnerabilityType = "mass-assignment"
	// VulnRaceCondition represents race condition vulnerability.
	VulnRaceCondition VulnerabilityType = "race-condition"
	// VulnPriceManip represents price manipulation.
	VulnPriceManip VulnerabilityType = "price-manipulation"
	// VulnQuantityManip represents quantity manipulation.
	VulnQuantityManip VulnerabilityType = "quantity-manipulation"
	// VulnWorkflowBypass represents workflow/process bypass.
	VulnWorkflowBypass VulnerabilityType = "workflow-bypass"
	// VulnRateLimitBypass represents rate limit bypass.
	VulnRateLimitBypass VulnerabilityType = "rate-limit-bypass"
	// VulnEnumeration represents user/resource enumeration.
	VulnEnumeration VulnerabilityType = "enumeration"
	// VulnBrokenAccess represents broken access control.
	VulnBrokenAccess VulnerabilityType = "broken-access-control"
	// VulnInsecureState represents insecure state management.
	VulnInsecureState VulnerabilityType = "insecure-state"
)

// Severity represents the severity level of a vulnerability.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Vulnerability represents a detected business logic vulnerability.
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Parameter   string            `json:"parameter,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	OriginalID  string            `json:"original_id,omitempty"`
	TestedID    string            `json:"tested_id,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	ConfirmedBy int               `json:"confirmed_by,omitempty"`
}

// TestCase represents a business logic test case.
type TestCase struct {
	Name        string            `json:"name"`
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	Expected    ExpectedResult    `json:"expected"`
	Variations  []TestVariation   `json:"variations,omitempty"`
}

// ExpectedResult represents expected test results.
type ExpectedResult struct {
	StatusCode     int               `json:"status_code,omitempty"`
	StatusCodes    []int             `json:"status_codes,omitempty"`
	ContainsAny    []string          `json:"contains_any,omitempty"`
	NotContains    []string          `json:"not_contains,omitempty"`
	HeaderContains map[string]string `json:"header_contains,omitempty"`
}

// TestVariation represents a variation of a test case.
type TestVariation struct {
	Name      string            `json:"name"`
	Parameter string            `json:"parameter"`
	Original  string            `json:"original"`
	Modified  string            `json:"modified"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// TesterConfig holds configuration for business logic testing.
type TesterConfig struct {
	Timeout       time.Duration
	UserAgent     string
	Concurrency   int
	RetryCount    int
	EnableRace    bool
	RaceCount     int
	Cookies       map[string]string
	AuthHeader    string
	SecondaryAuth string
	IDPatterns    []string
}

// Tester handles business logic testing.
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// DefaultConfig returns default configuration.
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:     duration.HTTPFuzzing,
		UserAgent:   ui.UserAgentWithContext("BizLogic Tester"),
		Concurrency: defaults.ConcurrencyMedium,
		RetryCount:  defaults.RetryLow,
		EnableRace:  true,
		RaceCount:   10,
		Cookies:     make(map[string]string),
		IDPatterns: []string{
			`[0-9]+`,
			`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,
			`[A-Za-z0-9]{20,}`,
		},
	}
}

// NewTester creates a new business logic tester.
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	return &Tester{
		config: config,
		client: httpclient.Fuzzing(),
	}
}

// TestIDOR tests for Insecure Direct Object Reference vulnerabilities.
func (t *Tester) TestIDOR(ctx context.Context, baseURL, path string, originalID, modifiedID string) (*Vulnerability, error) {
	// First, make a request with the original ID
	// Replace {id} placeholder if present, otherwise replace the ID in path only
	originalPath := strings.Replace(path, "{id}", originalID, -1)
	originalURL := baseURL + originalPath

	originalReq, err := http.NewRequestWithContext(ctx, "GET", originalURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating original request: %w", err)
	}

	t.applyHeaders(originalReq)

	originalResp, err := t.client.Do(originalReq)
	if err != nil {
		return nil, fmt.Errorf("original request: %w", err)
	}
	defer iohelper.DrainAndClose(originalResp.Body)

	originalBody, _ := iohelper.ReadBodyDefault(originalResp.Body)

	// Now test with modified ID - replace in path only, not in baseURL
	modifiedPath := strings.Replace(path, "{id}", modifiedID, -1)
	modifiedPath = strings.Replace(modifiedPath, "/"+originalID, "/"+modifiedID, 1)
	modifiedURL := baseURL + modifiedPath

	modifiedReq, err := http.NewRequestWithContext(ctx, "GET", modifiedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating modified request: %w", err)
	}

	t.applyHeaders(modifiedReq)

	modifiedResp, err := t.client.Do(modifiedReq)
	if err != nil {
		return nil, fmt.Errorf("modified request: %w", err)
	}
	defer iohelper.DrainAndClose(modifiedResp.Body)

	modifiedBody, _ := iohelper.ReadBodyDefault(modifiedResp.Body)

	// Check for IDOR - if we can access another user's resource
	if modifiedResp.StatusCode == 200 && originalResp.StatusCode == 200 {
		// If the responses are different and both successful, potential IDOR
		if string(originalBody) != string(modifiedBody) && len(modifiedBody) > 50 {
			return &Vulnerability{
				Type:        VulnIDOR,
				Description: "Possible IDOR vulnerability - accessed resource with different ID",
				Severity:    SeverityHigh,
				URL:         modifiedURL,
				Method:      "GET",
				OriginalID:  originalID,
				TestedID:    modifiedID,
				Evidence:    fmt.Sprintf("Original ID returned %d bytes, Modified ID returned %d bytes", len(originalBody), len(modifiedBody)),
				Remediation: "Implement proper authorization checks to verify the requesting user owns the resource",
				CVSS:        7.5,
			}, nil
		}
	}

	return nil, nil
}

// TestAuthBypass tests for authentication bypass vulnerabilities.
func (t *Tester) TestAuthBypass(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// Test common auth bypass techniques
	bypassHeaders := []struct {
		name  string
		value string
	}{
		{"X-Original-URL", "/admin"},
		{"X-Rewrite-URL", "/admin"},
		{"X-Custom-IP-Authorization", "127.0.0.1"},
		{"X-Forwarded-For", "127.0.0.1"},
		{"X-Real-IP", "127.0.0.1"},
		{"X-Originating-IP", "127.0.0.1"},
		{"X-Remote-IP", "127.0.0.1"},
		{"X-Remote-Addr", "127.0.0.1"},
		{"X-Client-IP", "127.0.0.1"},
		{"X-Host", "localhost"},
		{"X-Forwarded-Host", "localhost"},
	}

	for _, bypass := range bypassHeaders {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}

		t.applyHeaders(req)
		req.Header.Set(bypass.name, bypass.value)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)

		// Check for bypass indicators
		if resp.StatusCode == 200 && (len(body) > 100 || containsAdminIndicators(string(body))) {
			vulns = append(vulns, Vulnerability{
				Type:        VulnAuthBypass,
				Description: fmt.Sprintf("Authentication bypass via %s header", bypass.name),
				Severity:    SeverityCritical,
				URL:         targetURL,
				Method:      "GET",
				Parameter:   bypass.name,
				Evidence:    fmt.Sprintf("Header: %s: %s returned status %d", bypass.name, bypass.value, resp.StatusCode),
				Remediation: "Do not rely on client-provided headers for authentication or authorization",
				CVSS:        9.8,
			})
		}
	}

	return vulns, nil
}

// TestPrivilegeEscalation tests for privilege escalation vulnerabilities.
func (t *Tester) TestPrivilegeEscalation(ctx context.Context, targetURL string, lowPrivAuth, highPrivPath string) (*Vulnerability, error) {
	// Try accessing high-privilege endpoint with low-privilege auth
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL+highPrivPath, nil)
	if err != nil {
		return nil, err
	}

	t.applyHeaders(req)
	if lowPrivAuth != "" {
		req.Header.Set("Authorization", lowPrivAuth)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)

	if resp.StatusCode == 200 && len(body) > 50 {
		return &Vulnerability{
			Type:        VulnPrivEsc,
			Description: "Privilege escalation - low privilege user accessed admin endpoint",
			Severity:    SeverityCritical,
			URL:         targetURL + highPrivPath,
			Method:      "GET",
			Evidence:    fmt.Sprintf("Status: %d, Response length: %d", resp.StatusCode, len(body)),
			Remediation: "Implement role-based access control and verify user privileges server-side",
			CVSS:        9.1,
		}, nil
	}

	return nil, nil
}

// TestMassAssignment tests for mass assignment vulnerabilities.
func (t *Tester) TestMassAssignment(ctx context.Context, targetURL string, normalPayload, maliciousPayload string) (*Vulnerability, error) {
	// First, send normal request
	normalReq, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(normalPayload))
	if err != nil {
		return nil, err
	}

	t.applyHeaders(normalReq)
	normalReq.Header.Set("Content-Type", defaults.ContentTypeJSON)

	normalResp, err := t.client.Do(normalReq)
	if err != nil {
		return nil, err
	}
	iohelper.DrainAndClose(normalResp.Body)

	// Now try with malicious payload (adding admin/role fields)
	malReq, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(maliciousPayload))
	if err != nil {
		return nil, err
	}

	t.applyHeaders(malReq)
	malReq.Header.Set("Content-Type", defaults.ContentTypeJSON)

	malResp, err := t.client.Do(malReq)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(malResp.Body)

	malBody, _ := iohelper.ReadBodyDefault(malResp.Body)

	// Check for mass assignment indicators
	if malResp.StatusCode == 200 || malResp.StatusCode == 201 {
		// Check if admin/role fields were accepted
		if strings.Contains(string(malBody), "admin") ||
			strings.Contains(string(malBody), "role") ||
			strings.Contains(string(malBody), "isAdmin") {
			return &Vulnerability{
				Type:        VulnMassAssign,
				Description: "Mass assignment vulnerability - privileged fields accepted",
				Severity:    SeverityHigh,
				URL:         targetURL,
				Method:      "POST",
				Evidence:    fmt.Sprintf("Server accepted payload with admin/role fields: %s", string(malBody)[:min(200, len(malBody))]),
				Remediation: "Implement whitelist of allowed fields and ignore unknown parameters",
				CVSS:        8.1,
			}, nil
		}
	}

	return nil, nil
}

// TestRaceCondition tests for race condition vulnerabilities.
func (t *Tester) TestRaceCondition(ctx context.Context, targetURL, method, body string) ([]Vulnerability, error) {
	var vulns []Vulnerability
	var wg sync.WaitGroup
	var mu sync.Mutex

	responses := make([]RaceResponse, t.config.RaceCount)

	// Send concurrent requests
	start := make(chan struct{})

	for i := 0; i < t.config.RaceCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			<-start // Wait for signal

			req, err := http.NewRequestWithContext(ctx, method, targetURL, strings.NewReader(body))
			if err != nil {
				return
			}

			t.applyHeaders(req)
			if body != "" {
				req.Header.Set("Content-Type", defaults.ContentTypeJSON)
			}

			startTime := time.Now()
			resp, err := t.client.Do(req)
			duration := time.Since(startTime)

			if err != nil {
				return
			}
			defer iohelper.DrainAndClose(resp.Body)

			respBody, _ := iohelper.ReadBodyDefault(resp.Body)

			mu.Lock()
			responses[idx] = RaceResponse{
				StatusCode: resp.StatusCode,
				Body:       string(respBody),
				Duration:   duration,
			}
			mu.Unlock()
		}(i)
	}

	// Signal all goroutines to start simultaneously
	close(start)
	wg.Wait()

	// Analyze responses for race conditions
	successCount := 0
	uniqueResponses := make(map[string]int)

	for _, r := range responses {
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			successCount++
		}
		uniqueResponses[r.Body]++
	}

	// If multiple success responses on an operation that should only succeed once
	if successCount > 1 {
		vulns = append(vulns, Vulnerability{
			Type:        VulnRaceCondition,
			Description: fmt.Sprintf("Possible race condition - %d successful responses for concurrent requests", successCount),
			Severity:    SeverityHigh,
			URL:         targetURL,
			Method:      method,
			Evidence:    fmt.Sprintf("Sent %d concurrent requests, %d succeeded", t.config.RaceCount, successCount),
			Remediation: "Implement proper locking mechanisms, use database transactions, or implement idempotency keys",
			CVSS:        7.5,
		})
	}

	return vulns, nil
}

// RaceResponse holds a response from race condition testing.
type RaceResponse struct {
	StatusCode int
	Body       string
	Duration   time.Duration
}

// TestPriceManipulation tests for price manipulation vulnerabilities.
func (t *Tester) TestPriceManipulation(ctx context.Context, targetURL string, originalPrice, manipulatedPrice string) (*Vulnerability, error) {
	// Create request with manipulated price
	payload := strings.Replace(`{"price": PRICE}`, "PRICE", manipulatedPrice, 1)

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	t.applyHeaders(req)
	req.Header.Set("Content-Type", defaults.ContentTypeJSON)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		// Check if manipulated price was accepted
		if strings.Contains(string(body), manipulatedPrice) {
			return &Vulnerability{
				Type:        VulnPriceManip,
				Description: fmt.Sprintf("Price manipulation accepted - changed from %s to %s", originalPrice, manipulatedPrice),
				Severity:    SeverityHigh,
				URL:         targetURL,
				Method:      "POST",
				Parameter:   "price",
				Evidence:    fmt.Sprintf("Server accepted price: %s", manipulatedPrice),
				Remediation: "Never trust client-provided price values; always fetch prices server-side",
				CVSS:        8.1,
			}, nil
		}
	}

	return nil, nil
}

// TestWorkflowBypass tests for workflow bypass vulnerabilities.
func (t *Tester) TestWorkflowBypass(ctx context.Context, finalStepURL string, requiredSteps []string) (*Vulnerability, error) {
	// Try to access final step without completing previous steps
	req, err := http.NewRequestWithContext(ctx, "GET", finalStepURL, nil)
	if err != nil {
		return nil, err
	}

	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)

	if resp.StatusCode == 200 && len(body) > 20 {
		return &Vulnerability{
			Type:        VulnWorkflowBypass,
			Description: fmt.Sprintf("Workflow bypass - accessed final step without completing required steps: %v", requiredSteps),
			Severity:    SeverityMedium,
			URL:         finalStepURL,
			Method:      "GET",
			Evidence:    fmt.Sprintf("Accessed %s without completing workflow", finalStepURL),
			Remediation: "Implement server-side workflow state tracking and validate each step",
			CVSS:        6.5,
		}, nil
	}

	return nil, nil
}

// TestEnumeration tests for user/resource enumeration vulnerabilities.
func (t *Tester) TestEnumeration(ctx context.Context, targetURL string, validID, invalidID string) (*Vulnerability, error) {
	// Test with valid ID
	validURL := strings.Replace(targetURL, "{id}", validID, -1)
	validReq, err := http.NewRequestWithContext(ctx, "GET", validURL, nil)
	if err != nil {
		return nil, err
	}
	t.applyHeaders(validReq)

	validResp, err := t.client.Do(validReq)
	if err != nil {
		return nil, err
	}
	validBody, _ := iohelper.ReadBodyDefault(validResp.Body)
	iohelper.DrainAndClose(validResp.Body)

	// Test with invalid ID
	invalidURL := strings.Replace(targetURL, "{id}", invalidID, -1)
	invalidReq, err := http.NewRequestWithContext(ctx, "GET", invalidURL, nil)
	if err != nil {
		return nil, err
	}
	t.applyHeaders(invalidReq)

	invalidResp, err := t.client.Do(invalidReq)
	if err != nil {
		return nil, err
	}
	invalidBody, _ := iohelper.ReadBodyDefault(invalidResp.Body)
	iohelper.DrainAndClose(invalidResp.Body)

	// Check for enumeration - different responses indicate valid vs invalid
	if validResp.StatusCode != invalidResp.StatusCode || len(validBody) != len(invalidBody) {
		return &Vulnerability{
			Type:        VulnEnumeration,
			Description: "Resource enumeration possible - different responses for valid/invalid IDs",
			Severity:    SeverityMedium,
			URL:         targetURL,
			Method:      "GET",
			Evidence:    fmt.Sprintf("Valid ID: status %d, len %d; Invalid ID: status %d, len %d", validResp.StatusCode, len(validBody), invalidResp.StatusCode, len(invalidBody)),
			Remediation: "Return consistent responses regardless of resource existence; implement rate limiting",
			CVSS:        5.3,
		}, nil
	}

	return nil, nil
}

// ExtractIDs extracts potential IDs from a URL or path.
func ExtractIDs(urlStr string) []ExtractedID {
	var ids []ExtractedID

	patterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"numeric", regexp.MustCompile(`/(\d+)(?:/|$|\?)`)},
		{"uuid", regexp.MustCompile(`/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:/|$|\?)`)},
		{"alphanumeric", regexp.MustCompile(`/([a-zA-Z0-9]{20,})(?:/|$|\?)`)},
		{"query_numeric", regexp.MustCompile(`[?&](?:id|user_id|userId|ID)=(\d+)`)},
		{"query_uuid", regexp.MustCompile(`[?&](?:id|user_id|userId|ID)=([a-f0-9-]{36})`)},
	}

	for _, p := range patterns {
		matches := p.pattern.FindAllStringSubmatch(urlStr, -1)
		for _, match := range matches {
			if len(match) > 1 {
				ids = append(ids, ExtractedID{
					Type:  p.name,
					Value: match[1],
					Full:  match[0],
				})
			}
		}
	}

	return ids
}

// ExtractedID represents an extracted ID from a URL.
type ExtractedID struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Full  string `json:"full"`
}

// GenerateIDVariations generates variations of an ID for testing.
func GenerateIDVariations(id string) []string {
	variations := []string{}

	// Try numeric variations
	if isNumeric(id) {
		num := parseInt(id)
		variations = append(variations,
			fmt.Sprintf("%d", num+1),
			fmt.Sprintf("%d", num-1),
			fmt.Sprintf("%d", num+100),
			"0",
			"1",
			"-1",
			"9999999",
		)
	}

	// UUID variations
	if isUUID(id) {
		variations = append(variations,
			"00000000-0000-0000-0000-000000000000",
			"11111111-1111-1111-1111-111111111111",
			strings.Replace(id, id[0:8], "00000000", 1),
		)
	}

	// Common test IDs
	variations = append(variations,
		"admin",
		"root",
		"test",
		"guest",
	)

	return variations
}

// Scan performs a comprehensive business logic scan.
func (t *Tester) Scan(ctx context.Context, baseURL string, endpoints []string) ([]Vulnerability, error) {
	var vulns []Vulnerability
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, t.config.Concurrency)

	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			fullURL := baseURL + ep

			// Extract IDs from endpoint
			ids := ExtractIDs(ep)
			for _, id := range ids {
				variations := GenerateIDVariations(id.Value)
				for _, v := range variations {
					vuln, err := t.TestIDOR(ctx, baseURL, ep, id.Value, v)
					if err == nil && vuln != nil {
						mu.Lock()
						vulns = append(vulns, *vuln)
						mu.Unlock()
					}
				}
			}

			// Test auth bypass
			authVulns, err := t.TestAuthBypass(ctx, fullURL)
			if err == nil {
				mu.Lock()
				vulns = append(vulns, authVulns...)
				mu.Unlock()
			}
		}(endpoint)
	}

	wg.Wait()
	return vulns, nil
}

// VulnerabilityToJSON converts a vulnerability to JSON string.
func VulnerabilityToJSON(v Vulnerability) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetRemediation returns remediation advice for a vulnerability type.
func GetRemediation(vt VulnerabilityType) string {
	remediations := map[VulnerabilityType]string{
		VulnIDOR:            "Implement proper authorization checks to verify resource ownership",
		VulnAuthBypass:      "Do not trust client-provided headers for authentication decisions",
		VulnPrivEsc:         "Implement role-based access control with server-side verification",
		VulnMassAssign:      "Use allowlists for accepted parameters, reject unknown fields",
		VulnRaceCondition:   "Use database locks, transactions, or idempotency keys",
		VulnPriceManip:      "Fetch prices server-side, never trust client-provided values",
		VulnQuantityManip:   "Validate quantities server-side with business rule checks",
		VulnWorkflowBypass:  "Track workflow state server-side, validate each step",
		VulnRateLimitBypass: "Implement server-side rate limiting with proper key selection",
		VulnEnumeration:     "Return consistent responses, implement rate limiting",
		VulnBrokenAccess:    "Implement comprehensive access control with principle of least privilege",
		VulnInsecureState:   "Use secure server-side session management",
	}

	if r, ok := remediations[vt]; ok {
		return r
	}
	return "Review and implement proper security controls"
}

// AllVulnerabilityTypes returns all supported vulnerability types.
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnIDOR,
		VulnAuthBypass,
		VulnPrivEsc,
		VulnMassAssign,
		VulnRaceCondition,
		VulnPriceManip,
		VulnQuantityManip,
		VulnWorkflowBypass,
		VulnRateLimitBypass,
		VulnEnumeration,
		VulnBrokenAccess,
		VulnInsecureState,
	}
}

// Helper functions

func (t *Tester) applyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", t.config.UserAgent)

	if t.config.AuthHeader != "" {
		req.Header.Set("Authorization", t.config.AuthHeader)
	}

	for name, value := range t.config.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
}

func containsAdminIndicators(body string) bool {
	indicators := []string{
		"admin", "dashboard", "manage", "control panel",
		"settings", "configuration", "user list", "delete user",
	}
	lowerBody := strings.ToLower(body)
	for _, ind := range indicators {
		if strings.Contains(lowerBody, ind) {
			return true
		}
	}
	return false
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func parseInt(s string) int {
	var n int
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func isUUID(s string) bool {
	uuidPattern := regexcache.MustGet(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	return uuidPattern.MatchString(strings.ToLower(s))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ParseURL parses a URL string into components for testing.
func ParseURL(rawURL string) (*url.URL, error) {
	return url.Parse(rawURL)
}
