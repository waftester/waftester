// Package massassignment provides Mass Assignment vulnerability testing
package massassignment

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures mass assignment testing
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Concurrency: defaults.ConcurrencyLow,
		Timeout:     httpclient.TimeoutProbing,
	}
}

// Result represents a mass assignment test result
type Result struct {
	URL         string
	Method      string
	Parameter   string
	StatusCode  int
	Vulnerable  bool
	Evidence    string
	Severity    string
	OriginalReq map[string]interface{}
	ModifiedReq map[string]interface{}
	Timestamp   time.Time
}

// Scanner performs mass assignment testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new mass assignment scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyLow
	}
	if config.Timeout <= 0 {
		config.Timeout = httpclient.TimeoutProbing
	}

	return &Scanner{
		config:  config,
		client:  httpclient.Default(),
		results: make([]Result, 0),
	}
}

// Scan tests a URL for mass assignment vulnerability
func (s *Scanner) Scan(ctx context.Context, targetURL string, originalData map[string]interface{}) ([]Result, error) {
	results := make([]Result, 0)

	for _, param := range DangerousParameters() {
		result := s.testParameter(ctx, targetURL, param, originalData)
		if result.Vulnerable {
			results = append(results, result)
		}
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// testParameter tests if a dangerous parameter can be mass assigned
func (s *Scanner) testParameter(ctx context.Context, targetURL string, param DangerousParam, originalData map[string]interface{}) Result {
	result := Result{
		URL:         targetURL,
		Method:      "POST",
		Parameter:   param.Name,
		OriginalReq: originalData,
		Timestamp:   time.Now(),
	}

	// Create modified request with dangerous parameter
	modifiedData := make(map[string]interface{})
	for k, v := range originalData {
		modifiedData[k] = v
	}
	modifiedData[param.Name] = param.Value
	result.ModifiedReq = modifiedData

	jsonData, err := json.Marshal(modifiedData)
	if err != nil {
		return result
	}

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(jsonData))
	if err != nil {
		return result
	}

	req.Header.Set("Content-Type", defaults.ContentTypeJSON)
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	result.StatusCode = resp.StatusCode

	// Check if parameter was accepted
	result.Vulnerable, result.Evidence = s.detectVulnerability(resp.StatusCode, string(body), param)
	if result.Vulnerable {
		result.Severity = param.Severity
	}

	return result
}

// detectVulnerability checks if mass assignment succeeded
func (s *Scanner) detectVulnerability(statusCode int, body string, param DangerousParam) (bool, string) {
	// If request succeeded (2xx or 3xx) and response contains parameter or its value
	if statusCode >= 200 && statusCode < 400 {
		bodyLower := strings.ToLower(body)
		paramLower := strings.ToLower(param.Name)

		// Check if parameter appears in response
		if strings.Contains(bodyLower, paramLower) {
			return true, "Parameter " + param.Name + " accepted in response"
		}

		// Check for value in response (for booleans or specific values)
		valueStr := ""
		switch v := param.Value.(type) {
		case bool:
			valueStr = "true"
			if !v {
				valueStr = "false"
			}
		case string:
			valueStr = v
		}

		if valueStr != "" && strings.Contains(bodyLower, strings.ToLower(valueStr)) {
			// This is less reliable, only flag if combined with parameter name
			if strings.Contains(bodyLower, paramLower) {
				return true, "Parameter " + param.Name + " with value reflected"
			}
		}
	}

	return false, ""
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// DangerousParam represents a parameter that shouldn't be mass-assignable
type DangerousParam struct {
	Name     string
	Value    interface{}
	Severity string
	Category string
}

// DangerousParameters returns parameters that are dangerous if mass-assignable
func DangerousParameters() []DangerousParam {
	return []DangerousParam{
		// Role/Permission escalation
		{Name: "role", Value: "admin", Severity: "CRITICAL", Category: "privilege"},
		{Name: "isAdmin", Value: true, Severity: "CRITICAL", Category: "privilege"},
		{Name: "is_admin", Value: true, Severity: "CRITICAL", Category: "privilege"},
		{Name: "admin", Value: true, Severity: "CRITICAL", Category: "privilege"},
		{Name: "permissions", Value: []string{"admin", "write"}, Severity: "CRITICAL", Category: "privilege"},
		{Name: "role_id", Value: 1, Severity: "CRITICAL", Category: "privilege"},
		{Name: "user_type", Value: "admin", Severity: "CRITICAL", Category: "privilege"},
		{Name: "access_level", Value: "admin", Severity: "CRITICAL", Category: "privilege"},

		// Account status
		{Name: "verified", Value: true, Severity: "HIGH", Category: "account"},
		{Name: "is_verified", Value: true, Severity: "HIGH", Category: "account"},
		{Name: "email_verified", Value: true, Severity: "HIGH", Category: "account"},
		{Name: "active", Value: true, Severity: "HIGH", Category: "account"},
		{Name: "is_active", Value: true, Severity: "HIGH", Category: "account"},
		{Name: "approved", Value: true, Severity: "HIGH", Category: "account"},

		// Sensitive data
		{Name: "balance", Value: 999999, Severity: "CRITICAL", Category: "financial"},
		{Name: "credits", Value: 999999, Severity: "CRITICAL", Category: "financial"},
		{Name: "points", Value: 999999, Severity: "HIGH", Category: "financial"},
		{Name: "price", Value: 0.01, Severity: "CRITICAL", Category: "financial"},
		{Name: "discount", Value: 99, Severity: "HIGH", Category: "financial"},

		// ID manipulation
		{Name: "id", Value: 1, Severity: "HIGH", Category: "id"},
		{Name: "user_id", Value: 1, Severity: "HIGH", Category: "id"},
		{Name: "userId", Value: 1, Severity: "HIGH", Category: "id"},
		{Name: "owner_id", Value: 1, Severity: "HIGH", Category: "id"},
		{Name: "org_id", Value: 1, Severity: "HIGH", Category: "id"},
		{Name: "organization_id", Value: 1, Severity: "HIGH", Category: "id"},

		// Internal fields
		{Name: "created_at", Value: "2020-01-01", Severity: "MEDIUM", Category: "internal"},
		{Name: "updated_at", Value: "2020-01-01", Severity: "MEDIUM", Category: "internal"},
		{Name: "_id", Value: "injected", Severity: "HIGH", Category: "internal"},
	}
}

// RoleEscalationParams returns parameters specifically for role escalation
func RoleEscalationParams() []DangerousParam {
	var result []DangerousParam
	for _, p := range DangerousParameters() {
		if p.Category == "privilege" {
			result = append(result, p)
		}
	}
	return result
}

// FinancialParams returns parameters for financial manipulation
func FinancialParams() []DangerousParam {
	var result []DangerousParam
	for _, p := range DangerousParameters() {
		if p.Category == "financial" {
			result = append(result, p)
		}
	}
	return result
}
