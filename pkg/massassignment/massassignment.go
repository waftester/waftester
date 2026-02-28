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

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures mass assignment testing
type Config struct {
	attackconfig.Base
	Headers map[string]string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Base: attackconfig.Base{
			Concurrency: defaults.ConcurrencyLow,
			Timeout:     httpclient.TimeoutProbing,
		},
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
	Severity    finding.Severity
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

	client := config.Client
	if client == nil {
		client = httpclient.Default()
	}

	return &Scanner{
		config:  config,
		client:  client,
		results: make([]Result, 0),
	}
}

// Scan tests a URL for mass assignment vulnerability.
// Parameters are tested sequentially to avoid overwhelming the target
// and to simplify correlation of responses to individual parameters.
func (s *Scanner) Scan(ctx context.Context, targetURL string, originalData map[string]interface{}) ([]Result, error) {
	results := make([]Result, 0)

	for _, param := range DangerousParameters() {
		result := s.testParameter(ctx, targetURL, param, originalData)
		if result.Vulnerable {
			results = append(results, result)
			s.config.NotifyVulnerabilityFound()
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

// detectVulnerability checks if mass assignment succeeded.
// Note: Detection uses JSON field name matching which may produce false positives
// for very short parameter names that appear as substrings of other JSON keys.
func (s *Scanner) detectVulnerability(statusCode int, body string, param DangerousParam) (bool, string) {
	// If request succeeded (2xx or 3xx) and response contains parameter or its value
	if statusCode >= 200 && statusCode < 400 {
		bodyLower := strings.ToLower(body)
		paramLower := strings.ToLower(param.Name)

		// Check if parameter appears as a JSON field in response
		// Use quoted check to reduce false positives (e.g., "id" won't match "valid")
		quotedParam := `"` + paramLower + `"`
		if strings.Contains(bodyLower, quotedParam) {
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
	Severity finding.Severity
	Category string
}

// DangerousParameters returns parameters that are dangerous if mass-assignable
func DangerousParameters() []DangerousParam {
	return []DangerousParam{
		// Role/Permission escalation
		{Name: "role", Value: "admin", Severity: finding.Critical, Category: "privilege"},
		{Name: "isAdmin", Value: true, Severity: finding.Critical, Category: "privilege"},
		{Name: "is_admin", Value: true, Severity: finding.Critical, Category: "privilege"},
		{Name: "admin", Value: true, Severity: finding.Critical, Category: "privilege"},
		{Name: "permissions", Value: []string{"admin", "write"}, Severity: finding.Critical, Category: "privilege"},
		{Name: "role_id", Value: 1, Severity: finding.Critical, Category: "privilege"},
		{Name: "user_type", Value: "admin", Severity: finding.Critical, Category: "privilege"},
		{Name: "access_level", Value: "admin", Severity: finding.Critical, Category: "privilege"},

		// Account status
		{Name: "verified", Value: true, Severity: finding.High, Category: "account"},
		{Name: "is_verified", Value: true, Severity: finding.High, Category: "account"},
		{Name: "email_verified", Value: true, Severity: finding.High, Category: "account"},
		{Name: "active", Value: true, Severity: finding.High, Category: "account"},
		{Name: "is_active", Value: true, Severity: finding.High, Category: "account"},
		{Name: "approved", Value: true, Severity: finding.High, Category: "account"},

		// Sensitive data
		{Name: "balance", Value: 999999, Severity: finding.Critical, Category: "financial"},
		{Name: "credits", Value: 999999, Severity: finding.Critical, Category: "financial"},
		{Name: "points", Value: 999999, Severity: finding.High, Category: "financial"},
		{Name: "price", Value: 0.01, Severity: finding.Critical, Category: "financial"},
		{Name: "discount", Value: 99, Severity: finding.High, Category: "financial"},

		// ID manipulation
		{Name: "id", Value: 1, Severity: finding.High, Category: "id"},
		{Name: "user_id", Value: 1, Severity: finding.High, Category: "id"},
		{Name: "userId", Value: 1, Severity: finding.High, Category: "id"},
		{Name: "owner_id", Value: 1, Severity: finding.High, Category: "id"},
		{Name: "org_id", Value: 1, Severity: finding.High, Category: "id"},
		{Name: "organization_id", Value: 1, Severity: finding.High, Category: "id"},

		// Internal fields
		{Name: "created_at", Value: "2020-01-01", Severity: finding.Medium, Category: "internal"},
		{Name: "updated_at", Value: "2020-01-01", Severity: finding.Medium, Category: "internal"},
		{Name: "_id", Value: "injected", Severity: finding.High, Category: "internal"},

		// ---- Framework-specific parameters ----

		// Rails nested attribute patterns (user[role], user[admin])
		{Name: "user[admin]", Value: true, Severity: finding.Critical, Category: "rails"},
		{Name: "user[role]", Value: "admin", Severity: finding.Critical, Category: "rails"},
		{Name: "user[is_admin]", Value: true, Severity: finding.Critical, Category: "rails"},
		{Name: "user[role_id]", Value: 1, Severity: finding.Critical, Category: "rails"},
		{Name: "_destroy", Value: true, Severity: finding.High, Category: "rails"},
		{Name: "user[_destroy]", Value: true, Severity: finding.High, Category: "rails"},

		// Django model fields
		{Name: "is_staff", Value: true, Severity: finding.Critical, Category: "django"},
		{Name: "is_superuser", Value: true, Severity: finding.Critical, Category: "django"},
		{Name: "groups", Value: []int{1}, Severity: finding.Critical, Category: "django"},
		{Name: "user_permissions", Value: []int{1}, Severity: finding.Critical, Category: "django"},
		{Name: "is_active", Value: true, Severity: finding.High, Category: "django"},

		// Spring/Java patterns
		{Name: "class.module.classLoader", Value: "x", Severity: finding.Critical, Category: "spring"},
		{Name: "authorities", Value: []string{"ROLE_ADMIN"}, Severity: finding.Critical, Category: "spring"},
		{Name: "authority", Value: "ROLE_ADMIN", Severity: finding.Critical, Category: "spring"},
		{Name: "roles", Value: []string{"ADMIN"}, Severity: finding.Critical, Category: "spring"},
		{Name: "enabled", Value: true, Severity: finding.High, Category: "spring"},
		{Name: "accountNonLocked", Value: true, Severity: finding.High, Category: "spring"},
		{Name: "credentialsNonExpired", Value: true, Severity: finding.High, Category: "spring"},

		// Laravel/PHP patterns
		{Name: "guard_name", Value: "web", Severity: finding.High, Category: "laravel"},
		{Name: "is_admin", Value: 1, Severity: finding.Critical, Category: "laravel"},
		{Name: "role_names", Value: []string{"admin"}, Severity: finding.Critical, Category: "laravel"},

		// Node.js/Express patterns
		{Name: "__proto__", Value: map[string]interface{}{"isAdmin": true}, Severity: finding.Critical, Category: "nodejs"},
		{Name: "constructor", Value: map[string]interface{}{"prototype": map[string]interface{}{"isAdmin": true}}, Severity: finding.Critical, Category: "nodejs"},
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

// FrameworkParams returns parameters for a specific framework
func FrameworkParams(framework string) []DangerousParam {
	var result []DangerousParam
	for _, p := range DangerousParameters() {
		if p.Category == framework {
			result = append(result, p)
		}
	}
	return result
}
