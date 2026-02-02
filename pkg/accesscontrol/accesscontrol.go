// Package accesscontrol provides testing for Broken Access Control vulnerabilities (OWASP A01:2021)
package accesscontrol

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// VulnerabilityType represents different access control vulnerability types
type VulnerabilityType string

const (
	HorizontalPrivilegeEscalation VulnerabilityType = "horizontal_privilege_escalation"
	VerticalPrivilegeEscalation   VulnerabilityType = "vertical_privilege_escalation"
	InsecureDirectObjectReference VulnerabilityType = "insecure_direct_object_reference"
	MissingFunctionLevelAccess    VulnerabilityType = "missing_function_level_access"
	MetadataManipulation          VulnerabilityType = "metadata_manipulation"
	CORSMisconfiguration          VulnerabilityType = "cors_misconfiguration"
	ForceFullBrowsing             VulnerabilityType = "forceful_browsing"
	PathTraversalACL              VulnerabilityType = "path_traversal_acl"
)

// TestResult represents the result of an access control test
type TestResult struct {
	VulnType    VulnerabilityType `json:"vuln_type"`
	Endpoint    string            `json:"endpoint"`
	Method      string            `json:"method"`
	Vulnerable  bool              `json:"vulnerable"`
	Description string            `json:"description"`
	StatusCode  int               `json:"status_code"`
	Evidence    string            `json:"evidence,omitempty"`
	Severity    string            `json:"severity"`
	Remediation string            `json:"remediation"`
}

// Tester performs access control vulnerability testing
type Tester struct {
	client         *http.Client
	target         string
	authTokenLow   string // Low privilege user token
	authTokenHigh  string // High privilege user token (admin)
	authTokenOther string // Different user same privilege
	timeout        time.Duration
}

// TesterConfig holds configuration for the tester
type TesterConfig struct {
	Target         string
	AuthTokenLow   string
	AuthTokenHigh  string
	AuthTokenOther string
	Timeout        time.Duration
}

// NewTester creates a new access control tester
func NewTester(cfg TesterConfig) *Tester {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = httpclient.TimeoutProbing
	}

	return &Tester{
		client:         httpclient.Default(),
		target:         cfg.Target,
		authTokenLow:   cfg.AuthTokenLow,
		authTokenHigh:  cfg.AuthTokenHigh,
		authTokenOther: cfg.AuthTokenOther,
		timeout:        timeout,
	}
}

// AdminOnlyEndpoints returns common admin-only endpoints
func AdminOnlyEndpoints() []string {
	return []string{
		"/admin",
		"/admin/",
		"/admin/dashboard",
		"/admin/users",
		"/admin/settings",
		"/admin/config",
		"/admin/logs",
		"/api/admin",
		"/api/v1/admin",
		"/api/admin/users",
		"/management",
		"/manager",
		"/console",
		"/dashboard/admin",
		"/system/admin",
		"/control-panel",
		"/cp",
		"/backend",
		"/superadmin",
		"/root",
	}
}

// PrivilegedActions returns actions that require elevated privileges
func PrivilegedActions() []struct {
	Path   string
	Method string
	Desc   string
} {
	return []struct {
		Path   string
		Method string
		Desc   string
	}{
		{"/api/users", "DELETE", "Delete user"},
		{"/api/users/role", "PUT", "Change user role"},
		{"/api/settings", "PUT", "Modify settings"},
		{"/api/config", "POST", "Update configuration"},
		{"/api/logs/clear", "DELETE", "Clear logs"},
		{"/api/backup", "POST", "Create backup"},
		{"/api/restore", "POST", "Restore from backup"},
		{"/api/users/disable", "PUT", "Disable user account"},
		{"/api/permissions", "PUT", "Modify permissions"},
		{"/api/api-keys", "POST", "Generate API key"},
		{"/api/webhooks", "POST", "Create webhook"},
		{"/api/export/all", "GET", "Export all data"},
	}
}

// IDORTestCases returns test cases for IDOR testing
func IDORTestCases() []struct {
	PathTemplate string
	IDLocations  []string
	Description  string
} {
	return []struct {
		PathTemplate string
		IDLocations  []string
		Description  string
	}{
		{"/api/users/{id}", []string{"1", "2", "999", "admin"}, "User profile IDOR"},
		{"/api/orders/{id}", []string{"1", "2", "1000"}, "Order details IDOR"},
		{"/api/documents/{id}", []string{"1", "2", "private"}, "Document IDOR"},
		{"/api/messages/{id}", []string{"1", "2", "3"}, "Message IDOR"},
		{"/api/invoices/{id}", []string{"1", "100", "999"}, "Invoice IDOR"},
		{"/api/accounts/{id}/balance", []string{"1", "2"}, "Account balance IDOR"},
		{"/api/files/{id}/download", []string{"1", "confidential"}, "File download IDOR"},
		{"/api/reports/{id}", []string{"1", "annual"}, "Report IDOR"},
	}
}

// MetadataManipulationPayloads returns payloads for metadata manipulation
func MetadataManipulationPayloads() []struct {
	Header string
	Values []string
} {
	return []struct {
		Header string
		Values []string
	}{
		{"X-Original-URL", []string{"/admin", "/api/admin/users"}},
		{"X-Rewrite-URL", []string{"/admin", "/dashboard"}},
		{"X-Custom-IP-Authorization", []string{"127.0.0.1", "localhost"}},
		{"X-Forwarded-For", []string{"127.0.0.1", "10.0.0.1", "192.168.1.1"}},
		{"X-Forwarded-Host", []string{"localhost", "internal.local"}},
		{"X-Remote-IP", []string{"127.0.0.1"}},
		{"X-Client-IP", []string{"127.0.0.1"}},
		{"X-Real-IP", []string{"127.0.0.1", "10.0.0.1"}},
		{"X-Host", []string{"localhost"}},
		{"X-Originating-IP", []string{"127.0.0.1"}},
		{"True-Client-IP", []string{"127.0.0.1"}},
		{"Cluster-Client-IP", []string{"127.0.0.1"}},
	}
}

// TestVerticalPrivilegeEscalation tests for vertical privilege escalation
func (t *Tester) TestVerticalPrivilegeEscalation(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	// Test admin endpoints with low-privilege token
	for _, endpoint := range AdminOnlyEndpoints() {
		fullURL := t.target + endpoint

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		// Try with low privilege token
		if t.authTokenLow != "" {
			req.Header.Set("Authorization", "Bearer "+t.authTokenLow)
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   VerticalPrivilegeEscalation,
			Endpoint:   endpoint,
			Method:     "GET",
			StatusCode: resp.StatusCode,
			Severity:   "Critical",
		}

		// If we get 200 with low privilege token on admin endpoint, it's vulnerable
		if resp.StatusCode == 200 {
			result.Vulnerable = true
			result.Description = "Low privilege user can access admin endpoint"
			result.Evidence = fmt.Sprintf("Got HTTP %d on admin endpoint with low privilege token", resp.StatusCode)
			result.Remediation = "Implement proper role-based access control (RBAC)"
		} else {
			result.Vulnerable = false
			result.Description = "Admin endpoint properly protected"
		}

		results = append(results, result)
	}

	return results, nil
}

// TestHorizontalPrivilegeEscalation tests for horizontal privilege escalation
func (t *Tester) TestHorizontalPrivilegeEscalation(ctx context.Context, userID string, otherUserID string) ([]TestResult, error) {
	var results []TestResult

	testCases := IDORTestCases()

	for _, tc := range testCases {
		// Try to access other user's resources with our token
		path := strings.Replace(tc.PathTemplate, "{id}", otherUserID, 1)
		fullURL := t.target + path

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		if t.authTokenLow != "" {
			req.Header.Set("Authorization", "Bearer "+t.authTokenLow)
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   HorizontalPrivilegeEscalation,
			Endpoint:   path,
			Method:     "GET",
			StatusCode: resp.StatusCode,
			Severity:   "High",
		}

		if resp.StatusCode == 200 {
			result.Vulnerable = true
			result.Description = fmt.Sprintf("User can access other user's %s", tc.Description)
			result.Evidence = fmt.Sprintf("Successfully accessed user %s's resource with user %s's token", otherUserID, userID)
			result.Remediation = "Verify resource ownership before granting access"
		} else {
			result.Vulnerable = false
			result.Description = tc.Description + " properly protected"
		}

		results = append(results, result)
	}

	return results, nil
}

// TestMetadataManipulation tests for access control bypass via metadata/header manipulation
func (t *Tester) TestMetadataManipulation(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	adminEndpoint := "/admin"
	baseURL := t.target + adminEndpoint

	// First, get baseline (should be 403/401)
	baseReq, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return nil, err
	}
	baseResp, _ := t.client.Do(baseReq)
	if baseResp != nil {
		iohelper.DrainAndClose(baseResp.Body)
	}

	payloads := MetadataManipulationPayloads()

	for _, p := range payloads {
		for _, val := range p.Values {
			req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
			if err != nil {
				continue
			}

			req.Header.Set(p.Header, val)

			resp, err := t.client.Do(req)
			if err != nil {
				continue
			}
			iohelper.DrainAndClose(resp.Body)

			result := TestResult{
				VulnType: MetadataManipulation,
				Endpoint: adminEndpoint,
				Method:   "GET",
				Severity: "Critical",
			}

			// If adding header changes response from 403/401 to 200
			if baseResp != nil && (baseResp.StatusCode == 403 || baseResp.StatusCode == 401) && resp.StatusCode == 200 {
				result.Vulnerable = true
				result.StatusCode = resp.StatusCode
				result.Description = fmt.Sprintf("Access control bypassed via %s header", p.Header)
				result.Evidence = fmt.Sprintf("Header: %s: %s changed response from %d to %d", p.Header, val, baseResp.StatusCode, resp.StatusCode)
				result.Remediation = "Do not trust client-supplied headers for access control decisions"
			} else {
				result.Vulnerable = false
				result.StatusCode = resp.StatusCode
				result.Description = fmt.Sprintf("%s header manipulation blocked", p.Header)
			}

			results = append(results, result)
		}
	}

	return results, nil
}

// TestForcefulBrowsing tests for access to unlinked but accessible resources
func (t *Tester) TestForcefulBrowsing(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	// Common unlinked but sensitive paths
	sensitiveResources := []string{
		"/backup",
		"/backup.sql",
		"/backup.zip",
		"/database.sql",
		"/dump.sql",
		"/config.json",
		"/config.yaml",
		"/settings.json",
		"/.env",
		"/.git/config",
		"/phpinfo.php",
		"/info.php",
		"/test.php",
		"/debug",
		"/trace",
		"/metrics",
		"/actuator",
		"/actuator/env",
		"/actuator/health",
		"/swagger-ui.html",
		"/api-docs",
		"/graphql",
		"/graphiql",
		"/internal",
		"/private",
		"/secret",
	}

	for _, resource := range sensitiveResources {
		fullURL := t.target + resource

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   ForceFullBrowsing,
			Endpoint:   resource,
			Method:     "GET",
			StatusCode: resp.StatusCode,
			Severity:   "Medium",
		}

		if resp.StatusCode == 200 {
			result.Vulnerable = true
			result.Description = "Sensitive resource accessible without authentication"
			result.Evidence = fmt.Sprintf("Resource %s returned HTTP 200", resource)
			result.Remediation = "Remove sensitive files or protect with authentication"
		} else {
			result.Vulnerable = false
			result.Description = "Resource properly protected or not present"
		}

		results = append(results, result)
	}

	return results, nil
}

// TestMissingFunctionLevelAccess tests for missing function-level access control
func (t *Tester) TestMissingFunctionLevelAccess(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	actions := PrivilegedActions()

	for _, action := range actions {
		fullURL := t.target + action.Path

		req, err := http.NewRequestWithContext(ctx, action.Method, fullURL, nil)
		if err != nil {
			continue
		}

		// Try with low privilege token
		if t.authTokenLow != "" {
			req.Header.Set("Authorization", "Bearer "+t.authTokenLow)
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   MissingFunctionLevelAccess,
			Endpoint:   action.Path,
			Method:     action.Method,
			StatusCode: resp.StatusCode,
			Severity:   "Critical",
		}

		// Success response with low privilege is a vulnerability
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			result.Vulnerable = true
			result.Description = fmt.Sprintf("Low privilege user can perform: %s", action.Desc)
			result.Evidence = fmt.Sprintf("%s %s returned HTTP %d with low privilege token", action.Method, action.Path, resp.StatusCode)
			result.Remediation = "Implement proper authorization checks for all privileged functions"
		} else {
			result.Vulnerable = false
			result.Description = fmt.Sprintf("Function '%s' properly protected", action.Desc)
		}

		results = append(results, result)
	}

	return results, nil
}

// PathManipulationPayloads returns payloads for bypassing path-based ACLs
func PathManipulationPayloads() []string {
	return []string{
		"/ADMIN", // Case sensitivity
		"/Admin",
		"/aDmIn",
		"/admin/", // Trailing slash
		"/admin//",
		"//admin",  // Double slash
		"/./admin", // Dot segment
		"/admin/.",
		"/../admin", // Path traversal
		"/admin/../admin",
		"/admin;",      // Semicolon
		"/admin%00",    // Null byte
		"/admin%20",    // Encoded space
		"/admin%2e",    // Encoded dot
		"/admin%252e",  // Double encoded
		"/admin%c0%ae", // Overlong encoding
		"/admin?",      // Query string
		"/admin#",      // Fragment
		"/admin.json",  // Extension
		"/admin.html",
		"/admin/index.html",
		"/.;/admin", // Jetty bypass
		"/;/admin",
		"/admin;foo=bar",
	}
}

// TestPathTraversalACL tests for ACL bypass via path manipulation
func (t *Tester) TestPathTraversalACL(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	payloads := PathManipulationPayloads()

	// First, verify admin is blocked normally
	baseReq, err := http.NewRequestWithContext(ctx, "GET", t.target+"/admin", nil)
	if err != nil {
		return nil, err
	}
	baseResp, _ := t.client.Do(baseReq)
	var baseStatus int
	if baseResp != nil {
		baseStatus = baseResp.StatusCode
		iohelper.DrainAndClose(baseResp.Body)
	}

	for _, payload := range payloads {
		fullURL := t.target + payload

		// URL encode properly for special characters
		parsedURL, err := url.Parse(fullURL)
		if err != nil {
			fullURL = t.target + url.PathEscape(payload)
		} else {
			fullURL = parsedURL.String()
		}

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		iohelper.DrainAndClose(resp.Body)

		result := TestResult{
			VulnType:   PathTraversalACL,
			Endpoint:   payload,
			Method:     "GET",
			StatusCode: resp.StatusCode,
			Severity:   "High",
		}

		// If manipulated path gives access when normal path doesn't
		if (baseStatus == 403 || baseStatus == 401) && resp.StatusCode == 200 {
			result.Vulnerable = true
			result.Description = "ACL bypassed via path manipulation"
			result.Evidence = fmt.Sprintf("Path '%s' bypassed access control (normal returned %d, manipulated returned %d)", payload, baseStatus, resp.StatusCode)
			result.Remediation = "Normalize and canonicalize paths before ACL checks"
		} else {
			result.Vulnerable = false
			result.Description = "Path manipulation did not bypass ACL"
		}

		results = append(results, result)
	}

	return results, nil
}

// RunAllTests runs all access control tests
func (t *Tester) RunAllTests(ctx context.Context) ([]TestResult, error) {
	var allResults []TestResult

	// Vertical privilege escalation
	results, err := t.TestVerticalPrivilegeEscalation(ctx)
	if err == nil {
		allResults = append(allResults, results...)
	}

	// Metadata manipulation
	results, err = t.TestMetadataManipulation(ctx)
	if err == nil {
		allResults = append(allResults, results...)
	}

	// Forceful browsing
	results, err = t.TestForcefulBrowsing(ctx)
	if err == nil {
		allResults = append(allResults, results...)
	}

	// Missing function-level access
	results, err = t.TestMissingFunctionLevelAccess(ctx)
	if err == nil {
		allResults = append(allResults, results...)
	}

	// Path traversal ACL bypass
	results, err = t.TestPathTraversalACL(ctx)
	if err == nil {
		allResults = append(allResults, results...)
	}

	return allResults, nil
}

// SummarizeResults provides a summary of test results
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
			case "Critical":
				summary["critical"]++
			case "High":
				summary["high"]++
			case "Medium":
				summary["medium"]++
			}
		} else {
			summary["safe"]++
		}
	}

	return summary
}
