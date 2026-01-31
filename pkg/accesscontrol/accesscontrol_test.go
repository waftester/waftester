package accesscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminOnlyEndpoints(t *testing.T) {
	endpoints := AdminOnlyEndpoints()

	if len(endpoints) < 10 {
		t.Errorf("Expected at least 10 admin endpoints, got %d", len(endpoints))
	}

	// Check for common patterns
	hasAdmin := false
	hasAPI := false
	for _, e := range endpoints {
		if strings.Contains(e, "admin") {
			hasAdmin = true
		}
		if strings.Contains(e, "api") {
			hasAPI = true
		}
	}

	if !hasAdmin {
		t.Error("Expected admin-related endpoints")
	}
	if !hasAPI {
		t.Error("Expected API admin endpoints")
	}
}

func TestPrivilegedActions(t *testing.T) {
	actions := PrivilegedActions()

	if len(actions) < 5 {
		t.Errorf("Expected at least 5 privileged actions, got %d", len(actions))
	}

	methods := make(map[string]bool)
	for _, a := range actions {
		methods[a.Method] = true
	}

	// Should have variety of methods
	if len(methods) < 2 {
		t.Error("Expected variety of HTTP methods")
	}
}

func TestIDORTestCases(t *testing.T) {
	testCases := IDORTestCases()

	if len(testCases) < 5 {
		t.Errorf("Expected at least 5 IDOR test cases, got %d", len(testCases))
	}

	for _, tc := range testCases {
		if !strings.Contains(tc.PathTemplate, "{id}") {
			t.Errorf("IDOR test case should contain {id} placeholder: %s", tc.PathTemplate)
		}
		if len(tc.IDLocations) == 0 {
			t.Errorf("IDOR test case should have ID locations: %s", tc.PathTemplate)
		}
	}
}

func TestMetadataManipulationPayloads(t *testing.T) {
	payloads := MetadataManipulationPayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 metadata manipulation payloads, got %d", len(payloads))
	}

	// Check for common bypass headers
	headers := make(map[string]bool)
	for _, p := range payloads {
		headers[p.Header] = true
	}

	expected := []string{"X-Forwarded-For", "X-Real-IP", "X-Original-URL"}
	for _, exp := range expected {
		if !headers[exp] {
			t.Errorf("Expected header %s in payloads", exp)
		}
	}
}

func TestPathManipulationPayloads(t *testing.T) {
	payloads := PathManipulationPayloads()

	if len(payloads) < 10 {
		t.Errorf("Expected at least 10 path manipulation payloads, got %d", len(payloads))
	}

	// Check for various techniques
	hasCaseDiff := false
	hasTrailingSlash := false
	hasEncoding := false

	for _, p := range payloads {
		if strings.Contains(p, "ADMIN") || strings.Contains(p, "Admin") {
			hasCaseDiff = true
		}
		if strings.HasSuffix(p, "/") && strings.Contains(p, "admin") {
			hasTrailingSlash = true
		}
		if strings.Contains(p, "%") {
			hasEncoding = true
		}
	}

	if !hasCaseDiff {
		t.Error("Expected case sensitivity tests in payloads")
	}
	if !hasTrailingSlash {
		t.Error("Expected trailing slash tests in payloads")
	}
	if !hasEncoding {
		t.Error("Expected URL encoding tests in payloads")
	}
}

func TestVerticalPrivilegeEscalation(t *testing.T) {
	// Create test server with proper access control
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		// Admin endpoints should require high privilege
		if strings.HasPrefix(r.URL.Path, "/admin") {
			if auth == "Bearer admin-token" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Admin access granted"))
			} else {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Access denied"))
			}
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(TesterConfig{
		Target:       server.URL,
		AuthTokenLow: "low-priv-token",
	})

	results, err := tester.TestVerticalPrivilegeEscalation(context.Background())
	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	// Should have tested admin endpoints
	if len(results) == 0 {
		t.Error("Expected test results")
	}

	// All should report not vulnerable (403)
	for _, r := range results {
		if strings.HasPrefix(r.Endpoint, "/admin") && r.Vulnerable {
			t.Errorf("Admin endpoint should not be accessible with low privilege: %s", r.Endpoint)
		}
	}
}

func TestVerticalPrivilegeEscalationVulnerable(t *testing.T) {
	// Create VULNERABLE test server (no access control)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No auth check - vulnerable!
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to admin"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(TesterConfig{
		Target:       server.URL,
		AuthTokenLow: "low-priv-token",
	})

	results, err := tester.TestVerticalPrivilegeEscalation(context.Background())
	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	// Should detect vulnerabilities
	vulnCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnCount++
		}
	}

	if vulnCount == 0 {
		t.Error("Expected to detect privilege escalation vulnerabilities")
	}
}

func TestMetadataManipulationBypass(t *testing.T) {
	// Create VULNERABLE server that trusts X-Forwarded-For
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: trusting client-supplied header
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Admin access granted"))
			return
		}

		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(TesterConfig{
		Target: server.URL,
	})

	results, err := tester.TestMetadataManipulation(context.Background())
	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	// Should detect the bypass
	foundBypass := false
	for _, r := range results {
		if r.Vulnerable && strings.Contains(r.Evidence, "X-Forwarded-For") {
			foundBypass = true
			break
		}
	}

	if !foundBypass {
		t.Error("Expected to detect X-Forwarded-For bypass vulnerability")
	}
}

func TestForcefulBrowsing(t *testing.T) {
	// Create server with exposed sensitive file
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=secret123"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(TesterConfig{
		Target: server.URL,
	})

	results, err := tester.TestForcefulBrowsing(context.Background())
	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	// Should detect .env exposure
	foundEnv := false
	for _, r := range results {
		if r.Vulnerable && r.Endpoint == "/.env" {
			foundEnv = true
			break
		}
	}

	if !foundEnv {
		t.Error("Expected to detect exposed .env file")
	}
}

func TestMissingFunctionLevelAccess(t *testing.T) {
	// Create server where privileged functions are not protected
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DELETE /api/users is not protected (vulnerable)
		if r.Method == "DELETE" && r.URL.Path == "/api/users" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("User deleted"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(TesterConfig{
		Target:       server.URL,
		AuthTokenLow: "low-priv-token",
	})

	results, err := tester.TestMissingFunctionLevelAccess(context.Background())
	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	// Should detect missing function-level access control
	foundVuln := false
	for _, r := range results {
		if r.Vulnerable && r.Endpoint == "/api/users" && r.Method == "DELETE" {
			foundVuln = true
			break
		}
	}

	if !foundVuln {
		t.Error("Expected to detect missing function-level access control")
	}
}

func TestPathTraversalACLBypass(t *testing.T) {
	// Create server vulnerable to case-sensitivity bypass
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only blocks lowercase /admin
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// /Admin, /ADMIN etc. are not blocked (vulnerable)
		if strings.EqualFold(r.URL.Path, "/admin") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Admin panel"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(TesterConfig{
		Target: server.URL,
	})

	results, err := tester.TestPathTraversalACL(context.Background())
	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	// Should detect case-sensitivity bypass
	foundBypass := false
	for _, r := range results {
		if r.Vulnerable && (r.Endpoint == "/ADMIN" || r.Endpoint == "/Admin") {
			foundBypass = true
			break
		}
	}

	if !foundBypass {
		t.Error("Expected to detect case-sensitivity ACL bypass")
	}
}

func TestRunAllTests(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(TesterConfig{
		Target: server.URL,
	})

	results, err := tester.RunAllTests(context.Background())
	if err != nil {
		t.Fatalf("RunAllTests failed: %v", err)
	}

	// Should have run multiple test types
	if len(results) < 20 {
		t.Errorf("Expected at least 20 test results, got %d", len(results))
	}

	// Check various vuln types are represented
	vulnTypes := make(map[VulnerabilityType]bool)
	for _, r := range results {
		vulnTypes[r.VulnType] = true
	}

	expected := []VulnerabilityType{
		VerticalPrivilegeEscalation,
		MetadataManipulation,
		ForceFullBrowsing,
		MissingFunctionLevelAccess,
		PathTraversalACL,
	}

	for _, exp := range expected {
		if !vulnTypes[exp] {
			t.Errorf("Expected tests for vulnerability type: %s", exp)
		}
	}
}

func TestSummarizeResults(t *testing.T) {
	results := []TestResult{
		{Vulnerable: true, Severity: "Critical"},
		{Vulnerable: true, Severity: "Critical"},
		{Vulnerable: true, Severity: "High"},
		{Vulnerable: false, Severity: "Medium"},
		{Vulnerable: false, Severity: "Low"},
	}

	summary := SummarizeResults(results)

	if summary["total"] != 5 {
		t.Errorf("Expected total 5, got %d", summary["total"])
	}
	if summary["vulnerable"] != 3 {
		t.Errorf("Expected vulnerable 3, got %d", summary["vulnerable"])
	}
	if summary["safe"] != 2 {
		t.Errorf("Expected safe 2, got %d", summary["safe"])
	}
	if summary["critical"] != 2 {
		t.Errorf("Expected critical 2, got %d", summary["critical"])
	}
	if summary["high"] != 1 {
		t.Errorf("Expected high 1, got %d", summary["high"])
	}
}

func TestNewTester(t *testing.T) {
	tester := NewTester(TesterConfig{
		Target:        "http://example.com",
		AuthTokenLow:  "low-token",
		AuthTokenHigh: "high-token",
	})

	if tester.target != "http://example.com" {
		t.Errorf("Expected target http://example.com, got %s", tester.target)
	}
	if tester.authTokenLow != "low-token" {
		t.Errorf("Expected authTokenLow low-token, got %s", tester.authTokenLow)
	}
	if tester.client == nil {
		t.Error("Expected HTTP client to be initialized")
	}
}
