package bizlogic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewTester(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		tester := NewTester(nil)
		if tester == nil {
			t.Fatal("expected tester, got nil")
		}
		if tester.config.Concurrency != 10 {
			t.Errorf("expected concurrency 10, got %d", tester.config.Concurrency)
		}
		if tester.config.RaceCount != 10 {
			t.Errorf("expected RaceCount 10, got %d", tester.config.RaceCount)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:     60 * time.Second,
			Concurrency: 20,
			RaceCount:   5,
		}
		tester := NewTester(config)
		if tester.config.Concurrency != 20 {
			t.Errorf("expected concurrency 20, got %d", tester.config.Concurrency)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", config.Timeout)
	}

	if !config.EnableRace {
		t.Error("expected EnableRace to be true")
	}

	if len(config.IDPatterns) == 0 {
		t.Error("expected ID patterns")
	}
}

func TestTestIDOR(t *testing.T) {
	// Create test server with IDOR vulnerability
	userDB := map[string]string{
		"1": `{"id":1,"name":"Alice","email":"alice@example.com"}`,
		"2": `{"id":2,"name":"Bob","email":"bob@example.com"}`,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract user ID from path
		path := r.URL.Path
		for id, data := range userDB {
			if strings.Contains(path, "/users/"+id) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(data))
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()

	// Test IDOR - accessing user 2's data while "authenticated" as user 1
	vuln, err := tester.TestIDOR(ctx, server.URL, "/users/1", "1", "2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if vuln == nil {
		t.Log("No IDOR detected (this is expected if data is similar)")
	} else {
		if vuln.Type != VulnIDOR {
			t.Errorf("expected IDOR type, got %s", vuln.Type)
		}
	}
}

func TestTestAuthBypass(t *testing.T) {
	// Create test server vulnerable to auth bypass
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: trusts X-Custom-IP-Authorization header
		if r.Header.Get("X-Custom-IP-Authorization") == "127.0.0.1" {
			w.Write([]byte(`{"admin":true,"users":["admin","alice","bob"],"dashboard":"active"}`))
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()

	vulns, err := tester.TestAuthBypass(ctx, server.URL+"/admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(vulns) == 0 {
		t.Error("expected to detect auth bypass vulnerability")
	}

	for _, v := range vulns {
		if v.Type != VulnAuthBypass {
			t.Errorf("expected auth-bypass type, got %s", v.Type)
		}
	}
}

func TestTestMassAssignment(t *testing.T) {
	// Create test server vulnerable to mass assignment
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var data map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Vulnerable: accepts and echoes all fields including admin
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()

	normalPayload := `{"name":"test","email":"test@example.com"}`
	maliciousPayload := `{"name":"test","email":"test@example.com","isAdmin":true,"role":"admin"}`

	vuln, err := tester.TestMassAssignment(ctx, server.URL+"/users", normalPayload, maliciousPayload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if vuln == nil {
		t.Error("expected to detect mass assignment vulnerability")
	}

	if vuln != nil && vuln.Type != VulnMassAssign {
		t.Errorf("expected mass-assignment type, got %s", vuln.Type)
	}
}

func TestTestRaceCondition(t *testing.T) {
	// Create test server that might be vulnerable to race conditions
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt64(&requestCount, 1)
		// Simulate processing
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"success":true,"request":%d}`, count)))
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Timeout:   5 * time.Second,
		RaceCount: 5,
	})

	ctx := context.Background()

	vulns, err := tester.TestRaceCondition(ctx, server.URL+"/transfer", "POST", `{"amount":100}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// May or may not detect race condition depending on timing
	_ = vulns
}

func TestTestEnumeration(t *testing.T) {
	// Create test server with enumeration vulnerability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if strings.Contains(path, "/users/1") {
			w.Write([]byte(`{"id":1,"name":"Alice"}`))
			return
		}

		// Different response for non-existent users
		http.Error(w, "User not found", http.StatusNotFound)
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()

	vuln, err := tester.TestEnumeration(ctx, server.URL+"/users/{id}", "1", "99999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if vuln == nil {
		t.Error("expected to detect enumeration vulnerability")
	}

	if vuln != nil && vuln.Type != VulnEnumeration {
		t.Errorf("expected enumeration type, got %s", vuln.Type)
	}
}

func TestTestWorkflowBypass(t *testing.T) {
	// Create test server vulnerable to workflow bypass
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: allows access to checkout without cart
		if strings.Contains(r.URL.Path, "/checkout/complete") {
			w.Write([]byte(`{"order_id":"12345","status":"completed","total":100.00}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()

	vuln, err := tester.TestWorkflowBypass(ctx, server.URL+"/checkout/complete", []string{"/cart/add", "/cart/review", "/checkout/payment"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if vuln == nil {
		t.Error("expected to detect workflow bypass vulnerability")
	}

	if vuln != nil && vuln.Type != VulnWorkflowBypass {
		t.Errorf("expected workflow-bypass type, got %s", vuln.Type)
	}
}

func TestExtractIDs(t *testing.T) {
	tests := []struct {
		url      string
		expected int
	}{
		{"/users/123", 1},
		{"/users/123/posts/456", 2},
		{"/api/550e8400-e29b-41d4-a716-446655440000/data", 1},
		{"?id=123", 1},
		{"?userId=456&postId=789", 0}, // postId doesn't match patterns
		{"/api/resource", 0},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			ids := ExtractIDs(tt.url)
			if len(ids) < tt.expected {
				t.Errorf("expected at least %d IDs, got %d", tt.expected, len(ids))
			}
		})
	}
}

func TestGenerateIDVariations(t *testing.T) {
	t.Run("numeric ID", func(t *testing.T) {
		variations := GenerateIDVariations("123")
		if len(variations) < 5 {
			t.Errorf("expected at least 5 variations, got %d", len(variations))
		}

		// Should include adjacent numbers
		hasNext := false
		for _, v := range variations {
			if v == "124" {
				hasNext = true
				break
			}
		}
		if !hasNext {
			t.Error("expected variation 124")
		}
	})

	t.Run("UUID", func(t *testing.T) {
		variations := GenerateIDVariations("550e8400-e29b-41d4-a716-446655440000")
		if len(variations) < 3 {
			t.Errorf("expected at least 3 variations, got %d", len(variations))
		}
	})
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 12 {
		t.Errorf("expected 12 vulnerability types, got %d", len(types))
	}

	// Check for specific types
	typeMap := make(map[VulnerabilityType]bool)
	for _, vt := range types {
		typeMap[vt] = true
	}

	if !typeMap[VulnIDOR] {
		t.Error("expected IDOR type")
	}
	if !typeMap[VulnAuthBypass] {
		t.Error("expected AuthBypass type")
	}
	if !typeMap[VulnRaceCondition] {
		t.Error("expected RaceCondition type")
	}
}

func TestGetRemediation(t *testing.T) {
	tests := []VulnerabilityType{
		VulnIDOR,
		VulnAuthBypass,
		VulnPrivEsc,
		VulnMassAssign,
		VulnRaceCondition,
	}

	for _, vt := range tests {
		t.Run(string(vt), func(t *testing.T) {
			remediation := GetRemediation(vt)
			if remediation == "" {
				t.Errorf("expected remediation for %s", vt)
			}
		})
	}
}

func TestVulnerabilityToJSON(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnIDOR,
		Description: "IDOR vulnerability found",
		Severity:    SeverityHigh,
		URL:         "https://example.com/users/123",
		Method:      "GET",
		OriginalID:  "1",
		TestedID:    "2",
		Evidence:    "Different user data returned",
		CVSS:        7.5,
	}

	jsonStr, err := VulnerabilityToJSON(vuln)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(jsonStr, "idor") {
		t.Error("expected vulnerability type in JSON")
	}
}

func TestVulnerability(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnPrivEsc,
		Description: "Privilege escalation detected",
		Severity:    SeverityCritical,
		URL:         "https://example.com/admin",
		Method:      "GET",
		Evidence:    "Admin panel accessed with low-priv token",
		Remediation: "Implement RBAC",
		CVSS:        9.1,
	}

	data, err := json.Marshal(vuln)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Vulnerability
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Type != vuln.Type {
		t.Errorf("type mismatch")
	}
	if decoded.Severity != vuln.Severity {
		t.Errorf("severity mismatch")
	}
}

func TestTesterConfig(t *testing.T) {
	config := &TesterConfig{
		Timeout:       10 * time.Second,
		UserAgent:     "custom-agent/1.0",
		Concurrency:   5,
		EnableRace:    true,
		RaceCount:     20,
		AuthHeader:    "Bearer token123",
		SecondaryAuth: "Bearer token456",
		Cookies: map[string]string{
			"session": "abc123",
		},
	}

	if config.Timeout != 10*time.Second {
		t.Error("timeout mismatch")
	}
	if config.AuthHeader != "Bearer token123" {
		t.Error("auth header mismatch")
	}
	if len(config.Cookies) != 1 {
		t.Error("cookies mismatch")
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("isNumeric", func(t *testing.T) {
		if !isNumeric("12345") {
			t.Error("12345 should be numeric")
		}
		if isNumeric("abc") {
			t.Error("abc should not be numeric")
		}
		if isNumeric("123abc") {
			t.Error("123abc should not be numeric")
		}
	})

	t.Run("parseInt", func(t *testing.T) {
		if parseInt("123") != 123 {
			t.Error("expected 123")
		}
		if parseInt("0") != 0 {
			t.Error("expected 0")
		}
	})

	t.Run("isUUID", func(t *testing.T) {
		if !isUUID("550e8400-e29b-41d4-a716-446655440000") {
			t.Error("should be valid UUID")
		}
		if isUUID("not-a-uuid") {
			t.Error("should not be valid UUID")
		}
	})

	t.Run("containsAdminIndicators", func(t *testing.T) {
		if !containsAdminIndicators("Welcome to admin dashboard") {
			t.Error("should detect admin indicator")
		}
		if containsAdminIndicators("Hello world") {
			t.Error("should not detect admin indicator")
		}
	})
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Timeout:     5 * time.Second,
		Concurrency: 2,
	})

	ctx := context.Background()

	endpoints := []string{
		"/users/123",
		"/api/v1/accounts/456",
	}

	vulns, err := tester.Scan(ctx, server.URL, endpoints)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// May or may not find vulnerabilities depending on server behavior
	_ = vulns
}

func TestParseURL(t *testing.T) {
	u, err := ParseURL("https://example.com/path?query=value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if u.Host != "example.com" {
		t.Errorf("expected host example.com, got %s", u.Host)
	}

	if u.Path != "/path" {
		t.Errorf("expected path /path, got %s", u.Path)
	}
}

func TestExtractedID(t *testing.T) {
	id := ExtractedID{
		Type:  "numeric",
		Value: "123",
		Full:  "/users/123",
	}

	data, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ExtractedID
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Value != "123" {
		t.Error("value mismatch")
	}
}

func TestTestCase(t *testing.T) {
	tc := TestCase{
		Name:        "IDOR test",
		Type:        VulnIDOR,
		Description: "Test for IDOR vulnerability",
		Method:      "GET",
		Path:        "/users/{id}",
		Expected: ExpectedResult{
			StatusCode:  200,
			ContainsAny: []string{"id", "name"},
		},
	}

	data, err := json.Marshal(tc)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded TestCase
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Type != VulnIDOR {
		t.Error("type mismatch")
	}
}

func TestRaceResponse(t *testing.T) {
	rr := RaceResponse{
		StatusCode: 200,
		Body:       `{"success":true}`,
		Duration:   100 * time.Millisecond,
	}

	if rr.StatusCode != 200 {
		t.Error("status code mismatch")
	}
	if rr.Duration != 100*time.Millisecond {
		t.Error("duration mismatch")
	}
}
