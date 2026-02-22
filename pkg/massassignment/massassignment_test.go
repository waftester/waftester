package massassignment

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/waftester/waftester/pkg/httpclient"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 5 {
		t.Errorf("DefaultConfig().Concurrency = %d, want 5", config.Concurrency)
	}
	if config.Timeout != httpclient.TimeoutProbing {
		t.Errorf("DefaultConfig().Timeout = %v, want %v", config.Timeout, httpclient.TimeoutProbing)
	}
}

func TestNewScanner(t *testing.T) {
	config := DefaultConfig()
	scanner := NewScanner(config)
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	if scanner.client == nil {
		t.Error("Scanner client is nil")
	}
}

func TestScanner_Scan_Vulnerable(t *testing.T) {
	// Server that accepts any JSON and echoes it back
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var data map[string]interface{}
		json.Unmarshal(body, &data)

		// Echo back all parameters (vulnerable behavior)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL, map[string]interface{}{
		"name": "test",
	})

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable {
			foundVuln = true
			if r.Severity == "" {
				t.Error("Vulnerable result should have severity")
			}
		}
	}

	if !foundVuln {
		t.Error("Expected to find mass assignment vulnerability")
	}
}

func TestScanner_Scan_Safe(t *testing.T) {
	// Server that only accepts whitelisted parameters
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var data map[string]interface{}
		json.Unmarshal(body, &data)

		// Only return whitelisted fields
		response := map[string]interface{}{
			"name": data["name"],
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.Scan(context.Background(), server.URL, map[string]interface{}{
		"name": "test",
	})

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, r := range results {
		if r.Vulnerable {
			t.Errorf("Expected no vulnerabilities, found: %s", r.Parameter)
		}
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("GetResults returned nil")
	}
}

func TestDangerousParameters(t *testing.T) {
	params := DangerousParameters()
	if len(params) < 20 {
		t.Errorf("DangerousParameters count = %d, want at least 20", len(params))
	}

	// Check for critical privilege parameters
	foundRole := false
	foundAdmin := false
	for _, p := range params {
		if p.Name == "role" {
			foundRole = true
		}
		if p.Name == "isAdmin" {
			foundAdmin = true
		}
	}

	if !foundRole {
		t.Error("Expected 'role' in dangerous parameters")
	}
	if !foundAdmin {
		t.Error("Expected 'isAdmin' in dangerous parameters")
	}
}

func TestRoleEscalationParams(t *testing.T) {
	params := RoleEscalationParams()
	if len(params) < 5 {
		t.Errorf("RoleEscalationParams count = %d, want at least 5", len(params))
	}

	for _, p := range params {
		if p.Category != "privilege" {
			t.Errorf("RoleEscalationParams should only contain privilege category, got: %s", p.Category)
		}
	}
}

func TestFinancialParams(t *testing.T) {
	params := FinancialParams()
	if len(params) < 3 {
		t.Errorf("FinancialParams count = %d, want at least 3", len(params))
	}

	for _, p := range params {
		if p.Category != "financial" {
			t.Errorf("FinancialParams should only contain financial category, got: %s", p.Category)
		}
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:        "http://example.com/api/user",
		Method:     "POST",
		Parameter:  "isAdmin",
		StatusCode: 200,
		Vulnerable: true,
		Evidence:   "Parameter accepted",
		Severity:   "critical",
	}

	if result.URL != "http://example.com/api/user" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
	if result.Severity != "critical" {
		t.Error("Severity not set correctly")
	}
}

func TestDangerousParam_Categories(t *testing.T) {
	params := DangerousParameters()

	categories := make(map[string]int)
	for _, p := range params {
		categories[p.Category]++
	}

	expectedCategories := []string{"privilege", "account", "financial", "id", "internal"}
	for _, cat := range expectedCategories {
		if categories[cat] == 0 {
			t.Errorf("Expected category %s not found", cat)
		}
	}
}

func TestDangerousParam_Severities(t *testing.T) {
	params := DangerousParameters()

	hasCritical := false
	hasHigh := false
	hasMedium := false

	for _, p := range params {
		switch p.Severity {
		case "critical":
			hasCritical = true
		case "high":
			hasHigh = true
		case "medium":
			hasMedium = true
		}
	}

	if !hasCritical {
		t.Error("Expected critical severity parameters")
	}
	if !hasHigh {
		t.Error("Expected high severity parameters")
	}
	if !hasMedium {
		t.Error("Expected medium severity parameters")
	}
}
