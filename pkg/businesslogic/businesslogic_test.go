package businesslogic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 5 {
		t.Errorf("DefaultConfig().Concurrency = %d, want 5", config.Concurrency)
	}
	if config.Timeout != 15*1e9 {
		t.Errorf("DefaultConfig().Timeout = %v, want 15s", config.Timeout)
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

func TestScanner_TestNegativeQuantity_Vulnerable(t *testing.T) {
	// Server that accepts negative quantities
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var data map[string]interface{}
		json.Unmarshal(body, &data)

		// Accepts any quantity without validation
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.TestNegativeQuantity(context.Background(), server.URL, "quantity")

	if err != nil {
		t.Fatalf("TestNegativeQuantity error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability - negative quantity accepted")
	}
	if result.Severity != "HIGH" {
		t.Errorf("Expected HIGH severity, got: %s", result.Severity)
	}
}

func TestScanner_TestNegativeQuantity_Safe(t *testing.T) {
	// Server that rejects negative quantities
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var data map[string]interface{}
		json.Unmarshal(body, &data)

		if qty, ok := data["quantity"].(float64); ok && qty < 0 {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid quantity"})
			return
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.TestNegativeQuantity(context.Background(), server.URL, "quantity")

	if err != nil {
		t.Fatalf("TestNegativeQuantity error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability - negative quantity rejected")
	}
}

func TestScanner_TestPriceManipulation(t *testing.T) {
	// Server that accepts any price
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.TestPriceManipulation(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("TestPriceManipulation error: %v", err)
	}

	if len(results) < 3 {
		t.Errorf("Expected at least 3 results, got %d", len(results))
	}

	vulnCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnCount++
		}
	}

	if vulnCount == 0 {
		t.Error("Expected at least one vulnerability")
	}
}

func TestScanner_TestWorkflowBypass(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	// Create test servers for workflow steps
	step1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Step 1"))
	}))
	defer step1.Close()

	step2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Step 2"))
	}))
	defer step2.Close()

	step3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Step 3"))
	}))
	defer step3.Close()

	results, err := scanner.TestWorkflowBypass(context.Background(), []string{
		step1.URL, step2.URL, step3.URL,
	})

	if err != nil {
		t.Fatalf("TestWorkflowBypass error: %v", err)
	}

	// With 3 steps, we should have 1 result (testing skip from step 0 to step 2)
	if len(results) < 1 {
		t.Errorf("Expected at least 1 result, got %d", len(results))
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("GetResults returned nil")
	}
}

func TestCommonBusinessLogicTests(t *testing.T) {
	tests := CommonBusinessLogicTests()
	if len(tests) < 5 {
		t.Errorf("CommonBusinessLogicTests count = %d, want at least 5", len(tests))
	}

	// Check for critical tests
	found := map[string]bool{}
	for _, test := range tests {
		found[test] = true
	}

	expected := []string{"negative_quantity", "zero_price", "workflow_bypass"}
	for _, exp := range expected {
		if !found[exp] {
			t.Errorf("Expected test case: %s", exp)
		}
	}
}

func TestEcommerceTestCases(t *testing.T) {
	cases := EcommerceTestCases()
	if len(cases) < 3 {
		t.Errorf("EcommerceTestCases count = %d, want at least 3", len(cases))
	}

	if _, ok := cases["negative_quantity"]; !ok {
		t.Error("Expected negative_quantity test case")
	}
}

func TestFinancialTestCases(t *testing.T) {
	cases := FinancialTestCases()
	if len(cases) < 3 {
		t.Errorf("FinancialTestCases count = %d, want at least 3", len(cases))
	}

	if _, ok := cases["negative_transfer"]; !ok {
		t.Error("Expected negative_transfer test case")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:         "http://example.com/cart",
		TestType:    "negative_quantity",
		Description: "Testing negative values",
		StatusCode:  200,
		Vulnerable:  true,
		Evidence:    "Negative quantity accepted",
		Severity:    "HIGH",
	}

	if result.URL != "http://example.com/cart" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
	if result.TestType != "negative_quantity" {
		t.Error("TestType not set correctly")
	}
}
