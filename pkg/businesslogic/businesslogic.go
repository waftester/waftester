// Package businesslogic provides Business Logic vulnerability testing
package businesslogic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config configures business logic testing
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Concurrency: 5,
		Timeout:     15 * time.Second,
	}
}

// Result represents a business logic test result
type Result struct {
	URL          string
	TestType     string
	Description  string
	StatusCode   int
	ResponseSize int
	Vulnerable   bool
	Evidence     string
	Severity     string
	Timestamp    time.Time
}

// Scanner performs business logic testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new business logic scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = 5
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}

	return &Scanner{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		results: make([]Result, 0),
	}
}

// TestNegativeQuantity tests if negative quantities are accepted (e.g., -1 items)
func (s *Scanner) TestNegativeQuantity(ctx context.Context, targetURL string, quantityField string) (Result, error) {
	result := Result{
		URL:         targetURL,
		TestType:    "negative_quantity",
		Description: "Testing negative quantity acceptance",
		Timestamp:   time.Now(),
	}

	payload := map[string]interface{}{
		quantityField: -1,
	}
	jsonData, _ := json.Marshal(payload)

	req, _ := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(string(jsonData)))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)

	// If request succeeded, might be vulnerable
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.Vulnerable = true
		result.Evidence = "Negative quantity accepted"
		result.Severity = "HIGH"
	}

	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()

	return result, nil
}

// TestPriceManipulation tests if prices can be manipulated
func (s *Scanner) TestPriceManipulation(ctx context.Context, targetURL string) ([]Result, error) {
	results := make([]Result, 0)

	tests := []struct {
		name    string
		payload map[string]interface{}
	}{
		{"zero_price", map[string]interface{}{"price": 0}},
		{"negative_price", map[string]interface{}{"price": -100}},
		{"tiny_price", map[string]interface{}{"price": 0.01}},
		{"float_overflow", map[string]interface{}{"price": 0.001}},
	}

	for _, test := range tests {
		result := Result{
			URL:         targetURL,
			TestType:    "price_manipulation",
			Description: test.name,
			Timestamp:   time.Now(),
		}

		jsonData, _ := json.Marshal(test.payload)
		req, _ := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(string(jsonData)))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range s.config.Headers {
			req.Header.Set(k, v)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		result.StatusCode = resp.StatusCode
		result.ResponseSize = len(body)

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			result.Vulnerable = true
			result.Evidence = "Price manipulation accepted: " + test.name
			result.Severity = "CRITICAL"
		}

		results = append(results, result)
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// TestWorkflowBypass tests if workflow steps can be bypassed
func (s *Scanner) TestWorkflowBypass(ctx context.Context, steps []string) ([]Result, error) {
	results := make([]Result, 0)

	// Test skipping intermediate steps
	for i := 0; i < len(steps)-1; i++ {
		// Try to access step i+2 directly from step i (skipping i+1)
		if i+2 < len(steps) {
			result := Result{
				URL:         steps[i+2],
				TestType:    "workflow_bypass",
				Description: "Skipping step " + steps[i+1],
				Timestamp:   time.Now(),
			}

			req, _ := http.NewRequestWithContext(ctx, "GET", steps[i+2], nil)
			for k, v := range s.config.Headers {
				req.Header.Set(k, v)
			}

			resp, err := s.client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			result.StatusCode = resp.StatusCode
			result.ResponseSize = len(body)

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				result.Vulnerable = true
				result.Evidence = "Workflow step bypass possible"
				result.Severity = "HIGH"
			}

			results = append(results, result)
		}
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// CommonBusinessLogicTests returns common business logic test cases
func CommonBusinessLogicTests() []string {
	return []string{
		"negative_quantity",
		"zero_price",
		"negative_price",
		"coupon_reuse",
		"race_condition",
		"workflow_bypass",
		"role_escalation",
		"self_approval",
		"time_manipulation",
		"quantity_overflow",
	}
}

// EcommerceTestCases returns e-commerce specific test cases
func EcommerceTestCases() map[string]interface{} {
	return map[string]interface{}{
		"negative_quantity": map[string]interface{}{"quantity": -1},
		"zero_price":        map[string]interface{}{"price": 0},
		"negative_discount": map[string]interface{}{"discount": -100},
		"invalid_coupon":    map[string]interface{}{"coupon": "' OR '1'='1"},
		"overflow_quantity": map[string]interface{}{"quantity": 9999999999},
	}
}

// FinancialTestCases returns financial app specific test cases
func FinancialTestCases() map[string]interface{} {
	return map[string]interface{}{
		"negative_transfer": map[string]interface{}{"amount": -1000},
		"zero_transfer":     map[string]interface{}{"amount": 0},
		"same_account":      map[string]interface{}{"from": "123", "to": "123"},
		"overflow_amount":   map[string]interface{}{"amount": 999999999999},
		"precision_attack":  map[string]interface{}{"amount": 0.0000001},
	}
}
