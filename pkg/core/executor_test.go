package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/ui"
)

// TestMain resets global state before running tests
func TestMain(m *testing.M) {
	// Clear hosterrors cache before tests to prevent cross-test pollution
	hosterrors.ClearAll()
	code := m.Run()
	os.Exit(code)
}

// mockWriter collects results for testing
type mockWriter struct {
	mu      sync.Mutex
	results []*output.TestResult
}

func (m *mockWriter) Write(result *output.TestResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = append(m.results, result)
	return nil
}

func (m *mockWriter) Close() error {
	return nil
}

func (m *mockWriter) Results() []*output.TestResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.results
}

// TestNewExecutor tests executor creation
func TestNewExecutor(t *testing.T) {
	t.Run("basic config", func(t *testing.T) {
		cfg := ExecutorConfig{
			TargetURL:   "http://localhost:8080",
			Concurrency: 10,
			RateLimit:   100,
			Timeout:     5 * time.Second,
			Retries:     3,
			SkipVerify:  false,
		}
		e := NewExecutor(cfg)
		if e == nil {
			t.Fatal("NewExecutor returned nil")
		}
		if e.config.TargetURL != cfg.TargetURL {
			t.Errorf("expected TargetURL %s, got %s", cfg.TargetURL, e.config.TargetURL)
		}
		if e.httpClient == nil {
			t.Error("httpClient is nil")
		}
		if e.limiter == nil {
			t.Error("limiter is nil")
		}
	})

	t.Run("with proxy", func(t *testing.T) {
		cfg := ExecutorConfig{
			TargetURL:   "http://localhost:8080",
			Concurrency: 5,
			RateLimit:   50,
			Timeout:     3 * time.Second,
			Proxy:       "http://proxy.example.com:8080",
		}
		e := NewExecutor(cfg)
		if e == nil {
			t.Fatal("NewExecutor with proxy returned nil")
		}
	})

	t.Run("with skip verify", func(t *testing.T) {
		cfg := ExecutorConfig{
			TargetURL:   "https://localhost:8443",
			Concurrency: 1,
			RateLimit:   10,
			Timeout:     1 * time.Second,
			SkipVerify:  true,
		}
		e := NewExecutor(cfg)
		if e == nil {
			t.Fatal("NewExecutor with skip verify returned nil")
		}
	})
}

// TestExecuteTest tests the executeTest method with various scenarios
func TestExecuteTest(t *testing.T) {
	hosterrors.ClearAll() // Reset host error cache for clean test
	t.Run("GET request blocked 403", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify it's a GET request
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			// Verify User-Agent starts with waftester
			if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "waftester/") {
				t.Errorf("expected User-Agent starting with waftester/, got %s", ua)
			}
			// Check that payload is in query param
			if !strings.Contains(r.URL.RawQuery, "test=") {
				t.Error("expected 'test' query parameter")
			}
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		payload := payloads.Payload{
			ID:            "test-sqli-001",
			Category:      "sqli",
			Payload:       "' OR '1'='1",
			SeverityHint:  "critical",
			ExpectedBlock: true,
		}

		result := e.executeTest(context.Background(), payload)

		if result.Outcome != "Blocked" {
			t.Errorf("expected Blocked, got %s", result.Outcome)
		}
		if result.StatusCode != 403 {
			t.Errorf("expected status 403, got %d", result.StatusCode)
		}
		if result.Method != "GET" {
			t.Errorf("expected Method GET, got %s", result.Method)
		}
		if result.Category != "sqli" {
			t.Errorf("expected Category sqli, got %s", result.Category)
		}
	})

	t.Run("GET request blocked 406", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotAcceptable)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		payload := payloads.Payload{
			ID:            "test-xss-001",
			Payload:       "<script>alert(1)</script>",
			ExpectedBlock: true,
		}

		result := e.executeTest(context.Background(), payload)
		if result.Outcome != "Blocked" {
			t.Errorf("expected Blocked on 406, got %s", result.Outcome)
		}
	})

	t.Run("GET request blocked 429", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		result := e.executeTest(context.Background(), payloads.Payload{ID: "test"})
		if result.Outcome != "Blocked" {
			t.Errorf("expected Blocked on 429, got %s", result.Outcome)
		}
	})

	t.Run("GET request passed 200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		payload := payloads.Payload{
			ID:            "test-normal",
			Payload:       "normal-input",
			ExpectedBlock: false,
		}

		result := e.executeTest(context.Background(), payload)
		if result.Outcome != "Pass" {
			t.Errorf("expected Pass, got %s", result.Outcome)
		}
		if result.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", result.StatusCode)
		}
	})

	t.Run("expected block but got 200 - fail", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		payload := payloads.Payload{
			ID:            "test-sqli",
			Payload:       "' OR '1'='1",
			ExpectedBlock: true, // Expect block but server returns 200
		}

		result := e.executeTest(context.Background(), payload)
		if result.Outcome != "Fail" {
			t.Errorf("expected Fail (WAF bypass), got %s", result.Outcome)
		}
	})

	t.Run("404 is Pass", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		result := e.executeTest(context.Background(), payloads.Payload{ID: "test"})
		if result.Outcome != "Pass" {
			t.Errorf("expected Pass on 404, got %s", result.Outcome)
		}
	})

	t.Run("500 is Error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		result := e.executeTest(context.Background(), payloads.Payload{ID: "test"})
		if result.Outcome != "Error" {
			t.Errorf("expected Error on 500, got %s", result.Outcome)
		}
		if result.ErrorMessage == "" {
			t.Error("expected ErrorMessage to be set")
		}
	})

	t.Run("POST with body and content type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			ct := r.Header.Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("expected Content-Type application/json, got %s", ct)
			}
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		payload := payloads.Payload{
			ID:            "test-post",
			Category:      "sqli",
			Method:        "POST",
			Payload:       `{"data": "' OR '1'='1"}`,
			ContentType:   "application/json",
			ExpectedBlock: true,
		}

		result := e.executeTest(context.Background(), payload)
		if result.Outcome != "Blocked" {
			t.Errorf("expected Blocked, got %s", result.Outcome)
		}
		if result.Method != "POST" {
			t.Errorf("expected Method POST, got %s", result.Method)
		}
		if result.ContentType != "application/json" {
			t.Errorf("expected ContentType application/json, got %s", result.ContentType)
		}
	})

	t.Run("with TargetPath", func(t *testing.T) {
		var receivedPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedPath = r.URL.Path
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		payload := payloads.Payload{
			ID:            "test-path",
			TargetPath:    "/api/v1/users",
			Payload:       "test",
			ExpectedBlock: true,
		}

		result := e.executeTest(context.Background(), payload)
		if receivedPath != "/api/v1/users" {
			t.Errorf("expected path /api/v1/users, got %s", receivedPath)
		}
		if result.TargetPath != "/api/v1/users" {
			t.Errorf("expected TargetPath /api/v1/users, got %s", result.TargetPath)
		}
	})

	t.Run("timeout error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(500 * time.Millisecond) // Delay longer than timeout
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     100 * time.Millisecond, // Very short timeout
			Retries:     0,
		})

		result := e.executeTest(context.Background(), payloads.Payload{ID: "test"})
		if result.Outcome != "Error" {
			t.Errorf("expected Error on timeout, got %s", result.Outcome)
		}
		if result.ErrorMessage == "" {
			t.Error("expected ErrorMessage for timeout")
		}
	})

	t.Run("retry on failure", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 3 {
				// Simulate connection issues by closing connection
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
			Retries:     3,
		})

		result := e.executeTest(context.Background(), payloads.Payload{ID: "test", ExpectedBlock: true})
		if attempts < 2 {
			t.Errorf("expected retries, only got %d attempts", attempts)
		}
		// After retries, should succeed
		if result.Outcome != "Blocked" && result.Outcome != "Error" {
			t.Errorf("expected Blocked or Error after retries, got %s", result.Outcome)
		}
	})

	t.Run("latency tracking", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(50 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		result := e.executeTest(context.Background(), payloads.Payload{ID: "test"})
		if result.LatencyMs < 50 {
			t.Errorf("expected LatencyMs >= 50, got %d", result.LatencyMs)
		}
	})

	t.Run("risk score calculated", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		payload := payloads.Payload{
			ID:            "test",
			SeverityHint:  "critical",
			Category:      "sqli",
			ExpectedBlock: true,
		}

		result := e.executeTest(context.Background(), payload)
		// Fail case with critical severity should have high risk
		if result.RiskScore.RiskScore <= 0 {
			t.Errorf("expected RiskScore > 0, got %f", result.RiskScore.RiskScore)
		}
	})
}

// TestExecute tests the Execute method with parallel workers
func TestExecute(t *testing.T) {
	hosterrors.ClearAll() // Reset host error cache for clean test
	t.Run("multiple payloads parallel", func(t *testing.T) {
		requestCount := 0
		var mu sync.Mutex
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requestCount++
			mu.Unlock()
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 5,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		testPayloads := make([]payloads.Payload, 20)
		for i := 0; i < 20; i++ {
			testPayloads[i] = payloads.Payload{
				ID:            fmt.Sprintf("test-%d", i),
				Payload:       fmt.Sprintf("payload-%d", i),
				ExpectedBlock: true,
			}
		}

		writer := &mockWriter{}
		results := e.Execute(context.Background(), testPayloads, writer)

		if results.TotalTests != 20 {
			t.Errorf("expected TotalTests 20, got %d", results.TotalTests)
		}
		if requestCount != 20 {
			t.Errorf("expected 20 requests, got %d", requestCount)
		}
		if results.BlockedTests != 20 {
			t.Errorf("expected 20 blocked, got %d", results.BlockedTests)
		}
		if len(writer.Results()) != 20 {
			t.Errorf("expected 20 results written, got %d", len(writer.Results()))
		}
		if results.Duration <= 0 {
			t.Error("expected Duration > 0")
		}
		if results.RequestsPerSec <= 0 {
			t.Error("expected RequestsPerSec > 0")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 2,
			RateLimit:   10,
			Timeout:     5 * time.Second,
		})

		testPayloads := make([]payloads.Payload, 100)
		for i := 0; i < 100; i++ {
			testPayloads[i] = payloads.Payload{ID: fmt.Sprintf("test-%d", i)}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		writer := &mockWriter{}
		results := e.Execute(ctx, testPayloads, writer)

		// Should complete early due to cancellation
		if results.TotalTests != 100 {
			t.Errorf("expected TotalTests 100, got %d", results.TotalTests)
		}
		// Completed tests should be less than total
		completed := results.BlockedTests + results.PassedTests + results.FailedTests + results.ErrorTests
		if completed >= 100 {
			t.Errorf("expected less than 100 completed due to cancel, got %d", completed)
		}
	})

	t.Run("mixed outcomes", func(t *testing.T) {
		var counter int
		var mu sync.Mutex
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			c := counter
			counter++
			mu.Unlock()

			switch c % 4 {
			case 0:
				w.WriteHeader(http.StatusForbidden) // Blocked
			case 1:
				w.WriteHeader(http.StatusOK) // Pass or Fail
			case 2:
				w.WriteHeader(http.StatusNotFound) // Pass
			case 3:
				w.WriteHeader(http.StatusInternalServerError) // Error
			}
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1, // Sequential for predictable order
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		testPayloads := []payloads.Payload{
			{ID: "p1", ExpectedBlock: true},  // 403 -> Blocked
			{ID: "p2", ExpectedBlock: true},  // 200 -> Fail
			{ID: "p3", ExpectedBlock: false}, // 404 -> Pass
			{ID: "p4", ExpectedBlock: false}, // 500 -> Error
		}

		writer := &mockWriter{}
		results := e.Execute(context.Background(), testPayloads, writer)

		if results.BlockedTests != 1 {
			t.Errorf("expected 1 blocked, got %d", results.BlockedTests)
		}
		if results.FailedTests != 1 {
			t.Errorf("expected 1 failed, got %d", results.FailedTests)
		}
		if results.PassedTests != 1 {
			t.Errorf("expected 1 passed, got %d", results.PassedTests)
		}
		if results.ErrorTests != 1 {
			t.Errorf("expected 1 error, got %d", results.ErrorTests)
		}
	})
}

// TestRateLimiting verifies the rate limiter works
func TestRateLimiting(t *testing.T) {
	requestCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 10,
		RateLimit:   10, // Only 10 requests per second
		Timeout:     5 * time.Second,
	})

	testPayloads := make([]payloads.Payload, 30)
	for i := 0; i < 30; i++ {
		testPayloads[i] = payloads.Payload{ID: fmt.Sprintf("test-%d", i)}
	}

	start := time.Now()
	writer := &mockWriter{}
	e.Execute(context.Background(), testPayloads, writer)
	elapsed := time.Since(start)

	// With 30 requests at 10/sec, should take at least 2 seconds
	if elapsed < 2*time.Second {
		t.Errorf("rate limiting not working: 30 requests completed in %v", elapsed)
	}
}

// TestResultFields verifies all result fields are populated
func TestResultFields(t *testing.T) {
	hosterrors.ClearAll() // Reset host error cache for clean test
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
	})

	payload := payloads.Payload{
		ID:            "test-complete",
		Category:      "sqli",
		Payload:       "' OR '1'='1",
		Method:        "POST",
		TargetPath:    "/api/login",
		ContentType:   "application/json",
		SeverityHint:  "critical",
		ExpectedBlock: true,
	}

	result := e.executeTest(context.Background(), payload)

	// Verify all fields
	if result.ID != "test-complete" {
		t.Errorf("ID mismatch: %s", result.ID)
	}
	if result.Category != "sqli" {
		t.Errorf("Category mismatch: %s", result.Category)
	}
	if result.Payload != "' OR '1'='1" {
		t.Errorf("Payload mismatch: %s", result.Payload)
	}
	if result.Method != "POST" {
		t.Errorf("Method mismatch: %s", result.Method)
	}
	if result.TargetPath != "/api/login" {
		t.Errorf("TargetPath mismatch: %s", result.TargetPath)
	}
	if result.ContentType != "application/json" {
		t.Errorf("ContentType mismatch: %s", result.ContentType)
	}
	if result.Severity != "critical" {
		t.Errorf("Severity mismatch: %s", result.Severity)
	}
	if result.StatusCode != 403 {
		t.Errorf("StatusCode mismatch: %d", result.StatusCode)
	}
	if result.Outcome != "Blocked" {
		t.Errorf("Outcome mismatch: %s", result.Outcome)
	}
	if result.Timestamp == "" {
		t.Error("Timestamp not set")
	}
	if result.LatencyMs < 0 {
		t.Errorf("Invalid LatencyMs: %d", result.LatencyMs)
	}
}

// TestNoRedirectFollow verifies redirects are not followed
func TestNoRedirectFollow(t *testing.T) {
	hosterrors.ClearAll() // Reset host error cache for clean test
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/redirected", http.StatusFound)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
	})

	result := e.executeTest(context.Background(), payloads.Payload{ID: "test"})

	// Should get 302, not follow redirect
	if result.StatusCode != http.StatusFound {
		t.Errorf("expected 302 (no redirect follow), got %d", result.StatusCode)
	}
}

// TestDefaultMethod verifies GET is used when method not specified
func TestDefaultMethod(t *testing.T) {
	hosterrors.ClearAll() // Reset host error cache for clean test
	var receivedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
	})

	// No method specified in payload
	payload := payloads.Payload{ID: "test", Payload: "data"}
	result := e.executeTest(context.Background(), payload)

	if receivedMethod != "GET" {
		t.Errorf("expected default method GET, got %s", receivedMethod)
	}
	if result.Method != "GET" {
		t.Errorf("expected result.Method GET, got %s", result.Method)
	}
}

// TestQueryEscaping verifies payload is URL-escaped in query
func TestQueryEscaping(t *testing.T) {
	hosterrors.ClearAll() // Reset host error cache for clean test
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
	})

	payload := payloads.Payload{ID: "test", Payload: "a=1&b=2"}
	e.executeTest(context.Background(), payload)

	// Should be escaped
	if strings.Contains(receivedQuery, "&b=") {
		t.Errorf("expected URL escaping, got raw: %s", receivedQuery)
	}
	if !strings.Contains(receivedQuery, "test=") {
		t.Errorf("expected test= parameter, got: %s", receivedQuery)
	}
}

// TestExecuteWithProgress tests the progress-aware execution method
func TestExecuteWithProgress(t *testing.T) {
	hosterrors.ClearAll() // Reset host error cache for clean test
	t.Run("basic execution with progress", func(t *testing.T) {
		requestCount := 0
		var mu sync.Mutex
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requestCount++
			mu.Unlock()
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 5,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		testPayloads := make([]payloads.Payload, 10)
		for i := 0; i < 10; i++ {
			testPayloads[i] = payloads.Payload{
				ID:            fmt.Sprintf("test-%d", i),
				Category:      "sqli",
				SeverityHint:  "high",
				Payload:       fmt.Sprintf("payload-%d", i),
				ExpectedBlock: true,
			}
		}

		writer := &mockWriter{}
		progress := ui.NewProgress(ui.ProgressConfig{
			Total:       len(testPayloads),
			Width:       40,
			ShowPercent: true,
			Concurrency: 5,
		})

		results := e.ExecuteWithProgress(context.Background(), testPayloads, writer, progress)

		if results.TotalTests != 10 {
			t.Errorf("expected TotalTests 10, got %d", results.TotalTests)
		}
		if requestCount != 10 {
			t.Errorf("expected 10 requests, got %d", requestCount)
		}
		if results.BlockedTests != 10 {
			t.Errorf("expected 10 blocked, got %d", results.BlockedTests)
		}
		if len(writer.Results()) != 10 {
			t.Errorf("expected 10 results written, got %d", len(writer.Results()))
		}
	})

	t.Run("collects status code breakdown", func(t *testing.T) {
		var counter int
		var mu sync.Mutex
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			c := counter
			counter++
			mu.Unlock()

			if c < 3 {
				w.WriteHeader(http.StatusForbidden) // 403
			} else if c < 5 {
				w.WriteHeader(http.StatusOK) // 200
			} else {
				w.WriteHeader(http.StatusNotFound) // 404
			}
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1, // Sequential for predictable counts
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		testPayloads := make([]payloads.Payload, 6)
		for i := 0; i < 6; i++ {
			testPayloads[i] = payloads.Payload{
				ID:       fmt.Sprintf("test-%d", i),
				Category: "test",
			}
		}

		writer := &mockWriter{}
		progress := ui.NewProgress(ui.ProgressConfig{Total: 6})

		results := e.ExecuteWithProgress(context.Background(), testPayloads, writer, progress)

		if results.StatusCodes[403] != 3 {
			t.Errorf("expected 3 x 403, got %d", results.StatusCodes[403])
		}
		if results.StatusCodes[200] != 2 {
			t.Errorf("expected 2 x 200, got %d", results.StatusCodes[200])
		}
		if results.StatusCodes[404] != 1 {
			t.Errorf("expected 1 x 404, got %d", results.StatusCodes[404])
		}
	})

	t.Run("collects category breakdown", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		testPayloads := []payloads.Payload{
			{ID: "1", Category: "sqli"},
			{ID: "2", Category: "sqli"},
			{ID: "3", Category: "xss"},
			{ID: "4", Category: "traversal"},
		}

		writer := &mockWriter{}
		progress := ui.NewProgress(ui.ProgressConfig{Total: 4})

		results := e.ExecuteWithProgress(context.Background(), testPayloads, writer, progress)

		if results.CategoryBreakdown["sqli"] != 2 {
			t.Errorf("expected 2 sqli, got %d", results.CategoryBreakdown["sqli"])
		}
		if results.CategoryBreakdown["xss"] != 1 {
			t.Errorf("expected 1 xss, got %d", results.CategoryBreakdown["xss"])
		}
		if results.CategoryBreakdown["traversal"] != 1 {
			t.Errorf("expected 1 traversal, got %d", results.CategoryBreakdown["traversal"])
		}
	})

	t.Run("collects severity breakdown", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		testPayloads := []payloads.Payload{
			{ID: "1", SeverityHint: "critical"},
			{ID: "2", SeverityHint: "critical"},
			{ID: "3", SeverityHint: "high"},
			{ID: "4", SeverityHint: "medium"},
			{ID: "5", SeverityHint: "low"},
		}

		writer := &mockWriter{}
		progress := ui.NewProgress(ui.ProgressConfig{Total: 5})

		results := e.ExecuteWithProgress(context.Background(), testPayloads, writer, progress)

		if results.SeverityBreakdown["critical"] != 2 {
			t.Errorf("expected 2 critical, got %d", results.SeverityBreakdown["critical"])
		}
		if results.SeverityBreakdown["high"] != 1 {
			t.Errorf("expected 1 high, got %d", results.SeverityBreakdown["high"])
		}
	})

	t.Run("collects top errors", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		testPayloads := make([]payloads.Payload, 5)
		for i := 0; i < 5; i++ {
			testPayloads[i] = payloads.Payload{ID: fmt.Sprintf("test-%d", i)}
		}

		writer := &mockWriter{}
		progress := ui.NewProgress(ui.ProgressConfig{Total: 5})

		results := e.ExecuteWithProgress(context.Background(), testPayloads, writer, progress)

		if len(results.TopErrors) == 0 {
			t.Error("expected TopErrors to be populated")
		}
		// Should contain "Unexpected status: 500"
		found := false
		for _, err := range results.TopErrors {
			if strings.Contains(err, "500") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected TopErrors to contain 500 error, got %v", results.TopErrors)
		}
	})

	t.Run("context cancellation with progress", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 2,
			RateLimit:   10,
			Timeout:     5 * time.Second,
		})

		testPayloads := make([]payloads.Payload, 50)
		for i := 0; i < 50; i++ {
			testPayloads[i] = payloads.Payload{ID: fmt.Sprintf("test-%d", i)}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		writer := &mockWriter{}
		progress := ui.NewProgress(ui.ProgressConfig{Total: 50})

		results := e.ExecuteWithProgress(ctx, testPayloads, writer, progress)

		// Should complete early due to cancellation
		completed := results.BlockedTests + results.PassedTests + results.FailedTests + results.ErrorTests
		if completed >= 50 {
			t.Errorf("expected early cancellation, but all %d completed", completed)
		}
	})

	t.Run("mixed outcomes with stats", func(t *testing.T) {
		var counter int
		var mu sync.Mutex
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			c := counter
			counter++
			mu.Unlock()

			switch c % 4 {
			case 0:
				w.WriteHeader(http.StatusForbidden) // Blocked
			case 1:
				w.WriteHeader(http.StatusOK) // Pass or Fail
			case 2:
				w.WriteHeader(http.StatusNotFound) // Pass
			case 3:
				w.WriteHeader(http.StatusInternalServerError) // Error
			}
		}))
		defer server.Close()

		e := NewExecutor(ExecutorConfig{
			TargetURL:   server.URL,
			Concurrency: 1,
			RateLimit:   100,
			Timeout:     5 * time.Second,
		})

		testPayloads := []payloads.Payload{
			{ID: "p1", ExpectedBlock: true},  // 403 -> Blocked
			{ID: "p2", ExpectedBlock: true},  // 200 -> Fail
			{ID: "p3", ExpectedBlock: false}, // 404 -> Pass
			{ID: "p4", ExpectedBlock: false}, // 500 -> Error
		}

		writer := &mockWriter{}
		progress := ui.NewProgress(ui.ProgressConfig{Total: 4})

		results := e.ExecuteWithProgress(context.Background(), testPayloads, writer, progress)

		if results.BlockedTests != 1 {
			t.Errorf("expected 1 blocked, got %d", results.BlockedTests)
		}
		if results.FailedTests != 1 {
			t.Errorf("expected 1 failed, got %d", results.FailedTests)
		}
		if results.PassedTests != 1 {
			t.Errorf("expected 1 passed, got %d", results.PassedTests)
		}
		if results.ErrorTests != 1 {
			t.Errorf("expected 1 error, got %d", results.ErrorTests)
		}
		if results.RequestsPerSec <= 0 {
			t.Error("expected RequestsPerSec > 0")
		}
	})
}

// =============================================================================
// DEEP BUG-FINDING TESTS - Line by line analysis of executor.go
// =============================================================================

// TestExecutorConfigZeroValues tests behavior with zero/default config values
func TestExecutorConfigZeroValues(t *testing.T) {
	t.Run("zero concurrency defaults to 1", func(t *testing.T) {
		cfg := ExecutorConfig{
			TargetURL:   "http://localhost:8080",
			Concurrency: 0, // Zero - should default to 1
			RateLimit:   100,
			Timeout:     5 * time.Second,
		}

		e := NewExecutor(cfg)
		if e == nil {
			t.Fatal("NewExecutor returned nil")
		}

		// Should have defaulted to 1
		if e.config.Concurrency != 1 {
			t.Errorf("Zero concurrency should default to 1, got %d", e.config.Concurrency)
		}
	})

	t.Run("zero rate limit defaults to 100", func(t *testing.T) {
		cfg := ExecutorConfig{
			TargetURL:   "http://localhost:8080",
			Concurrency: 1,
			RateLimit:   0, // Zero rate limit - should default to 100
			Timeout:     5 * time.Second,
		}

		e := NewExecutor(cfg)
		if e == nil {
			t.Fatal("NewExecutor returned nil")
		}

		// Should have defaulted to 100
		if e.config.RateLimit != 100 {
			t.Errorf("Zero rate limit should default to 100, got %d", e.config.RateLimit)
		}
	})

	t.Run("zero timeout", func(t *testing.T) {
		cfg := ExecutorConfig{
			TargetURL:   "http://localhost:8080",
			Concurrency: 1,
			RateLimit:   10,
			Timeout:     0, // Zero timeout
		}

		e := NewExecutor(cfg)
		if e == nil {
			t.Fatal("Should create executor even with zero timeout")
		}

		// http.Client with Timeout=0 means no timeout
		t.Logf("NOTE: Zero timeout means no timeout (infinite wait)")
	})

	t.Run("negative values default to safe values", func(t *testing.T) {
		cfg := ExecutorConfig{
			TargetURL:   "http://localhost:8080",
			Concurrency: -1,
			RateLimit:   -10,
			Timeout:     -5 * time.Second,
			Retries:     -2,
		}

		e := NewExecutor(cfg)
		if e == nil {
			t.Fatal("NewExecutor returned nil")
		}

		// Should have safe defaults
		if e.config.Concurrency < 1 {
			t.Errorf("Negative concurrency should default to 1, got %d", e.config.Concurrency)
		}
		if e.config.RateLimit < 1 {
			t.Errorf("Negative rate limit should default to 100, got %d", e.config.RateLimit)
		}
		if e.config.Timeout <= 0 {
			t.Errorf("Negative timeout should default to positive, got %v", e.config.Timeout)
		}
		if e.config.Retries < 0 {
			t.Errorf("Negative retries should default to 0, got %d", e.config.Retries)
		}
	})
}

// TestExecutorInvalidProxy tests behavior with invalid proxy URLs
func TestExecutorInvalidProxy(t *testing.T) {
	invalidProxies := []string{
		"not-a-url",
		"://missing-scheme",
		"http://",
		"http:// spaces in url",
		"ftp://wrong-scheme.com",
	}

	for _, proxy := range invalidProxies {
		t.Run(proxy, func(t *testing.T) {
			cfg := ExecutorConfig{
				TargetURL:   "http://localhost:8080",
				Concurrency: 1,
				RateLimit:   10,
				Timeout:     5 * time.Second,
				Proxy:       proxy,
			}

			e := NewExecutor(cfg)
			if e == nil {
				t.Error("Should create executor even with invalid proxy")
			}
			// Invalid proxy will fail at request time, not creation time
		})
	}
}

// TestExecutorInvalidTargetURL tests behavior with invalid target URLs
func TestExecutorInvalidTargetURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"no scheme", "localhost:8080"},
		{"spaces", "http://local host:8080"},
		{"unicode", "http://日本語.example.com"},
		{"special chars", "http://example.com/path?q=a&b=<>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ExecutorConfig{
				TargetURL:   tt.url,
				Concurrency: 1,
				RateLimit:   10,
				Timeout:     5 * time.Second,
			}

			e := NewExecutor(cfg)
			if e == nil {
				t.Error("Should create executor even with invalid URL")
			}
			// Invalid URL will fail at request time
		})
	}
}

// TestExecuteTestMethodHandling tests HTTP method handling
func TestExecuteTestMethodHandling(t *testing.T) {
	methodReceived := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methodReceived = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
	})

	tests := []struct {
		payloadMethod string
		wantMethod    string
	}{
		{"", "GET"},      // Empty defaults to GET
		{"GET", "GET"},   // Explicit GET
		{"POST", "POST"}, // Explicit POST
		{"get", "get"},   // Lowercase - is this handled?
		{"post", "post"}, // Lowercase
		{"PUT", "PUT"},   // Other methods
		{"DELETE", "DELETE"},
		{"PATCH", "PATCH"},
		{"OPTIONS", "OPTIONS"},
		{"HEAD", "HEAD"},
		{"CONNECT", "CONNECT"},
		{"TRACE", "TRACE"},
		{"INVALID", "INVALID"}, // Non-standard method
	}

	for _, tt := range tests {
		t.Run(tt.payloadMethod, func(t *testing.T) {
			payload := payloads.Payload{
				ID:      "test",
				Payload: "test-payload",
				Method:  tt.payloadMethod,
			}

			result := e.executeTest(context.Background(), payload)

			if methodReceived != tt.wantMethod {
				t.Errorf("Method %q: server received %q, want %q",
					tt.payloadMethod, methodReceived, tt.wantMethod)
			}

			if result.Method != tt.wantMethod {
				t.Errorf("Result.Method = %q, want %q", result.Method, tt.wantMethod)
			}
		})
	}
}

// TestExecuteTestContentTypeHandling tests content type handling
func TestExecuteTestContentTypeHandling(t *testing.T) {
	contentTypeReceived := ""
	bodyReceived := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentTypeReceived = r.Header.Get("Content-Type")
		body := make([]byte, 10000)
		n, _ := r.Body.Read(body)
		bodyReceived = string(body[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
	})

	tests := []struct {
		name        string
		method      string
		contentType string
		payload     string
		wantBody    bool
	}{
		{"GET no content type", "GET", "", "test", false},
		{"GET with content type", "GET", "application/json", "test", false}, // GET ignores body
		{"POST with JSON", "POST", "application/json", `{"key":"value"}`, true},
		{"POST no content type", "POST", "", "data", false}, // No content type = no body?
		{"POST form data", "POST", "application/x-www-form-urlencoded", "a=1&b=2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := payloads.Payload{
				ID:          "test",
				Payload:     tt.payload,
				Method:      tt.method,
				ContentType: tt.contentType,
			}

			_ = e.executeTest(context.Background(), payload)

			if tt.wantBody {
				if contentTypeReceived != tt.contentType {
					t.Errorf("Content-Type: got %q, want %q", contentTypeReceived, tt.contentType)
				}
				if bodyReceived != tt.payload {
					t.Errorf("Body: got %q, want %q", bodyReceived, tt.payload)
				}
			}
		})
	}
}

// TestExecuteTestOutcomeClassification tests outcome classification logic
func TestExecuteTestOutcomeClassification(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		expectedBlock bool
		wantOutcome   string
	}{
		// WAF block status codes
		{"403 expected block", 403, true, "Blocked"},
		{"403 not expected", 403, false, "Blocked"},
		{"406 expected block", 406, true, "Blocked"},
		{"429 expected block", 429, true, "Blocked"},

		// Success codes
		{"200 expected block", 200, true, "Fail"}, // Should have been blocked!
		{"200 not expected", 200, false, "Pass"},  // Normal
		{"201 expected block", 201, true, "Fail"},
		{"201 not expected", 201, false, "Pass"},
		{"204 expected block", 204, true, "Fail"},
		{"204 not expected", 204, false, "Pass"},

		// 404 always Pass
		{"404 expected block", 404, true, "Pass"},
		{"404 not expected", 404, false, "Pass"},

		// Other codes = Error
		{"500 expected block", 500, true, "Error"},
		{"500 not expected", 500, false, "Error"},
		{"502 server", 502, false, "Error"},
		{"301 redirect", 301, false, "Error"},
		{"302 redirect", 302, false, "Error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			e := NewExecutor(ExecutorConfig{
				TargetURL:   server.URL,
				Concurrency: 1,
				RateLimit:   100,
				Timeout:     5 * time.Second,
			})

			payload := payloads.Payload{
				ID:            "test",
				Payload:       "test",
				ExpectedBlock: tt.expectedBlock,
			}

			result := e.executeTest(context.Background(), payload)

			if result.Outcome != tt.wantOutcome {
				t.Errorf("Status %d, ExpectedBlock=%v: got %q, want %q",
					tt.statusCode, tt.expectedBlock, result.Outcome, tt.wantOutcome)
			}
		})
	}
}

// TestExecuteTestTargetPathHandling tests target path in payloads
func TestExecuteTestTargetPathHandling(t *testing.T) {
	pathReceived := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathReceived = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
	})

	tests := []struct {
		name       string
		targetPath string
		wantPath   string
	}{
		{"empty path", "", "/"},
		{"root path", "/", "/"},
		{"simple path", "/api/test", "/api/test"},
		{"path with query", "/api?q=1", "/api"}, // Query separate
		{"deep path", "/a/b/c/d", "/a/b/c/d"},
		{"path with dots", "/api/../secret", "/api/../secret"}, // Not normalized?
		{"path with spaces", "/api/my path", "/api/my path"},   // URL encoded?
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := payloads.Payload{
				ID:         "test",
				Payload:    "test",
				TargetPath: tt.targetPath,
			}

			_ = e.executeTest(context.Background(), payload)

			if !strings.HasPrefix(pathReceived, tt.wantPath) && tt.wantPath != "" {
				t.Logf("TargetPath %q: received path %q", tt.targetPath, pathReceived)
			}
		})
	}
}

// TestExecuteTestRetryBehavior tests retry logic
func TestExecuteTestRetryBehavior(t *testing.T) {
	requestCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		count := requestCount
		mu.Unlock()

		if count <= 2 {
			// First 2 requests: close connection
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
		}
		// 3rd request succeeds
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     1 * time.Second,
		Retries:     3,
	})

	payload := payloads.Payload{ID: "test", Payload: "test"}
	result := e.executeTest(context.Background(), payload)

	mu.Lock()
	finalCount := requestCount
	mu.Unlock()

	t.Logf("Request count: %d, Outcome: %s", finalCount, result.Outcome)

	// Should have retried and eventually succeeded or errored
	if finalCount < 2 {
		t.Errorf("Expected at least 2 requests (with retries), got %d", finalCount)
	}
}

// TestExecuteTestLargePayload tests handling of very large payloads
func TestExecuteTestLargePayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
	})

	// Create a 1MB payload
	largePayload := strings.Repeat("x", 1024*1024)

	payload := payloads.Payload{
		ID:      "large",
		Payload: largePayload,
	}

	result := e.executeTest(context.Background(), payload)

	if result.Outcome == "Error" && strings.Contains(result.ErrorMessage, "too long") {
		t.Logf("Large payload rejected: %s", result.ErrorMessage)
	} else {
		t.Logf("Large payload (1MB) outcome: %s", result.Outcome)
	}
}

// TestExecuteTestSpecialCharactersInPayload tests special character handling
func TestExecuteTestSpecialCharactersInPayload(t *testing.T) {
	receivedQuery := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
	})

	tests := []struct {
		name    string
		payload string
	}{
		{"basic sql injection", "' OR '1'='1"},
		{"xss script tag", "<script>alert(1)</script>"},
		{"null byte", "test\x00null"},
		{"unicode", "日本語テスト"},
		{"emoji", "🔥💀🎯"},
		{"special chars", "&=?#%+"},
		{"newlines", "line1\nline2\rline3"},
		{"tabs", "col1\tcol2"},
		{"backslash", "path\\to\\file"},
		{"quotes mix", `"double" and 'single'`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := payloads.Payload{
				ID:      "test",
				Payload: tt.payload,
			}

			result := e.executeTest(context.Background(), payload)

			if result.Outcome == "Error" {
				t.Logf("Payload %q caused error: %s", tt.name, result.ErrorMessage)
			} else {
				t.Logf("Payload %q sent as query: %s", tt.name, receivedQuery)
			}
		})
	}
}

// TestExecuteTestContextCancellation tests immediate context cancellation
func TestExecuteTestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   server.URL,
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     30 * time.Second, // Long timeout
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	payload := payloads.Payload{ID: "test", Payload: "test"}

	start := time.Now()
	result := e.executeTest(ctx, payload)
	elapsed := time.Since(start)

	if result.Outcome != "Error" {
		t.Errorf("Expected Error outcome for cancelled context, got %s", result.Outcome)
	}

	if elapsed > 1*time.Second {
		t.Errorf("Cancelled request should return quickly, took %v", elapsed)
	}
}

// =============================================================================
// BUG-EXPOSING TESTS - These tests expose real bugs in the source code
// =============================================================================

// TestNewExecutorWithMalformedProxy exposes bug: url.Parse error ignored for proxy
// BUG: If proxy URL is malformed, url.Parse returns nil but error is ignored
// Then http.ProxyURL(nil) is called which may cause unexpected behavior
func TestNewExecutorWithMalformedProxy(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
	}{
		{"valid proxy", "http://proxy.example.com:8080"},
		{"malformed proxy with spaces", "http://proxy .com:8080"},
		{"malformed proxy colons", "http://:::invalid"},
		{"empty scheme", "://noscheme"},
		{"just colons", ":::"},
		{"control chars", "http://\x00\x01\x02"},
		{"unicode nonsense", "http://\u200b\u200b\u200b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Creating executor with malformed proxy should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("BUG EXPOSED: NewExecutor panicked with proxy=%q: %v", tt.proxyURL, r)
				}
			}()

			e := NewExecutor(ExecutorConfig{
				TargetURL:   "http://example.com",
				Concurrency: 1,
				RateLimit:   100,
				Timeout:     5 * time.Second,
				Proxy:       tt.proxyURL,
			})

			// Executor should be created, though proxy may not work
			if e == nil {
				t.Error("Expected executor to be created")
			}
		})
	}
}

// TestExecutorWithEmptyTargetURL tests behavior with empty target URL
func TestExecutorWithEmptyTargetURL(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("BUG EXPOSED: NewExecutor panicked with empty target: %v", r)
		}
	}()

	e := NewExecutor(ExecutorConfig{
		TargetURL:   "",
		Concurrency: 1,
		RateLimit:   100,
		Timeout:     5 * time.Second,
	})

	if e == nil {
		t.Error("Expected executor to be created even with empty target")
	}

	// Executing a test should handle the empty target gracefully
	payload := payloads.Payload{ID: "test", Payload: "test"}
	result := e.executeTest(context.Background(), payload)

	// Should return error, not panic
	if result.Outcome != "Error" {
		t.Logf("Outcome for empty target: %s", result.Outcome)
	}
}
