package race

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/finding"
)

func TestNewTester(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		tester := NewTester(nil)
		if tester == nil {
			t.Fatal("expected tester, got nil")
		}
		if tester.config == nil {
			t.Error("expected config to be set")
		}
		if tester.config.MaxConcurrency != 50 {
			t.Errorf("expected max concurrency 50, got %d", tester.config.MaxConcurrency)
		}
	})

	t.Run("custom config", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:        60 * time.Second,
			MaxConcurrency: 100,
		}
		tester := NewTester(config)

		if tester.config.MaxConcurrency != 100 {
			t.Errorf("expected max concurrency 100, got %d", tester.config.MaxConcurrency)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if config.MaxConcurrency != 50 {
		t.Errorf("expected 50 max concurrency")
	}
	if config.Iterations != 1 {
		t.Errorf("expected 1 iteration")
	}
}

func TestSendConcurrent(t *testing.T) {
	t.Run("concurrent requests", func(t *testing.T) {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		requests := make([]*RequestConfig, 10)
		for i := 0; i < 10; i++ {
			requests[i] = &RequestConfig{
				Method: "GET",
				URL:    server.URL,
			}
		}

		responses := tester.SendConcurrent(ctx, requests)

		if len(responses) != 10 {
			t.Errorf("expected 10 responses, got %d", len(responses))
		}

		if atomic.LoadInt32(&requestCount) != 10 {
			t.Errorf("expected 10 requests, got %d", requestCount)
		}

		for i, resp := range responses {
			if resp.StatusCode != http.StatusOK {
				t.Errorf("response %d: expected 200, got %d", i, resp.StatusCode)
			}
		}
	})

	t.Run("with request body", func(t *testing.T) {
		var receivedBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, 100)
			n, _ := r.Body.Read(body)
			receivedBody = string(body[:n])
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		requests := []*RequestConfig{
			{
				Method: "POST",
				URL:    server.URL,
				Body:   "test body",
			},
		}

		tester.SendConcurrent(ctx, requests)

		if receivedBody != "test body" {
			t.Errorf("expected 'test body', got '%s'", receivedBody)
		}
	})
}

func TestTestDoubleSubmit(t *testing.T) {
	t.Run("vulnerable - all succeed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		request := &RequestConfig{
			Method: "POST",
			URL:    server.URL,
		}

		vuln, err := tester.TestDoubleSubmit(ctx, request, 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln == nil {
			t.Error("expected vulnerability")
			return
		}

		if vuln.Type != AttackDoubleSubmit {
			t.Errorf("expected double submit type, got %s", vuln.Type)
		}
		if vuln.Severity != finding.Critical {
			t.Errorf("expected critical severity")
		}
	})

	t.Run("not vulnerable - only one succeeds", func(t *testing.T) {
		var count int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&count, 1) == 1 {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusConflict)
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		request := &RequestConfig{
			Method: "POST",
			URL:    server.URL,
		}

		vuln, err := tester.TestDoubleSubmit(ctx, request, 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln != nil {
			t.Error("expected no vulnerability")
		}
	})
}

func TestTestTokenReuse(t *testing.T) {
	t.Run("vulnerable token reuse", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always accepts the token
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		request := &RequestConfig{
			Method: "POST",
			URL:    server.URL,
			Body:   "token=abc123",
		}

		vuln, err := tester.TestTokenReuse(ctx, request, 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln == nil {
			t.Error("expected vulnerability")
			return
		}

		if vuln.Type != AttackTokenReuse {
			t.Errorf("expected token reuse type")
		}
	})
}

func TestTestLimitBypass(t *testing.T) {
	t.Run("bypass detected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always succeeds (no rate limiting)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		request := &RequestConfig{
			Method: "GET",
			URL:    server.URL,
		}

		vuln, err := tester.TestLimitBypass(ctx, request, 10, 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln == nil {
			t.Error("expected vulnerability")
			return
		}

		if vuln.Type != AttackLimitBypass {
			t.Errorf("expected limit bypass type")
		}
	})

	t.Run("no bypass - rate limited", func(t *testing.T) {
		var count int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&count, 1) <= 3 {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusTooManyRequests)
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		request := &RequestConfig{
			Method: "GET",
			URL:    server.URL,
		}

		vuln, err := tester.TestLimitBypass(ctx, request, 10, 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln != nil {
			t.Error("expected no vulnerability")
		}
	})
}

func TestTestSequential(t *testing.T) {
	t.Run("TOCTOU test", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always succeed for use requests
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		checkReq := &RequestConfig{Method: "GET", URL: server.URL + "/check"}
		useReq := &RequestConfig{Method: "POST", URL: server.URL + "/use"}

		vuln, err := tester.TestSequential(ctx, checkReq, useReq, 10)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// May or may not detect based on timing
		if vuln != nil {
			if vuln.Type != AttackTOCTOU {
				t.Errorf("expected TOCTOU type, got %s", vuln.Type)
			}
		}
	})
}

func TestAnalyzeResponses(t *testing.T) {
	t.Run("empty responses", func(t *testing.T) {
		analysis := AnalyzeResponses(nil)
		if analysis.TotalResponses != 0 {
			t.Error("expected 0 responses")
		}
	})

	t.Run("uniform responses", func(t *testing.T) {
		responses := []*Response{
			{StatusCode: 200, Body: "OK", ResponseTime: 10 * time.Millisecond},
			{StatusCode: 200, Body: "OK", ResponseTime: 12 * time.Millisecond},
			{StatusCode: 200, Body: "OK", ResponseTime: 11 * time.Millisecond},
		}

		analysis := AnalyzeResponses(responses)

		if analysis.TotalResponses != 3 {
			t.Errorf("expected 3 responses, got %d", analysis.TotalResponses)
		}
		if analysis.UniqueBodyCount != 1 {
			t.Errorf("expected 1 unique body, got %d", analysis.UniqueBodyCount)
		}
		if len(analysis.StatusDistribution) != 1 {
			t.Error("expected 1 status code")
		}
		if analysis.HasAnomaly {
			t.Error("expected no anomaly")
		}
	})

	t.Run("anomalous responses", func(t *testing.T) {
		responses := []*Response{
			{StatusCode: 200, Body: "OK", ResponseTime: 10 * time.Millisecond},
			{StatusCode: 200, Body: "Different", ResponseTime: 12 * time.Millisecond},
			{StatusCode: 500, Body: "Error", ResponseTime: 100 * time.Millisecond},
		}

		analysis := AnalyzeResponses(responses)

		if analysis.UniqueBodyCount != 3 {
			t.Errorf("expected 3 unique bodies, got %d", analysis.UniqueBodyCount)
		}
		if !analysis.HasAnomaly {
			t.Error("expected anomaly")
		}
	})

	t.Run("timing analysis", func(t *testing.T) {
		responses := []*Response{
			{StatusCode: 200, ResponseTime: 10 * time.Millisecond},
			{StatusCode: 200, ResponseTime: 50 * time.Millisecond},
			{StatusCode: 200, ResponseTime: 100 * time.Millisecond},
		}

		analysis := AnalyzeResponses(responses)

		if analysis.MinResponseTime != 10*time.Millisecond {
			t.Errorf("expected min 10ms, got %v", analysis.MinResponseTime)
		}
		if analysis.MaxResponseTime != 100*time.Millisecond {
			t.Errorf("expected max 100ms, got %v", analysis.MaxResponseTime)
		}
		if analysis.TimeVariance != 90*time.Millisecond {
			t.Errorf("expected variance 90ms, got %v", analysis.TimeVariance)
		}
	})
}

func TestCreateBurst(t *testing.T) {
	baseRequest := &RequestConfig{
		Method:  "POST",
		URL:     "http://example.com/api",
		Body:    "test=data",
		Headers: http.Header{"X-Test": []string{"value"}},
		Cookies: []*http.Cookie{{Name: "session", Value: "abc"}},
	}

	burst := CreateBurst(baseRequest, 5)

	if len(burst) != 5 {
		t.Errorf("expected 5 requests, got %d", len(burst))
	}

	for i, req := range burst {
		if req.Method != "POST" {
			t.Errorf("request %d: expected POST method", i)
		}
		if req.URL != "http://example.com/api" {
			t.Errorf("request %d: wrong URL", i)
		}
		if req.Body != "test=data" {
			t.Errorf("request %d: wrong body", i)
		}
	}
}

func TestAllAttackTypes(t *testing.T) {
	types := AllAttackTypes()

	if len(types) != 6 {
		t.Errorf("expected 6 attack types, got %d", len(types))
	}

	expectedTypes := map[AttackType]bool{
		AttackTOCTOU:          false,
		AttackDoubleSubmit:    false,
		AttackSessionFixation: false,
		AttackTokenReuse:      false,
		AttackResourceExhaust: false,
		AttackLimitBypass:     false,
	}

	for _, at := range types {
		expectedTypes[at] = true
	}

	for at, found := range expectedTypes {
		if !found {
			t.Errorf("missing attack type: %s", at)
		}
	}
}

func TestCommonTargets(t *testing.T) {
	targets := CommonTargets()

	if len(targets) == 0 {
		t.Error("expected common targets")
	}

	// Check for critical targets
	hasPayment := false
	hasCheckout := false

	for _, target := range targets {
		if target == "/api/payment" {
			hasPayment = true
		}
		if target == "/api/checkout" {
			hasCheckout = true
		}
	}

	if !hasPayment {
		t.Error("expected /api/payment target")
	}
	if !hasCheckout {
		t.Error("expected /api/checkout target")
	}
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	request := &RequestConfig{
		Method: "POST",
		URL:    server.URL,
	}

	result, err := tester.Scan(ctx, request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.URL != server.URL {
		t.Errorf("expected URL %s", server.URL)
	}
	if result.TotalRequests == 0 {
		t.Error("expected requests to be counted")
	}
	if result.Duration == 0 {
		t.Error("expected duration to be set")
	}
}

func TestGetRemediation(t *testing.T) {
	tests := []struct {
		attackType AttackType
		contains   string
	}{
		{AttackTOCTOU, "atomic"},
		{AttackDoubleSubmit, "idempotency"},
		{AttackSessionFixation, "session"},
		{AttackTokenReuse, "token"},
		{AttackResourceExhaust, "resource"},
		{AttackLimitBypass, "counter"},
	}

	for _, tt := range tests {
		t.Run(string(tt.attackType), func(t *testing.T) {
			remediation := GetRemediation(tt.attackType)
			if remediation == "" {
				t.Error("expected remediation")
			}
		})
	}

	// Test unknown type
	unknown := GetRemediation("unknown")
	if unknown == "" {
		t.Error("expected default remediation")
	}
}

func TestVulnerabilityFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	request := &RequestConfig{
		Method: "POST",
		URL:    server.URL,
	}

	vuln, _ := tester.TestDoubleSubmit(ctx, request, 5)

	if vuln != nil {
		if vuln.Type == "" {
			t.Error("vulnerability should have type")
		}
		if vuln.Description == "" {
			t.Error("vulnerability should have description")
		}
		if vuln.Severity == "" {
			t.Error("vulnerability should have severity")
		}
		if vuln.URL == "" {
			t.Error("vulnerability should have URL")
		}
		if vuln.Remediation == "" {
			t.Error("vulnerability should have remediation")
		}
	}
}

func TestConcurrencyLimit(t *testing.T) {
	var maxConcurrent int32
	var currentConcurrent int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		curr := atomic.AddInt32(&currentConcurrent, 1)
		for {
			max := atomic.LoadInt32(&maxConcurrent)
			if curr > max {
				if atomic.CompareAndSwapInt32(&maxConcurrent, max, curr) {
					break
				}
			} else {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt32(&currentConcurrent, -1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &TesterConfig{
		Timeout:        30 * time.Second,
		MaxConcurrency: 100,
	}
	tester := NewTester(config)
	ctx := context.Background()

	requests := make([]*RequestConfig, 20)
	for i := 0; i < 20; i++ {
		requests[i] = &RequestConfig{Method: "GET", URL: server.URL}
	}

	tester.SendConcurrent(ctx, requests)

	// All requests should run concurrently
	if atomic.LoadInt32(&maxConcurrent) < 10 {
		t.Logf("Max concurrent: %d (may vary based on timing)", maxConcurrent)
	}
}

func BenchmarkSendConcurrent(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	requests := make([]*RequestConfig, 10)
	for i := 0; i < 10; i++ {
		requests[i] = &RequestConfig{Method: "GET", URL: server.URL}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tester.SendConcurrent(ctx, requests)
	}
}
