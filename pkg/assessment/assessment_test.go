package assessment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/metrics"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.Concurrency <= 0 {
		t.Error("Concurrency should be > 0")
	}
	if cfg.RateLimit <= 0 {
		t.Error("RateLimit should be > 0")
	}
	if cfg.Timeout <= 0 {
		t.Error("Timeout should be > 0")
	}
}

func TestNew(t *testing.T) {
	a := New(nil)
	if a == nil {
		t.Fatal("New returned nil")
	}
	if a.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	if a.limiter == nil {
		t.Error("limiter should not be nil")
	}
	if a.corpusManager == nil {
		t.Error("corpusManager should not be nil")
	}
	if a.calculator == nil {
		t.Error("calculator should not be nil")
	}
}

func TestNewWithConfig(t *testing.T) {
	cfg := &Config{
		TargetURL: "https://example.com",
		Base: attackconfig.Base{
			Concurrency: 10,
			Timeout:     5 * time.Second,
		},
		RateLimit:     50,
		SkipTLSVerify: true,
		Verbose:       true,
	}

	a := New(cfg)
	if a.config.TargetURL != "https://example.com" {
		t.Errorf("TargetURL = %s, want https://example.com", a.config.TargetURL)
	}
	if a.config.Concurrency != 10 {
		t.Errorf("Concurrency = %d, want 10", a.config.Concurrency)
	}
}

func TestDetectWAFFromHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected string
	}{
		{
			name:     "Cloudflare",
			headers:  http.Header{"Cf-Ray": []string{"abc123"}},
			expected: "Cloudflare",
		},
		{
			name:     "AWS WAF with both headers",
			headers:  http.Header{"X-Amzn-Requestid": []string{"abc-123"}, "X-Amz-Cf-Id": []string{"xyz"}},
			expected: "AWS WAF",
		},
		{
			name:     "CloudFront only should NOT be AWS WAF",
			headers:  http.Header{"X-Amz-Cf-Id": []string{"xyz"}},
			expected: "", // CloudFront CDN alone is not AWS WAF
		},
		{
			name:     "Akamai",
			headers:  http.Header{"X-Akamai-Transformed": []string{"9"}},
			expected: "Akamai",
		},
		{
			name:     "ModSecurity",
			headers:  http.Header{"Server": []string{"Apache/2.4 ModSecurity"}},
			expected: "ModSecurity",
		},
		{
			name:     "Imperva",
			headers:  http.Header{"X-Iinfo": []string{"value"}},
			expected: "Imperva",
		},
		{
			name:     "Azure",
			headers:  http.Header{"X-Azure-Ref": []string{"value"}},
			expected: "Azure WAF",
		},
		{
			name:     "Sucuri",
			headers:  http.Header{"X-Sucuri-Id": []string{"value"}},
			expected: "Sucuri",
		},
		{
			name:     "Unknown",
			headers:  http.Header{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectWAFFromHeaders(tt.headers)
			if got != tt.expected {
				t.Errorf("detectWAFFromHeaders() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestDetectWAFFromResponse(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		statusCode int
		body       string
		expected   string
	}{
		{
			name:       "Cloudflare body",
			headers:    http.Header{},
			statusCode: 403,
			body:       "<html>Cloudflare</html>",
			expected:   "Cloudflare",
		},
		{
			name:       "ModSecurity body",
			headers:    http.Header{},
			statusCode: 403,
			body:       "ModSecurity Action",
			expected:   "ModSecurity",
		},
		{
			name:       "Coraza body",
			headers:    http.Header{},
			statusCode: 403,
			body:       "Blocked by Coraza",
			expected:   "Coraza",
		},
		{
			name:       "nginx WAF",
			headers:    http.Header{"Server": []string{"nginx"}},
			statusCode: 403,
			body:       "Forbidden",
			expected:   "nginx WAF",
		},
		{
			name:       "Unknown",
			headers:    http.Header{},
			statusCode: 200,
			body:       "OK",
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectWAFFromResponse(tt.headers, tt.statusCode, tt.body)
			if got != tt.expected {
				t.Errorf("detectWAFFromResponse() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestIsBlockedResponse(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   bool
	}{
		{200, false},
		{201, false},
		{301, false},
		{400, true},
		{403, true},
		{406, true},
		{418, true},
		{429, true},
		{500, false},
		{503, true},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.statusCode), func(t *testing.T) {
			if got := isBlockedResponse(tt.statusCode); got != tt.expected {
				t.Errorf("isBlockedResponse(%d) = %v, want %v", tt.statusCode, got, tt.expected)
			}
		})
	}
}

func TestGetBuiltinAttackPayloads(t *testing.T) {
	payloads := getBuiltinAttackPayloads()

	if len(payloads) == 0 {
		t.Fatal("getBuiltinAttackPayloads returned empty slice")
	}

	// Check for expected categories
	categories := make(map[string]int)
	for _, p := range payloads {
		categories[p.Category]++
	}

	expectedCategories := []string{"sqli", "xss", "cmdi", "traversal", "ssrf"}
	for _, cat := range expectedCategories {
		if categories[cat] == 0 {
			t.Errorf("Missing expected category: %s", cat)
		}
	}

	// Check payload structure
	for _, p := range payloads {
		if p.ID == "" {
			t.Error("Payload has empty ID")
		}
		if p.Payload == "" {
			t.Error("Payload has empty Payload")
		}
		if p.Category == "" {
			t.Error("Payload has empty Category")
		}
	}
}

func TestLoadAttackPayloads(t *testing.T) {
	a := New(&Config{
		Categories: []string{"sqli"},
	})

	payloads, err := a.loadAttackPayloads()
	if err != nil {
		t.Fatalf("loadAttackPayloads error: %v", err)
	}

	// Should only have sqli payloads
	for _, p := range payloads {
		if p.Category != "sqli" {
			t.Errorf("Expected only sqli category, got %s", p.Category)
		}
	}
}

func TestLoadFPCorpus(t *testing.T) {
	a := New(&Config{
		CorpusSources: []string{"builtin"},
	})

	ctx := context.Background()
	payloads, err := a.loadFPCorpus(ctx)
	if err != nil {
		t.Fatalf("loadFPCorpus error: %v", err)
	}

	if len(payloads) == 0 {
		t.Error("loadFPCorpus should return payloads")
	}
}

func TestRunWithMockServer(t *testing.T) {
	// Create a mock server that blocks some patterns
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("test")
		input := r.URL.Query().Get("input")

		// Block obvious attacks
		if contains(query, "script") || contains(query, "UNION") ||
			contains(query, "../") || contains(query, "etc/passwd") {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Blocked by WAF"))
			return
		}

		// Allow benign content
		if input != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	cfg := &Config{
		TargetURL: server.URL,
		Base: attackconfig.Base{
			Concurrency: 5,
			Timeout:     5 * time.Second,
		},
		RateLimit:       100,
		EnableFPTesting: true,
		CorpusSources:   []string{"builtin"},
		Categories:      []string{"xss", "traversal"}, // Limit for faster test
	}

	a := New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var progressCalls int
	progressFn := func(completed, total int64, phase string) {
		progressCalls++
	}

	m, err := a.Run(ctx, progressFn)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if m == nil {
		t.Fatal("metrics is nil")
	}

	// Check that we have results
	if m.Matrix.Total() == 0 {
		t.Error("No tests were run")
	}

	// Check that we detected some blocks
	if m.Matrix.TruePositives == 0 {
		t.Error("Expected some attacks to be blocked")
	}

	// Check that we detected some true negatives (benign allowed)
	if m.Matrix.TrueNegatives == 0 {
		t.Error("Expected some benign requests to be allowed")
	}

	// Check that progress was called
	if progressCalls == 0 {
		t.Error("progressFn should have been called")
	}
}

func TestGetResults(t *testing.T) {
	a := New(nil)

	// Add some mock results
	a.attackResults = []metrics.AttackResult{
		{ID: "test-1", Category: "sqli", Blocked: true},
	}
	a.benignResults = []metrics.BenignResult{
		{ID: "fp-1", Corpus: "builtin", Blocked: false},
	}

	attacks := a.GetAttackResults()
	if len(attacks) != 1 {
		t.Errorf("GetAttackResults count = %d, want 1", len(attacks))
	}

	benign := a.GetBenignResults()
	if len(benign) != 1 {
		t.Errorf("GetBenignResults count = %d, want 1", len(benign))
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b     int
		expected int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{5, 5, 5},
		{0, 10, 0},
	}

	for _, tt := range tests {
		if got := min(tt.a, tt.b); got != tt.expected {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.expected)
		}
	}
}

// Helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
