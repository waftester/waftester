package securitymisconfig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/waftester/waftester/pkg/httpclient"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 10 {
		t.Errorf("DefaultConfig().Concurrency = %d, want 10", config.Concurrency)
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

func TestScanner_TestSecurityHeaders_Missing(t *testing.T) {
	// Server without security headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.TestSecurityHeaders(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("TestSecurityHeaders error: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected results for security headers check")
	}

	vulnCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnCount++
		}
	}

	if vulnCount == 0 {
		t.Error("Expected at least one vulnerability for missing headers")
	}
}

func TestScanner_TestSecurityHeaders_Present(t *testing.T) {
	// Server with security headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.TestSecurityHeaders(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("TestSecurityHeaders error: %v", err)
	}

	for _, r := range results {
		if r.Vulnerable {
			t.Errorf("Expected no vulnerability for %s", r.Description)
		}
	}
}

func TestScanner_TestDebugEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug" {
			w.Write([]byte("Debug info"))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.TestDebugEndpoints(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("TestDebugEndpoints error: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected results for debug endpoints check")
	}

	// Should find /debug as vulnerable
	foundDebug := false
	for _, r := range results {
		if r.Description == "/debug" && r.Vulnerable {
			foundDebug = true
		}
	}

	if !foundDebug {
		t.Error("Expected /debug to be marked as vulnerable")
	}
}

func TestScanner_TestDefaultCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Write([]byte("Admin panel"))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.TestDefaultCredentials(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("TestDefaultCredentials error: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected results for admin endpoints check")
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("GetResults returned nil")
	}
}

func TestRequiredSecurityHeaders(t *testing.T) {
	headers := RequiredSecurityHeaders()
	if len(headers) < 5 {
		t.Errorf("RequiredSecurityHeaders count = %d, want at least 5", len(headers))
	}

	// Check for critical headers
	found := map[string]bool{}
	for _, h := range headers {
		found[h.Name] = true
	}

	expected := []string{"X-Frame-Options", "Strict-Transport-Security", "Content-Security-Policy"}
	for _, exp := range expected {
		if !found[exp] {
			t.Errorf("Expected header: %s", exp)
		}
	}
}

func TestDebugEndpoints(t *testing.T) {
	endpoints := DebugEndpoints()
	if len(endpoints) < 10 {
		t.Errorf("DebugEndpoints count = %d, want at least 10", len(endpoints))
	}

	// Check for critical endpoints
	found := map[string]bool{}
	for _, ep := range endpoints {
		found[ep] = true
	}

	expected := []string{"/.env", "/.git/config", "/phpinfo.php"}
	for _, exp := range expected {
		if !found[exp] {
			t.Errorf("Expected endpoint: %s", exp)
		}
	}
}

func TestAdminEndpoints(t *testing.T) {
	endpoints := AdminEndpoints()
	if len(endpoints) < 5 {
		t.Errorf("AdminEndpoints count = %d, want at least 5", len(endpoints))
	}
}

func TestSensitiveFiles(t *testing.T) {
	files := SensitiveFiles()
	if len(files) < 5 {
		t.Errorf("SensitiveFiles count = %d, want at least 5", len(files))
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:         "http://example.com",
		TestType:    "missing_header",
		Description: "X-Frame-Options",
		StatusCode:  200,
		Vulnerable:  true,
		Evidence:    "Missing security header",
		Severity:    "MEDIUM",
	}

	if result.URL != "http://example.com" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
}

func TestSecurityHeader_Validators(t *testing.T) {
	headers := RequiredSecurityHeaders()

	for _, h := range headers {
		if h.Name == "X-Frame-Options" && h.Validator != nil {
			if !h.Validator("DENY") {
				t.Error("DENY should be valid for X-Frame-Options")
			}
			if !h.Validator("SAMEORIGIN") {
				t.Error("SAMEORIGIN should be valid for X-Frame-Options")
			}
			if h.Validator("INVALID") {
				t.Error("INVALID should not be valid for X-Frame-Options")
			}
		}

		if h.Name == "X-Content-Type-Options" && h.Validator != nil {
			if !h.Validator("nosniff") {
				t.Error("nosniff should be valid for X-Content-Type-Options")
			}
		}
	}
}
