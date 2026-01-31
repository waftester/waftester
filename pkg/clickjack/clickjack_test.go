package clickjack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	if config.Concurrency != 10 {
		t.Errorf("expected Concurrency 10, got %d", config.Concurrency)
	}
}

func TestNewScanner(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
}

func TestScanner_Scan_Vulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.Scan(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("should be vulnerable without X-Frame-Options")
	}
}

func TestScanner_Scan_Protected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.Scan(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Vulnerable {
		t.Error("should not be vulnerable with X-Frame-Options: DENY")
	}
}

func TestScanner_Scan_CSPProtected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.Scan(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Vulnerable {
		t.Error("should not be vulnerable with CSP frame-ancestors 'none'")
	}
}

func TestExtractFrameAncestors(t *testing.T) {
	tests := []struct {
		csp      string
		expected string
	}{
		{"frame-ancestors 'none'", "'none'"},
		{"default-src 'self'; frame-ancestors 'self'", "'self'"},
		{"default-src 'self'", ""},
	}

	for _, tt := range tests {
		t.Run(tt.csp, func(t *testing.T) {
			result := extractFrameAncestors(tt.csp)
			if result != tt.expected {
				t.Errorf("extractFrameAncestors = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestScanner_IsFrameable(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	tests := []struct {
		xfo       string
		fa        string
		frameable bool
	}{
		{"DENY", "", false},
		{"SAMEORIGIN", "", false},
		{"", "'none'", false},
		{"", "'self'", false},
		{"", "", true},
		{"ALLOW-FROM", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.xfo+tt.fa, func(t *testing.T) {
			result := scanner.isFrameable(tt.xfo, tt.fa)
			if result != tt.frameable {
				t.Errorf("isFrameable = %v, want %v", result, tt.frameable)
			}
		})
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("expected non-nil results")
	}
}

func TestGeneratePOC(t *testing.T) {
	poc := GeneratePOC("https://example.com")
	if !strings.Contains(poc, "https://example.com") {
		t.Error("PoC should contain target URL")
	}
	if !strings.Contains(poc, "iframe") {
		t.Error("PoC should contain iframe")
	}
}

func TestScanner_ScanMultiple(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	urls := []string{server.URL, server.URL + "/page2"}

	results, err := scanner.ScanMultiple(context.Background(), urls)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected results")
	}
}

func TestScanner_CheckIframeLoad(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Content</body></html>"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	canLoad := scanner.CheckIframeLoad(context.Background(), server.URL)

	if !canLoad {
		t.Error("should be able to load in iframe")
	}
}

func TestScanner_CheckIframeLoad_FrameBuster(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><script>if (top !== self) top.location = self.location;</script></html>"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	canLoad := scanner.CheckIframeLoad(context.Background(), server.URL)

	if canLoad {
		t.Error("should not be able to load with frame-buster")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:           "https://example.com",
		XFrameOptions: "",
		Frameable:     true,
		Vulnerable:    true,
		Severity:      "MEDIUM",
		Timestamp:     time.Now(),
	}

	if !result.Frameable {
		t.Error("Frameable field incorrect")
	}
}
