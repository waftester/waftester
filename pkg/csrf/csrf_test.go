package csrf

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

func TestScanner_AnalyzePage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<form><input type="hidden" name="csrf_token" value="abc123"></form>`))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result := scanner.analyzePage(context.Background(), server.URL)

	if !result.HasCSRFToken {
		t.Error("expected to find CSRF token")
	}
	if result.TokenName != "csrf_token" {
		t.Errorf("expected token name csrf_token, got %s", result.TokenName)
	}
}

func TestScanner_AnalyzePage_NoToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<form><input type="text" name="username"></form>`))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result := scanner.analyzePage(context.Background(), server.URL)

	if result.HasCSRFToken {
		t.Error("should not find CSRF token")
	}
}

func TestScanner_Scan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.Scan(context.Background(), server.URL, "POST")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.URL != server.URL {
		t.Error("URL mismatch")
	}
}

func TestScanner_TestWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	vulnerable := scanner.testWithoutToken(context.Background(), server.URL, "POST")

	if !vulnerable {
		t.Error("server accepting POST without token should be vulnerable")
	}
}

func TestScanner_CheckSameSite(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "abc",
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	sameSite := scanner.checkSameSite(context.Background(), server.URL)

	if sameSite != "Strict" {
		t.Errorf("expected Strict, got %s", sameSite)
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
	poc := GeneratePOC("https://example.com/transfer", "POST", map[string]string{
		"amount": "1000",
		"to":     "attacker",
	})

	if poc == "" {
		t.Error("expected PoC content")
	}
	if !strings.Contains(poc, "https://example.com/transfer") {
		t.Error("PoC should contain target URL")
	}
	if !strings.Contains(poc, "amount") {
		t.Error("PoC should contain parameters")
	}
}

func TestCommonTargets(t *testing.T) {
	targets := CommonTargets()
	if len(targets) == 0 {
		t.Error("expected common targets")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:          "https://example.com",
		Method:       "POST",
		HasCSRFToken: false,
		Vulnerable:   true,
		Severity:     "MEDIUM",
		Timestamp:    time.Now(),
	}

	if result.Method != "POST" {
		t.Error("Method field incorrect")
	}
}
