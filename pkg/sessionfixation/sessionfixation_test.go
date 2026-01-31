package sessionfixation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
}

func TestScanner_Scan_Vulnerable(t *testing.T) {
	sessionValue := "FIXED_SESSION_12345"

	// Server that doesn't regenerate session after login
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if session cookie exists
		cookie, err := r.Cookie("session")
		if err != nil {
			// Set new session
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: sessionValue,
			})
		} else {
			// Keep the same session (vulnerable)
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: cookie.Value,
			})
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.Scan(context.Background(), server.URL, url.Values{
		"username": {"test"},
		"password": {"test"},
	})

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability - session not regenerated")
	}
	if result.SessionRegenerated {
		t.Error("Session should not be regenerated")
	}
	if result.Severity != "HIGH" {
		t.Errorf("Expected HIGH severity, got: %s", result.Severity)
	}
}

func TestScanner_Scan_Safe(t *testing.T) {
	callCount := 0

	// Server that regenerates session after login
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Always issue new session
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "SESSION_" + string(rune(callCount+'0')),
		})
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.Scan(context.Background(), server.URL, url.Values{
		"username": {"test"},
		"password": {"test"},
	})

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability - session was regenerated")
	}
	if !result.SessionRegenerated {
		t.Error("Session should be regenerated")
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("GetResults returned nil")
	}
}

func TestCommonSessionCookieNames(t *testing.T) {
	names := CommonSessionCookieNames()
	if len(names) < 10 {
		t.Errorf("CommonSessionCookieNames count = %d, want at least 10", len(names))
	}

	// Check for common names
	found := map[string]bool{
		"PHPSESSID":   false,
		"JSESSIONID":  false,
		"connect.sid": false,
	}

	for _, n := range names {
		if _, ok := found[n]; ok {
			found[n] = true
		}
	}

	for n, f := range found {
		if !f {
			t.Errorf("Expected session cookie name: %s", n)
		}
	}
}

func TestFixationPayloads(t *testing.T) {
	payloads := FixationPayloads()
	if len(payloads) < 3 {
		t.Errorf("FixationPayloads count = %d, want at least 3", len(payloads))
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:                "http://example.com/login",
		SessionCookie:      "PHPSESSID",
		PreAuthSession:     "abc123",
		PostAuthSession:    "abc123",
		SessionRegenerated: false,
		Vulnerable:         true,
		Evidence:           "Session not regenerated",
		Severity:           "HIGH",
	}

	if result.URL != "http://example.com/login" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
	if result.SessionRegenerated != false {
		t.Error("SessionRegenerated not set correctly")
	}
}

func TestScanner_IsSessionCookie(t *testing.T) {
	scanner := NewScanner(DefaultConfig())

	tests := []struct {
		name     string
		expected bool
	}{
		{"PHPSESSID", true},
		{"JSESSIONID", true},
		{"session", true},
		{"sessionid", true},
		{"connect.sid", true},
		{"auth_token", true},
		{"preference", false},
		{"tracking", false},
		{"_ga", false},
	}

	for _, tt := range tests {
		result := scanner.isSessionCookie(tt.name)
		if result != tt.expected {
			t.Errorf("isSessionCookie(%q) = %v, want %v", tt.name, result, tt.expected)
		}
	}
}
