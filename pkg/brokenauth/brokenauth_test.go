package brokenauth

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

func TestScanner_TestSessionManagement(t *testing.T) {
	// Server that sets a session cookie
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set a weak session cookie (no HttpOnly, no Secure)
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "abc123",
		})
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.TestSessionManagement(context.Background(), server.URL, url.Values{
		"username": {"test"},
		"password": {"test"},
	})

	if err != nil {
		t.Fatalf("TestSessionManagement error: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable {
			foundVuln = true
			if r.Severity != "HIGH" {
				t.Errorf("Severity = %s, want HIGH", r.Severity)
			}
		}
	}

	if !foundVuln {
		t.Error("Expected to find session vulnerability")
	}
}

func TestScanner_TestPasswordPolicy(t *testing.T) {
	// Server that accepts any password
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Registration successful"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	results, err := scanner.TestPasswordPolicy(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("TestPasswordPolicy error: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected results for password policy test")
	}

	vulnCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnCount++
		}
	}

	if vulnCount == 0 {
		t.Error("Expected weak password vulnerabilities")
	}
}

func TestScanner_TestAccountLockout_NoLockout(t *testing.T) {
	// Server that never locks accounts
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("Invalid credentials"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.TestAccountLockout(context.Background(), server.URL, "testuser", 10)

	if err != nil {
		t.Fatalf("TestAccountLockout error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability - no lockout mechanism")
	}
}

func TestScanner_TestAccountLockout_HasLockout(t *testing.T) {
	attempts := 0
	// Server that locks after 5 attempts
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts > 5 {
			w.WriteHeader(429)
			w.Write([]byte("Too many attempts"))
			return
		}
		w.WriteHeader(401)
		w.Write([]byte("Invalid credentials"))
	}))
	defer server.Close()

	scanner := NewScanner(DefaultConfig())
	result, err := scanner.TestAccountLockout(context.Background(), server.URL, "testuser", 10)

	if err != nil {
		t.Fatalf("TestAccountLockout error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability - lockout mechanism present")
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	results := scanner.GetResults()
	if results == nil {
		t.Error("GetResults returned nil")
	}
}

func TestWeakPasswords(t *testing.T) {
	passwords := WeakPasswords()
	if len(passwords) < 5 {
		t.Errorf("WeakPasswords count = %d, want at least 5", len(passwords))
	}

	// Should include common weak passwords
	found := map[string]bool{}
	for _, p := range passwords {
		found[p] = true
	}

	expected := []string{"password", "123456", "admin"}
	for _, exp := range expected {
		if !found[exp] {
			t.Errorf("Expected weak password: %s", exp)
		}
	}
}

func TestDefaultCredentials(t *testing.T) {
	creds := DefaultCredentials()
	if len(creds) < 3 {
		t.Errorf("DefaultCredentials count = %d, want at least 3", len(creds))
	}

	if _, ok := creds["admin"]; !ok {
		t.Error("Expected 'admin' in default credentials")
	}
}

func TestAuthBypassPayloads(t *testing.T) {
	payloads := AuthBypassPayloads()
	if len(payloads) < 3 {
		t.Errorf("AuthBypassPayloads count = %d, want at least 3", len(payloads))
	}

	// Should contain SQL injection patterns
	foundSQLi := false
	for _, p := range payloads {
		if len(p) > 0 && (p[0] == '\'' || p[0] == ')') {
			foundSQLi = true
		}
	}
	if !foundSQLi {
		t.Error("Expected SQL injection patterns in auth bypass payloads")
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:         "http://example.com/login",
		TestType:    "session_analysis",
		Description: "Session token analysis",
		StatusCode:  200,
		Vulnerable:  true,
		Evidence:    "missing HttpOnly flag",
		Severity:    "HIGH",
	}

	if result.URL != "http://example.com/login" {
		t.Error("URL not set correctly")
	}
	if result.Vulnerable != true {
		t.Error("Vulnerable not set correctly")
	}
}

func TestIsSessionCookie(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"PHPSESSID", true},
		{"session", true},
		{"auth_token", true},
		{"sid", true},
		{"preference", false},
		{"tracking", false},
	}

	for _, tt := range tests {
		result := isSessionCookie(tt.name)
		if result != tt.expected {
			t.Errorf("isSessionCookie(%q) = %v, want %v", tt.name, result, tt.expected)
		}
	}
}
