package cryptofailure

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWeakTLSVersions(t *testing.T) {
	versions := WeakTLSVersions()

	if len(versions) < 2 {
		t.Errorf("Expected at least 2 weak TLS versions, got %d", len(versions))
	}

	// Should include SSL 3.0, TLS 1.0, TLS 1.1
	if _, ok := versions[tls.VersionTLS10]; !ok {
		t.Error("Expected TLS 1.0 in weak versions")
	}
	if _, ok := versions[tls.VersionTLS11]; !ok {
		t.Error("Expected TLS 1.1 in weak versions")
	}
}

func TestWeakCipherSuites(t *testing.T) {
	ciphers := WeakCipherSuites()

	if len(ciphers) < 5 {
		t.Errorf("Expected at least 5 weak cipher suites, got %d", len(ciphers))
	}

	// Check for RC4 ciphers
	hasRC4 := false
	for cipher, name := range ciphers {
		_ = cipher
		if strings.Contains(name, "RC4") {
			hasRC4 = true
			break
		}
	}

	if !hasRC4 {
		t.Error("Expected RC4 in weak cipher suites")
	}
}

func TestSecretPatterns(t *testing.T) {
	patterns := SecretPatterns()

	if len(patterns) < 5 {
		t.Errorf("Expected at least 5 secret patterns, got %d", len(patterns))
	}

	// Check for common patterns
	expected := []string{"AWS Access Key", "JWT", "Private Key"}
	for _, exp := range expected {
		if _, ok := patterns[exp]; !ok {
			t.Errorf("Expected pattern for: %s", exp)
		}
	}
}

func TestWeakHashPatterns(t *testing.T) {
	patterns := WeakHashPatterns()

	if len(patterns) < 2 {
		t.Errorf("Expected at least 2 weak hash patterns, got %d", len(patterns))
	}

	// Should have MD5 and SHA1
	if _, ok := patterns["MD5 Hash"]; !ok {
		t.Error("Expected MD5 Hash pattern")
	}
	if _, ok := patterns["SHA1 Hash"]; !ok {
		t.Error("Expected SHA1 Hash pattern")
	}
}

func TestScanForSecrets(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected int
	}{
		{
			name:     "AWS Access Key",
			content:  "key = AKIAIOSFODNN7EXAMPLE",
			expected: 1,
		},
		{
			name:     "JWT Token",
			content:  "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			expected: 1,
		},
		{
			name:     "Private Key",
			content:  "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
			expected: 1,
		},
		{
			name:     "Database URL",
			content:  "DATABASE_URL=postgres://user:password@localhost:5432/db",
			expected: 1,
		},
		{
			name:     "No secrets",
			content:  "This is just regular content with no secrets.",
			expected: 0,
		},
		{
			name:     "GitHub Token",
			content:  "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			expected: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := ScanForSecrets(tc.content)
			if len(results) != tc.expected {
				t.Errorf("Expected %d secrets, found %d", tc.expected, len(results))
			}

			for _, r := range results {
				if !r.Vulnerable {
					t.Error("Expected vulnerable to be true")
				}
				if r.Severity != "Critical" {
					t.Errorf("Expected Critical severity, got %s", r.Severity)
				}
			}
		})
	}
}

func TestScanForWeakHashing(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "MD5 usage",
			content:  "hash = md5(password)",
			expected: true,
		},
		{
			name:     "SHA1 usage",
			content:  "digest = SHA1(data)",
			expected: true,
		},
		{
			name:     "MD5 hash value",
			content:  "hash: d41d8cd98f00b204e9800998ecf8427e",
			expected: true,
		},
		{
			name:     "Strong hash only",
			content:  "Using bcrypt for password hashing",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := ScanForWeakHashing(tc.content)
			found := len(results) > 0
			if found != tc.expected {
				t.Errorf("Expected weak hash found=%v, got %v", tc.expected, found)
			}
		})
	}
}

func TestTestHSTS(t *testing.T) {
	tests := []struct {
		name       string
		hstsHeader string
		vulnerable bool
	}{
		{
			name:       "No HSTS",
			hstsHeader: "",
			vulnerable: true,
		},
		{
			name:       "Has HSTS",
			hstsHeader: "max-age=31536000; includeSubDomains; preload",
			vulnerable: false,
		},
		{
			name:       "Minimal HSTS",
			hstsHeader: "max-age=86400",
			vulnerable: false, // Still not vulnerable, just suboptimal
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.hstsHeader != "" {
					w.Header().Set("Strict-Transport-Security", tc.hstsHeader)
				}
				w.WriteHeader(http.StatusOK)
			})

			server := httptest.NewTLSServer(handler)
			defer server.Close()

			tester := NewTester(server.URL, 5*time.Second)
			result, err := tester.TestHSTS(context.Background())
			if err != nil {
				t.Fatalf("Test failed: %v", err)
			}

			if result.Vulnerable != tc.vulnerable {
				t.Errorf("Expected vulnerable=%v, got %v", tc.vulnerable, result.Vulnerable)
			}
		})
	}
}

func TestTestHTTPDowngrade(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		location   string
		vulnerable bool
	}{
		{
			name:       "Redirect to HTTPS",
			statusCode: 301,
			location:   "https://example.com/",
			vulnerable: false,
		},
		{
			name:       "Redirect to HTTP",
			statusCode: 302,
			location:   "http://example.com/other",
			vulnerable: true,
		},
		{
			name:       "Serves content on HTTP",
			statusCode: 200,
			location:   "",
			vulnerable: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				w.WriteHeader(tc.statusCode)
			})

			server := httptest.NewServer(handler)
			defer server.Close()

			// Create tester with http URL
			tester := NewTester(strings.Replace(server.URL, "http://", "https://", 1), 5*time.Second)
			tester.target = server.URL // Override to HTTP for test

			result, err := tester.TestHTTPDowngrade(context.Background())
			if err != nil {
				t.Fatalf("Test failed: %v", err)
			}

			if result.Vulnerable != tc.vulnerable {
				t.Errorf("Expected vulnerable=%v, got %v", tc.vulnerable, result.Vulnerable)
			}
		})
	}
}

func TestScanResponseForSecrets(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return content with a secret
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"api_key": "AKIAIOSFODNN7EXAMPLE"}`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 5*time.Second)
	results, err := tester.ScanResponseForSecrets(context.Background(), "/api/config")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected to find secrets in response")
	}

	for _, r := range results {
		if !r.Vulnerable {
			t.Error("Expected vulnerable to be true")
		}
	}
}

func TestNewTester(t *testing.T) {
	tester := NewTester("https://example.com", 30*time.Second)

	if tester.target != "https://example.com" {
		t.Errorf("Expected target https://example.com, got %s", tester.target)
	}
	if tester.timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", tester.timeout)
	}

	// Test default timeout
	tester2 := NewTester("https://example.com", 0)
	if tester2.timeout != 10*time.Second {
		t.Errorf("Expected default timeout 10s, got %v", tester2.timeout)
	}
}

func TestSummarizeResults(t *testing.T) {
	results := []TestResult{
		{Vulnerable: true, Severity: "Critical"},
		{Vulnerable: true, Severity: "High"},
		{Vulnerable: true, Severity: "Medium"},
		{Vulnerable: false, Severity: "Low"},
		{Vulnerable: false, Severity: "Info"},
	}

	summary := SummarizeResults(results)

	if summary["total"] != 5 {
		t.Errorf("Expected total 5, got %d", summary["total"])
	}
	if summary["vulnerable"] != 3 {
		t.Errorf("Expected vulnerable 3, got %d", summary["vulnerable"])
	}
	if summary["safe"] != 2 {
		t.Errorf("Expected safe 2, got %d", summary["safe"])
	}
	if summary["critical"] != 1 {
		t.Errorf("Expected critical 1, got %d", summary["critical"])
	}
}

func TestSecretPatternMatching(t *testing.T) {
	patterns := SecretPatterns()

	// Test AWS Access Key pattern
	awsPattern := patterns["AWS Access Key"]
	if !awsPattern.MatchString("AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS Access Key pattern should match valid key")
	}
	if awsPattern.MatchString("not a key") {
		t.Error("AWS Access Key pattern should not match invalid key")
	}

	// Test JWT pattern
	jwtPattern := patterns["JWT"]
	validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	if !jwtPattern.MatchString(validJWT) {
		t.Error("JWT pattern should match valid JWT")
	}

	// Test Private Key pattern
	pkPattern := patterns["Private Key"]
	if !pkPattern.MatchString("-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("Private Key pattern should match RSA private key header")
	}
	if !pkPattern.MatchString("-----BEGIN PRIVATE KEY-----") {
		t.Error("Private Key pattern should match generic private key header")
	}
}
