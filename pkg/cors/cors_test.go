package cors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
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
	})

	t.Run("custom config", func(t *testing.T) {
		config := &TesterConfig{
			Base: attackconfig.Base{
				Timeout:   30 * time.Second,
				UserAgent: "Custom Agent",
			},
		}
		tester := NewTester(config)

		if tester.config.Timeout != 30*time.Second {
			t.Errorf("expected 30s timeout")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != httpclient.TimeoutProbing {
		t.Errorf("expected %v timeout, got %v", httpclient.TimeoutProbing, config.Timeout)
	}
	if config.FollowRedirects {
		t.Error("expected follow redirects to be false")
	}
}

func TestGenerateTestOrigins(t *testing.T) {
	t.Run("with valid URL", func(t *testing.T) {
		origins := GenerateTestOrigins("https://example.com/api")

		if len(origins) == 0 {
			t.Error("expected origins")
		}

		// Should contain evil.com test
		hasEvil := false
		hasNull := false
		hasSubdomain := false

		for _, o := range origins {
			if o.Origin == "https://evil.com" {
				hasEvil = true
			}
			if o.Origin == "null" {
				hasNull = true
			}
			if o.Type == VulnSubdomainTrust {
				hasSubdomain = true
			}
		}

		if !hasEvil {
			t.Error("expected evil.com origin")
		}
		if !hasNull {
			t.Error("expected null origin")
		}
		if !hasSubdomain {
			t.Error("expected subdomain trust test")
		}
	})

	t.Run("with invalid URL", func(t *testing.T) {
		origins := GenerateTestOrigins(":::invalid")

		if len(origins) == 0 {
			t.Error("expected default origins for invalid URL")
		}
	})
}

func TestTestOrigin(t *testing.T) {
	t.Run("origin reflected - vulnerable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		origin := &TestOrigin{
			Origin:      "https://evil.com",
			Type:        VulnOriginReflection,
			Description: "Test origin reflection",
		}

		vuln, err := tester.TestOrigin(ctx, server.URL, origin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln == nil {
			t.Fatal("expected vulnerability")
		}

		if vuln.Type != VulnOriginReflection {
			t.Errorf("expected origin reflection type")
		}
		if vuln.Severity != finding.Critical {
			t.Errorf("expected critical severity with credentials")
		}
		if !vuln.Credentials {
			t.Error("expected credentials to be true")
		}
	})

	t.Run("no CORS headers - not vulnerable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		origin := &TestOrigin{
			Origin: "https://evil.com",
			Type:   VulnOriginReflection,
		}

		vuln, err := tester.TestOrigin(ctx, server.URL, origin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln != nil {
			t.Error("expected no vulnerability")
		}
	})

	t.Run("null origin trusted", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		origin := &TestOrigin{
			Origin: "null",
			Type:   VulnNullOrigin,
		}

		vuln, err := tester.TestOrigin(ctx, server.URL, origin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln == nil {
			t.Fatal("expected vulnerability")
		}

		if vuln.Type != VulnNullOrigin {
			t.Errorf("expected null origin type, got %s", vuln.Type)
		}
	})

	t.Run("wildcard with credentials", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		origin := &TestOrigin{
			Origin: "https://evil.com",
			Type:   VulnOriginReflection,
		}

		vuln, err := tester.TestOrigin(ctx, server.URL, origin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln == nil {
			t.Fatal("expected vulnerability")
		}

		if vuln.Type != VulnWildcardCredentials {
			t.Errorf("expected wildcard credentials type, got %s", vuln.Type)
		}
		if vuln.Severity != finding.Critical {
			t.Error("expected critical severity")
		}
	})
}

func TestTestPreflight(t *testing.T) {
	t.Run("permissive preflight", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "OPTIONS" {
				w.Header().Set("Access-Control-Allow-Origin", "https://evil.com")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
				w.Header().Set("Access-Control-Allow-Headers", "*")
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vuln, err := tester.TestPreflight(ctx, server.URL, "https://evil.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln == nil {
			t.Fatal("expected vulnerability")
		}

		if vuln.Type != VulnPreflight {
			t.Errorf("expected preflight type")
		}
	})

	t.Run("restrictive preflight", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "OPTIONS" {
				w.Header().Set("Access-Control-Allow-Origin", "https://trusted.com")
				w.Header().Set("Access-Control-Allow-Methods", "GET")
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vuln, err := tester.TestPreflight(ctx, server.URL, "https://evil.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if vuln != nil {
			t.Error("expected no vulnerability")
		}
	})
}

func TestScan(t *testing.T) {
	t.Run("vulnerable target", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		result, err := tester.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.URL != server.URL {
			t.Errorf("expected URL %s", server.URL)
		}
		if result.TestedOrigins == 0 {
			t.Error("expected origins to be tested")
		}
		if len(result.Vulnerabilities) == 0 {
			t.Error("expected vulnerabilities")
		}
		if !result.CORSEnabled {
			t.Error("expected CORS to be detected as enabled")
		}
	})

	t.Run("safe target", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No CORS headers
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		result, err := tester.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.Vulnerabilities) != 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(result.Vulnerabilities))
		}
	})
}

func TestCheckCORSHeaders(t *testing.T) {
	t.Run("no CORS headers", func(t *testing.T) {
		headers := http.Header{}

		analysis := CheckCORSHeaders(headers)

		if analysis.CORSEnabled {
			t.Error("expected CORS disabled")
		}
		if !analysis.Secure {
			t.Error("expected secure (no CORS = no issues)")
		}
	})

	t.Run("wildcard origin", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Access-Control-Allow-Origin", "*")

		analysis := CheckCORSHeaders(headers)

		if !analysis.CORSEnabled {
			t.Error("expected CORS enabled")
		}
		if len(analysis.Issues) == 0 {
			t.Error("expected issues")
		}
		if analysis.Secure {
			t.Error("expected not secure")
		}
	})

	t.Run("wildcard with credentials", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Access-Control-Allow-Origin", "*")
		headers.Set("Access-Control-Allow-Credentials", "true")

		analysis := CheckCORSHeaders(headers)

		if !analysis.AllowCredentials {
			t.Error("expected credentials enabled")
		}

		hasCritical := false
		for _, issue := range analysis.Issues {
			if issue == "Critical: Wildcard with credentials" {
				hasCritical = true
			}
		}
		if !hasCritical {
			t.Error("expected critical issue")
		}
	})

	t.Run("null origin", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Access-Control-Allow-Origin", "null")

		analysis := CheckCORSHeaders(headers)

		if analysis.Secure {
			t.Error("expected not secure")
		}
	})

	t.Run("specific origin - secure", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Access-Control-Allow-Origin", "https://trusted.com")
		headers.Set("Access-Control-Allow-Methods", "GET, POST")

		analysis := CheckCORSHeaders(headers)

		if !analysis.CORSEnabled {
			t.Error("expected CORS enabled")
		}
		if !analysis.Secure {
			t.Error("expected secure")
		}
		if analysis.AllowMethods != "GET, POST" {
			t.Errorf("expected methods")
		}
	})
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 7 {
		t.Errorf("expected 7 vulnerability types, got %d", len(types))
	}

	expectedTypes := map[VulnerabilityType]bool{
		VulnOriginReflection:    false,
		VulnNullOrigin:          false,
		VulnWildcardCredentials: false,
		VulnSubdomainTrust:      false,
		VulnWeakRegex:           false,
		VulnCredentialExposure:  false,
		VulnPreflight:           false,
	}

	for _, vt := range types {
		expectedTypes[vt] = true
	}

	for vt, found := range expectedTypes {
		if !found {
			t.Errorf("missing vulnerability type: %s", vt)
		}
	}
}

func TestGetCORSHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://example.com")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	analysis, err := tester.GetCORSHeaders(ctx, server.URL, "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !analysis.CORSEnabled {
		t.Error("expected CORS enabled")
	}
	if analysis.AllowOrigin != "https://example.com" {
		t.Errorf("expected origin")
	}
	if analysis.MaxAge != "3600" {
		t.Errorf("expected max age")
	}
}

func TestVaryOriginCheck(t *testing.T) {
	t.Run("vary origin present", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Origin", "https://example.com")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		hasVary, err := tester.VaryOriginCheck(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !hasVary {
			t.Error("expected Vary: Origin")
		}
	})

	t.Run("vary origin missing", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "https://example.com")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		hasVary, err := tester.VaryOriginCheck(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if hasVary {
			t.Error("expected no Vary: Origin")
		}
	})
}

func TestExtractBaseDomain(t *testing.T) {
	tests := []struct {
		host     string
		expected string
	}{
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"sub.domain.example.com", "example.com"},
		{"example.com:8080", "example.com"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := extractBaseDomain(tt.host)
			if result != tt.expected {
				t.Errorf("extractBaseDomain(%s) = %s, expected %s", tt.host, result, tt.expected)
			}
		})
	}
}

func TestVulnerabilityFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	origin := &TestOrigin{
		Origin:      "https://evil.com",
		Type:        VulnOriginReflection,
		Description: "Test",
	}

	vuln, _ := tester.TestOrigin(ctx, server.URL, origin)

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
		if vuln.TestedOrigin == "" {
			t.Error("vulnerability should have tested origin")
		}
		if vuln.AllowOrigin == "" {
			t.Error("vulnerability should have allow origin")
		}
	}
}

func BenchmarkScan(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tester.Scan(ctx, server.URL)
	}
}
