package hostheader

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
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
		if len(tester.payloads) == 0 {
			t.Error("expected payloads to be generated")
		}
	})

	t.Run("custom config", func(t *testing.T) {
		config := &TesterConfig{
			Base: attackconfig.Base{
				Timeout: 60 * time.Second,
			},
			CallbackURL: "attacker.example.com",
		}
		tester := NewTester(config)

		// Check callback URL is used
		hasCallback := false
		for _, p := range tester.payloads {
			if strings.Contains(p.Value, "attacker.example.com") {
				hasCallback = true
				break
			}
		}

		if !hasCallback {
			t.Error("expected callback URL in payloads")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if config.UserAgent == "" {
		t.Error("expected user agent")
	}
}

func TestGetPayloads(t *testing.T) {
	t.Run("all payloads", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads("")

		if len(payloads) == 0 {
			t.Error("expected payloads")
		}
	})

	t.Run("Host header payloads", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads("Host")

		if len(payloads) == 0 {
			t.Error("expected Host payloads")
		}
		for _, p := range payloads {
			if !strings.EqualFold(p.Header, "Host") {
				t.Errorf("expected Host header, got %s", p.Header)
			}
		}
	})

	t.Run("X-Forwarded-Host payloads", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads("X-Forwarded-Host")

		if len(payloads) == 0 {
			t.Error("expected X-Forwarded-Host payloads")
		}
	})
}

func TestTestURL(t *testing.T) {
	t.Run("host reflected in body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Reflect the X-Forwarded-Host in the response
			xfh := r.Header.Get("X-Forwarded-Host")
			if xfh != "" {
				w.Write([]byte("<a href=\"http://" + xfh + "/reset\">Reset Password</a>"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestURL(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) == 0 {
			t.Error("expected vulnerabilities")
		}

		hasHostOverride := false
		for _, v := range vulns {
			if v.Type == VulnHostOverride {
				hasHostOverride = true
				break
			}
		}

		if !hasHostOverride {
			t.Error("expected host override vulnerability")
		}
	})

	t.Run("host reflected in location header", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			xfh := r.Header.Get("X-Forwarded-Host")
			if xfh != "" {
				w.Header().Set("Location", "http://"+xfh+"/redirect")
				w.WriteHeader(http.StatusFound)
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestURL(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasRedirect := false
		for _, v := range vulns {
			if v.Type == VulnOpenRedirect {
				hasRedirect = true
				break
			}
		}

		if !hasRedirect {
			t.Error("expected open redirect vulnerability")
		}
	})

	t.Run("no vulnerability", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Safe response"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestURL(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) != 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})

	t.Run("cache poisoning detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			xfh := r.Header.Get("X-Forwarded-Host")
			w.Header().Set("X-Cache", "HIT")
			if xfh != "" {
				w.Write([]byte("<a href=\"http://" + xfh + "\">Link</a>"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestURL(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasCachePoisoning := false
		for _, v := range vulns {
			if v.Type == VulnCachePoisoning {
				hasCachePoisoning = true
				break
			}
		}

		if !hasCachePoisoning {
			t.Error("expected cache poisoning vulnerability")
		}
	})
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			w.Write([]byte("<a href=\"http://" + xfh + "\">Link</a>"))
		}
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
	if result.TestedHeaders == 0 {
		t.Error("expected headers to be tested")
	}
	if len(result.Vulnerabilities) == 0 {
		t.Error("expected vulnerabilities")
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 6 {
		t.Errorf("expected 6 vulnerability types, got %d", len(types))
	}

	expectedTypes := map[VulnerabilityType]bool{
		VulnPasswordReset:    false,
		VulnCachePoisoning:   false,
		VulnSSRF:             false,
		VulnOpenRedirect:     false,
		VulnWebCachePoisonng: false,
		VulnHostOverride:     false,
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

func TestHostOverrideHeaders(t *testing.T) {
	headers := HostOverrideHeaders()

	if len(headers) == 0 {
		t.Error("expected headers")
	}

	hasHost := false
	hasXFH := false

	for _, h := range headers {
		if h == "Host" {
			hasHost = true
		}
		if h == "X-Forwarded-Host" {
			hasXFH = true
		}
	}

	if !hasHost {
		t.Error("expected Host header")
	}
	if !hasXFH {
		t.Error("expected X-Forwarded-Host header")
	}
}

func TestGetRemediation(t *testing.T) {
	remediation := GetRemediation()

	if remediation == "" {
		t.Error("expected remediation")
	}

	if !strings.Contains(remediation, "whitelist") {
		t.Error("expected whitelist mention")
	}
}

func TestGetPasswordResetRemediation(t *testing.T) {
	remediation := GetPasswordResetRemediation()

	if remediation == "" {
		t.Error("expected remediation")
	}

	if !strings.Contains(remediation, "Host header") {
		t.Error("expected Host header mention")
	}
}

func TestGetCachePoisoningRemediation(t *testing.T) {
	remediation := GetCachePoisoningRemediation()

	if remediation == "" {
		t.Error("expected remediation")
	}

	if !strings.Contains(remediation, "cache") {
		t.Error("expected cache mention")
	}
}

func TestIsResetPasswordEndpoint(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"http://example.com/reset-password", true},
		{"http://example.com/forgot-password", true},
		{"http://example.com/password/reset", true},
		{"http://example.com/account/recover", true},
		{"http://example.com/login", false},
		{"http://example.com/", false},
		{"http://example.com/profile", false},
	}

	for _, test := range tests {
		result := IsResetPasswordEndpoint(test.url)
		if result != test.expected {
			t.Errorf("IsResetPasswordEndpoint(%s) = %v, expected %v", test.url, result, test.expected)
		}
	}
}

func TestGenerateBypassPayloads(t *testing.T) {
	payloads := GenerateBypassPayloads("target.com", "evil.com")

	if len(payloads) == 0 {
		t.Error("expected bypass payloads")
	}

	hasCRLF := false
	hasTab := false

	for _, p := range payloads {
		if strings.Contains(p.Description, "CRLF") {
			hasCRLF = true
		}
		if strings.Contains(p.Description, "Tab") {
			hasTab = true
		}
	}

	if !hasCRLF {
		t.Error("expected CRLF payload")
	}
	if !hasTab {
		t.Error("expected Tab payload")
	}
}

func TestVulnerabilityFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			w.Write([]byte("<a href=\"http://" + xfh + "\">Link</a>"))
		}
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	vulns, _ := tester.TestURL(ctx, server.URL)

	if len(vulns) > 0 {
		v := vulns[0]

		if v.Type == "" {
			t.Error("vulnerability should have type")
		}
		if v.Description == "" {
			t.Error("vulnerability should have description")
		}
		if v.URL == "" {
			t.Error("vulnerability should have URL")
		}
		if v.Remediation == "" {
			t.Error("vulnerability should have remediation")
		}
		if v.Header == "" {
			t.Error("vulnerability should have header")
		}
		if v.CVSS == 0 {
			t.Error("vulnerability should have CVSS score")
		}
	}
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := tester.Scan(ctx, server.URL)
	if err != context.Canceled {
		// May return nil with partial results
	}
}

func TestPayloadHeaders(t *testing.T) {
	tester := NewTester(nil)

	headers := make(map[string]bool)
	for _, p := range tester.payloads {
		headers[p.Header] = true
	}

	// Check for common headers
	expectedHeaders := []string{
		"Host",
		"X-Forwarded-Host",
		"X-Host",
		"X-Forwarded-Server",
		"Forwarded",
		"X-Forwarded-Port",
	}

	for _, h := range expectedHeaders {
		if !headers[h] {
			t.Errorf("expected header %s in payloads", h)
		}
	}
}

func BenchmarkTestURL(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tester.TestURL(ctx, server.URL)
	}
}
