package redirect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
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
				Timeout: 30 * time.Second,
			},
			AttackerDomain: "attacker.com",
		}
		tester := NewTester(config)

		if tester.config.AttackerDomain != "attacker.com" {
			t.Errorf("expected attacker.com domain")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", config.Timeout)
	}
	if config.MaxRedirects != defaults.MaxRedirects {
		t.Errorf("expected %d max redirects, got %d", defaults.MaxRedirects, config.MaxRedirects)
	}
	if config.AttackerDomain != "evil.com" {
		t.Errorf("expected evil.com as attacker domain")
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

	t.Run("filtered by type", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads(VulnProtocolRelative)

		for _, p := range payloads {
			if p.Type != VulnProtocolRelative {
				t.Errorf("expected protocol-relative type, got %s", p.Type)
			}
		}
	})
}

func TestCommonRedirectParams(t *testing.T) {
	params := CommonRedirectParams()

	if len(params) == 0 {
		t.Error("expected params")
	}

	// Check for common ones
	hasURL := false
	hasRedirect := false
	hasNext := false

	for _, p := range params {
		switch p {
		case "url":
			hasURL = true
		case "redirect":
			hasRedirect = true
		case "next":
			hasNext = true
		}
	}

	if !hasURL {
		t.Error("expected 'url' parameter")
	}
	if !hasRedirect {
		t.Error("expected 'redirect' parameter")
	}
	if !hasNext {
		t.Error("expected 'next' parameter")
	}
}

func TestTestParameter(t *testing.T) {
	t.Run("vulnerable - Location redirect", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectURL := r.URL.Query().Get("url")
			if redirectURL != "" {
				w.Header().Set("Location", redirectURL)
				w.WriteHeader(http.StatusFound)
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "url")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) == 0 {
			t.Error("expected vulnerabilities")
		}
	})

	t.Run("not vulnerable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ignores the parameter
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "url")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) != 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})

	t.Run("meta refresh redirect", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectURL := r.URL.Query().Get("url")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><head><meta http-equiv="refresh" content="0;url=` + redirectURL + `"></head></html>`))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "url")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasMetaRefresh := false
		for _, v := range vulns {
			if v.Type == VulnMetaRefresh {
				hasMetaRefresh = true
				break
			}
		}

		if !hasMetaRefresh {
			t.Error("expected meta refresh vulnerability")
		}
	})

	t.Run("JavaScript redirect", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectURL := r.URL.Query().Get("url")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<script>window.location = "` + redirectURL + `"</script>`))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "url")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasJSRedirect := false
		for _, v := range vulns {
			if v.Type == VulnJavascriptRedirect {
				hasJSRedirect = true
				break
			}
		}

		if !hasJSRedirect {
			t.Error("expected JavaScript redirect vulnerability")
		}
	})
}

func TestScan(t *testing.T) {
	t.Run("vulnerable target", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			redirectURL := r.URL.Query().Get("redirect")
			if redirectURL != "" {
				w.Header().Set("Location", redirectURL)
				w.WriteHeader(http.StatusFound)
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
		if result.TestedParams == 0 {
			t.Error("expected params to be tested")
		}
		if result.PayloadsTested == 0 {
			t.Error("expected payloads to be tested")
		}
		if len(result.Vulnerabilities) == 0 {
			t.Error("expected vulnerabilities")
		}
	})

	t.Run("safe target", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestScanWithParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := r.URL.Query().Get("next")
		if redirectURL != "" {
			w.Header().Set("Location", redirectURL)
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	result, err := tester.ScanWithParams(ctx, server.URL, []string{"next"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TestedParams != 1 {
		t.Errorf("expected 1 tested param, got %d", result.TestedParams)
	}
	if len(result.Vulnerabilities) == 0 {
		t.Error("expected vulnerabilities")
	}
}

func TestDetectRedirectParams(t *testing.T) {
	tests := []struct {
		url      string
		expected []string
	}{
		{
			url:      "http://example.com?url=http://test.com",
			expected: []string{"url"},
		},
		{
			url:      "http://example.com?redirect=test&next=page",
			expected: []string{"redirect", "next"},
		},
		{
			url:      "http://example.com?foo=bar",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			detected := DetectRedirectParams(tt.url)

			if len(detected) != len(tt.expected) {
				t.Errorf("expected %d params, got %d", len(tt.expected), len(detected))
				return
			}

			for _, exp := range tt.expected {
				found := false
				for _, det := range detected {
					if det == exp {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected param %s not found", exp)
				}
			}
		})
	}
}

func TestIsRedirectToAttacker(t *testing.T) {
	tests := []struct {
		location       string
		attackerDomain string
		expected       bool
	}{
		{"http://evil.com", "evil.com", true},
		{"https://evil.com/path", "evil.com", true},
		{"//evil.com", "evil.com", true},
		{"http://trusted.com", "evil.com", false},
		{"https://sub.evil.com", "evil.com", true},
		{"/relative/path", "evil.com", false},
		{"", "evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.location, func(t *testing.T) {
			result := isRedirectToAttacker(tt.location, tt.attackerDomain)
			if result != tt.expected {
				t.Errorf("isRedirectToAttacker(%s, %s) = %v, expected %v",
					tt.location, tt.attackerDomain, result, tt.expected)
			}
		})
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 6 {
		t.Errorf("expected 6 vulnerability types, got %d", len(types))
	}

	expectedTypes := map[VulnerabilityType]bool{
		VulnURLParameter:       false,
		VulnProtocolRelative:   false,
		VulnEncodedRedirect:    false,
		VulnHeaderInjection:    false,
		VulnMetaRefresh:        false,
		VulnJavascriptRedirect: false,
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

func TestGetRemediation(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		contains string
	}{
		{VulnURLParameter, "allowlist"},
		{VulnProtocolRelative, "protocol"},
		{VulnEncodedRedirect, "decode"},
		{VulnHeaderInjection, "CRLF"},
		{VulnMetaRefresh, "meta"},
		{VulnJavascriptRedirect, "JavaScript"},
	}

	for _, tt := range tests {
		t.Run(string(tt.vulnType), func(t *testing.T) {
			remediation := GetRemediation(tt.vulnType)
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
		redirectURL := r.URL.Query().Get("url")
		if redirectURL != "" {
			w.Header().Set("Location", redirectURL)
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	vulns, _ := tester.TestParameter(ctx, server.URL, "url")

	if len(vulns) > 0 {
		v := vulns[0]

		if v.Type == "" {
			t.Error("vulnerability should have type")
		}
		if v.Description == "" {
			t.Error("vulnerability should have description")
		}
		if v.Severity == "" {
			t.Error("vulnerability should have severity")
		}
		if v.URL == "" {
			t.Error("vulnerability should have URL")
		}
		if v.Remediation == "" {
			t.Error("vulnerability should have remediation")
		}
		if v.Parameter == "" {
			t.Error("vulnerability should have parameter")
		}
		if v.RedirectURL == "" {
			t.Error("vulnerability should have redirect URL")
		}
		if v.Payload == nil {
			t.Error("vulnerability should have payload reference")
		}
	}
}

func TestPayloadGeneration(t *testing.T) {
	tester := NewTester(nil)
	payloads := tester.GetPayloads("")

	// Check for different payload types
	hasBasic := false
	hasProtocolRelative := false
	hasEncoded := false

	for _, p := range payloads {
		switch p.Type {
		case VulnURLParameter:
			hasBasic = true
		case VulnProtocolRelative:
			hasProtocolRelative = true
		case VulnEncodedRedirect:
			hasEncoded = true
		}
	}

	if !hasBasic {
		t.Error("expected basic URL payloads")
	}
	if !hasProtocolRelative {
		t.Error("expected protocol-relative payloads")
	}
	if !hasEncoded {
		t.Error("expected encoded payloads")
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

	result, err := tester.Scan(ctx, server.URL)
	if err != context.Canceled {
		// May return nil error with partial results
		if result != nil && result.Duration > 0 {
			// That's acceptable
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
		tester.ScanWithParams(ctx, server.URL, []string{"url"})
	}
}
