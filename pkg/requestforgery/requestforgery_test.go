package requestforgery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestSplittingPayloads(t *testing.T) {
	payloads := RequestSplittingPayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 request splitting payloads, got %d", len(payloads))
	}

	hasCRLF := false
	hasEncoded := false

	for _, p := range payloads {
		if strings.Contains(p.Payload, "\r\n") {
			hasCRLF = true
		}
		if strings.Contains(p.Payload, "%0d%0a") {
			hasEncoded = true
		}
	}

	if !hasCRLF {
		t.Error("Expected raw CRLF payloads")
	}
	if !hasEncoded {
		t.Error("Expected URL-encoded CRLF payloads")
	}
}

func TestHostHeaderPayloads(t *testing.T) {
	payloads := HostHeaderPayloads()

	if len(payloads) < 10 {
		t.Errorf("Expected at least 10 host header payloads, got %d", len(payloads))
	}

	hasLocalhost := false
	hasMetadata := false
	hasPrivateIP := false

	for _, p := range payloads {
		if p.Host == "localhost" || p.Host == "127.0.0.1" {
			hasLocalhost = true
		}
		if p.Host == "169.254.169.254" {
			hasMetadata = true
		}
		if strings.HasPrefix(p.Host, "10.") || strings.HasPrefix(p.Host, "192.168.") {
			hasPrivateIP = true
		}
	}

	if !hasLocalhost {
		t.Error("Expected localhost payloads")
	}
	if !hasMetadata {
		t.Error("Expected AWS metadata IP")
	}
	if !hasPrivateIP {
		t.Error("Expected private IP payloads")
	}
}

func TestMethodOverrideHeaders(t *testing.T) {
	headers := MethodOverrideHeaders()

	if len(headers) < 5 {
		t.Errorf("Expected at least 5 method override headers, got %d", len(headers))
	}

	headerNames := make(map[string]bool)
	methods := make(map[string]bool)

	for _, h := range headers {
		headerNames[h.Header] = true
		methods[h.Method] = true
	}

	if !headerNames["X-HTTP-Method-Override"] {
		t.Error("Expected X-HTTP-Method-Override header")
	}
	if !methods["DELETE"] {
		t.Error("Expected DELETE method")
	}
	if !methods["PUT"] {
		t.Error("Expected PUT method")
	}
}

func TestProxyHeaderPayloads(t *testing.T) {
	payloads := ProxyHeaderPayloads()

	if len(payloads) < 10 {
		t.Errorf("Expected at least 10 proxy header payloads, got %d", len(payloads))
	}

	headers := make(map[string]bool)
	for _, p := range payloads {
		headers[p.Header] = true
	}

	expected := []string{"X-Forwarded-Host", "X-Original-URL", "X-Forwarded-For"}
	for _, exp := range expected {
		if !headers[exp] {
			t.Errorf("Expected header %s in payloads", exp)
		}
	}
}

func TestAbsoluteURIPayloads(t *testing.T) {
	payloads := AbsoluteURIPayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 absolute URI payloads, got %d", len(payloads))
	}

	hasHTTP := false
	hasGopher := false
	hasFile := false

	for _, p := range payloads {
		if strings.HasPrefix(p.URI, "http://") {
			hasHTTP = true
		}
		if strings.HasPrefix(p.URI, "gopher://") {
			hasGopher = true
		}
		if strings.HasPrefix(p.URI, "file://") {
			hasFile = true
		}
	}

	if !hasHTTP {
		t.Error("Expected HTTP URIs")
	}
	if !hasGopher {
		t.Error("Expected Gopher protocol URI")
	}
	if !hasFile {
		t.Error("Expected File protocol URI")
	}
}

func TestCacheKeyPayloads(t *testing.T) {
	payloads := CacheKeyPayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 cache key payloads, got %d", len(payloads))
	}

	hasUTM := false
	hasCacheBuster := false

	for _, p := range payloads {
		if strings.Contains(p.Param, "utm_") {
			hasUTM = true
		}
		if strings.Contains(p.Param, "cb=") || strings.Contains(p.Param, "_=") {
			hasCacheBuster = true
		}
	}

	if !hasUTM {
		t.Error("Expected UTM parameter payloads")
	}
	if !hasCacheBuster {
		t.Error("Expected cache buster payloads")
	}
}

func TestRefererSpoofingPayloads(t *testing.T) {
	payloads := RefererSpoofingPayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 Referer spoofing payloads, got %d", len(payloads))
	}

	hasAdmin := false
	hasEmpty := false

	for _, p := range payloads {
		if strings.Contains(p, "admin") {
			hasAdmin = true
		}
		if p == "" {
			hasEmpty = true
		}
	}

	if !hasAdmin {
		t.Error("Expected admin-related Referer payloads")
	}
	if !hasEmpty {
		t.Error("Expected empty Referer payload")
	}
}

func TestOriginSpoofingPayloads(t *testing.T) {
	payloads := OriginSpoofingPayloads()

	if len(payloads) < 5 {
		t.Errorf("Expected at least 5 Origin spoofing payloads, got %d", len(payloads))
	}

	hasEvil := false
	hasNull := false
	hasLocalhost := false

	for _, p := range payloads {
		if strings.Contains(p, "evil") {
			hasEvil = true
		}
		if p == "null" {
			hasNull = true
		}
		if strings.Contains(p, "localhost") || strings.Contains(p, "127.0.0.1") {
			hasLocalhost = true
		}
	}

	if !hasEvil {
		t.Error("Expected evil.com Origin payload")
	}
	if !hasNull {
		t.Error("Expected null Origin payload")
	}
	if !hasLocalhost {
		t.Error("Expected localhost Origin payload")
	}
}

func TestNewTester(t *testing.T) {
	tester := NewTester("http://example.com", 0)

	if tester.target != "http://example.com" {
		t.Errorf("Expected target http://example.com, got %s", tester.target)
	}
	if tester.client == nil {
		t.Error("Expected HTTP client to be initialized")
	}
}

func TestHostHeaderInjection(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: reflects Host header in response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to " + r.Host))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 0)
	results, err := tester.TestHostHeaderInjection(context.Background())

	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable {
			foundVuln = true
			break
		}
	}

	if !foundVuln {
		t.Error("Expected to detect Host header reflection")
	}
}

func TestProxyHeaderInjection(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: reflects X-Forwarded-Host
		fwdHost := r.Header.Get("X-Forwarded-Host")
		if fwdHost != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Forwarded from: " + fwdHost))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 0)
	results, err := tester.TestProxyHeaderInjection(context.Background())

	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable && r.Technique == "X-Forwarded-Host" {
			foundVuln = true
			break
		}
	}

	if !foundVuln {
		t.Error("Expected to detect X-Forwarded-Host injection")
	}
}

func TestOriginSpoofing(t *testing.T) {
	tests := []struct {
		name       string
		acao       string
		acac       string
		origin     string
		vulnerable bool
	}{
		{
			name:       "Wildcard ACAO",
			acao:       "*",
			vulnerable: true,
		},
		{
			name:       "Reflected Origin",
			acao:       "REFLECT",
			vulnerable: true,
		},
		{
			name:       "Null Origin Allowed",
			acao:       "null",
			vulnerable: true,
		},
		{
			name:       "Specific Origin",
			acao:       "https://trusted.com",
			vulnerable: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				origin := r.Header.Get("Origin")

				if tc.acao == "REFLECT" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				} else {
					w.Header().Set("Access-Control-Allow-Origin", tc.acao)
				}
				if tc.acac != "" {
					w.Header().Set("Access-Control-Allow-Credentials", tc.acac)
				}
				w.WriteHeader(http.StatusOK)
			})

			server := httptest.NewServer(handler)
			defer server.Close()

			tester := NewTester(server.URL, 0)
			results, err := tester.TestOriginSpoofing(context.Background())

			if err != nil {
				t.Fatalf("Test failed: %v", err)
			}

			foundVuln := false
			for _, r := range results {
				if r.Vulnerable {
					foundVuln = true
					break
				}
			}

			if foundVuln != tc.vulnerable {
				t.Errorf("Expected vulnerable=%v, got %v", tc.vulnerable, foundVuln)
			}
		})
	}
}

func TestMethodOverride(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for method override headers
		override := r.Header.Get("X-HTTP-Method-Override")
		if override == "DELETE" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Deleted"))
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 0)
	results, err := tester.TestMethodOverride(context.Background(), "/resource")

	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable && r.Payload == "DELETE" {
			foundVuln = true
			break
		}
	}

	if !foundVuln {
		t.Error("Expected to detect DELETE method override")
	}
}

func TestRefererSpoofing(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: grants access based on Referer
		referer := r.Header.Get("Referer")
		if strings.Contains(referer, "admin") {
			w.WriteHeader(http.StatusOK)
			// Return enough content to trigger vulnerability detection (>100 bytes)
			w.Write([]byte("Admin panel content here with sensitive data. This is a protected admin area with user management, system settings, and other administrative functions."))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 0)
	results, err := tester.TestRefererSpoofing(context.Background(), "/admin")

	if err != nil {
		t.Fatalf("Test failed: %v", err)
	}

	foundVuln := false
	for _, r := range results {
		if r.Vulnerable && strings.Contains(r.Payload, "admin") {
			foundVuln = true
			break
		}
	}

	if !foundVuln {
		t.Error("Expected to detect Referer-based access bypass")
	}
}

func TestRunAllTests(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tester := NewTester(server.URL, 0)
	results, err := tester.RunAllTests(context.Background())

	if err != nil {
		t.Fatalf("RunAllTests failed: %v", err)
	}

	if len(results) < 10 {
		t.Errorf("Expected at least 10 test results, got %d", len(results))
	}

	// Check various vuln types are represented
	vulnTypes := make(map[VulnerabilityType]bool)
	for _, r := range results {
		vulnTypes[r.VulnType] = true
	}

	expected := []VulnerabilityType{
		HostHeaderInjection,
		ProxyHeaderInjection,
		OriginSpoofing,
		CacheKeyInjection,
	}

	for _, exp := range expected {
		if !vulnTypes[exp] {
			t.Errorf("Expected tests for vulnerability type: %s", exp)
		}
	}
}

func TestSummarizeResults(t *testing.T) {
	results := []TestResult{
		{Vulnerable: true, Severity: "Critical"},
		{Vulnerable: true, Severity: "High"},
		{Vulnerable: false, Severity: "Medium"},
		{Vulnerable: false, Severity: "Low"},
	}

	summary := SummarizeResults(results)

	if summary["total"] != 4 {
		t.Errorf("Expected total 4, got %d", summary["total"])
	}
	if summary["vulnerable"] != 2 {
		t.Errorf("Expected vulnerable 2, got %d", summary["vulnerable"])
	}
	if summary["safe"] != 2 {
		t.Errorf("Expected safe 2, got %d", summary["safe"])
	}
	if summary["critical"] != 1 {
		t.Errorf("Expected critical 1, got %d", summary["critical"])
	}
	if summary["high"] != 1 {
		t.Errorf("Expected high 1, got %d", summary["high"])
	}
}

func TestMin(t *testing.T) {
	if min(5, 10) != 5 {
		t.Error("min(5, 10) should be 5")
	}
	if min(10, 5) != 5 {
		t.Error("min(10, 5) should be 5")
	}
	if min(5, 5) != 5 {
		t.Error("min(5, 5) should be 5")
	}
}
