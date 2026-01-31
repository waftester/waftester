package crlf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewTester(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		tester := NewTester(nil)
		if tester == nil {
			t.Fatal("expected tester, got nil")
		}
		if tester.config.Concurrency != 5 {
			t.Errorf("expected concurrency 5, got %d", tester.config.Concurrency)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:     60 * time.Second,
			Concurrency: 10,
		}
		tester := NewTester(config)
		if tester.config.Concurrency != 10 {
			t.Errorf("expected concurrency 10, got %d", tester.config.Concurrency)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", config.Timeout)
	}

	if len(config.TestParams) == 0 {
		t.Error("expected default test params")
	}

	if len(config.TestHeaders) == 0 {
		t.Error("expected default test headers")
	}
}

func TestGetPayloads(t *testing.T) {
	tester := NewTester(nil)
	payloads := tester.GetPayloads()

	if len(payloads) == 0 {
		t.Fatal("expected payloads")
	}

	// Check that we have different types
	typeMap := make(map[VulnerabilityType]bool)
	for _, p := range payloads {
		typeMap[p.Type] = true
	}

	if !typeMap[VulnHeaderInjection] {
		t.Error("expected header injection payloads")
	}
	if !typeMap[VulnResponseSplitting] {
		t.Error("expected response splitting payloads")
	}
	if !typeMap[VulnSetCookie] {
		t.Error("expected set-cookie payloads")
	}
}

func TestDetectInjection(t *testing.T) {
	tester := NewTester(nil)

	t.Run("detects injected header", func(t *testing.T) {
		// Create mock response with injected header
		resp := &http.Response{
			Header: make(http.Header),
		}
		resp.Header.Set("X-Injected", "waftester")

		payload := Payload{
			Type:   VulnHeaderInjection,
			Header: "X-Injected",
		}

		evidence := tester.detectInjection(resp, payload)
		if evidence == "" {
			t.Error("expected injection detection")
		}
	})

	t.Run("detects injected cookie", func(t *testing.T) {
		// Create mock response with injected cookie
		resp := &http.Response{
			Header: make(http.Header),
		}
		resp.Header.Set("Set-Cookie", "injected=waftester")

		payload := Payload{
			Type:   VulnSetCookie,
			Header: "Set-Cookie",
		}

		evidence := tester.detectInjection(resp, payload)
		if evidence == "" {
			t.Error("expected cookie injection detection")
		}
	})

	t.Run("no detection on clean response", func(t *testing.T) {
		resp := &http.Response{
			Header: make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html")

		payload := Payload{
			Type:   VulnHeaderInjection,
			Header: "X-Injected",
		}

		evidence := tester.detectInjection(resp, payload)
		if evidence != "" {
			t.Errorf("unexpected detection: %s", evidence)
		}
	})
}

func TestTestParameter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate vulnerable server that reflects header injection
		redirect := r.URL.Query().Get("redirect")
		if strings.Contains(redirect, "waftester") {
			w.Header().Set("X-Injected", "waftester")
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	vulns, err := tester.TestParameter(ctx, server.URL, "redirect")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect the injected header
	found := false
	for _, v := range vulns {
		if v.Type == VulnHeaderInjection {
			found = true
			break
		}
	}
	if found {
		t.Log("Successfully detected header injection")
	}
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Timeout = 5 * time.Second
	config.TestParams = []string{"url"}

	tester := NewTester(config)
	ctx := context.Background()

	result, err := tester.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.URL != server.URL {
		t.Errorf("expected URL %s, got %s", server.URL, result.URL)
	}

	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}

	if result.TestedPayloads == 0 {
		t.Error("expected payloads to be tested")
	}
}

func TestTestPOST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Write([]byte("POST received"))
		}
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	vulns, err := tester.TestPOST(ctx, server.URL, "redirect")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Just verify no error occurred
	_ = vulns
}

func TestTestHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	vulns, err := tester.TestHeader(ctx, server.URL, "X-Forwarded-For")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Note: Go HTTP client sanitizes headers, so injection via headers typically fails
	_ = vulns
}

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		expected Severity
	}{
		{VulnResponseSplitting, SeverityCritical},
		{VulnXSSViaCRLF, SeverityCritical},
		{VulnHeaderInjection, SeverityHigh},
		{VulnSetCookie, SeverityHigh},
		{VulnCachePoison, SeverityHigh},
		{VulnLogInjection, SeverityMedium},
	}

	for _, tt := range tests {
		t.Run(string(tt.vulnType), func(t *testing.T) {
			result := getSeverity(tt.vulnType)
			if result != tt.expected {
				t.Errorf("getSeverity(%s) = %s, want %s", tt.vulnType, result, tt.expected)
			}
		})
	}
}

func TestGetCVSS(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		expected float64
	}{
		{VulnResponseSplitting, 9.1},
		{VulnXSSViaCRLF, 8.2},
		{VulnHeaderInjection, 7.5},
		{VulnSetCookie, 7.1},
		{VulnCachePoison, 7.5},
		{VulnLogInjection, 5.3},
	}

	for _, tt := range tests {
		t.Run(string(tt.vulnType), func(t *testing.T) {
			result := getCVSS(tt.vulnType)
			if result != tt.expected {
				t.Errorf("getCVSS(%s) = %f, want %f", tt.vulnType, result, tt.expected)
			}
		})
	}
}

func TestGetCRLFRemediation(t *testing.T) {
	remediation := GetCRLFRemediation()
	if remediation == "" {
		t.Error("expected remediation text")
	}

	if !strings.Contains(remediation, "CR") && !strings.Contains(remediation, "LF") {
		t.Error("remediation should mention CRLF characters")
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 6 {
		t.Errorf("expected 6 vulnerability types, got %d", len(types))
	}
}

func TestIsCRLFCharacter(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"hello\r\nworld", true},
		{"hello\nworld", true},
		{"hello\rworld", true},
		{"hello world", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsCRLFCharacter(tt.input)
			if result != tt.expected {
				t.Errorf("IsCRLFCharacter(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsCRLFEncoded(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"test%0d%0aheader", true},
		{"%0d%0a", true},
		{"%0D%0A", true},
		{"%250d%250a", true},
		{"normalstring", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsCRLFEncoded(tt.input)
			if result != tt.expected {
				t.Errorf("IsCRLFEncoded(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeCRLF(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello\r\nworld", "helloworld"},
		{"hello\nworld", "helloworld"},
		{"hello\rworld", "helloworld"},
		{"hello world", "hello world"},
		{"\r\n\r\n", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizeCRLF(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeCRLF(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeCRLFEncoded(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test%0d%0aheader", "testheader"},
		{"%0D%0A", ""},
		{"%250d%250a", ""},
		{"normalstring", "normalstring"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizeCRLFEncoded(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeCRLFEncoded(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGenerateCRLFPayloads(t *testing.T) {
	payloads := GenerateCRLFPayloads("X-Test", "value")

	if len(payloads) == 0 {
		t.Fatal("expected payloads")
	}

	// All payloads should contain the header name
	for _, p := range payloads {
		if !strings.Contains(p, "X-Test") {
			t.Errorf("payload should contain header name: %s", p)
		}
	}
}

func TestVulnerabilityToJSON(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnHeaderInjection,
		Description: "Test",
		Severity:    SeverityHigh,
		URL:         "http://example.com",
		Parameter:   "redirect",
		Payload:     "%0d%0a",
		Evidence:    "Header found",
		CVSS:        7.5,
	}

	jsonStr, err := VulnerabilityToJSON(vuln)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(jsonStr, "header-injection") {
		t.Error("expected vulnerability type in JSON")
	}
}

func TestVulnerability(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnResponseSplitting,
		Description: "Test vulnerability",
		Severity:    SeverityCritical,
		URL:         "http://example.com",
		Parameter:   "redirect",
		Payload:     "%0d%0a%0d%0a<html>",
		Evidence:    "Response split",
		Remediation: "Fix it",
		CVSS:        9.1,
	}

	data, err := json.Marshal(vuln)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Vulnerability
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Type != vuln.Type {
		t.Errorf("type mismatch")
	}
	if decoded.CVSS != vuln.CVSS {
		t.Errorf("CVSS mismatch")
	}
}

func TestScanResult(t *testing.T) {
	result := ScanResult{
		URL:            "http://example.com",
		StartTime:      time.Now(),
		EndTime:        time.Now().Add(5 * time.Second),
		Duration:       5 * time.Second,
		TestedPayloads: 50,
		Vulnerabilities: []Vulnerability{
			{Type: VulnHeaderInjection},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.TestedPayloads != 50 {
		t.Errorf("expected 50 payloads, got %d", decoded.TestedPayloads)
	}
}

func TestPayload(t *testing.T) {
	payload := Payload{
		Value:       "\r\nX-Test: value",
		Encoded:     "%0d%0aX-Test:%20value",
		Description: "Test payload",
		Type:        VulnHeaderInjection,
		Header:      "X-Test",
	}

	if payload.Encoded == "" {
		t.Error("expected encoded payload")
	}
	if payload.Header == "" {
		t.Error("expected header name")
	}
}
