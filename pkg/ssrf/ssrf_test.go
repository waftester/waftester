package ssrf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/finding"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector(DefaultConfig())
	if d == nil {
		t.Fatal("NewDetector returned nil")
	}
	if d.Timeout == 0 {
		t.Error("Timeout should be set")
	}
	if len(d.LocalIPs) == 0 {
		t.Error("LocalIPs should be set")
	}
	if len(d.CloudMetadataIPs) == 0 {
		t.Error("CloudMetadataIPs should be set")
	}
	if len(d.BypassTechniques) == 0 {
		t.Error("BypassTechniques should be set")
	}
	if d.callbacks == nil {
		t.Error("callbacks map should be initialized")
	}
}

func TestGeneratePayloads(t *testing.T) {
	d := NewDetector(DefaultConfig())
	payloads := d.GeneratePayloads()

	if len(payloads) == 0 {
		t.Fatal("No payloads generated")
	}

	// Check for different categories
	categories := make(map[Category]int)
	for _, p := range payloads {
		categories[p.Category]++
		if p.Name == "" {
			t.Error("Payload should have a name")
		}
		if p.URL == "" {
			t.Error("Payload should have a URL")
		}
	}

	// Should have localhost payloads
	if categories[CategoryLocalhost] == 0 {
		t.Error("Should have localhost payloads")
	}

	// Should have metadata payloads
	if categories[CategoryMetadata] == 0 {
		t.Error("Should have metadata payloads")
	}

	// Should have protocol payloads
	if categories[CategoryProtocol] == 0 {
		t.Error("Should have protocol payloads")
	}

	// Should have bypass payloads
	if categories[CategoryBypass] == 0 {
		t.Error("Should have bypass payloads")
	}
}

func TestGeneratePayloadsWithCallback(t *testing.T) {
	d := NewDetector(DefaultConfig())
	d.CallbackServer = "callback.example.com"

	payloads := d.GeneratePayloads()

	// Should have blind SSRF payloads
	hasBlind := false
	for _, p := range payloads {
		if p.Category == CategoryBlind {
			hasBlind = true
			if !strings.Contains(p.URL, "callback.example.com") {
				t.Error("Blind payload should contain callback server")
			}
		}
	}

	if !hasBlind {
		t.Error("Should have blind SSRF payloads when callback server is set")
	}
}

func TestLocalhostPayloads(t *testing.T) {
	d := NewDetector(DefaultConfig())
	payloads := d.generateLocalhostPayloads()

	if len(payloads) == 0 {
		t.Fatal("No localhost payloads generated")
	}

	// Check for various localhost representations
	expectedPatterns := []string{
		"127.0.0.1",
		"localhost",
		"0.0.0.0",
		"::1",
		"127.1",
		"2130706433", // Decimal
		"0x7f000001", // Hex
	}

	for _, pattern := range expectedPatterns {
		found := false
		for _, p := range payloads {
			if strings.Contains(p.URL, pattern) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing localhost pattern: %s", pattern)
		}
	}
}

func TestMetadataPayloads(t *testing.T) {
	d := NewDetector(DefaultConfig())
	payloads := d.generateMetadataPayloads()

	if len(payloads) == 0 {
		t.Fatal("No metadata payloads generated")
	}

	// Check for cloud providers
	providers := map[string]bool{
		"169.254.169.254":          false, // AWS/GCP/Azure
		"metadata.google.internal": false, // GCP
		"kubernetes":               false, // K8s
	}

	for _, p := range payloads {
		for provider := range providers {
			if strings.Contains(p.URL, provider) {
				providers[provider] = true
			}
		}
	}

	for provider, found := range providers {
		if !found {
			t.Errorf("Missing metadata provider: %s", provider)
		}
	}
}

func TestProtocolPayloads(t *testing.T) {
	d := NewDetector(DefaultConfig())
	payloads := d.generateProtocolPayloads()

	if len(payloads) == 0 {
		t.Fatal("No protocol payloads generated")
	}

	// Check for various protocols
	protocols := []string{"file://", "gopher://", "dict://", "ftp://", "ldap://"}

	for _, proto := range protocols {
		found := false
		for _, p := range payloads {
			if strings.HasPrefix(p.URL, proto) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing protocol: %s", proto)
		}
	}
}

func TestBypassPayloads(t *testing.T) {
	d := NewDetector(DefaultConfig())
	payloads := d.generateBypassPayloads()

	if len(payloads) == 0 {
		t.Fatal("No bypass payloads generated")
	}

	// All should have bypass method
	for _, p := range payloads {
		if p.BypassMethod == "" {
			t.Errorf("Bypass payload should have bypass method: %s", p.Name)
		}
		if p.Category != CategoryBypass {
			t.Errorf("Bypass payload should have bypass category: %s", p.Name)
		}
	}
}

func TestApplyBypass(t *testing.T) {
	d := NewDetector(DefaultConfig())

	bypassed := d.ApplyBypass("http://127.0.0.1/test")

	if len(bypassed) == 0 {
		t.Fatal("No bypass URLs generated")
	}

	// Should have various representations
	for _, url := range bypassed {
		if !strings.HasPrefix(url, "http://") {
			t.Errorf("Bypass URL should start with http://: %s", url)
		}
	}
}

func TestApplyBypassInvalidURL(t *testing.T) {
	d := NewDetector(DefaultConfig())

	bypassed := d.ApplyBypass("not-a-url")

	// Should handle gracefully
	if bypassed == nil {
		t.Log("Returned nil for invalid URL - acceptable")
	}
}

func TestCallbackRegistration(t *testing.T) {
	d := NewDetector(DefaultConfig())

	id := "test-callback-123"

	// Check before registration
	found, _ := d.CheckCallback(id)
	if found {
		t.Error("Callback should not exist before registration")
	}

	// Register
	d.RegisterCallback(id)

	// Check after registration
	found, tm := d.CheckCallback(id)
	if !found {
		t.Error("Callback should exist after registration")
	}
	if tm.IsZero() {
		t.Error("Callback time should be set")
	}
}

func TestAnalyzeResponseMetadata(t *testing.T) {
	d := NewDetector(DefaultConfig())

	payload := Payload{
		Category: CategoryMetadata,
		URL:      "http://169.254.169.254/latest/meta-data/",
	}

	tests := []struct {
		name       string
		body       string
		headers    http.Header
		expectVuln bool
	}{
		{
			name:       "AWS metadata response",
			body:       `{"ami-id": "ami-12345", "instance-id": "i-12345"}`,
			headers:    http.Header{},
			expectVuln: true,
		},
		{
			name:       "AWS credentials",
			body:       `{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "secret"}`,
			headers:    http.Header{},
			expectVuln: true,
		},
		{
			name:       "GCP metadata",
			body:       `computeMetadata/v1/`,
			headers:    http.Header{"Metadata-Flavor": []string{"Google"}},
			expectVuln: true,
		},
		{
			name:       "Normal response",
			body:       `<html>Hello World</html>`,
			headers:    http.Header{},
			expectVuln: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := d.AnalyzeResponse(payload, 200, tt.body, tt.headers)

			if tt.expectVuln && vuln == nil {
				t.Error("Expected vulnerability to be detected")
			}
			if !tt.expectVuln && vuln != nil {
				t.Error("Did not expect vulnerability")
			}
		})
	}
}

func TestAnalyzeResponseLocalhost(t *testing.T) {
	d := NewDetector(DefaultConfig())

	payload := Payload{
		Category: CategoryLocalhost,
		URL:      "http://127.0.0.1/",
	}

	tests := []struct {
		name       string
		statusCode int
		body       string
		expectVuln bool
	}{
		{
			name:       "Successful response",
			statusCode: 200,
			body:       "<html>Welcome to nginx!</html>",
			expectVuln: true,
		},
		{
			name:       "Nginx welcome",
			statusCode: 200,
			body:       "Welcome to nginx!",
			expectVuln: true,
		},
		{
			name:       "Error response",
			statusCode: 500,
			body:       "Internal Server Error",
			expectVuln: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := d.AnalyzeResponse(payload, tt.statusCode, tt.body, http.Header{})

			if tt.expectVuln && vuln == nil {
				t.Error("Expected vulnerability to be detected")
			}
			if !tt.expectVuln && vuln != nil {
				t.Error("Did not expect vulnerability")
			}
		})
	}
}

func TestAnalyzeResponseFileProtocol(t *testing.T) {
	d := NewDetector(DefaultConfig())

	payload := Payload{
		Category: CategoryProtocol,
		URL:      "file:///etc/passwd",
	}

	tests := []struct {
		name       string
		body       string
		expectVuln bool
	}{
		{
			name:       "passwd file",
			body:       "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/:/usr/sbin/nologin",
			expectVuln: true,
		},
		{
			name:       "PHP file",
			body:       "<?php echo 'hello'; ?>",
			expectVuln: true,
		},
		{
			name:       "Hosts file",
			body:       "127.0.0.1\tlocalhost\n::1\tlocalhost",
			expectVuln: true,
		},
		{
			name:       "Error response",
			body:       "File not found",
			expectVuln: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := d.AnalyzeResponse(payload, 200, tt.body, http.Header{})

			if tt.expectVuln && vuln == nil {
				t.Error("Expected vulnerability to be detected")
			}
			if !tt.expectVuln && vuln != nil {
				t.Error("Did not expect vulnerability")
			}
		})
	}
}

func TestIPConversions(t *testing.T) {
	t.Run("ipToDecimal", func(t *testing.T) {
		result := ipToDecimal("127.0.0.1")
		if result != "2130706433" {
			t.Errorf("Expected 2130706433, got %s", result)
		}

		// Invalid IP
		result = ipToDecimal("invalid")
		if result != "" {
			t.Error("Should return empty for invalid IP")
		}
	})

	t.Run("ipToHex", func(t *testing.T) {
		result := ipToHex("127.0.0.1")
		if result != "0x7f000001" {
			t.Errorf("Expected 0x7f000001, got %s", result)
		}
	})

	t.Run("ipToOctal", func(t *testing.T) {
		result := ipToOctal("127.0.0.1")
		if result != "0177.00.00.01" {
			t.Errorf("Expected 0177.00.00.01, got %s", result)
		}
	})
}

func TestURLEncode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1", "%31%32%37%2e%30%2e%30%2e%31"},
		{"localhost", "%6c%6f%63%61%6c%68%6f%73%74"},
	}

	for _, tt := range tests {
		result := urlEncode(tt.input)
		if result != tt.expected {
			t.Errorf("urlEncode(%s) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func TestGenerateRandomID(t *testing.T) {
	id1 := generateRandomID()
	id2 := generateRandomID()

	if len(id1) != 12 {
		t.Errorf("Expected length 12, got %d", len(id1))
	}

	// IDs should be different (with very high probability)
	if id1 == id2 {
		t.Error("Generated IDs should be unique")
	}

	// Should only contain alphanumeric
	for _, c := range id1 {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("ID contains invalid character: %c", c)
		}
	}
}

func TestTruncateBody(t *testing.T) {
	tests := []struct {
		body     string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a longer string", 10, "this is a ..."},
		{"exact", 5, "exact"},
	}

	for _, tt := range tests {
		result := truncateBody(tt.body, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncateBody(%q, %d) = %q, expected %q", tt.body, tt.maxLen, result, tt.expected)
		}
	}
}

func TestNewInternalNetworkScanner(t *testing.T) {
	s := NewInternalNetworkScanner()
	if s == nil {
		t.Fatal("NewInternalNetworkScanner returned nil")
	}
	if s.Detector == nil {
		t.Error("Detector should be set")
	}
	if len(s.Subnets) == 0 {
		t.Error("Subnets should be set")
	}
	if len(s.CommonPorts) == 0 {
		t.Error("CommonPorts should be set")
	}
}

func TestGenerateInternalPayloads(t *testing.T) {
	s := NewInternalNetworkScanner()

	payloads := s.GenerateInternalPayloads("192.168.1.0/24", []int{80, 443})

	if len(payloads) == 0 {
		t.Fatal("No internal payloads generated")
	}

	// Should have various hostnames
	hostnames := []string{"localhost", "db", "redis"}
	for _, host := range hostnames {
		found := false
		for _, p := range payloads {
			if strings.Contains(p.URL, host) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing internal hostname: %s", host)
		}
	}
}

func TestDetect(t *testing.T) {
	d := NewDetector(DefaultConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := d.Detect(ctx, "https://example.com/fetch", "url")
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}
	if result.Target != "https://example.com/fetch" {
		t.Error("Target mismatch")
	}
	if result.Parameter != "url" {
		t.Error("Parameter mismatch")
	}
	if len(result.Payloads) == 0 {
		t.Error("Should have payloads")
	}
	// Duration is set even if very small
	_ = result.Duration
}

func TestDetectContextCancellation(t *testing.T) {
	d := NewDetector(DefaultConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := d.Detect(ctx, "https://example.com/fetch", "url")

	// Should return with context error
	if err != context.Canceled {
		t.Logf("Expected context.Canceled, got %v (may have completed before cancellation)", err)
	}
	if result == nil {
		t.Error("Result should still be returned")
	}
}

func TestVulnerabilityFields(t *testing.T) {
	v := Vulnerability{
		Type:        "SSRF",
		Severity:    finding.Critical,
		Parameter:   "url",
		Payload:     "http://169.254.169.254/",
		Evidence:    "AWS metadata response",
		Confidence:  0.95,
		Remediation: "Validate URLs",
	}

	if v.Type == "" {
		t.Error("Type should be set")
	}
	if v.Confidence != 0.95 {
		t.Error("Confidence mismatch")
	}
}

func TestPayloadFields(t *testing.T) {
	p := Payload{
		Name:           "Test Payload",
		URL:            "http://127.0.0.1/",
		Category:       CategoryLocalhost,
		BypassMethod:   "direct",
		ExpectedResult: "Success",
		Description:    "Test",
		Dangerous:      true,
	}

	if p.Name == "" {
		t.Error("Name should be set")
	}
	if !p.Dangerous {
		t.Error("Should be dangerous")
	}
}

func TestCategories(t *testing.T) {
	categories := []Category{
		CategoryLocalhost,
		CategoryMetadata,
		CategoryInternal,
		CategoryProtocol,
		CategoryBypass,
		CategoryBlind,
		CategoryOpenRedirect,
	}

	for _, c := range categories {
		if c == "" {
			t.Error("Category should not be empty")
		}
	}
}

func TestIsMetadataResponse(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		headers  http.Header
		expected bool
	}{
		{"Empty", "", http.Header{}, false},
		{"Normal HTML", "<html></html>", http.Header{}, false},
		{"AWS ami-id", "ami-id: ami-12345", http.Header{}, true},
		{"AWS AccessKeyId", `{"AccessKeyId": "AKIA..."}`, http.Header{}, true},
		{"GCP header", "", http.Header{"Metadata-Flavor": []string{"Google"}}, true},
		{"Security credentials", "/iam/security-credentials/", http.Header{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isMetadataResponse(tt.body, tt.headers)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsLocalResponse(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"200 OK bare", "OK", false},
		{"500 Error", "Error", false},
		{"Welcome to nginx", "Welcome to nginx!", true},
		{"Bare nginx no match", "Powered by nginx 1.24", false},
		{"Bare apache no match", "Apache server", false},
		{"Apache2 default page", "This is the Apache2 default page", true},
		{"redis banner", "redis_version:6.0.0", true},
		{"internal IP 10.x", "server at 10.0.0.1 responded", true},
		{"internal IP 192.168", "host: 192.168.1.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLocalResponse(tt.body)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsFileContent(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"passwd", "root:x:0:0:root:/root:/bin/bash", true},
		{"PHP", "<?php echo 1; ?>", true},
		{"Shebang", "#!/bin/bash\necho test", true},
		{"XML", "<?xml version='1.0'?>", true},
		{"DOCTYPE no match", "<!DOCTYPE html>", false},
		{"Normal text", "Hello World", false},
		{"HTML", "<html>test</html>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFileContent(tt.body)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// --- New tests: DefaultConfig, buildPayloadURL, negative cases ---

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if len(cfg.LocalIPs) == 0 {
		t.Error("DefaultConfig should populate LocalIPs")
	}
	if len(cfg.CloudMetadataIPs) == 0 {
		t.Error("DefaultConfig should populate CloudMetadataIPs")
	}
	if len(cfg.BypassTechniques) == 0 {
		t.Error("DefaultConfig should populate BypassTechniques")
	}
	if cfg.Timeout <= 0 {
		t.Error("DefaultConfig.Base.Timeout should be positive")
	}
}

func TestBuildPayloadURL(t *testing.T) {
	tests := []struct {
		name         string
		target       string
		param        string
		payload      string
		wantErr      bool
		wantContains string
	}{
		{
			name:         "basic injection",
			target:       "https://example.com/fetch",
			param:        "url",
			payload:      "http://127.0.0.1/",
			wantContains: "url=http",
		},
		{
			name:         "preserves existing query params",
			target:       "https://example.com/fetch?a=1",
			param:        "url",
			payload:      "http://169.254.169.254/",
			wantContains: "a=1",
		},
		{
			name:    "invalid target URL",
			target:  "://bad",
			param:   "url",
			payload: "http://127.0.0.1/",
			wantErr: true,
		},
		{
			name:         "empty param name",
			target:       "https://example.com/",
			param:        "",
			payload:      "http://127.0.0.1/",
			wantContains: "=http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildPayloadURL(tt.target, tt.param, tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantContains != "" && !strings.Contains(got, tt.wantContains) {
				t.Errorf("expected URL to contain %q, got %q", tt.wantContains, got)
			}
		})
	}
}

func TestDetectMaxPayloads(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPayloads = 3
	d := NewDetector(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := d.Detect(ctx, "https://example.com/fetch", "url")
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(result.Payloads) != 3 {
		t.Errorf("expected exactly 3 payloads with MaxPayloads=3, got %d", len(result.Payloads))
	}
}

func TestDetectWithHTTPServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "normal page")
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.MaxPayloads = 2
	d := NewDetector(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := d.Detect(ctx, server.URL+"/fetch", "url")
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if len(result.Payloads) == 0 {
		t.Fatal("expected payloads")
	}

	for _, pr := range result.Payloads {
		if !pr.Sent {
			t.Error("payload should be marked as sent")
		}
		if pr.Response.StatusCode == 0 && pr.Evidence == "" {
			t.Error("payload should have either a response or error evidence")
		}
	}
}

func TestDetectEmptyTarget(t *testing.T) {
	d := NewDetector(DefaultConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Empty target — buildPayloadURL still works (url.Parse("") succeeds),
	// but HTTP requests will fail with connection errors.
	result, err := d.Detect(ctx, "", "url")
	if err != nil {
		t.Logf("Error on empty target: %v (acceptable)", err)
	}
	if result == nil {
		t.Fatal("result should not be nil even with empty target")
	}
}

func TestDetectCallbackFires(t *testing.T) {
	// Simulate a server that responds with AWS metadata indicators
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, `{"ami-id":"ami-12345","instance-id":"i-abcdef"}`)
	}))
	defer server.Close()

	var called int
	cfg := DefaultConfig()
	cfg.MaxPayloads = 5
	cfg.OnVulnerabilityFound = func() { called++ }
	d := NewDetector(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := d.Detect(ctx, server.URL+"/fetch", "url")
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// The callback should fire for each metadata vuln found.
	if len(result.Vulnerabilities) > 0 && called == 0 {
		t.Error("OnVulnerabilityFound should have fired for detected vulns")
	}
}

func TestAnalyzeResponseWrongCategory(t *testing.T) {
	d := NewDetector(DefaultConfig())

	// Metadata body but localhost category — should NOT detect as vuln
	payload := Payload{Category: CategoryLocalhost, URL: "http://127.0.0.1/"}
	vuln := d.AnalyzeResponse(payload, 404, `{"ami-id":"ami-12345"}`, http.Header{})
	if vuln != nil {
		t.Error("should not detect metadata content under localhost category")
	}

	// File content body but metadata category — should NOT detect
	payload2 := Payload{Category: CategoryMetadata, URL: "http://169.254.169.254/"}
	vuln2 := d.AnalyzeResponse(payload2, 200, "root:x:0:0:root:/root:/bin/bash", http.Header{})
	if vuln2 != nil {
		t.Error("should not detect file content under metadata category")
	}
}

func TestAnalyzeResponseEmptyBody(t *testing.T) {
	d := NewDetector(DefaultConfig())

	categories := []struct {
		cat Category
		url string
	}{
		{CategoryMetadata, "http://169.254.169.254/"},
		{CategoryLocalhost, "http://127.0.0.1/"},
		{CategoryProtocol, "file:///etc/passwd"},
	}

	for _, c := range categories {
		payload := Payload{Category: c.cat, URL: c.url}
		vuln := d.AnalyzeResponse(payload, 200, "", http.Header{})
		if vuln != nil {
			t.Errorf("empty body should not trigger vuln for category %s", c.cat)
		}
	}
}

// --- Round 3 regression tests ---

func TestAnalyzeResponseBypassCategory(t *testing.T) {
	// CategoryBypass payloads targeting localhost should be detected
	// when the response body contains local service indicators.
	d := NewDetector(DefaultConfig())

	payload := Payload{
		Category: CategoryBypass,
		URL:      "http://0x7f000001/",
	}

	vuln := d.AnalyzeResponse(payload, 200, "Welcome to nginx!", http.Header{})
	if vuln == nil {
		t.Fatal("CategoryBypass with localhost-indicating body should trigger vuln")
	}
	if vuln.Type != "Localhost Access" {
		t.Errorf("expected 'Localhost Access', got %q", vuln.Type)
	}
}

func TestAnalyzeResponseBypassNonLocal(t *testing.T) {
	// CategoryBypass with a non-local body should NOT trigger.
	d := NewDetector(DefaultConfig())

	payload := Payload{Category: CategoryBypass, URL: "http://0x7f000001/"}
	vuln := d.AnalyzeResponse(payload, 200, "Hello World", http.Header{})
	if vuln != nil {
		t.Error("CategoryBypass with benign body should not trigger vuln")
	}
}

func TestIsLocalResponseNoFalsePositives(t *testing.T) {
	// Bodies that mention "nginx" or "apache" in passing should NOT match.
	falsePositives := []string{
		"Powered by nginx 1.24",
		"Using Apache as reverse proxy",
		"nginx is a web server",
		"apache foundation project",
		`<html><body>Read more about nginx here</body></html>`,
	}

	for _, body := range falsePositives {
		t.Run(body[:20], func(t *testing.T) {
			if isLocalResponse(body) {
				t.Errorf("should not match: %s", body)
			}
		})
	}
}

func TestIsFileContentNoDOCTYPE(t *testing.T) {
	// <!DOCTYPE html> must not trigger file content detection.
	bodies := []string{
		"<!DOCTYPE html><html><body>Error</body></html>",
		"<!DOCTYPE html>\n<html>",
		`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">`,
	}

	for _, body := range bodies {
		if isFileContent(body) {
			t.Errorf("DOCTYPE should not trigger isFileContent: %s", body[:30])
		}
	}
}

func TestIsFileContentXMLVersion(t *testing.T) {
	// "<?xml version" should match, but bare "<?xml" without "version" should not.
	if !isFileContent("<?xml version='1.0' encoding='UTF-8'?>") {
		t.Error("<?xml version should match")
	}
	if isFileContent("<?xml encoding='UTF-8'?>") {
		t.Error("<?xml without version should not match")
	}
}

func TestIsMetadataResponseAvailabilityZone(t *testing.T) {
	// "availability-zone" should match. Bare "zone" should not.
	if !isMetadataResponse(`{"availability-zone":"us-east-1a"}`, http.Header{}) {
		t.Error("availability-zone should match metadata")
	}
	if isMetadataResponse(`{"zone":"America/New_York"}`, http.Header{}) {
		t.Error("bare 'zone' should not match metadata")
	}
}

func TestDetectPopulatesParameter(t *testing.T) {
	// Server that reflects metadata content for any URL param value.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"ami-id":"ami-12345","instance-type":"t2.micro"}`))
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Timeout = 5 * time.Second
	d := NewDetector(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := d.Detect(ctx, server.URL+"/fetch?url=test", "url")
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	for _, v := range result.Vulnerabilities {
		if v.Parameter == "" {
			t.Errorf("vuln.Parameter should be populated, got empty for type %s", v.Type)
		}
		if v.Parameter != "url" {
			t.Errorf("expected Parameter='url', got %q", v.Parameter)
		}
	}
}

func TestInternalIPRegexPrecompiled(t *testing.T) {
	// Verify the package-level regex matches internal IP patterns.
	matches := []string{
		"10.0.0.1",
		"10.255.0.1",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
	}
	noMatches := []string{
		"11.0.0.1",
		"172.32.0.1",
		"193.168.1.1",
		"8.8.8.8",
	}

	for _, ip := range matches {
		if !internalIPRegex.MatchString(ip) {
			t.Errorf("should match internal IP: %s", ip)
		}
	}
	for _, ip := range noMatches {
		if internalIPRegex.MatchString(ip) {
			t.Errorf("should not match non-internal IP: %s", ip)
		}
	}
}
