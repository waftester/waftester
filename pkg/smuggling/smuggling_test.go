package smuggling

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector(DefaultConfig())
	if d == nil {
		t.Fatal("NewDetector returned nil")
	}
	if d.Timeout == 0 {
		t.Error("Timeout should be set")
	}
	if d.ReadTimeout == 0 {
		t.Error("ReadTimeout should be set")
	}
	if !d.SafeMode {
		t.Error("SafeMode should default to true")
	}
}

func TestNewHTTP2Detector(t *testing.T) {
	d := NewHTTP2Detector()
	if d == nil {
		t.Fatal("NewHTTP2Detector returned nil")
	}
	if d.Detector == nil {
		t.Error("Embedded Detector should be set")
	}
}

func TestVulnTypes(t *testing.T) {
	types := []VulnType{
		VulnCLTE,
		VulnTECL,
		VulnTETE,
		VulnH2CL,
		VulnH2TE,
		VulnWebSocket,
		VulnHTTP2,
	}

	for _, vt := range types {
		if vt == "" {
			t.Error("VulnType should not be empty")
		}
	}
}

func TestGeneratePayloads(t *testing.T) {
	d := NewDetector(DefaultConfig())
	payloads := d.GeneratePayloads("example.com")

	if len(payloads) == 0 {
		t.Fatal("No payloads generated")
	}

	for _, p := range payloads {
		if p.Name == "" {
			t.Error("Payload should have a name")
		}
		if p.Type == "" {
			t.Error("Payload should have a type")
		}
		if p.Raw == "" {
			t.Error("Payload should have raw content")
		}
		if !strings.Contains(p.Raw, "example.com") {
			t.Error("Payload should contain host")
		}
	}
}

func TestPayloadHostSubstitution(t *testing.T) {
	d := NewDetector(DefaultConfig())

	hosts := []string{
		"test.com",
		"sub.example.com",
		"192.168.1.1",
		"[::1]",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			payloads := d.GeneratePayloads(host)
			for _, p := range payloads {
				if !strings.Contains(p.Raw, "Host: "+host) && !strings.Contains(p.Raw, "Host: evil.com") {
					t.Errorf("Payload should contain Host header with %s", host)
				}
			}
		})
	}
}

func TestDetectWithTestServer(t *testing.T) {
	// Create a simple test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	d := NewDetector(DefaultConfig())
	d.Timeout = 2 * time.Second
	d.ReadTimeout = 1 * time.Second
	d.DelayMs = 100

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := d.Detect(ctx, server.URL)
	// Detect now returns accumulated errors when all techniques fail,
	// which is expected against a normal HTTP server.
	if err != nil {
		t.Logf("Detect error (expected against normal server): %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}
	if result.Target != server.URL {
		t.Errorf("Target mismatch: got %s", result.Target)
	}
}

func TestDetectInvalidURL(t *testing.T) {
	d := NewDetector(DefaultConfig())
	ctx := context.Background()

	// Test with an actually invalid URL that has an invalid scheme
	_, err := d.Detect(ctx, "://invalid")
	if err == nil {
		t.Error("Should error on invalid URL")
	}
}

func TestDetectContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Slow response
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDetector(DefaultConfig())
	d.Timeout = 1 * time.Second
	d.DelayMs = 10

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result, _ := d.Detect(ctx, server.URL)
	// Should complete without hanging
	if result == nil {
		t.Error("Result should not be nil even with cancellation")
	}
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"regular error", fmt.Errorf("some error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTimeout(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestContainsDesyncIndicator(t *testing.T) {
	tests := []struct {
		name     string
		resp     string
		expected bool
	}{
		{"empty", "", false},
		{"normal 200", "HTTP/1.1 200 OK\r\n\r\nBody", false},
		{"single 400 bad request", "HTTP/1.1 400 Bad Request\r\n\r\n", true},
		{"single 200 no anomaly", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello", false},
		{"multiple responses", "HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", true},
		{"400 with multiple", "HTTP/1.1 400 Bad Request\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsDesyncIndicator(tt.resp)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for response: %s", tt.expected, result, tt.resp)
			}
		})
	}
}

func TestSendRawRequestConnection(t *testing.T) {
	// Create a TCP server that echoes
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		_ = n
	}()

	addr := listener.Addr().(*net.TCPAddr)

	d := NewDetector(DefaultConfig())
	d.Timeout = 2 * time.Second
	d.ReadTimeout = 1 * time.Second

	ctx := context.Background()
	duration, resp, err := d.sendRawRequest(ctx, "127.0.0.1", fmt.Sprintf("%d", addr.Port), false, "GET / HTTP/1.1\r\nHost: test\r\n\r\n")

	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	// Duration can be 0 or very small if request is fast
	_ = duration
	if !strings.Contains(resp, "HTTP/1.1 200") {
		t.Errorf("Expected HTTP 200, got: %s", resp)
	}
}

func TestSendRawRequestTimeout(t *testing.T) {
	// Create a TCP server that doesn't respond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read but don't respond - let it timeout
		buf := make([]byte, 1024)
		conn.Read(buf)
		time.Sleep(5 * time.Second)
	}()

	addr := listener.Addr().(*net.TCPAddr)

	d := NewDetector(DefaultConfig())
	d.Timeout = 500 * time.Millisecond
	d.ReadTimeout = 200 * time.Millisecond

	ctx := context.Background()
	start := time.Now()
	_, _, err = d.sendRawRequest(ctx, "127.0.0.1", fmt.Sprintf("%d", addr.Port), false, "GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	elapsed := time.Since(start)

	// Should timeout within reasonable time
	if elapsed > 2*time.Second {
		t.Error("Request took too long, should have timed out")
	}
	// Error is acceptable (timeout)
	_ = err
}

func TestDetectWithHTTPS(t *testing.T) {
	// Just ensure HTTPS URL parsing works
	d := NewDetector(DefaultConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This will fail to connect but should parse correctly
	result, _ := d.Detect(ctx, "https://nonexistent.example.com:8443/path")

	if result == nil {
		t.Skip("Could not create result - may be expected for unreachable host")
	}
}

func TestHTTP2DetectorDetectH2Smuggling(t *testing.T) {
	d := NewHTTP2Detector()

	ctx := context.Background()
	result, err := d.DetectH2Smuggling(ctx, "https://example.com")

	if err != nil {
		t.Fatalf("DetectH2Smuggling failed: %v", err)
	}
	if result == nil {
		t.Fatal("Result should not be nil")
	}
	if len(result.TestedTechniques) != 0 {
		t.Error("Unimplemented H2 detection should not list tested techniques")
	}
	if len(result.Vulnerabilities) != 0 {
		t.Error("Unimplemented H2 detection should not report vulnerabilities")
	}
}

func TestVulnerabilityFields(t *testing.T) {
	v := Vulnerability{
		Type:        VulnCLTE,
		Technique:   "test technique",
		Description: "test description",
		Severity:    "high",
		Evidence:    []Evidence{{Request: "test", Response: "resp"}},
		Confidence:  0.9,
		Exploitable: true,
		FrontEnd:    "nginx",
		BackEnd:     "apache",
	}

	if v.Type != VulnCLTE {
		t.Error("Type mismatch")
	}
	if v.Confidence != 0.9 {
		t.Error("Confidence mismatch")
	}
	if !v.Exploitable {
		t.Error("Should be exploitable")
	}
	if len(v.Evidence) != 1 {
		t.Error("Should have 1 evidence")
	}
}

func TestEvidenceFields(t *testing.T) {
	e := Evidence{
		Request:  "GET / HTTP/1.1",
		Response: "HTTP/1.1 200 OK",
		Timing:   500 * time.Millisecond,
		Notes:    "Test note",
	}

	if e.Request == "" {
		t.Error("Request should be set")
	}
	if e.Timing != 500*time.Millisecond {
		t.Error("Timing mismatch")
	}
}

func TestResultFields(t *testing.T) {
	r := Result{
		Target:           "https://example.com",
		Vulnerabilities:  []Vulnerability{{Type: VulnCLTE}},
		TestedTechniques: []string{"CL.TE", "TE.CL"},
		SafeMode:         true,
		Duration:         5 * time.Second,
	}

	if r.Target == "" {
		t.Error("Target should be set")
	}
	if len(r.Vulnerabilities) != 1 {
		t.Error("Should have 1 vulnerability")
	}
	if len(r.TestedTechniques) != 2 {
		t.Error("Should have 2 techniques")
	}
}

func TestPayloadFields(t *testing.T) {
	p := Payload{
		Name:        "Test Payload",
		Type:        VulnCLTE,
		Raw:         "POST / HTTP/1.1\r\n",
		Description: "Test description",
	}

	if p.Name == "" {
		t.Error("Name should be set")
	}
	if p.Type != VulnCLTE {
		t.Error("Type mismatch")
	}
}

// --- New tests: DefaultConfig, negative cases ---

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout <= 0 {
		t.Error("DefaultConfig.Timeout should be positive")
	}
	if cfg.ReadTimeout <= 0 {
		t.Error("DefaultConfig.ReadTimeout should be positive")
	}
	if !cfg.SafeMode {
		t.Error("DefaultConfig.SafeMode should be true")
	}
	if cfg.DelayMs <= 0 {
		t.Error("DefaultConfig.DelayMs should be positive")
	}
	if cfg.MaxRetries <= 0 {
		t.Error("DefaultConfig.MaxRetries should be positive")
	}
	if len(cfg.CustomPorts) == 0 {
		t.Error("DefaultConfig.CustomPorts should be populated")
	}
}

func TestDetectEmptyTarget(t *testing.T) {
	d := NewDetector(DefaultConfig())
	d.Timeout = 500 * time.Millisecond
	d.ReadTimeout = 200 * time.Millisecond
	d.DelayMs = 0

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := d.Detect(ctx, "")
	// Empty hostname is now rejected early.
	if err == nil {
		t.Error("expected error for empty target")
	}
	if result != nil && len(result.Vulnerabilities) > 0 {
		t.Error("expected no vulnerabilities for empty target")
	}
}

func TestDetectCallbackFires(t *testing.T) {
	// TCP echo server that returns multiple HTTP responses to trigger CL.0
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				c.Read(buf)
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}(conn)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)

	var called int
	cfg := DefaultConfig()
	cfg.Timeout = 1 * time.Second
	cfg.ReadTimeout = 500 * time.Millisecond
	cfg.DelayMs = 10
	cfg.OnVulnerabilityFound = func() { called++ }
	d := NewDetector(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := d.Detect(ctx, fmt.Sprintf("http://127.0.0.1:%d/", addr.Port))
	if err != nil {
		t.Logf("Detect error: %v (may be expected)", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}

	// If any vulns were found, callback should have fired.
	if len(result.Vulnerabilities) > 0 && called == 0 {
		t.Error("OnVulnerabilityFound should have fired")
	}
}

func TestSendRawRequestConnectionRefused(t *testing.T) {
	d := NewDetector(DefaultConfig())
	d.Timeout = 500 * time.Millisecond

	ctx := context.Background()
	_, _, err := d.sendRawRequest(ctx, "127.0.0.1", "1", false, "GET / HTTP/1.1\r\n\r\n")
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

func TestGeneratePayloadsEmptyHost(t *testing.T) {
	d := NewDetector(DefaultConfig())
	payloads := d.GeneratePayloads("")

	// Should still produce payloads (with empty host).
	if len(payloads) == 0 {
		t.Error("should generate payloads even with empty host")
	}
}

// --- Round 3 regression tests ---

func TestVulnCL0Type(t *testing.T) {
	// VulnCL0 constant should exist and be distinct from VulnCLTE.
	if VulnCL0 == "" {
		t.Fatal("VulnCL0 should not be empty")
	}
	if VulnCL0 == VulnCLTE {
		t.Error("VulnCL0 should differ from VulnCLTE")
	}
	if string(VulnCL0) != "CL.0" {
		t.Errorf("expected VulnCL0='CL.0', got %q", VulnCL0)
	}
}

func TestContainsDesyncIndicatorCaseInsensitive(t *testing.T) {
	// Multiple HTTP/1. versions with different casing should still match.
	resp := "http/1.0 200 OK\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
	if !containsDesyncIndicator(resp) {
		t.Error("case-insensitive multi-response should trigger indicator")
	}
}

func TestContainsDesyncIndicatorMalformed(t *testing.T) {
	// "malformed" as an anomalous keyword should trigger.
	if !containsDesyncIndicator("Error: malformed request received") {
		t.Error("'malformed' should trigger desync indicator")
	}
	// "invalid request" should trigger.
	if !containsDesyncIndicator("400 Invalid Request") {
		t.Error("'invalid request' should trigger desync indicator")
	}
}

func TestContainsDesyncIndicatorNoFalsePositive(t *testing.T) {
	// A single clean 200 response with no anomaly keywords should not trigger.
	if containsDesyncIndicator("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>OK</html>") {
		t.Error("single clean response should not trigger indicator")
	}
}

func TestDetectEmptyHostnameError(t *testing.T) {
	d := NewDetector(DefaultConfig())
	d.Timeout = 200 * time.Millisecond
	d.ReadTimeout = 100 * time.Millisecond

	ctx := context.Background()
	_, err := d.Detect(ctx, "")
	if err == nil {
		t.Error("empty target should return error")
	}
}

func TestDetectAccumulatesErrors(t *testing.T) {
	// A target where all techniques fail should return a non-nil error.
	d := NewDetector(DefaultConfig())
	d.Timeout = 200 * time.Millisecond
	d.ReadTimeout = 100 * time.Millisecond
	d.DelayMs = 0

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use a port that refuses connections.
	result, err := d.Detect(ctx, "http://127.0.0.1:1/")
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if len(result.Vulnerabilities) == 0 && err == nil {
		t.Error("if no vulns found and all techniques failed, error should be returned")
	}
}

func TestH2SmugglingStubbedEmpty(t *testing.T) {
	d := NewHTTP2Detector()
	result, err := d.DetectH2Smuggling(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.TestedTechniques) != 0 {
		t.Error("stub should return empty TestedTechniques")
	}
	if len(result.Vulnerabilities) != 0 {
		t.Error("stub should return empty Vulnerabilities")
	}
}
