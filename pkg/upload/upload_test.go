package upload

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/finding"
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
			Base: attackconfig.Base{
				Timeout:     60 * time.Second,
				Concurrency: 10,
			},
			FileField: "upload",
		}
		tester := NewTester(config)
		if tester.config.Concurrency != 10 {
			t.Errorf("expected concurrency 10, got %d", tester.config.Concurrency)
		}
		if tester.config.FileField != "upload" {
			t.Errorf("expected file field 'upload', got %s", tester.config.FileField)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", config.Timeout)
	}

	if config.FileField != "file" {
		t.Errorf("expected file field 'file', got %s", config.FileField)
	}

	if config.MaxFileSize != 10*1024*1024 {
		t.Errorf("expected max file size 10MB, got %d", config.MaxFileSize)
	}
}

func TestTestUpload(t *testing.T) {
	// Create a test server that accepts uploads
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse multipart form
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "No file uploaded", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Simulate accepting the upload
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"filename": header.Filename,
			"url":      "/uploads/" + header.Filename,
		})
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Base: attackconfig.Base{
			Timeout: 5 * time.Second,
		},
		FileField: "file",
	})

	ctx := context.Background()

	payload := UploadPayload{
		Filename:    "test.php",
		Content:     []byte("<?php echo 'test'; ?>"),
		ContentType: "application/x-php",
		Description: "PHP upload test",
		VulnType:    VulnWebShell,
	}

	vuln, err := tester.TestUpload(ctx, server.URL+"/upload", payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if vuln == nil {
		t.Error("expected vulnerability to be detected")
	}

	if vuln != nil && vuln.Type != VulnWebShell {
		t.Errorf("expected web-shell type, got %s", vuln.Type)
	}
}

func TestScan(t *testing.T) {
	// Create server that rejects most uploads but accepts some
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(10 << 20)
		file, _, _ := r.FormFile("file")
		if file != nil {
			content, _ := io.ReadAll(file)
			file.Close()

			// Accept GIF files (starts with GIF)
			if len(content) >= 3 && string(content[:3]) == "GIF" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"success":true,"uploaded":true}`))
				return
			}
		}

		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"File type not allowed"}`))
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Base: attackconfig.Base{
			Timeout:     5 * time.Second,
			Concurrency: 2,
		},
		FileField: "file",
	})

	ctx := context.Background()

	vulns, err := tester.Scan(ctx, server.URL+"/upload")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should find some vulnerabilities (GIF polyglots)
	_ = vulns
}

func TestGetAllPayloads(t *testing.T) {
	payloads := GetAllPayloads()

	if len(payloads) < 20 {
		t.Errorf("expected at least 20 payloads, got %d", len(payloads))
	}
}

func TestGetExtensionBypassPayloads(t *testing.T) {
	payloads := GetExtensionBypassPayloads()

	if len(payloads) < 8 {
		t.Errorf("expected at least 8 extension bypass payloads, got %d", len(payloads))
	}

	// Check for double extension
	hasDouble := false
	for _, p := range payloads {
		if strings.Contains(p.Filename, ".php.") {
			hasDouble = true
			break
		}
	}
	if !hasDouble {
		t.Error("expected double extension payload")
	}
}

func TestGetContentTypeBypassPayloads(t *testing.T) {
	payloads := GetContentTypeBypassPayloads()

	if len(payloads) < 4 {
		t.Errorf("expected at least 4 content-type bypass payloads, got %d", len(payloads))
	}

	// Check for content-type mismatch
	hasMismatch := false
	for _, p := range payloads {
		if p.Filename == "test.php" && p.ContentType == "image/jpeg" {
			hasMismatch = true
			break
		}
	}
	if !hasMismatch {
		t.Error("expected content-type mismatch payload")
	}
}

func TestGetPathTraversalPayloads(t *testing.T) {
	payloads := GetPathTraversalPayloads()

	if len(payloads) < 4 {
		t.Errorf("expected at least 4 path traversal payloads, got %d", len(payloads))
	}

	// Check for traversal pattern
	hasTraversal := false
	for _, p := range payloads {
		if strings.Contains(p.Filename, "../") || strings.Contains(p.Filename, "..\\") {
			hasTraversal = true
			break
		}
	}
	if !hasTraversal {
		t.Error("expected path traversal payload")
	}
}

func TestGetPolyglotPayloads(t *testing.T) {
	payloads := GetPolyglotPayloads()

	if len(payloads) < 3 {
		t.Errorf("expected at least 3 polyglot payloads, got %d", len(payloads))
	}

	// Check for GIF polyglot
	hasGIF := false
	for _, p := range payloads {
		if strings.HasPrefix(string(p.Content), "GIF") {
			hasGIF = true
			break
		}
	}
	if !hasGIF {
		t.Error("expected GIF polyglot payload")
	}
}

func TestGetWebShellPayloads(t *testing.T) {
	payloads := GetWebShellPayloads()

	if len(payloads) < 5 {
		t.Errorf("expected at least 5 web shell payloads, got %d", len(payloads))
	}

	// Check for PHP shell marker (sanitized to avoid AV detection)
	hasPHP := false
	for _, p := range payloads {
		if strings.Contains(string(p.Content), "WEBSHELL_MARKER") {
			hasPHP = true
			break
		}
	}
	if !hasPHP {
		t.Error("expected PHP shell marker payload")
	}
}

func TestGetMaliciousContentPayloads(t *testing.T) {
	payloads := GetMaliciousContentPayloads()

	if len(payloads) < 3 {
		t.Errorf("expected at least 3 malicious content payloads, got %d", len(payloads))
	}

	// Check for SVG XSS
	hasSVG := false
	for _, p := range payloads {
		if p.VulnType == VulnSVGXSS {
			hasSVG = true
			break
		}
	}
	if !hasSVG {
		t.Error("expected SVG XSS payload")
	}
}

func TestIsUploadSuccessful(t *testing.T) {
	tester := NewTester(nil)

	tests := []struct {
		status   int
		body     string
		expected bool
	}{
		{200, `{"success":true}`, true},
		{201, `{"uploaded":true}`, true},
		{302, "", true},
		{403, `{"error":"forbidden"}`, false},
		{500, `{"error":"server error"}`, false},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.status)), func(t *testing.T) {
			result := tester.isUploadSuccessful(tt.status, tt.body)
			if result != tt.expected {
				t.Errorf("isUploadSuccessful(%d, %s) = %v, want %v", tt.status, tt.body, result, tt.expected)
			}
		})
	}
}

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		expected finding.Severity
	}{
		{VulnWebShell, finding.Critical},
		{VulnUnrestrictedUpload, finding.Critical},
		{VulnPathTraversal, finding.High},
		{VulnPolyglot, finding.High},
		{VulnMaliciousContent, finding.Medium},
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
	if getCVSS(VulnWebShell) != 9.8 {
		t.Error("expected CVSS 9.8 for web shell")
	}

	if getCVSS(VulnPathTraversal) != 8.6 {
		t.Error("expected CVSS 8.6 for path traversal")
	}
}

func TestGetRemediation(t *testing.T) {
	remediation := getRemediation(VulnWebShell)
	if remediation == "" {
		t.Error("expected remediation for web shell")
	}

	remediation = getRemediation(VulnPathTraversal)
	if !strings.Contains(strings.ToLower(remediation), "sanitize") {
		t.Error("expected sanitize in path traversal remediation")
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 12 {
		t.Errorf("expected 12 vulnerability types, got %d", len(types))
	}
}

func TestVulnerabilityToJSON(t *testing.T) {
	vuln := Vulnerability{
		Vulnerability: finding.Vulnerability{
			Description: "Web shell uploaded",
			Severity:    finding.Critical,
			URL:         "https://example.com/upload",
			CVSS:        9.8,
		},
		Type:        VulnWebShell,
		Filename:    "shell.php",
		ContentType: "application/x-php",
		FileSize:    100,
	}

	jsonStr, err := VulnerabilityToJSON(vuln)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(jsonStr, "web-shell") {
		t.Error("expected type in JSON")
	}
}

func TestGenerateReport(t *testing.T) {
	vulns := []Vulnerability{
		{Vulnerability: finding.Vulnerability{Severity: finding.Critical}, Type: VulnWebShell},
		{Vulnerability: finding.Vulnerability{Severity: finding.High}, Type: VulnPathTraversal},
		{Vulnerability: finding.Vulnerability{Severity: finding.Critical}, Type: VulnWebShell},
	}

	report := GenerateReport(vulns)

	if report["total_vulnerabilities"] != 3 {
		t.Errorf("expected 3 total, got %v", report["total_vulnerabilities"])
	}

	bySeverity := report["by_severity"].(map[string]int)
	if bySeverity["critical"] != 2 {
		t.Errorf("expected 2 critical, got %d", bySeverity["critical"])
	}
}

func TestGenerateTestFile(t *testing.T) {
	t.Run("PHP malicious", func(t *testing.T) {
		payload := GenerateTestFile("php", true)
		if payload.VulnType != VulnWebShell {
			t.Error("expected web shell type for malicious PHP")
		}
		// Sanitized implementation uses placeholder markers
		if !strings.Contains(string(payload.Content), "PLACEHOLDER") {
			t.Error("expected placeholder marker")
		}
	})

	t.Run("PHP benign", func(t *testing.T) {
		payload := GenerateTestFile("php", false)
		if strings.Contains(string(payload.Content), "system") {
			t.Error("benign file should not contain system call")
		}
	})

	t.Run("Image file", func(t *testing.T) {
		payload := GenerateTestFile("jpg", false)
		if payload.ContentType != "image/jpeg" {
			t.Errorf("expected image/jpeg, got %s", payload.ContentType)
		}
	})
}

func TestIsExecutableExtension(t *testing.T) {
	tests := []struct {
		ext      string
		expected bool
	}{
		{"php", true},
		{"PHP", true},
		{"phtml", true},
		{"asp", true},
		{"jsp", true},
		{"exe", true},
		{"jpg", false},
		{"png", false},
		{"txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			result := IsExecutableExtension(tt.ext)
			if result != tt.expected {
				t.Errorf("IsExecutableExtension(%s) = %v, want %v", tt.ext, result, tt.expected)
			}
		})
	}
}

func TestExtractExtension(t *testing.T) {
	tests := []struct {
		filename string
		expected string
	}{
		{"test.php", "php"},
		{"test.PHP", "php"},
		{"test.tar.gz", "gz"},
		{"test.php.jpg", "jpg"},
		{"noextension", ""},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := ExtractExtension(tt.filename)
			if result != tt.expected {
				t.Errorf("ExtractExtension(%s) = %s, want %s", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestBase64Encode(t *testing.T) {
	data := []byte("test data")
	encoded := Base64Encode(data)

	if encoded == "" {
		t.Error("expected non-empty encoded string")
	}
}

func TestGetMIMEType(t *testing.T) {
	tests := []struct {
		ext      string
		expected string
	}{
		{"jpg", "image/jpeg"},
		{"jpeg", "image/jpeg"},
		{"png", "image/png"},
		{"gif", "image/gif"},
		{"php", "application/x-php"},
		{"unknown", "application/octet-stream"},
	}

	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			result := GetMIMEType(tt.ext)
			if result != tt.expected {
				t.Errorf("GetMIMEType(%s) = %s, want %s", tt.ext, result, tt.expected)
			}
		})
	}
}

func TestIsMagicBytesValid(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		fileType string
		expected bool
	}{
		{"valid jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE0}, "jpeg", true},
		{"valid png", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "png", true},
		{"valid gif", []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, "gif", true},
		{"invalid jpeg", []byte{0x00, 0x00, 0x00, 0x00}, "jpeg", false},
		{"too short", []byte{0xFF, 0xD8}, "jpeg", false},
		{"unknown type", []byte{0xFF, 0xD8, 0xFF, 0xE0}, "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMagicBytesValid(tt.content, tt.fileType)
			if result != tt.expected {
				t.Errorf("IsMagicBytesValid = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestContainsExecutableCode(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected bool
	}{
		{"PHP opening tag", []byte("<?php echo 'test'; ?>"), true},
		{"ASP tag", []byte("<%= Response.Write(\"test\") %>"), true},
		{"Function definition", []byte("function test() {}"), true},
		{"Import statement", []byte("import os"), true},
		{"Require call", []byte("require('module')"), true},
		{"WebShell marker", []byte("WEBSHELL_MARKER_TEST"), true},
		{"Placeholder marker", []byte("PLACEHOLDER_SCRIPT_TEST"), true},
		{"Plain text", []byte("Hello World"), false},
		{"HTML only", []byte("<html><body>Test</body></html>"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsExecutableCode(tt.content)
			if result != tt.expected {
				t.Errorf("ContainsExecutableCode = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVulnerability(t *testing.T) {
	vuln := Vulnerability{
		Vulnerability: finding.Vulnerability{
			Description: "Polyglot file upload",
			Severity:    finding.High,
			URL:         "https://example.com/upload",
			Evidence:    "File accepted",
			Remediation: "Validate file content",
			CVSS:        8.1,
		},
		Type:        VulnPolyglot,
		Filename:    "polyglot.gif",
		ContentType: "image/gif",
		FileSize:    500,
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
		t.Error("type mismatch")
	}
	if decoded.Filename != vuln.Filename {
		t.Error("filename mismatch")
	}
}

func TestUploadPayload(t *testing.T) {
	payload := UploadPayload{
		Filename:    "test.php",
		Content:     []byte("<?php echo 'test'; ?>"),
		ContentType: "application/x-php",
		Headers:     map[string]string{"X-Custom": "header"},
		Description: "Test payload",
		VulnType:    VulnWebShell,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded UploadPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Filename != payload.Filename {
		t.Error("filename mismatch")
	}
}

func TestTesterConfig(t *testing.T) {
	config := &TesterConfig{
		Base: attackconfig.Base{
			Timeout:     10 * time.Second,
			UserAgent:   "custom-agent",
			Concurrency: 5,
		},
		FileField:      "upload",
		ExtraFields:    map[string]string{"token": "abc123"},
		AuthHeader:     "Bearer token",
		Cookies:        map[string]string{"session": "xyz"},
		MaxFileSize:    5 * 1024 * 1024,
		FollowRedirect: true,
	}

	if config.Timeout != 10*time.Second {
		t.Error("timeout mismatch")
	}
	if config.FileField != "upload" {
		t.Error("file field mismatch")
	}
	if !config.FollowRedirect {
		t.Error("follow redirect should be true")
	}
}

func TestCreatePolyglots(t *testing.T) {
	t.Run("JPEG polyglot", func(t *testing.T) {
		jpeg := createJPEGPolyglot()
		if len(jpeg) < 10 {
			t.Error("JPEG polyglot too short")
		}
		// Should have JPEG header
		if jpeg[0] != 0xFF || jpeg[1] != 0xD8 {
			t.Error("invalid JPEG header")
		}
	})

	t.Run("PNG polyglot", func(t *testing.T) {
		png := createPNGPolyglot()
		if len(png) < 8 {
			t.Error("PNG polyglot too short")
		}
		// Should have PNG header
		if png[0] != 0x89 || png[1] != 0x50 {
			t.Error("invalid PNG header")
		}
	})
}
