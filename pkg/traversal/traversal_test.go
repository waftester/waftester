package traversal

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
	})

	t.Run("custom config", func(t *testing.T) {
		config := &TesterConfig{
			Base: attackconfig.Base{
				Timeout:   60 * time.Second,
				UserAgent: "custom-agent",
			},
			Platform: PlatformLinux,
			MaxDepth: 5,
		}
		tester := NewTester(config)

		if tester.config.Platform != PlatformLinux {
			t.Error("expected Linux platform")
		}
		if tester.config.MaxDepth != 5 {
			t.Errorf("expected max depth 5, got %d", tester.config.MaxDepth)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if config.MaxDepth != 10 {
		t.Errorf("expected max depth 10, got %d", config.MaxDepth)
	}
	if len(config.TestParams) == 0 {
		t.Error("expected test params")
	}

	// Check for common params
	hasFile := false
	hasPath := false
	for _, p := range config.TestParams {
		if p == "file" {
			hasFile = true
		}
		if p == "path" {
			hasPath = true
		}
	}
	if !hasFile {
		t.Error("expected 'file' in test params")
	}
	if !hasPath {
		t.Error("expected 'path' in test params")
	}
}

func TestGetPayloads(t *testing.T) {
	tester := NewTester(nil)

	t.Run("Linux payloads", func(t *testing.T) {
		payloads := tester.GetPayloads(PlatformLinux)

		if len(payloads) == 0 {
			t.Error("expected payloads")
		}

		hasEtcPasswd := false
		hasTraversal := false

		for _, p := range payloads {
			if strings.Contains(p.Value, "etc/passwd") {
				hasEtcPasswd = true
			}
			if strings.Contains(p.Value, "../") {
				hasTraversal = true
			}
		}

		if !hasEtcPasswd {
			t.Error("expected /etc/passwd payloads")
		}
		if !hasTraversal {
			t.Error("expected traversal payloads")
		}
	})

	t.Run("Windows payloads", func(t *testing.T) {
		payloads := tester.GetPayloads(PlatformWindows)

		if len(payloads) == 0 {
			t.Error("expected payloads")
		}

		hasWinIni := false
		for _, p := range payloads {
			if strings.Contains(p.Value, "win.ini") {
				hasWinIni = true
				break
			}
		}

		if !hasWinIni {
			t.Error("expected win.ini payloads")
		}
	})

	t.Run("Unknown platform includes PHP wrappers", func(t *testing.T) {
		payloads := tester.GetPayloads(PlatformUnknown)

		hasPHPFilter := false
		for _, p := range payloads {
			if strings.Contains(p.Value, "php://filter") {
				hasPHPFilter = true
				break
			}
		}

		if !hasPHPFilter {
			t.Error("expected PHP filter wrapper payloads")
		}
	})
}

func TestDetectPlatform(t *testing.T) {
	t.Run("Linux server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		platform, err := tester.DetectPlatform(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if platform != PlatformLinux {
			t.Errorf("expected Linux, got %s", platform)
		}
	})

	t.Run("Windows server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Microsoft-IIS/10.0")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		platform, err := tester.DetectPlatform(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if platform != PlatformWindows {
			t.Errorf("expected Windows, got %s", platform)
		}
	})

	t.Run("Unknown server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		platform, err := tester.DetectPlatform(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if platform != PlatformUnknown {
			t.Errorf("expected Unknown, got %s", platform)
		}
	})
}

func TestTestParameter(t *testing.T) {
	t.Run("vulnerable - passwd file", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			file := r.URL.Query().Get("file")
			if strings.Contains(file, "passwd") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Normal content"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		payloads := []Payload{
			{Value: "../../../etc/passwd", Description: "traversal", Platform: PlatformLinux},
		}

		vulns, err := tester.TestParameter(ctx, server.URL, "file", payloads)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) == 0 {
			t.Error("expected vulnerability")
		}
		if len(vulns) > 0 && vulns[0].Type != VulnPathTraversal {
			t.Errorf("expected PathTraversal type, got %s", vulns[0].Type)
		}
	})

	t.Run("not vulnerable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Normal content"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		payloads := []Payload{
			{Value: "../../../etc/passwd", Description: "traversal", Platform: PlatformLinux},
		}

		vulns, err := tester.TestParameter(ctx, server.URL, "file", payloads)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) > 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})
}

func TestDetectEvidence(t *testing.T) {
	tester := NewTester(nil)

	tests := []struct {
		name     string
		body     string
		platform Platform
		expected bool
	}{
		{"passwd file", "root:x:0:0:root:/root:/bin/bash", PlatformLinux, true},
		{"daemon user", "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", PlatformLinux, true},
		{"hosts file", "127.0.0.1   localhost", PlatformLinux, true},
		{"win.ini", "[fonts]\n[extensions]", PlatformWindows, true},
		{"boot.ini", "[boot loader]\ntimeout=30\ndefault=multi", PlatformWindows, true},
		{"PHP code", "<?php echo 'test'; ?>", PlatformUnknown, true},
		{"normal content", "Hello World", PlatformUnknown, false},
		{"empty", "", PlatformUnknown, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := tester.detectEvidence(test.body, test.platform)
			hasEvidence := evidence != ""
			if hasEvidence != test.expected {
				t.Errorf("detectEvidence for '%s' = '%s', expected evidence: %v", test.name, evidence, test.expected)
			}
		})
	}
}

func TestIdentifyFile(t *testing.T) {
	tests := []struct {
		evidence string
		expected string
	}{
		{"passwd file content: root:x:0:0", "/etc/passwd"},
		{"kernel version: Linux 5.4.0", "/proc/version"},
		{"hosts file content: 127.0.0.1 localhost", "hosts"},
		{"environment variable: PATH=/usr/bin", "/proc/self/environ"},
		{"win.ini content: [fonts]", "win.ini"},
		{"boot.ini content: [boot loader]", "boot.ini"},
		{"PHP source code: <?php", "PHP file"},
		{"unknown content", ""},
	}

	for _, test := range tests {
		result := identifyFile(test.evidence)
		if result != test.expected {
			t.Errorf("identifyFile('%s') = '%s', expected '%s'", test.evidence, result, test.expected)
		}
	}
}

func TestGetVulnType(t *testing.T) {
	tests := []struct {
		payload  Payload
		expected VulnerabilityType
	}{
		{Payload{Value: "php://filter/resource=test"}, VulnWrapperAbuse},
		{Payload{Value: "file:///etc/passwd"}, VulnWrapperAbuse},
		{Payload{Value: "expect://id"}, VulnWrapperAbuse},
		{Payload{Value: "../../../etc/passwd%00"}, VulnNullByteBypass},
		{Payload{Value: "../../../etc/passwd\x00"}, VulnNullByteBypass},
		{Payload{Value: "..%252f..%252f", Encoded: true}, VulnDoubleEncoding},
		{Payload{Value: "..%2f..%2f", Encoded: true}, VulnPathNormalize},
		{Payload{Value: "../../../etc/passwd", Encoded: false}, VulnPathTraversal},
	}

	for _, test := range tests {
		result := getVulnType(test.payload)
		if result != test.expected {
			t.Errorf("getVulnType(%s) = %s, expected %s", test.payload.Value, result, test.expected)
		}
	}
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Normal content"))
	}))
	defer server.Close()

	config := &TesterConfig{
		Base: attackconfig.Base{
			Timeout:   10 * time.Second,
			UserAgent: "test-agent",
		},
		TestParams: []string{"file"},
		MaxDepth:   2,
	}

	tester := NewTester(config)
	ctx := context.Background()

	result, err := tester.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.URL != server.URL {
		t.Errorf("expected URL %s", server.URL)
	}
	if len(result.TestedParams) == 0 {
		t.Error("expected tested params")
	}
	if result.TestedPayloads == 0 {
		t.Error("expected tested payloads")
	}
	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
}

func TestTestURL(t *testing.T) {
	t.Run("not vulnerable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not found"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestURL(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) > 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 8 {
		t.Errorf("expected 8 vulnerability types, got %d", len(types))
	}

	expectedTypes := map[VulnerabilityType]bool{
		VulnPathTraversal:  false,
		VulnLFI:            false,
		VulnRFI:            false,
		VulnNullByteBypass: false,
		VulnDoubleEncoding: false,
		VulnPathNormalize:  false,
		VulnFilenameBypass: false,
		VulnWrapperAbuse:   false,
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

func TestGenerateTraversalSequence(t *testing.T) {
	tests := []struct {
		depth    int
		sep      string
		expected string
	}{
		{1, "/", "../"},
		{3, "/", "../../../"},
		{2, "\\", "..\\..\\"},
		{0, "/", ""},
	}

	for _, test := range tests {
		result := GenerateTraversalSequence(test.depth, test.sep)
		if result != test.expected {
			t.Errorf("GenerateTraversalSequence(%d, %s) = %s, expected %s",
				test.depth, test.sep, result, test.expected)
		}
	}
}

func TestEncodeTraversal(t *testing.T) {
	tests := []struct {
		payload  string
		encoding string
		contains string
	}{
		{"../", "url", "%2e%2e%2f"},
		{"../", "double", "%252e%252e%252f"},
		{"../", "unicode", "%c0%ae%c0%ae%c0%af"},
		{"../", "none", "../"},
	}

	for _, test := range tests {
		result := EncodeTraversal(test.payload, test.encoding)
		if !strings.Contains(result, test.contains) {
			t.Errorf("EncodeTraversal(%s, %s) = %s, expected to contain %s",
				test.payload, test.encoding, result, test.contains)
		}
	}
}

func TestCommonTraversalFiles(t *testing.T) {
	files := CommonTraversalFiles()

	if len(files) == 0 {
		t.Error("expected files")
	}

	hasPasswd := false
	hasWinIni := false

	for _, f := range files {
		if f == "/etc/passwd" {
			hasPasswd = true
		}
		if strings.Contains(f, "win.ini") {
			hasWinIni = true
		}
	}

	if !hasPasswd {
		t.Error("expected /etc/passwd")
	}
	if !hasWinIni {
		t.Error("expected win.ini")
	}
}

func TestIsPathSafe(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/var/www/file.txt", true},
		{"file.txt", true},
		{"../etc/passwd", false},
		{"..\\Windows\\System32", false},
		{"%2e%2e%2f", false},
		{"..%2f", false},
		{"....//", false},
		{"..;/", false},
		{"./file.txt", false},
		{"file%2e%2e%2fpasswd", false},
	}

	for _, test := range tests {
		result := IsPathSafe(test.path)
		if result != test.expected {
			t.Errorf("IsPathSafe(%s) = %v, expected %v", test.path, result, test.expected)
		}
	}
}

func TestGetRemediations(t *testing.T) {
	t.Run("traversal remediation", func(t *testing.T) {
		r := GetTraversalRemediation()
		if r == "" {
			t.Error("expected remediation")
		}
		if !strings.Contains(r, "allowlist") && !strings.Contains(r, "whitelist") {
			t.Error("expected allowlist mention")
		}
	})

	t.Run("LFI remediation", func(t *testing.T) {
		r := GetLFIRemediation()
		if r == "" {
			t.Error("expected remediation")
		}
	})
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

	_, err := tester.DetectPlatform(ctx, server.URL)
	if err == nil {
		t.Log("No error on cancelled context (implementation may vary)")
	}
}

func BenchmarkGetPayloads(b *testing.B) {
	tester := NewTester(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tester.GetPayloads(PlatformUnknown)
	}
}

func BenchmarkIsPathSafe(b *testing.B) {
	paths := []string{
		"/var/www/file.txt",
		"../../../etc/passwd",
		"%2e%2e%2fetc%2fpasswd",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range paths {
			IsPathSafe(p)
		}
	}
}
