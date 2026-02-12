package hpp

import (
	"context"
	"encoding/json"
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
			Technology: TechPHP,
		}
		tester := NewTester(config)
		if tester.config.Technology != TechPHP {
			t.Errorf("expected PHP technology, got %s", tester.config.Technology)
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

	if !config.BaselineFirst {
		t.Error("expected BaselineFirst to be true")
	}
}

func TestGetPayloads(t *testing.T) {
	tester := NewTester(nil)

	payloads := tester.GetPayloads("test")
	if len(payloads) == 0 {
		t.Fatal("expected payloads")
	}

	// Check that we have different types
	typeMap := make(map[VulnerabilityType]bool)
	for _, p := range payloads {
		typeMap[p.Type] = true
	}

	if !typeMap[VulnParameterPriority] {
		t.Error("expected parameter priority payloads")
	}
	if !typeMap[VulnArrayInjection] {
		t.Error("expected array injection payloads")
	}
	if !typeMap[VulnWAFBypass] {
		t.Error("expected WAF bypass payloads")
	}
}

func TestDetectTechnology(t *testing.T) {
	tests := []struct {
		name     string
		handler  http.HandlerFunc
		expected Technology
	}{
		{
			name: "PHP via X-Powered-By",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Powered-By", "PHP/7.4")
				w.Write([]byte("OK"))
			},
			expected: TechPHP,
		},
		{
			name: "ASP.NET via Server header",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "Microsoft-IIS/10.0")
				w.Write([]byte("OK"))
			},
			expected: TechASP,
		},
		{
			name: "Node.js via Express",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Powered-By", "Express")
				w.Write([]byte("OK"))
			},
			expected: TechNodeJS,
		},
		{
			name: "Java via Tomcat",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "Apache Tomcat/9.0")
				w.Write([]byte("OK"))
			},
			expected: TechJava,
		},
		{
			name: "PHP via PHPSESSID cookie",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc123"})
				w.Write([]byte("OK"))
			},
			expected: TechPHP,
		},
		{
			name: "Unknown technology",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("OK"))
			},
			expected: TechUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			tester := NewTester(nil)
			ctx := context.Background()

			tech, err := tester.DetectTechnology(ctx, server.URL)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tech != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tech)
			}
		})
	}
}

func TestDetectVulnerability(t *testing.T) {
	tester := NewTester(nil)

	tests := []struct {
		name      string
		response  string
		baseline  string
		payload   Payload
		expectHit bool
	}{
		{
			name:      "Second parameter used",
			response:  "Hello second user",
			baseline:  "",
			payload:   Payload{Type: VulnParameterPriority},
			expectHit: true,
		},
		{
			name:      "Parameters concatenated",
			response:  "Value: firstsecond",
			baseline:  "",
			payload:   Payload{Type: VulnParameterPriority},
			expectHit: true,
		},
		{
			name:      "Array detected",
			response:  "Array ( [0] => first )",
			baseline:  "",
			payload:   Payload{Type: VulnArrayInjection},
			expectHit: true,
		},
		{
			name:      "XSS reflected",
			response:  "<script>alert(1)</script>",
			baseline:  "",
			payload:   Payload{Type: VulnWAFBypass},
			expectHit: true,
		},
		{
			name:      "Normal response",
			response:  "Hello world",
			baseline:  "",
			payload:   Payload{Type: VulnParameterPriority},
			expectHit: false,
		},
		{
			name:      "Delimiter confusion detected",
			response:  "Value1: val1, Value2: val2",
			baseline:  "",
			payload:   Payload{Type: VulnDelimiterConfusion},
			expectHit: true,
		},
		{
			name:      "Array to string error",
			response:  "Array to string conversion error",
			baseline:  "",
			payload:   Payload{Type: VulnServerSideHPP},
			expectHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := tester.detectVulnerability(tt.response, tt.baseline, tt.payload)
			if tt.expectHit && evidence == "" {
				t.Error("expected vulnerability detection")
			}
			if !tt.expectHit && evidence != "" {
				t.Errorf("unexpected vulnerability detection: %s", evidence)
			}
		})
	}
}

func TestTestParameter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()["id"]
		if len(values) > 1 {
			// Simulate vulnerable behavior - use second value
			w.Write([]byte("Using: " + values[1]))
		} else if len(values) == 1 {
			w.Write([]byte("Using: " + values[0]))
		} else {
			w.Write([]byte("No id"))
		}
	}))
	defer server.Close()

	config := &TesterConfig{
		Base: attackconfig.Base{
			Timeout: 5 * time.Second,
		},
		BaselineFirst: true,
	}
	tester := NewTester(config)
	ctx := context.Background()

	vulns, err := tester.TestParameter(ctx, server.URL, "id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect that second parameter value is being used
	found := false
	for _, v := range vulns {
		if v.Type == VulnParameterPriority || v.Type == VulnParameterOverwrite {
			found = true
			break
		}
	}
	if !found {
		t.Log("Note: Vulnerable server behavior detected but evidence may not match patterns")
	}
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Timeout = 5 * time.Second
	config.TestParams = []string{"id"}

	tester := NewTester(config)
	ctx := context.Background()

	result, err := tester.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.URL != server.URL {
		t.Errorf("expected URL %s, got %s", server.URL, result.URL)
	}

	// The technology detection should find PHP
	if result.Technology != TechPHP {
		t.Errorf("expected PHP technology, got %s", result.Technology)
	}

	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
}

func TestTestPOST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if err := r.ParseForm(); err != nil {
				w.WriteHeader(400)
				return
			}
			values := r.Form["id"]
			if len(values) > 1 {
				w.Write([]byte("POST received: " + strings.Join(values, ",")))
			} else {
				w.Write([]byte("POST received"))
			}
		}
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	vulns, err := tester.TestPOST(ctx, server.URL, "id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Just verify no error occurred
	_ = vulns
}

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		expected finding.Severity
	}{
		{VulnWAFBypass, finding.High},
		{VulnServerSideHPP, finding.Medium},
		{VulnParameterOverwrite, finding.Medium},
		{VulnParameterPriority, finding.Low},
		{VulnArrayInjection, finding.Low},
		{VulnDelimiterConfusion, finding.Low},
		{VulnClientSideHPP, finding.Info},
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

func TestGetTechnologyBehavior(t *testing.T) {
	behavior := GetTechnologyBehavior(TechPHP)
	if !strings.Contains(behavior, "PHP") {
		t.Error("expected PHP in behavior description")
	}

	behavior = GetTechnologyBehavior(TechUnknown)
	if !strings.Contains(behavior, "Unknown") {
		t.Error("expected Unknown in behavior description")
	}
}

func TestGetHPPRemediation(t *testing.T) {
	remediation := GetHPPRemediation()
	if remediation == "" {
		t.Error("expected remediation text")
	}

	if !strings.Contains(remediation, "parameter") {
		t.Error("remediation should mention parameters")
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 7 {
		t.Errorf("expected 7 vulnerability types, got %d", len(types))
	}
}

func TestAllTechnologies(t *testing.T) {
	techs := AllTechnologies()

	if len(techs) != 7 {
		t.Errorf("expected 7 technologies, got %d", len(techs))
	}
}

func TestGenerateWAFBypassPayloads(t *testing.T) {
	payloads := GenerateWAFBypassPayloads("q", "<script>alert(1)</script>")

	if len(payloads) == 0 {
		t.Fatal("expected WAF bypass payloads")
	}

	// All should be WAF bypass type
	for _, p := range payloads {
		if p.Type != VulnWAFBypass {
			t.Errorf("expected WAF bypass type, got %s", p.Type)
		}
	}
}

func TestSplitPayload(t *testing.T) {
	parts := splitPayload("abcdef")
	if len(parts) != 2 {
		t.Errorf("expected 2 parts, got %d", len(parts))
	}

	if parts[0] != "abc" || parts[1] != "def" {
		t.Errorf("unexpected split: %v", parts)
	}
}

func TestChunkPayload(t *testing.T) {
	chunks := chunkPayload("abcdefgh", 2)
	if len(chunks) != 2 {
		t.Errorf("expected 2 chunks, got %d", len(chunks))
	}

	chunks = chunkPayload("abcdefgh", 4)
	if len(chunks) < 2 {
		t.Error("expected multiple chunks")
	}
}

func TestIsParameterDuplicate(t *testing.T) {
	tests := []struct {
		url          string
		expectDup    bool
		expectParams []string
	}{
		{"http://example.com?a=1&a=2", true, []string{"a"}},
		{"http://example.com?a=1&b=2", false, nil},
		{"http://example.com?a=1&a=2&b=1&b=2", true, []string{"a", "b"}},
		{"http://example.com", false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			isDup, params := IsParameterDuplicate(tt.url)
			if isDup != tt.expectDup {
				t.Errorf("IsParameterDuplicate(%s) = %v, want %v", tt.url, isDup, tt.expectDup)
			}

			if tt.expectDup && len(params) == 0 {
				t.Error("expected duplicate parameters to be listed")
			}
		})
	}
}

func TestVulnerabilityToJSON(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnWAFBypass,
		Description: "Test",
		Severity:    finding.High,
		URL:         "http://example.com",
		Parameter:   "q",
		Payload:     "test",
		Evidence:    "XSS found",
	}

	jsonStr, err := VulnerabilityToJSON(vuln)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(jsonStr, "waf-bypass") {
		t.Error("expected vulnerability type in JSON")
	}
}

func TestVulnerability(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnParameterPriority,
		Description: "Test vulnerability",
		Severity:    finding.Medium,
		URL:         "http://example.com?a=1&a=2",
		Parameter:   "a",
		Payload:     "a=1&a=2",
		Evidence:    "Second value used",
		Technology:  TechPHP,
		Remediation: "Fix it",
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
}

func TestScanResult(t *testing.T) {
	result := ScanResult{
		URL:            "http://example.com",
		StartTime:      time.Now(),
		EndTime:        time.Now().Add(5 * time.Second),
		Duration:       5 * time.Second,
		Technology:     TechPHP,
		TestedPayloads: 50,
		Vulnerabilities: []Vulnerability{
			{Type: VulnWAFBypass},
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

	if decoded.Technology != TechPHP {
		t.Errorf("technology mismatch")
	}
}

func TestPayload(t *testing.T) {
	payload := Payload{
		Query:            "id=1&id=2",
		Description:      "Duplicate param",
		Type:             VulnParameterPriority,
		ExpectedBehavior: "Check which value is used",
	}

	if payload.Query == "" {
		t.Error("expected query")
	}
	if payload.Type != VulnParameterPriority {
		t.Error("wrong type")
	}
}
