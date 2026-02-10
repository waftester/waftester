package prototype

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
}

func TestGetPayloads(t *testing.T) {
	tester := NewTester(nil)
	payloads := tester.GetPayloads()

	if len(payloads) == 0 {
		t.Fatal("expected payloads")
	}

	// Check that we have different types
	typeMap := make(map[VulnerabilityType]bool)
	hasJSON := false
	hasQuery := false

	for _, p := range payloads {
		typeMap[p.Type] = true
		if p.IsJSON {
			hasJSON = true
		} else {
			hasQuery = true
		}
	}

	if !typeMap[VulnQueryParam] {
		t.Error("expected query param payloads")
	}
	if !typeMap[VulnJSONBody] {
		t.Error("expected JSON body payloads")
	}
	if !hasJSON {
		t.Error("expected JSON payloads")
	}
	if !hasQuery {
		t.Error("expected query payloads")
	}
}

func TestDetectPollution(t *testing.T) {
	tester := NewTester(nil)

	tests := []struct {
		name      string
		body      string
		expectHit bool
	}{
		{
			name:      "Marker in response",
			body:      `{"result": "ppmarker"}`,
			expectHit: true,
		},
		{
			name:      "__proto__ in response",
			body:      `Error: Cannot set __proto__`,
			expectHit: true,
		},
		{
			name:      "Normal response",
			body:      `{"status": "ok"}`,
			expectHit: false,
		},
		{
			name:      "Pollution pattern in error",
			body:      `Error: Object.prototype has been modified`,
			expectHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := tester.detectPollution(tt.body, nil)
			if tt.expectHit && evidence == "" {
				t.Error("expected pollution detection")
			}
			if !tt.expectHit && evidence != "" {
				t.Errorf("unexpected detection: %s", evidence)
			}
		})
	}
}

func TestTestParameter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate vulnerable server that reflects pollution
		if strings.Contains(r.URL.RawQuery, "__proto__") {
			w.Write([]byte(`{"polluted": "ppmarker"}`))
			return
		}
		if r.Method == "POST" {
			w.Write([]byte(`{"status": "ok"}`))
			return
		}
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	vulns, err := tester.TestParameter(ctx, server.URL, "data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect pollution via query param
	found := false
	for _, v := range vulns {
		if v.Type == VulnQueryParam {
			found = true
			break
		}
	}
	if found {
		t.Log("Successfully detected query param pollution")
	}
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Timeout = 5 * time.Second
	config.TestParams = []string{"data"}

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

func TestTestJSONBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.Header.Get("Content-Type") == "application/json" {
			w.Write([]byte(`{"received": true}`))
			return
		}
		w.WriteHeader(400)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	payload := Payload{
		Value:  `{"__proto__":{"test":"ppmarker"}}`,
		Type:   VulnJSONBody,
		IsJSON: true,
	}

	vuln, err := tester.testJSONBody(ctx, server.URL, "data", payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No vulnerability expected on clean server
	_ = vuln
}

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		expected finding.Severity
	}{
		{VulnRCE, finding.Critical},
		{VulnServerSide, finding.High},
		{VulnClientSide, finding.Medium},
		{VulnJSONBody, finding.Medium},
		{VulnQueryParam, finding.Medium},
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
		{VulnRCE, 9.8},
		{VulnServerSide, 8.1},
		{VulnClientSide, 6.1},
		{VulnJSONBody, 7.5},
		{VulnQueryParam, 6.1},
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

func TestGetPrototypePollutionRemediation(t *testing.T) {
	remediation := GetPrototypePollutionRemediation()
	if remediation == "" {
		t.Error("expected remediation text")
	}

	if !strings.Contains(remediation, "prototype") {
		t.Error("remediation should mention prototype")
	}
	if !strings.Contains(remediation, "__proto__") {
		t.Error("remediation should mention __proto__")
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 7 {
		t.Errorf("expected 7 vulnerability types, got %d", len(types))
	}
}

func TestIsPrototypePollutionPayload(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{`{"__proto__":{"a":"b"}}`, true},
		{`constructor.prototype.test`, true},
		{`Object.prototype`, true},
		{`{"normal": "data"}`, false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsPrototypePollutionPayload(tt.input)
			if result != tt.expected {
				t.Errorf("IsPrototypePollutionPayload(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizePrototypePollution(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`{"__proto__":{"a":"b"}}`, `{"":{"a":"b"}}`},
		{`constructor.prototype.test`, `..test`},
		{`normal data`, `normal data`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizePrototypePollution(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizePrototypePollution(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGeneratePollutionPayloads(t *testing.T) {
	payloads := GeneratePollutionPayloads("isAdmin", "true")

	if len(payloads) == 0 {
		t.Fatal("expected payloads")
	}

	// Check that all payloads contain the property
	for _, p := range payloads {
		if !strings.Contains(p.Value, "isAdmin") {
			t.Errorf("payload should contain property name: %s", p.Value)
		}
	}
}

func TestKnownGadgets(t *testing.T) {
	gadgets := KnownGadgets()

	if len(gadgets) == 0 {
		t.Fatal("expected known gadgets")
	}

	// Check for some known gadgets
	hasShell := false
	hasNodeOptions := false

	for _, g := range gadgets {
		if g == "shell" {
			hasShell = true
		}
		if g == "NODE_OPTIONS" {
			hasNodeOptions = true
		}
	}

	if !hasShell {
		t.Error("expected 'shell' gadget")
	}
	if !hasNodeOptions {
		t.Error("expected 'NODE_OPTIONS' gadget")
	}
}

func TestVulnerabilityToJSON(t *testing.T) {
	vuln := Vulnerability{
		Vulnerability: finding.Vulnerability{
			Description: "Test",
			Severity:    finding.High,
			URL:         "http://example.com",
			Payload:     `{"__proto__":{}}`,
			Evidence:    "Pollution detected",
			CVSS:        7.5,
		},
		Type: VulnJSONBody,
	}

	jsonStr, err := VulnerabilityToJSON(vuln)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(jsonStr, "json-body-pollution") {
		t.Error("expected vulnerability type in JSON")
	}
}

func TestVulnerability(t *testing.T) {
	vuln := Vulnerability{
		Vulnerability: finding.Vulnerability{
			Description: "Test vulnerability",
			Severity:    finding.Critical,
			URL:         "http://example.com",
			Parameter:   "data",
			Payload:     `{"__proto__":{"shell":"node"}}`,
			Evidence:    "RCE detected",
			Remediation: "Fix it",
			CVSS:        9.8,
		},
		Type:   VulnRCE,
		Gadget: "shell",
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
	if decoded.Gadget != vuln.Gadget {
		t.Errorf("gadget mismatch")
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
			{Type: VulnJSONBody},
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
		Value:       `{"__proto__":{"test":"value"}}`,
		Type:        VulnJSONBody,
		Description: "Test pollution",
		IsJSON:      true,
	}

	if !payload.IsJSON {
		t.Error("expected IsJSON to be true")
	}
	if payload.Type != VulnJSONBody {
		t.Error("wrong type")
	}
}
