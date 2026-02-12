package deserialize

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/finding"
)

func TestNewTester(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		tester := NewTester(nil)
		if tester == nil {
			t.Fatal("expected non-nil tester")
		}
		if tester.config.Timeout != 30*time.Second {
			t.Errorf("expected 30s timeout, got %v", tester.config.Timeout)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &TesterConfig{
			Base: attackconfig.Base{
				Timeout:     60 * time.Second,
				Concurrency: 10,
			},
		}
		tester := NewTester(config)
		if tester.config.Timeout != 60*time.Second {
			t.Errorf("expected 60s timeout, got %v", tester.config.Timeout)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if config.Concurrency != 5 {
		t.Errorf("expected 5 concurrency, got %d", config.Concurrency)
	}
	if len(config.Parameters) == 0 {
		t.Error("expected default parameters")
	}
}

func TestTestPayload(t *testing.T) {
	// Server that simulates deserialization error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return deserialization error for testing
		w.WriteHeader(500)
		w.Write([]byte("ClassNotFoundException: java.lang.Runtime"))
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	payload := Payload{
		Name:     "java-test",
		Data:     "JAVA_DESER_MARKER_CC",
		Encoded:  false, // Don't encode so it passes through directly
		VulnType: VulnJavaDeserial,
	}

	vuln, err := tester.TestPayload(ctx, server.URL, "data", payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vuln == nil {
		t.Error("expected vulnerability to be detected")
	}
}

func TestTestPOST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(500)
			w.Write([]byte("InvalidClassException in ObjectInputStream"))
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	payload := Payload{
		Name:        "java-post",
		Data:        "JAVA_DESER_MARKER",
		ContentType: "application/x-java-serialized-object",
		VulnType:    VulnJavaDeserial,
	}

	vuln, err := tester.TestPOST(ctx, server.URL, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vuln == nil {
		t.Error("expected vulnerability to be detected")
	}
}

func TestScan(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Base: attackconfig.Base{
			Timeout:     5 * time.Second,
			Concurrency: 2,
		},
		Parameters: []string{"data"},
	})

	ctx := context.Background()
	vulns, err := tester.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Scan should complete without error
	_ = vulns
	if atomic.LoadInt64(&requestCount) == 0 {
		t.Error("expected some requests to be made")
	}
}

func TestGetAllPayloads(t *testing.T) {
	payloads := GetAllPayloads()

	if len(payloads) < 10 {
		t.Errorf("expected at least 10 payloads, got %d", len(payloads))
	}
}

func TestGetJavaPayloads(t *testing.T) {
	payloads := GetJavaPayloads()

	if len(payloads) < 3 {
		t.Errorf("expected at least 3 Java payloads, got %d", len(payloads))
	}

	// Check for Commons Collections
	hasCC := false
	for _, p := range payloads {
		if strings.Contains(p.GadgetChain, "CommonsCollections") {
			hasCC = true
			break
		}
	}
	if !hasCC {
		t.Error("expected Commons Collections gadget chain")
	}
}

func TestGetPHPPayloads(t *testing.T) {
	payloads := GetPHPPayloads()

	if len(payloads) < 2 {
		t.Errorf("expected at least 2 PHP payloads, got %d", len(payloads))
	}
}

func TestGetPythonPayloads(t *testing.T) {
	payloads := GetPythonPayloads()

	if len(payloads) < 2 {
		t.Errorf("expected at least 2 Python payloads, got %d", len(payloads))
	}

	// Check for pickle
	hasPickle := false
	for _, p := range payloads {
		if strings.Contains(p.Description, "pickle") {
			hasPickle = true
			break
		}
	}
	if !hasPickle {
		t.Error("expected pickle payload")
	}
}

func TestGetRubyPayloads(t *testing.T) {
	payloads := GetRubyPayloads()

	if len(payloads) < 2 {
		t.Errorf("expected at least 2 Ruby payloads, got %d", len(payloads))
	}
}

func TestGetDotNetPayloads(t *testing.T) {
	payloads := GetDotNetPayloads()

	if len(payloads) < 3 {
		t.Errorf("expected at least 3 .NET payloads, got %d", len(payloads))
	}

	// Check for ViewState
	hasViewState := false
	for _, p := range payloads {
		if strings.Contains(p.Description, "ViewState") {
			hasViewState = true
			break
		}
	}
	if !hasViewState {
		t.Error("expected ViewState payload")
	}
}

func TestGetNodePayloads(t *testing.T) {
	payloads := GetNodePayloads()

	if len(payloads) < 2 {
		t.Errorf("expected at least 2 Node.js payloads, got %d", len(payloads))
	}
}

func TestGetYAMLPayloads(t *testing.T) {
	payloads := GetYAMLPayloads()

	if len(payloads) < 2 {
		t.Errorf("expected at least 2 YAML payloads, got %d", len(payloads))
	}
}

func TestIsVulnerable(t *testing.T) {
	tester := NewTester(nil)

	tests := []struct {
		name       string
		statusCode int
		body       string
		expected   bool
	}{
		{"Java exception", 500, "ClassNotFoundException in ObjectInputStream", true},
		{"PHP unserialize", 500, "Error in unserialize()", true},
		{"Python pickle", 500, "pickle.loads error", true},
		{"Ruby marshal", 500, "Marshal.load failed", true},
		{"ViewState error", 500, "Invalid ViewState", true},
		{"Normal response", 200, "Hello World", false},
		{"Generic 500", 500, "Internal Server Exception Error", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tester.isVulnerable(tt.statusCode, tt.body, VulnJavaDeserial)
			if result != tt.expected {
				t.Errorf("isVulnerable = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetRemediation(t *testing.T) {
	tests := []VulnerabilityType{
		VulnJavaDeserial,
		VulnPHPDeserial,
		VulnPythonDeserial,
		VulnRubyDeserial,
		VulnDotNetDeserial,
	}

	for _, vt := range tests {
		rem := getRemediation(vt)
		if rem == "" {
			t.Errorf("expected remediation for %s", vt)
		}
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) < 9 {
		t.Errorf("expected at least 9 vulnerability types, got %d", len(types))
	}
}

func TestVulnerabilityToJSON(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnJavaDeserial,
		Description: "Java deserialization",
		Severity:    finding.Critical,
		CVSS:        9.8,
	}

	jsonStr, err := VulnerabilityToJSON(vuln)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(jsonStr, "java-deserialization") {
		t.Error("expected type in JSON")
	}
}

func TestGenerateReport(t *testing.T) {
	vulns := []Vulnerability{
		{Type: VulnJavaDeserial, Severity: finding.Critical},
		{Type: VulnPHPDeserial, Severity: finding.Critical},
		{Type: VulnJavaDeserial, Severity: finding.Critical},
	}

	report := GenerateReport(vulns)

	if report["total_vulnerabilities"] != 3 {
		t.Errorf("expected 3 total, got %v", report["total_vulnerabilities"])
	}

	byType := report["by_type"].(map[string]int)
	if byType["java-deserialization"] != 2 {
		t.Errorf("expected 2 Java, got %d", byType["java-deserialization"])
	}
}

func TestDetectSerializationFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected VulnerabilityType
	}{
		{"Java serialized", []byte{0xAC, 0xED, 0x00, 0x05}, VulnJavaDeserial},
		{"PHP serialized", []byte("a:2:{s:4:\"name\";s:4:\"test\";}"), VulnPHPDeserial},
		{"PHP object", []byte("O:8:\"stdClass\":0:{}"), VulnPHPDeserial},
		{"Ruby Marshal", []byte{0x04, 0x08, 0x00}, VulnRubyDeserial},
		{"YAML document", []byte("---\nname: test"), VulnYAMLDeserial},
		{"YAML Python", []byte("!!python/object:__main__.MyClass {}"), VulnYAMLDeserial},
		{"Unknown format", []byte("random data"), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectSerializationFormat(tt.data)
			if result != tt.expected {
				t.Errorf("DetectSerializationFormat = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsBase64Encoded(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"SGVsbG8gV29ybGQ=", true},
		{"dGVzdA==", true},
		{"YWJjZGVm", true},
		{"not base64!", false},
		{"ab", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsBase64Encoded(tt.input)
			if result != tt.expected {
				t.Errorf("IsBase64Encoded(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDecodeBase64(t *testing.T) {
	encoded := "SGVsbG8gV29ybGQ="
	decoded, err := DecodeBase64(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != "Hello World" {
		t.Errorf("expected 'Hello World', got %q", string(decoded))
	}
}

func TestEncodeBase64(t *testing.T) {
	data := []byte("Hello World")
	encoded := EncodeBase64(data)
	if encoded != "SGVsbG8gV29ybGQ=" {
		t.Errorf("expected 'SGVsbG8gV29ybGQ=', got %q", encoded)
	}
}

func TestGetGadgetChains(t *testing.T) {
	t.Run("Java chains", func(t *testing.T) {
		chains := GetGadgetChains(VulnJavaDeserial)
		if len(chains) < 10 {
			t.Errorf("expected at least 10 Java chains, got %d", len(chains))
		}
	})

	t.Run(".NET chains", func(t *testing.T) {
		chains := GetGadgetChains(VulnDotNetDeserial)
		if len(chains) < 5 {
			t.Errorf("expected at least 5 .NET chains, got %d", len(chains))
		}
	})

	t.Run("PHP chains", func(t *testing.T) {
		chains := GetGadgetChains(VulnPHPDeserial)
		if len(chains) < 5 {
			t.Errorf("expected at least 5 PHP chains, got %d", len(chains))
		}
	})

	t.Run("Unknown type", func(t *testing.T) {
		chains := GetGadgetChains(VulnYAMLDeserial)
		if chains != nil {
			t.Error("expected nil for unknown type")
		}
	})
}

func TestPayloadStruct(t *testing.T) {
	payload := Payload{
		Name:        "test-payload",
		Data:        "test data",
		Encoded:     true,
		ContentType: "application/octet-stream",
		VulnType:    VulnJavaDeserial,
		Description: "Test payload",
		GadgetChain: "CommonsCollections1",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var decoded Payload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decoded.Name != payload.Name {
		t.Errorf("name mismatch: got %q, want %q", decoded.Name, payload.Name)
	}
}

func TestVulnerabilityStruct(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnPythonDeserial,
		Description: "Python pickle deserialization",
		Severity:    finding.Critical,
		URL:         "https://example.com/api",
		Parameter:   "data",
		Payload:     "pickle payload",
		Evidence:    "Exception in response",
		Remediation: "Use safe loader",
		CVSS:        9.8,
		GadgetChain: "",
	}

	if vuln.Type != VulnPythonDeserial {
		t.Error("type mismatch")
	}
	if vuln.Severity != finding.Critical {
		t.Error("severity mismatch")
	}
	if vuln.CVSS != 9.8 {
		t.Error("CVSS mismatch")
	}
}

func TestTesterConfig(t *testing.T) {
	config := &TesterConfig{
		Base: attackconfig.Base{
			Timeout:     60 * time.Second,
			UserAgent:   "Test/1.0",
			Concurrency: 10,
		},
		Parameters:     []string{"data", "input"},
		AuthHeader:     "Bearer token",
		Cookies:        map[string]string{"session": "abc123"},
		CallbackURL:    "https://callback.example.com",
		FollowRedirect: true,
	}

	if config.Timeout != 60*time.Second {
		t.Error("timeout mismatch")
	}
	if config.Concurrency != 10 {
		t.Error("concurrency mismatch")
	}
	if len(config.Parameters) != 2 {
		t.Error("parameters count mismatch")
	}
}

func TestApplyHeaders(t *testing.T) {
	config := &TesterConfig{
		Base: attackconfig.Base{
			UserAgent: "Test-Agent",
		},
		AuthHeader: "Bearer test123",
		Cookies:    map[string]string{"session": "abc"},
	}
	tester := NewTester(config)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	tester.applyHeaders(req)

	if req.Header.Get("User-Agent") != "Test-Agent" {
		t.Error("User-Agent not set")
	}
	if req.Header.Get("Authorization") != "Bearer test123" {
		t.Error("Authorization not set")
	}
}
