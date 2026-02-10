package apifuzz

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
		if tester.config.Concurrency != 10 {
			t.Errorf("expected concurrency 10, got %d", tester.config.Concurrency)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &TesterConfig{
			Base:          attackconfig.Base{Timeout: 60 * time.Second, Concurrency: 20},
			MaxIterations: 500,
		}
		tester := NewTester(config)
		if tester.config.Concurrency != 20 {
			t.Errorf("expected concurrency 20, got %d", tester.config.Concurrency)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", config.Timeout)
	}

	if config.MaxIterations != 100 {
		t.Errorf("expected MaxIterations 100, got %d", config.MaxIterations)
	}

	if !config.EnableSmart {
		t.Error("expected EnableSmart to be true")
	}

	if len(config.Dictionary) == 0 {
		t.Error("expected dictionary to have entries")
	}
}

func TestDefaultDictionary(t *testing.T) {
	dict := DefaultDictionary()

	if len(dict) == 0 {
		t.Fatal("expected dictionary entries")
	}

	// Check for some expected entries
	hasNull := false
	hasEmpty := false
	for _, entry := range dict {
		if entry == "null" {
			hasNull = true
		}
		if entry == "" {
			hasEmpty = true
		}
	}

	if !hasNull {
		t.Error("expected 'null' in dictionary")
	}
	if !hasEmpty {
		t.Error("expected empty string in dictionary")
	}
}

func TestTypeConfusionPayloads(t *testing.T) {
	tester := NewTester(nil)

	tests := []struct {
		paramType ParameterType
		minCount  int
	}{
		{ParamString, 10},
		{ParamInteger, 10},
		{ParamBoolean, 10},
		{ParamArray, 10},
		{ParamObject, 10},
	}

	for _, tt := range tests {
		t.Run(string(tt.paramType), func(t *testing.T) {
			payloads := tester.typeConfusionPayloads(tt.paramType)
			if len(payloads) < tt.minCount {
				t.Errorf("expected at least %d payloads, got %d", tt.minCount, len(payloads))
			}
		})
	}
}

func TestBoundaryPayloads(t *testing.T) {
	tester := NewTester(nil)

	t.Run("with max length", func(t *testing.T) {
		maxLen := 10
		param := Parameter{
			Name:      "test",
			Type:      ParamString,
			MaxLength: &maxLen,
		}

		payloads := tester.boundaryPayloads(param)

		// Should include boundary length strings
		hasMax := false
		hasOverMax := false
		for _, p := range payloads {
			if len(p) == maxLen {
				hasMax = true
			}
			if len(p) == maxLen+1 {
				hasOverMax = true
			}
		}

		if !hasMax {
			t.Error("expected max length payload")
		}
		if !hasOverMax {
			t.Error("expected over max length payload")
		}
	})

	t.Run("with min/max values", func(t *testing.T) {
		min := 0.0
		max := 100.0
		param := Parameter{
			Name:    "test",
			Type:    ParamNumber,
			Minimum: &min,
			Maximum: &max,
		}

		payloads := tester.boundaryPayloads(param)

		if len(payloads) < 5 {
			t.Errorf("expected at least 5 payloads, got %d", len(payloads))
		}
	})
}

func TestInjectionPayloads(t *testing.T) {
	tester := NewTester(nil)

	payloads := tester.injectionPayloads()

	if len(payloads) < 10 {
		t.Errorf("expected at least 10 injection payloads, got %d", len(payloads))
	}

	// Check for SQL injection payloads
	hasSQLi := false
	for _, p := range payloads {
		if strings.Contains(p, "OR") || strings.Contains(p, "UNION") {
			hasSQLi = true
			break
		}
	}
	if !hasSQLi {
		t.Error("expected SQL injection payloads")
	}
}

func TestFormatPayloads(t *testing.T) {
	tester := NewTester(nil)

	tests := []struct {
		format   string
		minCount int
	}{
		{"email", 3},
		{"uuid", 3},
		{"url", 3},
		{"date", 3},
		{"ipv4", 3},
		{"unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			payloads := tester.formatPayloads(tt.format)
			if len(payloads) < tt.minCount {
				t.Errorf("expected at least %d payloads, got %d", tt.minCount, len(payloads))
			}
		})
	}
}

func TestRandomMutation(t *testing.T) {
	tester := NewTester(nil)

	// Generate multiple mutations and ensure they're different
	mutations := make(map[string]bool)
	for i := 0; i < 10; i++ {
		m := tester.randomMutation()
		mutations[m] = true
	}

	// Should have at least some variety
	if len(mutations) < 3 {
		t.Error("expected more variety in random mutations")
	}
}

func TestFuzzEndpoint(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")

		// Simulate error on certain inputs
		if strings.Contains(param, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"SQL syntax error near ' at line 1"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"ok"}`))
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Base:          attackconfig.Base{Timeout: 5 * time.Second},
		MaxIterations: 10,
		Dictionary:    []string{"test", "'", "1=1"},
	})

	endpoint := Endpoint{
		Path:   "/api/users",
		Method: "GET",
		Parameters: []Parameter{
			{Name: "id", In: "query", Type: ParamString},
		},
	}

	ctx := context.Background()
	vulns, err := tester.FuzzEndpoint(ctx, server.URL, endpoint)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect the SQL error
	if len(vulns) == 0 {
		t.Error("expected to detect vulnerabilities")
	}
}

func TestFuzzAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Base:          attackconfig.Base{Timeout: 5 * time.Second, Concurrency: 2},
		MaxIterations: 5,
		Dictionary:    []string{"test"},
	})

	endpoints := []Endpoint{
		{Path: "/api/v1/users", Method: "GET"},
		{Path: "/api/v1/posts", Method: "GET"},
	}

	ctx := context.Background()
	_, err := tester.FuzzAPI(ctx, server.URL, endpoints)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendFuzzRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"received":"` + r.URL.Query().Get("test") + `"}`))
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Base: attackconfig.Base{Timeout: 5 * time.Second},
	})

	endpoint := Endpoint{
		Path:   "/test",
		Method: "GET",
	}

	param := Parameter{
		Name: "test",
		In:   "query",
		Type: ParamString,
	}

	ctx := context.Background()
	resp, err := tester.sendFuzzRequest(ctx, server.URL, endpoint, param, "payload123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if !strings.Contains(resp.Body, "payload123") {
		t.Error("expected payload in response")
	}
}

func TestSendBodyFuzzRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"received"}`))
	}))
	defer server.Close()

	tester := NewTester(&TesterConfig{
		Base: attackconfig.Base{Timeout: 5 * time.Second},
	})

	endpoint := Endpoint{
		Path:   "/test",
		Method: "POST",
		RequestBody: &RequestBody{
			ContentType: "application/json",
		},
	}

	ctx := context.Background()
	resp, err := tester.sendBodyFuzzRequest(ctx, server.URL, endpoint, `{"test":"value"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestGenerateBodyPayloads(t *testing.T) {
	tester := NewTester(nil)

	body := &RequestBody{
		ContentType: "application/json",
	}

	payloads := tester.generateBodyPayloads(body)

	if len(payloads) < 5 {
		t.Errorf("expected at least 5 body payloads, got %d", len(payloads))
	}

	// Check for prototype pollution payload
	hasPrototype := false
	for _, p := range payloads {
		if strings.Contains(p, "__proto__") {
			hasPrototype = true
			break
		}
	}
	if !hasPrototype {
		t.Error("expected prototype pollution payload")
	}
}

func TestAnalyzeResponse(t *testing.T) {
	tester := NewTester(&TesterConfig{
		SkipCodes: []int{404},
	})

	endpoint := Endpoint{Path: "/test", Method: "GET"}
	param := Parameter{Name: "id", Type: ParamString}

	t.Run("skips 404", func(t *testing.T) {
		resp := &FuzzResponse{StatusCode: 404}
		vuln := tester.analyzeResponse(endpoint, param, "test", resp)
		if vuln != nil {
			t.Error("expected nil for 404")
		}
	})

	t.Run("detects error indicator", func(t *testing.T) {
		resp := &FuzzResponse{
			StatusCode: 500,
			Body:       "Fatal error: Uncaught exception in...",
		}
		vuln := tester.analyzeResponse(endpoint, param, "test", resp)
		if vuln == nil {
			t.Error("expected to detect error")
		}
	})

	t.Run("detects slow response", func(t *testing.T) {
		resp := &FuzzResponse{
			StatusCode:   200,
			Body:         "ok",
			ResponseTime: 15 * time.Second,
		}
		vuln := tester.analyzeResponse(endpoint, param, "test", resp)
		if vuln == nil {
			t.Error("expected to detect DoS")
		}
		if vuln != nil && vuln.Type != VulnDoS {
			t.Errorf("expected DoS type, got %s", vuln.Type)
		}
	})
}

func TestHasErrorIndicator(t *testing.T) {
	tests := []struct {
		body     string
		expected bool
	}{
		{"Fatal error occurred", true},
		{"Exception thrown", true},
		{"Stack trace:", true},
		{"Everything is fine", false},
		{"OK", false},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			result := hasErrorIndicator(tt.body)
			if result != tt.expected {
				t.Errorf("hasErrorIndicator(%s) = %v, want %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestHasInjectionIndicator(t *testing.T) {
	tests := []struct {
		body    string
		payload string
		expect  bool
	}{
		{"Payload: test123 was received", "test123", true},
		{"MySQL syntax error near 'x'", "x", true},
		{"OK", "test", false},
	}

	for _, tt := range tests {
		t.Run(tt.body[:min(20, len(tt.body))], func(t *testing.T) {
			result := hasInjectionIndicator(tt.body, tt.payload)
			if result != tt.expect {
				t.Errorf("got %v, want %v", result, tt.expect)
			}
		})
	}
}

func TestHasInfoDisclosure(t *testing.T) {
	tests := []struct {
		body     string
		expected bool
	}{
		{"Stack trace at main.go:123", true},
		{"at com.example.Main(Main.java:42)", true},
		{"password: secret123", true},
		{"/home/user/app/file.txt", true},
		{"C:\\Users\\admin\\file.txt", true},
		{"Everything OK", false},
	}

	for _, tt := range tests {
		t.Run(tt.body[:min(20, len(tt.body))], func(t *testing.T) {
			result := hasInfoDisclosure(tt.body)
			if result != tt.expected {
				t.Errorf("hasInfoDisclosure(%s) = %v, want %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestParseOpenAPISpec(t *testing.T) {
	spec := `{
		"openapi": "3.0.0",
		"paths": {
			"/users": {
				"get": {
					"parameters": [
						{"name": "id", "in": "query", "schema": {"type": "integer"}}
					]
				},
				"post": {}
			},
			"/posts/{postId}": {
				"get": {
					"parameters": [
						{"name": "postId", "in": "path", "required": true, "schema": {"type": "string"}}
					]
				}
			}
		}
	}`

	endpoints, err := ParseOpenAPISpec([]byte(spec))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(endpoints) < 2 {
		t.Errorf("expected at least 2 endpoints, got %d", len(endpoints))
	}

	// Check for users endpoint
	hasUsers := false
	for _, ep := range endpoints {
		if ep.Path == "/users" && ep.Method == "GET" {
			hasUsers = true
			if len(ep.Parameters) == 0 {
				t.Error("expected parameters for /users")
			}
		}
	}
	if !hasUsers {
		t.Error("expected /users endpoint")
	}
}

func TestParseOpenAPISpecInvalid(t *testing.T) {
	_, err := ParseOpenAPISpec([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 9 {
		t.Errorf("expected 9 vulnerability types, got %d", len(types))
	}
}

func TestVulnerabilityToJSON(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnInjection,
		Description: "SQL injection detected",
		Severity:    finding.High,
		Endpoint:    "/api/users",
		Method:      "GET",
		Parameter:   "id",
		Payload:     "' OR '1'='1",
		CVSS:        8.6,
	}

	jsonStr, err := VulnerabilityToJSON(vuln)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(jsonStr, "injection") {
		t.Error("expected type in JSON")
	}
}

func TestGenerateFuzzReport(t *testing.T) {
	vulns := []Vulnerability{
		{Type: VulnInjection, Severity: finding.High},
		{Type: VulnInjection, Severity: finding.High},
		{Type: VulnDoS, Severity: finding.Medium},
	}

	report := GenerateFuzzReport(vulns)

	if report["total_vulnerabilities"] != 3 {
		t.Errorf("expected 3 total, got %v", report["total_vulnerabilities"])
	}

	bySeverity := report["by_severity"].(map[string]int)
	if bySeverity["high"] != 2 {
		t.Errorf("expected 2 high severity, got %d", bySeverity["high"])
	}

	byType := report["by_type"].(map[string]int)
	if byType["injection"] != 2 {
		t.Errorf("expected 2 injection, got %d", byType["injection"])
	}
}

func TestVulnerability(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnBoundaryError,
		Description: "Boundary error",
		Severity:    finding.Medium,
		Endpoint:    "/test",
		Method:      "POST",
		CVSS:        5.5,
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
}

func TestFuzzResponse(t *testing.T) {
	resp := FuzzResponse{
		StatusCode:   200,
		ContentType:  "application/json",
		Body:         `{"test":"value"}`,
		Headers:      map[string]string{"X-Custom": "header"},
		ResponseTime: 100 * time.Millisecond,
		Size:         16,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded FuzzResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.StatusCode != 200 {
		t.Error("status code mismatch")
	}
}

func TestEndpoint(t *testing.T) {
	endpoint := Endpoint{
		Path:   "/users/{id}",
		Method: "GET",
		Parameters: []Parameter{
			{Name: "id", In: "path", Type: ParamInteger, Required: true},
		},
		Headers: map[string]string{"Accept": "application/json"},
	}

	data, err := json.Marshal(endpoint)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Endpoint
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Path != endpoint.Path {
		t.Error("path mismatch")
	}
	if len(decoded.Parameters) != 1 {
		t.Error("parameters mismatch")
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("IntPtr", func(t *testing.T) {
		p := IntPtr(42)
		if *p != 42 {
			t.Error("IntPtr failed")
		}
	})

	t.Run("Float64Ptr", func(t *testing.T) {
		p := Float64Ptr(3.14)
		if *p != 3.14 {
			t.Error("Float64Ptr failed")
		}
	})

	t.Run("StrToInt", func(t *testing.T) {
		if StrToInt("123") != 123 {
			t.Error("StrToInt failed")
		}
		if StrToInt("invalid") != 0 {
			t.Error("StrToInt should return 0 for invalid")
		}
	})

	t.Run("truncate", func(t *testing.T) {
		if truncate("hello", 3) != "hel..." {
			t.Error("truncate failed")
		}
		if truncate("hi", 10) != "hi" {
			t.Error("truncate should not modify short strings")
		}
	})

	t.Run("extractEvidence", func(t *testing.T) {
		long := strings.Repeat("a", 1000)
		result := extractEvidence(long)
		if len(result) > 510 {
			t.Error("extractEvidence should truncate")
		}
	})
}

func TestParameter(t *testing.T) {
	min := 0.0
	max := 100.0
	minLen := 1
	maxLen := 50

	param := Parameter{
		Name:      "test",
		In:        "query",
		Type:      ParamNumber,
		Required:  true,
		Minimum:   &min,
		Maximum:   &max,
		MinLength: &minLen,
		MaxLength: &maxLen,
		Pattern:   `^\d+$`,
		Format:    "int64",
	}

	data, err := json.Marshal(param)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Parameter
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Name != "test" {
		t.Error("name mismatch")
	}
	if *decoded.Maximum != 100.0 {
		t.Error("maximum mismatch")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
