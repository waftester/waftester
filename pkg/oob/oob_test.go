package oob

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultInteractshConfig(t *testing.T) {
	config := DefaultInteractshConfig()

	if config.ServerURL != "https://interact.sh" {
		t.Errorf("expected interact.sh, got %s", config.ServerURL)
	}
	if config.PollInterval != 5*time.Second {
		t.Errorf("expected 5s poll interval, got %v", config.PollInterval)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
}

func TestNewInteractshClient(t *testing.T) {
	client := NewInteractshClient(DefaultInteractshConfig())

	if client == nil {
		t.Fatal("NewInteractshClient returned nil")
	}
	if client.correlationID == "" {
		t.Error("expected correlation ID")
	}
	if client.serverURL != "https://interact.sh" {
		t.Errorf("unexpected server URL: %s", client.serverURL)
	}
}

func TestNewInteractshClient_Defaults(t *testing.T) {
	client := NewInteractshClient(InteractshConfig{})

	if client.serverURL != "https://interact.sh" {
		t.Error("should use default server URL")
	}
	if client.pollInterval != 5*time.Second {
		t.Error("should use default poll interval")
	}
}

func TestInteractshClient_GetServer(t *testing.T) {
	tests := []struct {
		serverURL string
		expected  string
	}{
		{"https://interact.sh", "interact.sh"},
		{"http://interact.sh", "interact.sh"},
		{"https://custom.oob.io", "custom.oob.io"},
	}

	for _, tt := range tests {
		t.Run(tt.serverURL, func(t *testing.T) {
			client := NewInteractshClient(InteractshConfig{ServerURL: tt.serverURL})
			if client.GetServer() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, client.GetServer())
			}
		})
	}
}

func TestInteractshClient_GetCorrelationID(t *testing.T) {
	client := NewInteractshClient(DefaultInteractshConfig())

	id := client.GetCorrelationID()
	if len(id) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("expected 16 char correlation ID, got %d: %s", len(id), id)
	}
}

func TestInteractshClient_GeneratePayload(t *testing.T) {
	client := NewInteractshClient(InteractshConfig{ServerURL: "https://interact.sh"})

	payload := client.GeneratePayload(PayloadConfig{})

	if payload == "" {
		t.Error("expected non-empty payload")
	}
	if !containsString(payload, "interact.sh") {
		t.Errorf("payload should contain server: %s", payload)
	}
}

func TestInteractshClient_GenerateDNSPayload(t *testing.T) {
	client := NewInteractshClient(InteractshConfig{ServerURL: "https://interact.sh"})

	payload := client.GenerateDNSPayload()

	if payload == "" {
		t.Error("expected non-empty payload")
	}
	// Should be a domain, not a URL
	if containsString(payload, "http") {
		t.Error("DNS payload should not contain http")
	}
}

func TestInteractshClient_GenerateHTTPPayload(t *testing.T) {
	client := NewInteractshClient(InteractshConfig{ServerURL: "https://interact.sh"})

	payload := client.GenerateHTTPPayload()

	if !containsString(payload, "http://") {
		t.Errorf("HTTP payload should start with http://: %s", payload)
	}
}

func TestInteractshClient_GenerateHTTPSPayload(t *testing.T) {
	client := NewInteractshClient(InteractshConfig{ServerURL: "https://interact.sh"})

	payload := client.GenerateHTTPSPayload()

	if !containsString(payload, "https://") {
		t.Errorf("HTTPS payload should start with https://: %s", payload)
	}
}

func TestInteractshClient_Register(t *testing.T) {
	client := NewInteractshClient(DefaultInteractshConfig())

	err := client.Register(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should be idempotent
	err = client.Register(context.Background())
	if err != nil {
		t.Errorf("second register should not error: %v", err)
	}
}

func TestInteractshClient_Close(t *testing.T) {
	client := NewInteractshClient(DefaultInteractshConfig())
	_ = client.Register(context.Background())

	err := client.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if client.registered {
		t.Error("client should not be registered after close")
	}
}

func TestInteractshClient_GetInteractions(t *testing.T) {
	client := NewInteractshClient(DefaultInteractshConfig())

	interactions := client.GetInteractions()
	if interactions == nil {
		t.Error("expected non-nil interactions")
	}
	if len(interactions) != 0 {
		t.Errorf("expected 0 interactions, got %d", len(interactions))
	}
}

func TestInteractshClient_ClearInteractions(t *testing.T) {
	client := NewInteractshClient(DefaultInteractshConfig())
	client.interactions = []Interaction{{ID: "test"}}

	client.ClearInteractions()

	if len(client.interactions) != 0 {
		t.Error("interactions should be cleared")
	}
}

func TestInteractshClient_Poll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": [
			{
				"protocol": "http",
				"unique-id": "abc123",
				"full-id": "abc123.correlation.interact.sh",
				"remote-address": "1.2.3.4:12345",
				"timestamp": "2025-01-01T00:00:00Z"
			}
		]}`))
	}))
	defer server.Close()

	client := NewInteractshClient(InteractshConfig{
		ServerURL: server.URL,
		Timeout:   5 * time.Second,
	})

	interactions, err := client.Poll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(interactions))
	}

	if interactions[0].ID != "abc123" {
		t.Errorf("wrong ID: %s", interactions[0].ID)
	}
	if interactions[0].Type != InteractionHTTP {
		t.Errorf("wrong type: %s", interactions[0].Type)
	}
}

func TestInteractshClient_Poll_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	client := NewInteractshClient(InteractshConfig{
		ServerURL: server.URL,
	})

	_, err := client.Poll(context.Background())
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestNewOOBDetector(t *testing.T) {
	mock := NewMockClient("mock.oob.io")
	detector := NewOOBDetector(mock)

	if detector == nil {
		t.Fatal("NewOOBDetector returned nil")
	}
	if detector.payloads == nil {
		t.Error("payloads map not initialized")
	}
}

func TestOOBDetector_RegisterPayload(t *testing.T) {
	mock := NewMockClient("mock.oob.io")
	detector := NewOOBDetector(mock)

	info := PayloadInfo{
		ID:        "test-id",
		Payload:   "test-payload",
		TestName:  "test",
		TargetURL: "http://example.com",
	}

	detector.RegisterPayload(info)

	if _, ok := detector.payloads["test-id"]; !ok {
		t.Error("payload not registered")
	}
}

func TestOOBDetector_GeneratePayload(t *testing.T) {
	// Use InteractshClient for this test since GeneratePayload uses type assertion
	client := NewInteractshClient(InteractshConfig{ServerURL: "https://interact.sh"})
	detector := NewOOBDetector(client)

	payload := detector.GeneratePayload("TestXXE", "http://target.com", "file", "xxe")

	if payload == "" {
		t.Error("expected non-empty payload")
	}

	// Should be registered
	if len(detector.payloads) == 0 {
		t.Error("payload should be registered")
	}
}

func TestOOBDetector_GeneratePayload_Types(t *testing.T) {
	client := NewInteractshClient(InteractshConfig{ServerURL: "https://interact.sh"})
	detector := NewOOBDetector(client)

	tests := []struct {
		vulnType string
		check    func(string) bool
	}{
		{"xxe", func(p string) bool { return containsString(p, "http") }},
		{"ssrf", func(p string) bool { return containsString(p, "http") }},
		{"log4j", func(p string) bool { return containsString(p, "jndi") }},
		{"blind_xss", func(p string) bool { return containsString(p, "script") }},
		{"dns", func(p string) bool { return !containsString(p, "http://") }},
	}

	for _, tt := range tests {
		t.Run(tt.vulnType, func(t *testing.T) {
			payload := detector.GeneratePayload("Test", "http://target.com", "param", tt.vulnType)
			if !tt.check(payload) {
				t.Errorf("payload check failed for %s: %s", tt.vulnType, payload)
			}
		})
	}
}

func TestOOBDetector_CheckInteractions(t *testing.T) {
	mock := NewMockClient("mock.oob.io")
	detector := NewOOBDetector(mock)

	// Register a payload
	info := PayloadInfo{
		ID:       "abc123",
		Payload:  "test.abc123.mock.oob.io",
		TestName: "TestSSRF",
		VulnType: "ssrf",
	}
	detector.RegisterPayload(info)

	// Add matching interaction
	mock.AddInteraction(Interaction{
		ID:     "xyz",
		FullID: "xyz.abc123.mock.oob.io",
		Type:   InteractionHTTP,
	})

	vulns, err := detector.CheckInteractions(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	if !vulns[0].Confirmed {
		t.Error("vulnerability should be confirmed")
	}
	if vulns[0].TestName != "TestSSRF" {
		t.Errorf("wrong test name: %s", vulns[0].TestName)
	}
}

func TestOOBDetector_GetDetectedVulnerabilities(t *testing.T) {
	mock := NewMockClient("mock.oob.io")
	detector := NewOOBDetector(mock)

	vulns := detector.GetDetectedVulnerabilities()
	if vulns == nil {
		t.Error("expected non-nil vulnerabilities")
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", len(vulns))
	}
}

func TestPayloadTemplates_XXEPayload(t *testing.T) {
	templates := NewPayloadTemplates("interact.sh")

	payload := templates.XXEPayload("abc123")

	if !containsString(payload, "<!DOCTYPE") {
		t.Error("XXE payload should contain DOCTYPE")
	}
	if !containsString(payload, "abc123") {
		t.Error("XXE payload should contain ID")
	}
	if !containsString(payload, "interact.sh") {
		t.Error("XXE payload should contain server")
	}
}

func TestPayloadTemplates_SSRFPayload(t *testing.T) {
	templates := NewPayloadTemplates("interact.sh")

	payload := templates.SSRFPayload("abc123")

	if !containsString(payload, "http://") {
		t.Error("SSRF payload should be HTTP URL")
	}
	if !containsString(payload, "ssrf") {
		t.Error("SSRF payload should contain path")
	}
}

func TestPayloadTemplates_Log4jPayload(t *testing.T) {
	templates := NewPayloadTemplates("interact.sh")

	payload := templates.Log4jPayload("abc123")

	if !containsString(payload, "${jndi:ldap://") {
		t.Error("Log4j payload should contain JNDI lookup")
	}
}

func TestPayloadTemplates_BlindXSSPayload(t *testing.T) {
	templates := NewPayloadTemplates("interact.sh")

	payload := templates.BlindXSSPayload("abc123")

	if !containsString(payload, "<script") {
		t.Error("BlindXSS payload should contain script tag")
	}
}

func TestPayloadTemplates_LDAPInjectionPayload(t *testing.T) {
	templates := NewPayloadTemplates("interact.sh")

	payload := templates.LDAPInjectionPayload("abc123")

	if !containsString(payload, "uid=") {
		t.Error("LDAP payload should contain uid filter")
	}
}

func TestProtocolToType(t *testing.T) {
	tests := []struct {
		protocol string
		expected InteractionType
	}{
		{"dns", InteractionDNS},
		{"DNS", InteractionDNS},
		{"http", InteractionHTTP},
		{"https", InteractionHTTPS},
		{"smtp", InteractionSMTP},
		{"ldap", InteractionLDAP},
		{"ftp", InteractionFTP},
		{"unknown", InteractionHTTP}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			result := protocolToType(tt.protocol)
			if result != tt.expected {
				t.Errorf("protocolToType(%s) = %s, want %s", tt.protocol, result, tt.expected)
			}
		})
	}
}

func TestDetermineSeverity(t *testing.T) {
	tests := []struct {
		vulnType string
		expected string
	}{
		{"log4j", "critical"},
		{"jndi", "critical"},
		{"rce", "critical"},
		{"xxe", "high"},
		{"ssrf", "high"},
		{"blind_sqli", "high"},
		{"blind_xss", "medium"},
		{"xss", "medium"},
		{"unknown", "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.vulnType, func(t *testing.T) {
			result := determineSeverity(tt.vulnType)
			if result != tt.expected {
				t.Errorf("determineSeverity(%s) = %s, want %s", tt.vulnType, result, tt.expected)
			}
		})
	}
}

func TestGenerateCorrelationID(t *testing.T) {
	id1 := generateCorrelationID()
	id2 := generateCorrelationID()

	if len(id1) != 16 {
		t.Errorf("expected 16 chars, got %d", len(id1))
	}
	if id1 == id2 {
		t.Error("IDs should be unique")
	}
}

func TestGenerateUniqueID(t *testing.T) {
	id1 := generateUniqueID()
	id2 := generateUniqueID()

	if len(id1) != 8 {
		t.Errorf("expected 8 chars, got %d", len(id1))
	}
	if id1 == id2 {
		t.Error("IDs should be unique")
	}
}

func TestMockClient(t *testing.T) {
	mock := NewMockClient("mock.oob.io")

	if mock.GetServer() != "mock.oob.io" {
		t.Error("wrong server")
	}

	payload := mock.GeneratePayload(PayloadConfig{})
	if !containsString(payload, "mock.oob.io") {
		t.Error("payload should contain server")
	}

	if err := mock.Register(context.Background()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := mock.Close(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMockClient_Poll(t *testing.T) {
	mock := NewMockClient("mock.oob.io")

	// Add interactions
	mock.AddInteraction(Interaction{ID: "1"})
	mock.AddInteraction(Interaction{ID: "2"})

	interactions, err := mock.Poll(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(interactions) != 2 {
		t.Errorf("expected 2 interactions, got %d", len(interactions))
	}

	// Second poll should be empty
	interactions, _ = mock.Poll(context.Background())
	if len(interactions) != 0 {
		t.Error("second poll should return empty")
	}
}

func TestInteractionTypes(t *testing.T) {
	types := []InteractionType{
		InteractionDNS,
		InteractionHTTP,
		InteractionHTTPS,
		InteractionSMTP,
		InteractionLDAP,
		InteractionFTP,
	}

	seen := make(map[InteractionType]bool)
	for _, typ := range types {
		if seen[typ] {
			t.Errorf("duplicate type: %s", typ)
		}
		seen[typ] = true
	}
}

func TestPayloadInfo_Fields(t *testing.T) {
	now := time.Now()
	info := PayloadInfo{
		ID:         "test-id",
		Payload:    "test-payload",
		TestName:   "TestCase",
		TargetURL:  "http://target.com",
		Parameter:  "param",
		InjectedAt: now,
		VulnType:   "ssrf",
	}

	if info.ID != "test-id" {
		t.Error("ID field incorrect")
	}
	if info.VulnType != "ssrf" {
		t.Error("VulnType field incorrect")
	}
}

func TestDetectedVulnerability_Fields(t *testing.T) {
	vuln := DetectedVulnerability{
		PayloadInfo: PayloadInfo{TestName: "Test"},
		Interaction: Interaction{ID: "int-1"},
		Confirmed:   true,
		Severity:    "high",
	}

	if !vuln.Confirmed {
		t.Error("Confirmed field incorrect")
	}
	if vuln.Severity != "high" {
		t.Error("Severity field incorrect")
	}
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStringHelper(s, substr))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
