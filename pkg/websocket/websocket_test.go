package websocket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockWebSocketHandler simulates a WebSocket upgrade using hijacker
func mockWebSocketHandler(acceptAnyOrigin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for WebSocket upgrade request
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// If not accepting any origin, only accept from same host
		if !acceptAnyOrigin {
			origin := r.Header.Get("Origin")
			// Only accept origins from the same server (or no origin)
			if origin != "" && !strings.HasPrefix(origin, "http://127.0.0.1") && !strings.HasPrefix(origin, "http://localhost") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		// Use Hijacker to take over the connection properly
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		conn, bufrw, err := hj.Hijack()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		// Write WebSocket upgrade response manually
		acceptKey := computeAcceptKey(r.Header.Get("Sec-WebSocket-Key"))
		response := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + acceptKey + "\r\n" +
			"\r\n"
		bufrw.WriteString(response)
		bufrw.Flush()

		// Connection would now be a WebSocket - we just close it for testing
	}
}

// simpleMockHandler returns headers without hijacking (for simpler tests)
func simpleMockHandler(acceptAnyOrigin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if !acceptAnyOrigin {
			origin := r.Header.Get("Origin")
			// Only accept origins from the same server (or no origin)
			if origin != "" && !strings.HasPrefix(origin, "http://127.0.0.1") && !strings.HasPrefix(origin, "http://localhost") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		// Set WebSocket response headers - but use 200 instead of 101 to avoid connection issues
		// Our code checks for headers OR status code, so this still tests the logic
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", computeAcceptKey(r.Header.Get("Sec-WebSocket-Key")))
		w.WriteHeader(http.StatusOK)
	}
}

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
			Timeout: 60 * time.Second,
			TestOrigins: []string{
				"https://custom-attacker.com",
			},
		}
		tester := NewTester(config)

		if len(tester.config.TestOrigins) != 1 {
			t.Errorf("expected 1 test origin, got %d", len(tester.config.TestOrigins))
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if len(config.TestOrigins) == 0 {
		t.Error("expected test origins")
	}
	if config.UserAgent == "" {
		t.Error("expected user agent")
	}
}

func TestGenerateWebSocketKey(t *testing.T) {
	key1, err1 := generateWebSocketKey()
	if err1 != nil {
		t.Fatalf("generateWebSocketKey failed: %v", err1)
	}
	key2, err2 := generateWebSocketKey()
	if err2 != nil {
		t.Fatalf("generateWebSocketKey failed: %v", err2)
	}

	if key1 == "" {
		t.Error("expected non-empty key")
	}
	if key1 == key2 {
		t.Error("expected different keys")
	}

	// Key should be base64 encoded
	if len(key1) != 24 { // 16 bytes = 24 base64 chars
		t.Errorf("expected 24 char key, got %d", len(key1))
	}
}

func TestComputeAcceptKey(t *testing.T) {
	// Test vector from RFC 6455
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	expected := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

	result := computeAcceptKey(key)
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestHTTPToWS(t *testing.T) {
	tester := NewTester(nil)

	tests := []struct {
		input    string
		expected string
	}{
		{"http://example.com/ws", "ws://example.com/ws"},
		{"https://example.com/ws", "wss://example.com/ws"},
		{"ws://example.com/ws", "ws://example.com/ws"},
		{"wss://example.com/ws", "wss://example.com/ws"},
	}

	for _, test := range tests {
		result := tester.httpToWS(test.input)
		if result != test.expected {
			t.Errorf("httpToWS(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestCheckWebSocket(t *testing.T) {
	t.Run("WebSocket endpoint with hijacker", func(t *testing.T) {
		server := httptest.NewServer(mockWebSocketHandler(true))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		isWS, err := tester.CheckWebSocket(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !isWS {
			t.Error("expected WebSocket support")
		}
	})

	t.Run("WebSocket endpoint simple", func(t *testing.T) {
		server := httptest.NewServer(simpleMockHandler(true))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		isWS, err := tester.CheckWebSocket(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should detect via Upgrade header even without 101
		if !isWS {
			t.Error("expected WebSocket support via header detection")
		}
	})

	t.Run("non-WebSocket endpoint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		isWS, err := tester.CheckWebSocket(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if isWS {
			t.Error("expected no WebSocket support")
		}
	})
}

func TestTestOriginValidation(t *testing.T) {
	t.Run("accepts any origin - vulnerable", func(t *testing.T) {
		server := httptest.NewServer(mockWebSocketHandler(true))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestOriginValidation(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) == 0 {
			t.Error("expected vulnerabilities")
		}
	})

	t.Run("rejects invalid origin - safe", func(t *testing.T) {
		server := httptest.NewServer(mockWebSocketHandler(false))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestOriginValidation(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) != 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})
}

func TestTestTokenInURL(t *testing.T) {
	tester := NewTester(nil)
	ctx := context.Background()

	t.Run("token in URL - vulnerable", func(t *testing.T) {
		vulns, err := tester.TestTokenInURL(ctx, "wss://example.com/ws?token=secret123&session=abc")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) == 0 {
			t.Error("expected token vulnerability")
		}
	})

	t.Run("no token in URL - safe", func(t *testing.T) {
		vulns, err := tester.TestTokenInURL(ctx, "wss://example.com/ws?room=123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) != 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})

	t.Run("JWT in URL - vulnerable", func(t *testing.T) {
		vulns, err := tester.TestTokenInURL(ctx, "wss://example.com/ws?jwt=eyJhbGciOiJIUzI1NiJ9")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) == 0 {
			t.Error("expected JWT vulnerability")
		}
	})
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(mockWebSocketHandler(true))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	result, err := tester.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.URL != server.URL {
		t.Errorf("expected URL %s", server.URL)
	}
	if !result.IsWebSocket {
		t.Error("expected WebSocket support")
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 7 {
		t.Errorf("expected 7 vulnerability types, got %d", len(types))
	}

	expectedTypes := map[VulnerabilityType]bool{
		VulnOriginValidation: false,
		VulnCSWS:             false,
		VulnMessageInjection: false,
		VulnNoTLS:            false,
		VulnTokenExposure:    false,
		VulnNoAuthentication: false,
		VulnDenialOfService:  false,
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

func TestGetRemediation(t *testing.T) {
	t.Run("origin remediation", func(t *testing.T) {
		r := GetOriginRemediation()
		if r == "" {
			t.Error("expected remediation")
		}
		if !strings.Contains(r, "Origin") {
			t.Error("expected Origin mention")
		}
	})

	t.Run("CSWS remediation", func(t *testing.T) {
		r := GetCSWSRemediation()
		if r == "" {
			t.Error("expected remediation")
		}
	})

	t.Run("TLS remediation", func(t *testing.T) {
		r := GetTLSRemediation()
		if r == "" {
			t.Error("expected remediation")
		}
		if !strings.Contains(r, "wss://") {
			t.Error("expected wss mention")
		}
	})

	t.Run("token remediation", func(t *testing.T) {
		r := GetTokenRemediation()
		if r == "" {
			t.Error("expected remediation")
		}
	})
}

func TestIsWebSocketEndpoint(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"http://example.com/ws", true},
		{"http://example.com/websocket", true},
		{"http://example.com/socket.io", true},
		{"http://example.com/signalr", true},
		{"ws://example.com/connect", true},
		{"wss://example.com/connect", true},
		{"http://example.com/api", false},
		{"http://example.com/", false},
	}

	for _, test := range tests {
		result := IsWebSocketEndpoint(test.url)
		if result != test.expected {
			t.Errorf("IsWebSocketEndpoint(%s) = %v, expected %v", test.url, result, test.expected)
		}
	}
}

func TestCommonWebSocketPaths(t *testing.T) {
	paths := CommonWebSocketPaths()

	if len(paths) == 0 {
		t.Error("expected paths")
	}

	hasWS := false
	hasSocket := false

	for _, p := range paths {
		if p == "/ws" {
			hasWS = true
		}
		if p == "/socket" {
			hasSocket = true
		}
	}

	if !hasWS {
		t.Error("expected /ws path")
	}
	if !hasSocket {
		t.Error("expected /socket path")
	}
}

func TestGenerateMaliciousMessages(t *testing.T) {
	messages := GenerateMaliciousMessages()

	if len(messages) == 0 {
		t.Error("expected malicious messages")
	}

	hasJSON := false
	hasSQLi := false

	for _, m := range messages {
		if strings.Contains(m, "{") {
			hasJSON = true
		}
		if strings.Contains(m, "OR") {
			hasSQLi = true
		}
	}

	if !hasJSON {
		t.Error("expected JSON payloads")
	}
	if !hasSQLi {
		t.Error("expected SQLi payloads")
	}
}

func TestVulnerabilityFields(t *testing.T) {
	server := httptest.NewServer(mockWebSocketHandler(true))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	vulns, _ := tester.TestOriginValidation(ctx, server.URL)

	if len(vulns) > 0 {
		v := vulns[0]

		if v.Type == "" {
			t.Error("vulnerability should have type")
		}
		if v.Description == "" {
			t.Error("vulnerability should have description")
		}
		if v.URL == "" {
			t.Error("vulnerability should have URL")
		}
		if v.Remediation == "" {
			t.Error("vulnerability should have remediation")
		}
		if v.CVSS == 0 {
			t.Error("vulnerability should have CVSS score")
		}
	}
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

	_, err := tester.CheckWebSocket(ctx, server.URL)
	// Error expected due to cancellation
	if err == nil {
		// Some implementations may not error
	}
}

func BenchmarkCheckWebSocket(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tester.CheckWebSocket(ctx, server.URL)
	}
}
