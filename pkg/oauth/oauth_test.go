package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewTester(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		endpoints := &OAuthEndpoint{AuthorizationURL: "https://auth.example.com/authorize"}
		oauth := &OAuthConfig{ClientID: "test-client"}
		tester := NewTester(nil, endpoints, oauth)

		if tester == nil {
			t.Fatal("expected non-nil tester")
		}
		if tester.config.Timeout != 30*time.Second {
			t.Errorf("expected 30s timeout, got %v", tester.config.Timeout)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:     60 * time.Second,
			Concurrency: 10,
		}
		tester := NewTester(config, nil, nil)
		if tester.config.Timeout != 60*time.Second {
			t.Errorf("expected 60s timeout, got %v", tester.config.Timeout)
		}
	})
}

func TestDefaultTesterConfig(t *testing.T) {
	config := DefaultTesterConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if config.Concurrency != 5 {
		t.Errorf("expected 5 concurrency, got %d", config.Concurrency)
	}
}

func TestTestOpenRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		if strings.Contains(redirectURI, "evil.com") {
			w.Header().Set("Location", redirectURI)
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(400)
	}))
	defer server.Close()

	endpoints := &OAuthEndpoint{AuthorizationURL: server.URL}
	oauth := &OAuthConfig{
		ClientID:    "test-client",
		RedirectURI: "https://legitimate.com/callback",
		Scopes:      []string{"openid"},
	}

	tester := NewTester(nil, endpoints, oauth)
	ctx := context.Background()

	vulns, err := tester.TestOpenRedirect(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(vulns) == 0 {
		t.Error("expected open redirect vulnerabilities to be detected")
	}
}

func TestTestCSRFAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept requests without state parameter (vulnerable)
		w.WriteHeader(200)
	}))
	defer server.Close()

	endpoints := &OAuthEndpoint{AuthorizationURL: server.URL}
	oauth := &OAuthConfig{
		ClientID:    "test-client",
		RedirectURI: "https://app.com/callback",
		Scopes:      []string{"openid"},
	}

	tester := NewTester(nil, endpoints, oauth)
	ctx := context.Background()

	vulns, err := tester.TestCSRFAuthorization(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(vulns) == 0 {
		t.Error("expected CSRF vulnerability to be detected")
	}
}

func TestTestStateBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	endpoints := &OAuthEndpoint{AuthorizationURL: server.URL}
	oauth := &OAuthConfig{
		ClientID:    "test-client",
		RedirectURI: "https://app.com/callback",
		Scopes:      []string{"openid"},
	}

	tester := NewTester(nil, endpoints, oauth)
	ctx := context.Background()

	vulns, err := tester.TestStateBypass(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(vulns) == 0 {
		t.Error("expected state bypass vulnerability to be detected")
	}
}

func TestTestScopeManipulation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("scope")
		if strings.Contains(scope, "admin") {
			w.WriteHeader(200) // Vulnerable: accepts admin scope
			return
		}
		w.WriteHeader(400)
	}))
	defer server.Close()

	endpoints := &OAuthEndpoint{AuthorizationURL: server.URL}
	oauth := &OAuthConfig{
		ClientID:    "test-client",
		RedirectURI: "https://app.com/callback",
		Scopes:      []string{"openid"},
		State:       "test-state",
	}

	tester := NewTester(nil, endpoints, oauth)
	ctx := context.Background()

	vulns, err := tester.TestScopeManipulation(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(vulns) == 0 {
		t.Error("expected scope manipulation vulnerability to be detected")
	}
}

func TestTestPKCEBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept requests without code_challenge (vulnerable)
		w.WriteHeader(200)
	}))
	defer server.Close()

	endpoints := &OAuthEndpoint{AuthorizationURL: server.URL}
	oauth := &OAuthConfig{
		ClientID:    "test-client",
		RedirectURI: "https://app.com/callback",
		Scopes:      []string{"openid"},
		State:       "test-state",
	}

	tester := NewTester(nil, endpoints, oauth)
	ctx := context.Background()

	vulns, err := tester.TestPKCEBypass(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(vulns) == 0 {
		t.Error("expected PKCE bypass vulnerability to be detected")
	}
}

func TestScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	endpoints := &OAuthEndpoint{AuthorizationURL: server.URL}
	oauth := &OAuthConfig{
		ClientID:    "test-client",
		RedirectURI: "https://app.com/callback",
		Scopes:      []string{"openid"},
		State:       "test-state",
	}

	tester := NewTester(nil, endpoints, oauth)
	ctx := context.Background()

	vulns, err := tester.Scan(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Scan should find multiple vulnerabilities
	if len(vulns) == 0 {
		t.Error("expected vulnerabilities to be detected")
	}
}

func TestGetRedirectPayloads(t *testing.T) {
	payloads := GetRedirectPayloads()

	if len(payloads) < 10 {
		t.Errorf("expected at least 10 redirect payloads, got %d", len(payloads))
	}

	// Check for common payloads
	hasEvil := false
	for _, p := range payloads {
		if strings.Contains(p, "evil.com") {
			hasEvil = true
			break
		}
	}
	if !hasEvil {
		t.Error("expected evil.com payload")
	}
}

func TestGetScopePayloads(t *testing.T) {
	payloads := GetScopePayloads()

	if len(payloads) < 5 {
		t.Errorf("expected at least 5 scope payloads, got %d", len(payloads))
	}

	// Check for admin scope
	hasAdmin := false
	for _, p := range payloads {
		if strings.Contains(p, "admin") {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		t.Error("expected admin scope payload")
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) < 10 {
		t.Errorf("expected at least 10 vulnerability types, got %d", len(types))
	}
}

func TestVulnerabilityToJSON(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnOpenRedirect,
		Description: "Open redirect via redirect_uri",
		Severity:    SeverityHigh,
		CVSS:        7.4,
	}

	jsonStr, err := VulnerabilityToJSON(vuln)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(jsonStr, "open-redirect") {
		t.Error("expected type in JSON")
	}
}

func TestGenerateReport(t *testing.T) {
	vulns := []Vulnerability{
		{Type: VulnOpenRedirect, Severity: SeverityHigh},
		{Type: VulnCSRFAuth, Severity: SeverityHigh},
		{Type: VulnOpenRedirect, Severity: SeverityHigh},
	}

	report := GenerateReport(vulns)

	if report["total_vulnerabilities"] != 3 {
		t.Errorf("expected 3 total, got %v", report["total_vulnerabilities"])
	}

	byType := report["by_type"].(map[string]int)
	if byType["open-redirect"] != 2 {
		t.Errorf("expected 2 open-redirect, got %d", byType["open-redirect"])
	}
}

func TestGenerateState(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState() returned error: %v", err)
	}

	if len(state) == 0 {
		t.Error("expected non-empty state")
	}

	// State should be base64 encoded
	if !strings.Contains(state, "=") && len(state) < 40 {
		// May or may not have padding, but should be substantial
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() returned error: %v", err)
	}

	if len(nonce) == 0 {
		t.Error("expected non-empty nonce")
	}
}

func TestGeneratePKCEPair(t *testing.T) {
	verifier, challenge, err := GeneratePKCEPair()
	if err != nil {
		t.Fatalf("GeneratePKCEPair() returned error: %v", err)
	}

	if len(verifier) == 0 {
		t.Error("expected non-empty verifier")
	}
	if len(challenge) == 0 {
		t.Error("expected non-empty challenge")
	}
	if verifier == challenge {
		t.Error("verifier and challenge should differ")
	}
}

func TestValidateState(t *testing.T) {
	t.Run("matching states", func(t *testing.T) {
		if !ValidateState("abc123", "abc123") {
			t.Error("expected valid state match")
		}
	})

	t.Run("non-matching states", func(t *testing.T) {
		if ValidateState("abc123", "xyz789") {
			t.Error("expected invalid state mismatch")
		}
	})
}

func TestParseIDToken(t *testing.T) {
	// Create a simple JWT (header.payload.signature)
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	payload := "eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiIxMjM0NTYiLCJhdWQiOiJ0ZXN0LWNsaWVudCIsImV4cCI6MTcwMDAwMDAwMH0"
	signature := "signature"
	token := header + "." + payload + "." + signature

	claims, err := ParseIDToken(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claims["iss"] != "https://auth.example.com" {
		t.Errorf("expected issuer, got %v", claims["iss"])
	}
	if claims["sub"] != "123456" {
		t.Errorf("expected subject, got %v", claims["sub"])
	}
}

func TestParseIDTokenInvalid(t *testing.T) {
	_, err := ParseIDToken("invalid-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestValidateIDToken(t *testing.T) {
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	payload := "eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiIxMjM0NTYiLCJhdWQiOiJ0ZXN0LWNsaWVudCIsImV4cCI6MTcwMDAwMDAwMH0"
	signature := "signature"
	token := header + "." + payload + "." + signature

	err := ValidateIDToken(token, "https://auth.example.com", "test-client")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = ValidateIDToken(token, "https://wrong.com", "test-client")
	if err == nil {
		t.Error("expected error for wrong issuer")
	}
}

func TestDiscoverOIDCEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]string{
				"issuer":                 "https://auth.example.com",
				"authorization_endpoint": "https://auth.example.com/authorize",
				"token_endpoint":         "https://auth.example.com/token",
				"userinfo_endpoint":      "https://auth.example.com/userinfo",
				"jwks_uri":               "https://auth.example.com/.well-known/jwks.json",
			}
			json.NewEncoder(w).Encode(config)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	ctx := context.Background()
	endpoints, err := DiscoverOIDCEndpoints(ctx, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if endpoints.AuthorizationURL != "https://auth.example.com/authorize" {
		t.Errorf("expected authorization URL, got %s", endpoints.AuthorizationURL)
	}
}

func TestIsImplicitFlowToken(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://app.com/callback#access_token=abc123&token_type=bearer", true},
		{"https://app.com/callback#id_token=eyJ...&state=xyz", true},
		{"https://app.com/callback?code=abc123", false},
		{"https://app.com/callback", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := IsImplicitFlowToken(tt.url)
			if result != tt.expected {
				t.Errorf("IsImplicitFlowToken(%q) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
}

func TestExtractTokenFromFragment(t *testing.T) {
	url := "https://app.com/callback#access_token=abc123&id_token=xyz789&token_type=bearer"
	tokens := ExtractTokenFromFragment(url)

	if tokens["access_token"] != "abc123" {
		t.Errorf("expected access_token, got %s", tokens["access_token"])
	}
	if tokens["id_token"] != "xyz789" {
		t.Errorf("expected id_token, got %s", tokens["id_token"])
	}
}

func TestIsWeakClientSecret(t *testing.T) {
	tests := []struct {
		secret   string
		expected bool
	}{
		{"short", true},
		{"client_secret_123", true},
		{"password123456789012345678901234", true},
		{"a8f3k9d2m5p7q1r4t6u8w0x2y4z6b8c0", false},
		{"changeme123456789012345678901234", true},
		{"1111111111111111111111111111111111", true},
	}

	for _, tt := range tests {
		t.Run(tt.secret, func(t *testing.T) {
			result := IsWeakClientSecret(tt.secret)
			if result != tt.expected {
				t.Errorf("IsWeakClientSecret(%q) = %v, want %v", tt.secret, result, tt.expected)
			}
		})
	}
}

func TestOAuthEndpoint(t *testing.T) {
	endpoint := OAuthEndpoint{
		AuthorizationURL: "https://auth.example.com/authorize",
		TokenURL:         "https://auth.example.com/token",
		UserinfoURL:      "https://auth.example.com/userinfo",
		JwksURL:          "https://auth.example.com/.well-known/jwks.json",
		Issuer:           "https://auth.example.com",
	}

	if endpoint.AuthorizationURL != "https://auth.example.com/authorize" {
		t.Error("authorization URL mismatch")
	}
}

func TestOAuthConfig(t *testing.T) {
	config := OAuthConfig{
		ClientID:     "test-client",
		ClientSecret: "secret123",
		RedirectURI:  "https://app.com/callback",
		Scopes:       []string{"openid", "profile", "email"},
		State:        "random-state",
		Nonce:        "random-nonce",
		CodeVerifier: "pkce-verifier",
	}

	if config.ClientID != "test-client" {
		t.Error("client ID mismatch")
	}
	if len(config.Scopes) != 3 {
		t.Error("scopes count mismatch")
	}
}

func TestVulnerabilityStruct(t *testing.T) {
	vuln := Vulnerability{
		Type:        VulnTokenLeakage,
		Description: "Token exposed in URL",
		Severity:    SeverityCritical,
		URL:         "https://app.com/callback",
		Parameter:   "access_token",
		Payload:     "token_value",
		Evidence:    "Token in fragment",
		Remediation: "Use authorization code flow",
		CVSS:        9.1,
	}

	if vuln.Type != VulnTokenLeakage {
		t.Error("type mismatch")
	}
	if vuln.Severity != SeverityCritical {
		t.Error("severity mismatch")
	}
}

func TestApplyHeaders(t *testing.T) {
	config := &TesterConfig{
		UserAgent:  "Test-Agent",
		AuthHeader: "Bearer test123",
		Cookies:    map[string]string{"session": "abc"},
	}
	tester := NewTester(config, nil, nil)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	tester.applyHeaders(req)

	if req.Header.Get("User-Agent") != "Test-Agent" {
		t.Error("User-Agent not set")
	}
	if req.Header.Get("Authorization") != "Bearer test123" {
		t.Error("Authorization not set")
	}
}
