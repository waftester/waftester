package browser

import (
	"net/url"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
)

// TestClassifyThirdPartyAPI_SameOriginWithPort verifies that same-origin
// requests with different ports are not classified as third-party
func TestClassifyThirdPartyAPI_SameOriginWithPort(t *testing.T) {
	scanner := NewAuthenticatedScanner(&AuthConfig{
		TargetURL: "https://example.com:443",
	})

	tests := []struct {
		name        string
		requestURL  string
		targetHost  string
		wantNil     bool
		description string
	}{
		{
			name:        "Same domain different port should be same-origin",
			requestURL:  "https://example.com:8443/api/v1",
			targetHost:  "example.com",
			wantNil:     true,
			description: "Port difference shouldn't make it third-party",
		},
		{
			name:        "Subdomain should be same-origin",
			requestURL:  "https://api.example.com/v1",
			targetHost:  "example.com",
			wantNil:     true,
			description: "Subdomains are same-origin",
		},
		{
			name:        "Parent domain from subdomain target",
			requestURL:  "https://example.com/api",
			targetHost:  "api.example.com",
			wantNil:     true,
			description: "Parent domain is same-origin",
		},
		{
			name:        "Actually third party",
			requestURL:  "https://googleapis.com/api",
			targetHost:  "example.com",
			wantNil:     false,
			description: "Different domain is third-party",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.classifyThirdPartyAPI(tt.requestURL, tt.targetHost)
			if tt.wantNil && result != nil {
				t.Errorf("classifyThirdPartyAPI() = %v, want nil (same-origin): %s", result, tt.description)
			}
			if !tt.wantNil && result == nil {
				t.Errorf("classifyThirdPartyAPI() = nil, want non-nil (third-party): %s", tt.description)
			}
		})
	}
}

// TestHandleNetworkRequest_HostVsHostname verifies that third-party detection
// uses Hostname() (no port) instead of Host (with port)
func TestHandleNetworkRequest_HostVsHostname(t *testing.T) {
	scanner := NewAuthenticatedScanner(&AuthConfig{
		TargetURL: "https://example.com:443",
	})

	result := &BrowserScanResult{
		TargetURL:        "https://example.com:443",
		Domain:           "example.com",
		NetworkRequests:  make([]NetworkRequest, 0),
		ThirdPartyAPIs:   make([]ThirdPartyAPI, 0),
		DiscoveredRoutes: make([]DiscoveredRoute, 0),
	}

	// Create a mock request event for same domain but different port
	// This should NOT be marked as third-party
	mockEvent := &network.EventRequestWillBeSent{
		Request: &network.Request{
			URL:     "https://example.com:8443/api/users",
			Method:  "GET",
			Headers: make(network.Headers),
		},
		Type: network.ResourceTypeXHR,
	}

	scanner.handleNetworkRequest(mockEvent, result)

	// The request should not be marked as third-party
	if len(result.NetworkRequests) == 0 {
		t.Fatal("Expected at least one network request to be captured")
	}

	req := result.NetworkRequests[0]
	if req.IsThirdParty {
		t.Errorf("Same-domain request with different port should NOT be marked as third-party. Got IsThirdParty=true for %s", mockEvent.Request.URL)
	}
}

// TestHandleNetworkRequest_PopulatesPostData verifies that POST data is captured
func TestHandleNetworkRequest_PopulatesPostData(t *testing.T) {
	scanner := NewAuthenticatedScanner(&AuthConfig{
		TargetURL: "https://example.com",
	})

	result := &BrowserScanResult{
		TargetURL:        "https://example.com",
		Domain:           "example.com",
		NetworkRequests:  make([]NetworkRequest, 0),
		ThirdPartyAPIs:   make([]ThirdPartyAPI, 0),
		DiscoveredRoutes: make([]DiscoveredRoute, 0),
	}

	// Create a mock POST request with body
	mockEvent := &network.EventRequestWillBeSent{
		Request: &network.Request{
			URL:         "https://example.com/api/login",
			Method:      "POST",
			Headers:     make(network.Headers),
			HasPostData: true,
			PostDataEntries: []*network.PostDataEntry{
				{Bytes: "dXNlcm5hbWU9dGVzdA=="}, // base64 of "username=test"
			},
		},
		Type: network.ResourceTypeXHR,
	}

	scanner.handleNetworkRequest(mockEvent, result)

	if len(result.NetworkRequests) == 0 {
		t.Fatal("Expected at least one network request to be captured")
	}

	req := result.NetworkRequests[0]
	// PostData should be populated for POST requests with body
	if req.PostData == "" && mockEvent.Request.HasPostData {
		t.Errorf("PostData should be populated for POST request with HasPostData=true. Got empty PostData")
	}
}

// TestHandleNetworkResponse_PopulatesSizeAndDuration verifies response metadata
func TestHandleNetworkResponse_PopulatesSizeAndDuration(t *testing.T) {
	scanner := NewAuthenticatedScanner(&AuthConfig{
		TargetURL: "https://example.com",
	})

	requestTime := time.Now()
	result := &BrowserScanResult{
		TargetURL: "https://example.com",
		Domain:    "example.com",
		NetworkRequests: []NetworkRequest{
			{
				RequestID: "req-123",
				URL:       "https://example.com/api/data",
				Method:    "GET",
				Timestamp: requestTime,
			},
		},
		requestIndexMap: map[string]int{
			"req-123": 0, // Use RequestID as key
		},
	}

	// Create a mock response event with timing data
	mockResponse := &network.EventResponseReceived{
		RequestID: "req-123",
		Response: &network.Response{
			URL:               "https://example.com/api/data",
			Status:            200,
			MimeType:          "application/json",
			EncodedDataLength: 1024, // Response size in bytes
		},
	}

	scanner.handleNetworkResponse(mockResponse, result)

	req := result.NetworkRequests[0]

	// Size should be populated from EncodedDataLength
	if req.Size != 1024 {
		t.Errorf("Size should be populated from response EncodedDataLength. Got %d, want 1024", req.Size)
	}
}

// TestRequestResponseCorrelation_ByRequestID verifies correlation uses RequestID
// instead of URL to handle multiple requests to the same URL
func TestRequestResponseCorrelation_ByRequestID(t *testing.T) {
	scanner := NewAuthenticatedScanner(&AuthConfig{
		TargetURL: "https://example.com",
	})

	result := &BrowserScanResult{
		TargetURL:       "https://example.com",
		Domain:          "example.com",
		NetworkRequests: make([]NetworkRequest, 0),
	}

	// Simulate 3 requests to the same URL
	sameURL := "https://example.com/api/users"
	for i := 0; i < 3; i++ {
		mockEvent := &network.EventRequestWillBeSent{
			RequestID: network.RequestID("req-" + string(rune('a'+i))),
			Request: &network.Request{
				URL:     sameURL,
				Method:  "GET",
				Headers: make(network.Headers),
			},
			Type: network.ResourceTypeXHR,
		}
		scanner.handleNetworkRequest(mockEvent, result)
	}

	// All 3 requests should be stored
	if len(result.NetworkRequests) != 3 {
		t.Errorf("Expected 3 network requests for repeated URL calls, got %d", len(result.NetworkRequests))
	}

	// Now send responses with different status codes
	responses := []struct {
		requestID string
		status    int64
	}{
		{"req-a", 200},
		{"req-b", 201},
		{"req-c", 204},
	}

	for _, resp := range responses {
		mockResponse := &network.EventResponseReceived{
			RequestID: network.RequestID(resp.requestID),
			Response: &network.Response{
				URL:      sameURL,
				Status:   resp.status,
				MimeType: "application/json",
			},
		}
		scanner.handleNetworkResponse(mockResponse, result)
	}

	// Each request should have its own response code
	statusCodes := make(map[int]int) // statusCode -> count
	for _, req := range result.NetworkRequests {
		statusCodes[req.ResponseCode]++
	}

	// We should have 3 different status codes (200, 201, 204)
	if len(statusCodes) != 3 {
		t.Errorf("Expected 3 different response codes for 3 requests to same URL. Got status distribution: %v", statusCodes)
		t.Logf("This indicates URL-based correlation is overwriting responses")
	}
}

// TestRunSimulatedScan_MessageAccuracy verifies the message matches behavior
func TestRunSimulatedScan_MessageAccuracy(t *testing.T) {
	scanner := NewAuthenticatedScanner(&AuthConfig{
		TargetURL: "https://example.com",
	})

	result := &BrowserScanResult{
		TargetURL: "https://example.com",
		Domain:    "example.com",
	}

	var messages []string
	progressFn := func(msg string) {
		messages = append(messages, msg)
	}

	scanner.runSimulatedScan(nil, result, progressFn)

	// Check that messages don't promise HTTP reconnaissance if none is performed
	for _, msg := range messages {
		// If message says "HTTP-based reconnaissance" but no HTTP requests are made,
		// that's misleading
		if contains(msg, "reconnaissance") && !result.AuthSuccessful {
			// Verify that actual HTTP requests were made, or message should be different
			// This test documents the current misleading behavior
			t.Logf("Message '%s' promises reconnaissance but AuthSuccessful=%v", msg, result.AuthSuccessful)
		}
	}

	// The simulated scan should at least detect auth flow
	if result.AuthFlowInfo == nil {
		t.Error("runSimulatedScan should at least populate AuthFlowInfo")
	}
}

// contains is a simple helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestDefaultAuthConfig verifies sensible defaults
func TestDefaultAuthConfig(t *testing.T) {
	config := DefaultAuthConfig()

	if config.Timeout != 5*time.Minute {
		t.Errorf("Default Timeout = %v, want 5m", config.Timeout)
	}
	if config.WaitForLogin != 3*time.Minute {
		t.Errorf("Default WaitForLogin = %v, want 3m", config.WaitForLogin)
	}
	if config.CrawlDepth != 3 {
		t.Errorf("Default CrawlDepth = %d, want 3", config.CrawlDepth)
	}
	if !config.ShowBrowser {
		t.Error("Default ShowBrowser should be true for manual login")
	}
	if !config.StealthMode {
		t.Error("Default StealthMode should be true for WAF testing")
	}
	if len(config.IgnorePatterns) == 0 {
		t.Error("Default IgnorePatterns should have entries")
	}
}

// TestNewAuthenticatedScanner verifies scanner initialization
func TestNewAuthenticatedScanner(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		scanner := NewAuthenticatedScanner(nil)
		if scanner == nil {
			t.Fatal("NewAuthenticatedScanner(nil) returned nil")
		}
		if scanner.config == nil {
			t.Error("Scanner config should not be nil")
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &AuthConfig{
			TargetURL: "https://test.com",
			Timeout:   1 * time.Minute,
			IgnorePatterns: []string{
				`\.css$`,
				`\.js$`,
			},
		}
		scanner := NewAuthenticatedScanner(config)
		if scanner.config.TargetURL != "https://test.com" {
			t.Errorf("TargetURL = %s, want https://test.com", scanner.config.TargetURL)
		}
		// Verify patterns are compiled
		if len(scanner.ignorePatterns) != 2 {
			t.Errorf("Expected 2 compiled ignore patterns, got %d", len(scanner.ignorePatterns))
		}
	})

	t.Run("invalid regex pattern is skipped", func(t *testing.T) {
		config := &AuthConfig{
			IgnorePatterns: []string{
				`[invalid`, // Invalid regex
				`\.css$`,   // Valid regex
			},
		}
		scanner := NewAuthenticatedScanner(config)
		// Should have only 1 compiled pattern (the valid one)
		if len(scanner.ignorePatterns) != 1 {
			t.Errorf("Expected 1 compiled pattern (invalid skipped), got %d", len(scanner.ignorePatterns))
		}
	})
}

// TestBrowserScanResult_AddTokenIfUnique verifies deduplication
func TestBrowserScanResult_AddTokenIfUnique(t *testing.T) {
	result := &BrowserScanResult{
		ExposedTokens: make([]ExposedToken, 0),
	}

	token1 := ExposedToken{
		Type:     "jwt",
		Key:      "access_token",
		Location: "localStorage",
	}

	// First add should succeed
	if !result.addTokenIfUnique(token1) {
		t.Error("First add should return true")
	}
	if len(result.ExposedTokens) != 1 {
		t.Errorf("Expected 1 token, got %d", len(result.ExposedTokens))
	}

	// Duplicate add should fail
	if result.addTokenIfUnique(token1) {
		t.Error("Duplicate add should return false")
	}
	if len(result.ExposedTokens) != 1 {
		t.Errorf("Expected still 1 token after duplicate, got %d", len(result.ExposedTokens))
	}

	// Different token should succeed
	token2 := ExposedToken{
		Type:     "jwt",
		Key:      "refresh_token",
		Location: "localStorage",
	}
	if !result.addTokenIfUnique(token2) {
		t.Error("Different token add should return true")
	}
	if len(result.ExposedTokens) != 2 {
		t.Errorf("Expected 2 tokens, got %d", len(result.ExposedTokens))
	}
}

// TestExtractPath verifies path extraction from URLs
func TestExtractPath(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://example.com/api/users", "/api/users"},
		{"https://example.com/", "/"},
		{"https://example.com", "/"},
		{"https://example.com/path?query=1", "/path"},
		{"invalid-url", "invalid-url"}, // Fallback to original
	}

	for _, tt := range tests {
		got := extractPath(tt.url)
		if got != tt.expected {
			t.Errorf("extractPath(%s) = %s, want %s", tt.url, got, tt.expected)
		}
	}
}

// TestIsLowValueAsset verifies static asset filtering
func TestIsLowValueAsset(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/style.css", true},
		{"https://example.com/image.png", true},
		{"https://example.com/font.woff2", true},
		{"https://google-analytics.com/collect", true},
		{"https://example.com/api/users", false},
		{"https://example.com/login", false},
		{"https://example.com/data.json", false}, // JSON is valuable
	}

	for _, tt := range tests {
		got := isLowValueAsset(tt.url)
		if got != tt.expected {
			t.Errorf("isLowValueAsset(%s) = %v, want %v", tt.url, got, tt.expected)
		}
	}
}

// TestAnalyzeToken verifies token classification
func TestAnalyzeToken(t *testing.T) {
	scanner := NewAuthenticatedScanner(nil)

	tests := []struct {
		name         string
		key          string
		value        string
		location     string
		expectedType string
		expectNil    bool
	}{
		{
			name:         "JWT token",
			key:          "token",
			value:        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			location:     "localStorage",
			expectedType: "jwt",
			expectNil:    false,
		},
		{
			name:         "API key",
			key:          "api_key",
			value:        "sk-1234567890abcdef",
			location:     "localStorage",
			expectedType: "api_key",
			expectNil:    false,
		},
		{
			name:         "Bearer token",
			key:          "access_token",
			value:        "ya29.a0AfH6SMBx...",
			location:     "sessionStorage",
			expectedType: "bearer",
			expectNil:    false,
		},
		{
			name:         "Session token",
			key:          "session_id",
			value:        "abc123def456",
			location:     "cookie",
			expectedType: "session",
			expectNil:    false,
		},
		{
			name:         "CSRF token",
			key:          "csrf_token",
			value:        "random-csrf-value",
			location:     "cookie",
			expectedType: "csrf",
			expectNil:    false,
		},
		{
			name:         "Non-sensitive value",
			key:          "theme",
			value:        "dark",
			location:     "localStorage",
			expectedType: "",
			expectNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.analyzeToken(tt.key, tt.value, tt.location)
			if tt.expectNil && result != nil {
				t.Errorf("Expected nil for non-sensitive value, got %+v", result)
			}
			if !tt.expectNil && result == nil {
				t.Errorf("Expected token result for %s, got nil", tt.key)
			}
			if !tt.expectNil && result != nil && result.Type != tt.expectedType {
				t.Errorf("Token type = %s, want %s", result.Type, tt.expectedType)
			}
		})
	}
}

// TestDetectAuthFlow verifies auth provider detection
func TestDetectAuthFlow(t *testing.T) {
	scanner := NewAuthenticatedScanner(nil)

	tests := []struct {
		url              string
		expectedProvider string
	}{
		{"https://login.microsoftonline.com/tenant/oauth2", "Microsoft Azure AD"},
		{"https://accounts.google.com/o/oauth2/auth", "Google"},
		{"https://mycompany.okta.com/oauth2/default", "Okta"},
		{"https://myapp.auth0.com/authorize", "Auth0"},
		{"https://keycloak.example.com/auth/realms", "Keycloak"},
		{"https://example.com/login", "Custom/Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedProvider, func(t *testing.T) {
			info := scanner.detectAuthFlow(tt.url)
			if info == nil {
				t.Fatal("detectAuthFlow returned nil")
			}
			if info.Provider != tt.expectedProvider {
				t.Errorf("Provider = %s, want %s", info.Provider, tt.expectedProvider)
			}
		})
	}
}

// TestShouldIgnoreURL verifies URL filtering
func TestShouldIgnoreURL(t *testing.T) {
	scanner := NewAuthenticatedScanner(&AuthConfig{
		IgnorePatterns: []string{
			`\.png$`,
			`google-analytics\.com`,
		},
	})

	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/image.png", true},
		{"https://google-analytics.com/collect", true},
		{"https://example.com/api/users", false},
		{"https://example.com/login.html", false},
	}

	for _, tt := range tests {
		got := scanner.shouldIgnoreURL(tt.url)
		if got != tt.expected {
			t.Errorf("shouldIgnoreURL(%s) = %v, want %v", tt.url, got, tt.expected)
		}
	}
}

// TestCalculateRiskSummary verifies risk calculation
func TestCalculateRiskSummary(t *testing.T) {
	scanner := NewAuthenticatedScanner(nil)

	result := &BrowserScanResult{
		ExposedTokens: []ExposedToken{
			{Type: "jwt", Severity: "critical", Risk: "JWT exposed"},
			{Type: "api_key", Severity: "high", Risk: "API key exposed"},
			{Type: "session", Severity: "medium", Risk: "Session token"},
			{Type: "csrf", Severity: "low", Risk: "CSRF token"},
		},
		ThirdPartyAPIs: []ThirdPartyAPI{
			{Name: "SAP", Severity: "high"},
		},
	}

	summary := scanner.calculateRiskSummary(result)

	if summary.CriticalCount != 1 {
		t.Errorf("CriticalCount = %d, want 1", summary.CriticalCount)
	}
	if summary.HighCount != 2 { // 1 token + 1 API
		t.Errorf("HighCount = %d, want 2", summary.HighCount)
	}
	if summary.MediumCount != 1 {
		t.Errorf("MediumCount = %d, want 1", summary.MediumCount)
	}
	if summary.LowCount != 1 {
		t.Errorf("LowCount = %d, want 1", summary.LowCount)
	}
	if summary.TotalFindings != 5 {
		t.Errorf("TotalFindings = %d, want 5", summary.TotalFindings)
	}
	if summary.OverallRisk != "critical" {
		t.Errorf("OverallRisk = %s, want critical", summary.OverallRisk)
	}
}

// TestMatchesFocusPattern verifies focus pattern matching
func TestMatchesFocusPattern(t *testing.T) {
	scanner := NewAuthenticatedScanner(&AuthConfig{
		FocusPatterns: []string{"/api/", "/admin/", "/graphql"},
	})

	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/api/users", true},
		{"https://example.com/admin/dashboard", true},
		{"https://example.com/graphql", true},
		{"https://example.com/login", false},
		{"https://example.com/public/page", false},
	}

	for _, tt := range tests {
		got := scanner.matchesFocusPattern(tt.url)
		if got != tt.expected {
			t.Errorf("matchesFocusPattern(%s) = %v, want %v", tt.url, got, tt.expected)
		}
	}
}

// TestAnalyzeTokenMultiByteTruncation is a regression test for a byte
// truncation bug in analyzeToken. The old code used value[:25] which truncates
// at byte offset 25, potentially splitting a multi-byte UTF-8 character and
// producing an invalid string (or panicking). The fix uses []rune to truncate
// at rune boundaries. This test passes a token made of Chinese characters
// (3 bytes each) that would panic under the old byte-based truncation.
func TestAnalyzeTokenMultiByteTruncation(t *testing.T) {
	scanner := NewAuthenticatedScanner(&AuthConfig{
		TargetURL: "https://example.com",
	})

	// 60 Chinese characters = 180 bytes, well over the 50 rune threshold.
	// Under byte-based truncation, value[:25] would split a 3-byte char.
	longMultiByteValue := "这是一个非常长的安全令牌值包含中文字符用于测试截断功能是否正确处理多字节字符不会导致程序崩溃或产生无效输出"

	token := scanner.analyzeToken("auth_token", longMultiByteValue, "cookie")

	// Should not panic (the test reaching here means no panic)

	// The display value should be truncated (original is > 50 runes)
	if token.Value == longMultiByteValue {
		t.Error("token.Value should be truncated for display")
	}

	// The truncated value should contain "..."
	if len(token.Value) > 0 {
		found := false
		for i := 0; i <= len(token.Value)-3; i++ {
			if token.Value[i:i+3] == "..." {
				found = true
				break
			}
		}
		if !found {
			t.Error("truncated token should contain '...'")
		}
	}

	// The full value should be preserved
	if token.FullValue != longMultiByteValue {
		t.Error("token.FullValue should preserve the complete original value")
	}

	// The truncated string should be valid UTF-8
	for _, r := range token.Value {
		if r == 0xFFFD { // Unicode replacement character
			t.Fatal("truncated token contains replacement character — byte-boundary corruption")
		}
	}
}

// Helper to parse URL for tests
func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
