// Package websocket provides WebSocket security testing capabilities.
// It tests for WebSocket hijacking, message injection, origin validation bypass,
// and other WebSocket-specific vulnerabilities.
package websocket

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

// VulnerabilityType represents the type of WebSocket vulnerability
type VulnerabilityType string

const (
	VulnOriginValidation VulnerabilityType = "origin-validation-bypass"
	VulnCSWS             VulnerabilityType = "cross-site-websocket-hijacking"
	VulnMessageInjection VulnerabilityType = "message-injection"
	VulnNoTLS            VulnerabilityType = "unencrypted-websocket"
	VulnTokenExposure    VulnerabilityType = "token-in-url"
	VulnNoAuthentication VulnerabilityType = "missing-authentication"
	VulnDenialOfService  VulnerabilityType = "denial-of-service"
)

// Vulnerability represents a detected WebSocket vulnerability
type Vulnerability struct {
	finding.Vulnerability
	Type VulnerabilityType
}

// ScanResult represents the result of a WebSocket scan
type ScanResult struct {
	URL             string
	IsWebSocket     bool
	SupportsWS      bool
	SupportsWSS     bool
	Vulnerabilities []Vulnerability
	StartTime       time.Time
	Duration        time.Duration
}

// TesterConfig holds configuration for the WebSocket tester
type TesterConfig struct {
	attackconfig.Base
	TestOrigins []string // Origins to test for bypass
}

// Tester provides WebSocket security testing capabilities
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Base: attackconfig.Base{
			Timeout:   duration.HTTPFuzzing,
			UserAgent: ui.UserAgent(),
		},
		TestOrigins: []string{
			"https://evil.com",
			"https://attacker.com",
			"null",
			"file://",
		},
	}
}

// NewTester creates a new WebSocket tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = httpclient.New(httpclient.WithTimeout(config.Timeout))
	}

	return &Tester{
		config: config,
		client: client,
	}
}

// generateWebSocketKey generates a random WebSocket key.
// Returns an error if cryptographic randomness is unavailable.
func generateWebSocketKey() (string, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generating WebSocket key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// computeAcceptKey computes the expected Sec-WebSocket-Accept value
func computeAcceptKey(key string) string {
	magic := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// CheckWebSocket checks if a URL supports WebSocket
func (t *Tester) CheckWebSocket(ctx context.Context, targetURL string) (bool, error) {
	// Use HTTP URL for request (WebSocket handshake happens over HTTP)
	httpURL := t.wsToHTTP(targetURL)

	req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
	if err != nil {
		return false, err
	}

	key, err := generateWebSocketKey()
	if err != nil {
		return false, err
	}

	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return false, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Check for 101 Switching Protocols
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// Validate Sec-WebSocket-Accept header per RFC 6455 §4.2.2
		expectedAccept := computeAcceptKey(key)
		actualAccept := resp.Header.Get("Sec-WebSocket-Accept")
		if actualAccept != "" && actualAccept != expectedAccept {
			return false, nil // Invalid accept key — not a valid WebSocket upgrade
		}
		return true, nil
	}

	// Check for WebSocket upgrade header in response
	upgrade := resp.Header.Get("Upgrade")
	if strings.EqualFold(upgrade, "websocket") {
		return true, nil
	}

	return false, nil
}

// httpToWS converts HTTP URL to WebSocket URL for display
func (t *Tester) httpToWS(httpURL string) string {
	u, err := url.Parse(httpURL)
	if err != nil {
		return httpURL
	}

	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "wss", "ws":
		// Already WebSocket
	default:
		u.Scheme = "ws"
	}

	return u.String()
}

// wsToHTTP converts WebSocket URL to HTTP URL for requests
func (t *Tester) wsToHTTP(wsURL string) string {
	u, err := url.Parse(wsURL)
	if err != nil {
		return wsURL
	}

	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}

	return u.String()
}

// TestOriginValidation tests if the WebSocket endpoint validates Origin
func (t *Tester) TestOriginValidation(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// Use HTTP URL for request
	httpURL := t.wsToHTTP(targetURL)

	for _, origin := range t.config.TestOrigins {
		req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
		if err != nil {
			continue
		}

		key, err := generateWebSocketKey()
		if err != nil {
			return nil, err
		}

		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Key", key)
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Origin", origin)
		req.Header.Set("User-Agent", t.config.UserAgent)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		// Store values we need before closing
		statusCode := resp.StatusCode
		secWSAccept := resp.Header.Get("Sec-WebSocket-Accept")

		// Don't try to read body on WebSocket upgrade - just close it
		iohelper.DrainAndClose(resp.Body)

		// If we get 101 with evil origin, it's vulnerable
		if statusCode == http.StatusSwitchingProtocols {
			vulns = append(vulns, Vulnerability{
				Vulnerability: finding.Vulnerability{
					Description: fmt.Sprintf("WebSocket accepts connection from origin: %s", origin),
					Severity:    finding.High,
					URL:         targetURL,
					Evidence:    fmt.Sprintf("Status: %d, Origin: %s", statusCode, origin),
					Remediation: GetOriginRemediation(),
					CVSS:        7.4,
				},
				Type: VulnOriginValidation,
			})
		}

		// Check if Sec-WebSocket-Accept matches expected key (upgrade truly accepted)
		expectedAccept := computeAcceptKey(key)
		if secWSAccept != "" && secWSAccept == expectedAccept {
			vulns = append(vulns, Vulnerability{
				Vulnerability: finding.Vulnerability{
					Description: fmt.Sprintf("Cross-site WebSocket hijacking possible with origin: %s", origin),
					Severity:    finding.Critical,
					URL:         targetURL,
					Evidence:    fmt.Sprintf("Sec-WebSocket-Accept: %s", secWSAccept),
					Remediation: GetCSWSRemediation(),
					CVSS:        8.1,
				},
				Type: VulnCSWS,
			})
		}
	}

	return vulns, nil
}

// TestTLS checks if WebSocket uses encryption
func (t *Tester) TestTLS(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Check if using unencrypted WebSocket
	if u.Scheme == "ws" || u.Scheme == "http" {
		// Build HTTP URL for the actual request
		httpURL := "http://" + u.Host + u.Path
		if u.RawQuery != "" {
			httpURL += "?" + u.RawQuery
		}

		req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
		if err != nil {
			return vulns, err
		}

		wsKey, err := generateWebSocketKey()
		if err != nil {
			return nil, fmt.Errorf("generating WebSocket key: %w", err)
		}

		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Key", wsKey)
		req.Header.Set("Sec-WebSocket-Version", "13")

		resp, err := t.client.Do(req)
		if err == nil {
			iohelper.DrainAndClose(resp.Body)
			if resp.StatusCode == http.StatusSwitchingProtocols {
				vulns = append(vulns, Vulnerability{
					Vulnerability: finding.Vulnerability{
						Description: "WebSocket connection without TLS encryption",
						Severity:    finding.Medium,
						URL:         targetURL,
						Evidence:    "Server accepts ws:// connections",
						Remediation: GetTLSRemediation(),
						CVSS:        5.3,
					},
					Type: VulnNoTLS,
				})
			}
		}
	}

	return vulns, nil
}

// TestTokenInURL checks if tokens are exposed in WebSocket URL
func (t *Tester) TestTokenInURL(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Patterns for sensitive data in URL
	sensitivePatterns := []string{
		`(?i)(token|jwt|auth|key|session|sid|api_?key)=[^&]+`,
		`(?i)bearer[=\s][^&]+`,
		`(?i)password=[^&]+`,
		`(?i)secret=[^&]+`,
	}

	queryStr := u.RawQuery
	for _, pattern := range sensitivePatterns {
		re := regexcache.MustGet(pattern)
		if match := re.FindString(queryStr); match != "" {
			vulns = append(vulns, Vulnerability{
				Vulnerability: finding.Vulnerability{
					Description: "Sensitive token exposed in WebSocket URL",
					Severity:    finding.Medium,
					URL:         targetURL,
					Evidence:    fmt.Sprintf("Found: %s", match),
					Remediation: GetTokenRemediation(),
					CVSS:        5.3,
				},
				Type: VulnTokenExposure,
			})
		}
	}

	return vulns, nil
}

// Scan performs a full WebSocket security scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		URL:       targetURL,
		StartTime: startTime,
	}

	// Check if URL supports WebSocket
	isWS, err := t.CheckWebSocket(ctx, targetURL)
	if err != nil { //nolint:nilerr // intentional: check failure means not WebSocket
		result.Duration = time.Since(startTime)
		return result, nil
	}
	result.IsWebSocket = isWS

	u, _ := url.Parse(targetURL)
	if u != nil {
		result.SupportsWSS = u.Scheme == "https" || u.Scheme == "wss"
		result.SupportsWS = u.Scheme == "http" || u.Scheme == "ws"
	}

	if !isWS {
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// Run origin validation tests
	originVulns, _ := t.TestOriginValidation(ctx, targetURL)
	result.Vulnerabilities = append(result.Vulnerabilities, originVulns...)

	// Run TLS tests
	tlsVulns, _ := t.TestTLS(ctx, targetURL)
	result.Vulnerabilities = append(result.Vulnerabilities, tlsVulns...)

	// Check for tokens in URL
	tokenVulns, _ := t.TestTokenInURL(ctx, targetURL)
	result.Vulnerabilities = append(result.Vulnerabilities, tokenVulns...)

	result.Duration = time.Since(startTime)
	return result, nil
}

// AllVulnerabilityTypes returns all WebSocket vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnOriginValidation,
		VulnCSWS,
		VulnMessageInjection,
		VulnNoTLS,
		VulnTokenExposure,
		VulnNoAuthentication,
		VulnDenialOfService,
	}
}

// GetOriginRemediation returns remediation for Origin validation bypass
func GetOriginRemediation() string {
	return `1. Implement strict Origin header validation
2. Maintain a whitelist of allowed origins
3. Reject connections from null or unexpected origins
4. Use CSRF tokens for WebSocket handshake
5. Implement additional authentication in WebSocket messages`
}

// GetCSWSRemediation returns remediation for Cross-Site WebSocket Hijacking
func GetCSWSRemediation() string {
	return `1. Validate Origin header against trusted domains
2. Implement CSRF protection tokens
3. Use SameSite cookie attribute
4. Require re-authentication for sensitive operations
5. Don't rely solely on cookies for WebSocket authentication`
}

// GetTLSRemediation returns remediation for unencrypted WebSocket
func GetTLSRemediation() string {
	return `1. Use wss:// instead of ws://
2. Redirect all ws:// connections to wss://
3. Implement HSTS to prevent downgrade attacks
4. Ensure TLS 1.2+ is used
5. Use secure cipher suites`
}

// GetTokenRemediation returns remediation for token exposure in URL
func GetTokenRemediation() string {
	return `1. Pass tokens in Sec-WebSocket-Protocol header
2. Use first WebSocket message for authentication
3. Implement token exchange after handshake
4. Use short-lived tokens for URL parameters
5. Log and monitor token usage patterns`
}

// IsWebSocketEndpoint checks if a URL likely serves WebSocket
func IsWebSocketEndpoint(urlStr string) bool {
	indicators := []string{
		"/ws", "/wss", "/websocket",
		"/socket", "/socket.io",
		"/signalr", "/hub",
		"/realtime", "/live",
		"/stream", "/feed",
		"/chat", "/notifications",
	}

	lower := strings.ToLower(urlStr)
	for _, indicator := range indicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	return u.Scheme == "ws" || u.Scheme == "wss"
}

// CommonWebSocketPaths returns common WebSocket endpoint paths
func CommonWebSocketPaths() []string {
	return []string{
		"/ws",
		"/wss",
		"/websocket",
		"/socket",
		"/socket.io",
		"/socket.io/",
		"/sockjs",
		"/signalr",
		"/signalr/",
		"/hub",
		"/graphql",
		"/subscriptions",
		"/realtime",
		"/live",
		"/stream",
		"/chat",
		"/notifications",
		"/events",
	}
}

// GenerateMaliciousMessages generates payloads for message injection testing
func GenerateMaliciousMessages() []string {
	return []string{
		// JSON injection
		`{"type":"admin","action":"delete"}`,
		`{"__proto__":{"admin":true}}`,
		`{"constructor":{"prototype":{"admin":true}}}`,

		// Command injection in messages
		`{"cmd":"exec","data":"; cat /etc/passwd"}`,
		`{"script":"<script>alert(1)</script>"}`,

		// Large message (DoS)
		strings.Repeat("A", 1024*1024),

		// Unicode attacks
		`{"data":"\u0000\u0001\u0002"}`,

		// SQLi in messages
		`{"id":"1' OR '1'='1"}`,

		// Path traversal
		`{"file":"../../../etc/passwd"}`,
	}
}
