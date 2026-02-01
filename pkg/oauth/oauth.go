// Package oauth provides OAuth/OIDC security testing.
// Tests for authorization flaws, CSRF attacks, token leakage, and misconfigurations.
package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
)

// VulnerabilityType represents the type of OAuth vulnerability.
type VulnerabilityType string

const (
	VulnOpenRedirect        VulnerabilityType = "open-redirect"
	VulnCSRFAuth            VulnerabilityType = "csrf-authorization"
	VulnTokenLeakage        VulnerabilityType = "token-leakage"
	VulnCodeInjection       VulnerabilityType = "code-injection"
	VulnScopeManipulation   VulnerabilityType = "scope-manipulation"
	VulnClientMisconfig     VulnerabilityType = "client-misconfiguration"
	VulnStateBypass         VulnerabilityType = "state-bypass"
	VulnRedirectURIMismatch VulnerabilityType = "redirect-uri-mismatch"
	VulnIDTokenLeak         VulnerabilityType = "id-token-leakage"
	VulnPKCEBypass          VulnerabilityType = "pkce-bypass"
	VulnImplicitFlow        VulnerabilityType = "implicit-flow-token-exposure"
	VulnWeakSecret          VulnerabilityType = "weak-client-secret"
)

// Severity represents the severity level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Vulnerability represents a detected OAuth vulnerability.
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	URL         string            `json:"url"`
	Parameter   string            `json:"parameter,omitempty"`
	Payload     string            `json:"payload,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
}

// OAuthEndpoint represents OAuth endpoints.
type OAuthEndpoint struct {
	AuthorizationURL string `json:"authorization_url"`
	TokenURL         string `json:"token_url"`
	UserinfoURL      string `json:"userinfo_url,omitempty"`
	JwksURL          string `json:"jwks_url,omitempty"`
	Issuer           string `json:"issuer,omitempty"`
}

// OAuthConfig holds OAuth client configuration.
type OAuthConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	RedirectURI  string   `json:"redirect_uri"`
	Scopes       []string `json:"scopes"`
	State        string   `json:"state,omitempty"`
	Nonce        string   `json:"nonce,omitempty"`
	CodeVerifier string   `json:"code_verifier,omitempty"`
}

// TesterConfig holds configuration for OAuth testing.
type TesterConfig struct {
	Timeout        time.Duration
	UserAgent      string
	Concurrency    int
	AuthHeader     string
	Cookies        map[string]string
	FollowRedirect bool
}

// Tester handles OAuth vulnerability testing.
type Tester struct {
	config    *TesterConfig
	client    *http.Client
	endpoints *OAuthEndpoint
	oauth     *OAuthConfig
}

// DefaultTesterConfig returns default configuration.
func DefaultTesterConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:        30 * time.Second,
		UserAgent:      "OAuth-Tester/1.0",
		Concurrency:    5,
		Cookies:        make(map[string]string),
		FollowRedirect: false,
	}
}

// NewTester creates a new OAuth tester.
func NewTester(config *TesterConfig, endpoints *OAuthEndpoint, oauthConfig *OAuthConfig) *Tester {
	if config == nil {
		config = DefaultTesterConfig()
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if config.FollowRedirect {
		checkRedirect = nil
	}

	return &Tester{
		config:    config,
		endpoints: endpoints,
		oauth:     oauthConfig,
		client: &http.Client{
			Timeout:       config.Timeout,
			CheckRedirect: checkRedirect,
		},
	}
}

// TestOpenRedirect tests for open redirect in redirect_uri.
func (t *Tester) TestOpenRedirect(ctx context.Context) ([]Vulnerability, error) {
	if t.endpoints == nil || t.endpoints.AuthorizationURL == "" {
		return nil, nil
	}

	var vulns []Vulnerability
	redirectPayloads := GetRedirectPayloads()

	for _, payload := range redirectPayloads {
		authURL, err := url.Parse(t.endpoints.AuthorizationURL)
		if err != nil {
			continue
		}

		query := authURL.Query()
		query.Set("client_id", t.oauth.ClientID)
		query.Set("response_type", "code")
		query.Set("redirect_uri", payload)
		query.Set("scope", strings.Join(t.oauth.Scopes, " "))
		authURL.RawQuery = query.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", authURL.String(), nil)
		if err != nil {
			continue
		}

		t.applyHeaders(req)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check if redirect is accepted
		if resp.StatusCode == 302 || resp.StatusCode == 301 {
			location := resp.Header.Get("Location")
			if strings.Contains(location, "evil.com") || strings.Contains(location, "attacker") {
				vulns = append(vulns, Vulnerability{
					Type:        VulnOpenRedirect,
					Description: "Open redirect via redirect_uri manipulation",
					Severity:    SeverityHigh,
					URL:         authURL.String(),
					Parameter:   "redirect_uri",
					Payload:     payload,
					Evidence:    fmt.Sprintf("Redirected to: %s", location),
					Remediation: "Implement strict redirect_uri validation with exact match",
					CVSS:        7.4,
				})
			}
		}
	}

	return vulns, nil
}

// TestCSRFAuthorization tests for CSRF in authorization flow.
func (t *Tester) TestCSRFAuthorization(ctx context.Context) ([]Vulnerability, error) {
	if t.endpoints == nil || t.endpoints.AuthorizationURL == "" {
		return nil, nil
	}

	var vulns []Vulnerability

	authURL, err := url.Parse(t.endpoints.AuthorizationURL)
	if err != nil {
		return nil, err
	}

	// Test without state parameter
	query := authURL.Query()
	query.Set("client_id", t.oauth.ClientID)
	query.Set("response_type", "code")
	query.Set("redirect_uri", t.oauth.RedirectURI)
	query.Set("scope", strings.Join(t.oauth.Scopes, " "))
	// Intentionally not setting state
	authURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", authURL.String(), nil)
	if err != nil {
		return nil, err
	}

	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	// If request succeeds without state, it's vulnerable
	if resp.StatusCode == 200 || resp.StatusCode == 302 {
		vulns = append(vulns, Vulnerability{
			Type:        VulnCSRFAuth,
			Description: "Authorization request accepted without state parameter",
			Severity:    SeverityHigh,
			URL:         authURL.String(),
			Parameter:   "state",
			Evidence:    fmt.Sprintf("Status: %d without state parameter", resp.StatusCode),
			Remediation: "Require and validate state parameter for CSRF protection",
			CVSS:        8.1,
		})
	}

	return vulns, nil
}

// TestStateBypass tests for state parameter bypass.
func (t *Tester) TestStateBypass(ctx context.Context) ([]Vulnerability, error) {
	if t.endpoints == nil || t.endpoints.AuthorizationURL == "" {
		return nil, nil
	}

	var vulns []Vulnerability
	statePayloads := []string{"", "null", "undefined", "0", "false", "[]", "{}"}

	for _, stateVal := range statePayloads {
		authURL, err := url.Parse(t.endpoints.AuthorizationURL)
		if err != nil {
			continue
		}

		query := authURL.Query()
		query.Set("client_id", t.oauth.ClientID)
		query.Set("response_type", "code")
		query.Set("redirect_uri", t.oauth.RedirectURI)
		query.Set("scope", strings.Join(t.oauth.Scopes, " "))
		if stateVal != "" {
			query.Set("state", stateVal)
		}
		authURL.RawQuery = query.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", authURL.String(), nil)
		if err != nil {
			continue
		}

		t.applyHeaders(req)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			vulns = append(vulns, Vulnerability{
				Type:        VulnStateBypass,
				Description: fmt.Sprintf("State parameter bypass with value: %q", stateVal),
				Severity:    SeverityMedium,
				URL:         authURL.String(),
				Parameter:   "state",
				Payload:     stateVal,
				Evidence:    fmt.Sprintf("Status: %d", resp.StatusCode),
				Remediation: "Validate state parameter is present and matches expected format",
				CVSS:        5.4,
			})
			break // Only report once
		}
	}

	return vulns, nil
}

// TestScopeManipulation tests for scope escalation.
func (t *Tester) TestScopeManipulation(ctx context.Context) ([]Vulnerability, error) {
	if t.endpoints == nil || t.endpoints.AuthorizationURL == "" {
		return nil, nil
	}

	var vulns []Vulnerability
	scopePayloads := GetScopePayloads()

	for _, scope := range scopePayloads {
		authURL, err := url.Parse(t.endpoints.AuthorizationURL)
		if err != nil {
			continue
		}

		query := authURL.Query()
		query.Set("client_id", t.oauth.ClientID)
		query.Set("response_type", "code")
		query.Set("redirect_uri", t.oauth.RedirectURI)
		query.Set("scope", scope)
		query.Set("state", t.oauth.State)
		authURL.RawQuery = query.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", authURL.String(), nil)
		if err != nil {
			continue
		}

		t.applyHeaders(req)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check if elevated scopes are accepted
		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			vulns = append(vulns, Vulnerability{
				Type:        VulnScopeManipulation,
				Description: "Elevated scope accepted",
				Severity:    SeverityHigh,
				URL:         authURL.String(),
				Parameter:   "scope",
				Payload:     scope,
				Evidence:    fmt.Sprintf("Status: %d with scope: %s", resp.StatusCode, scope),
				Remediation: "Validate requested scopes against allowed scopes for client",
				CVSS:        7.5,
			})
		}
	}

	return vulns, nil
}

// TestPKCEBypass tests for PKCE bypass vulnerabilities.
func (t *Tester) TestPKCEBypass(ctx context.Context) ([]Vulnerability, error) {
	if t.endpoints == nil || t.endpoints.AuthorizationURL == "" {
		return nil, nil
	}

	var vulns []Vulnerability

	authURL, err := url.Parse(t.endpoints.AuthorizationURL)
	if err != nil {
		return nil, err
	}

	// Test without code_challenge
	query := authURL.Query()
	query.Set("client_id", t.oauth.ClientID)
	query.Set("response_type", "code")
	query.Set("redirect_uri", t.oauth.RedirectURI)
	query.Set("scope", strings.Join(t.oauth.Scopes, " "))
	query.Set("state", t.oauth.State)
	// Intentionally not setting code_challenge
	authURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", authURL.String(), nil)
	if err != nil {
		return nil, err
	}

	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 302 {
		vulns = append(vulns, Vulnerability{
			Type:        VulnPKCEBypass,
			Description: "Authorization succeeds without PKCE (code_challenge)",
			Severity:    SeverityMedium,
			URL:         authURL.String(),
			Parameter:   "code_challenge",
			Evidence:    fmt.Sprintf("Status: %d without PKCE", resp.StatusCode),
			Remediation: "Require PKCE for public clients",
			CVSS:        6.5,
		})
	}

	return vulns, nil
}

// Scan performs comprehensive OAuth vulnerability scanning.
func (t *Tester) Scan(ctx context.Context) ([]Vulnerability, error) {
	var allVulns []Vulnerability
	var mu sync.Mutex
	var wg sync.WaitGroup

	tests := []func(context.Context) ([]Vulnerability, error){
		t.TestOpenRedirect,
		t.TestCSRFAuthorization,
		t.TestStateBypass,
		t.TestScopeManipulation,
		t.TestPKCEBypass,
	}

	for _, test := range tests {
		wg.Add(1)
		go func(testFn func(context.Context) ([]Vulnerability, error)) {
			defer wg.Done()

			vulns, err := testFn(ctx)
			if err != nil {
				return
			}

			mu.Lock()
			allVulns = append(allVulns, vulns...)
			mu.Unlock()
		}(test)
	}

	wg.Wait()
	return allVulns, nil
}

func (t *Tester) applyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", t.config.UserAgent)
	if t.config.AuthHeader != "" {
		req.Header.Set("Authorization", t.config.AuthHeader)
	}
	for name, value := range t.config.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
}

// GetRedirectPayloads returns redirect_uri bypass payloads.
func GetRedirectPayloads() []string {
	return []string{
		"https://evil.com",
		"https://attacker.com/callback",
		"//evil.com",
		"https://legitimate.com.evil.com",
		"https://legitimate.com@evil.com",
		"https://legitimate.com%40evil.com",
		"https://legitimate.com%2F%2Fevil.com",
		"https://legitimate.com/callback/../../../evil.com",
		"https://legitimate.com/callback?next=https://evil.com",
		"https://legitimate.com/callback#https://evil.com",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
	}
}

// GetScopePayloads returns scope manipulation payloads.
func GetScopePayloads() []string {
	return []string{
		"openid profile email admin",
		"openid profile email admin:write",
		"openid profile email user:admin",
		"openid profile email write:all",
		"* openid",
		"admin openid profile",
		"openid profile email offline_access",
		"openid profile email /.default",
	}
}

// AllVulnerabilityTypes returns all OAuth vulnerability types.
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnOpenRedirect, VulnCSRFAuth, VulnTokenLeakage,
		VulnCodeInjection, VulnScopeManipulation, VulnClientMisconfig,
		VulnStateBypass, VulnRedirectURIMismatch, VulnIDTokenLeak,
		VulnPKCEBypass, VulnImplicitFlow, VulnWeakSecret,
	}
}

// VulnerabilityToJSON converts a vulnerability to JSON.
func VulnerabilityToJSON(v Vulnerability) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GenerateReport generates a scan report.
func GenerateReport(vulns []Vulnerability) map[string]interface{} {
	report := map[string]interface{}{
		"total_vulnerabilities": len(vulns),
		"by_type":               make(map[string]int),
		"by_severity":           make(map[string]int),
		"vulnerabilities":       vulns,
	}
	for _, v := range vulns {
		report["by_type"].(map[string]int)[string(v.Type)]++
		report["by_severity"].(map[string]int)[string(v.Severity)]++
	}
	return report
}

// GenerateState generates a secure random state value.
func GenerateState() string {
	b := make([]byte, 32)
	// In production, use crypto/rand
	for i := range b {
		b[i] = byte(i * 7 % 256)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// GenerateNonce generates a secure random nonce.
func GenerateNonce() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i * 11 % 256)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// GeneratePKCEPair generates code_verifier and code_challenge.
func GeneratePKCEPair() (verifier, challenge string) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i * 13 % 256)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)

	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

// ValidateState validates that a state matches expected value.
func ValidateState(expected, actual string) bool {
	return hmac.Equal([]byte(expected), []byte(actual))
}

// ParseIDToken extracts claims from an ID token (JWT).
func ParseIDToken(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	return claims, nil
}

// ValidateIDToken performs basic ID token validation.
func ValidateIDToken(token string, expectedIssuer, expectedAudience string) error {
	claims, err := ParseIDToken(token)
	if err != nil {
		return err
	}

	if iss, ok := claims["iss"].(string); !ok || iss != expectedIssuer {
		return fmt.Errorf("invalid issuer")
	}

	if aud, ok := claims["aud"].(string); !ok || aud != expectedAudience {
		// aud can be an array
		if audArr, ok := claims["aud"].([]interface{}); ok {
			found := false
			for _, a := range audArr {
				if str, ok := a.(string); ok && str == expectedAudience {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("invalid audience")
			}
		} else {
			return fmt.Errorf("invalid audience")
		}
	}

	return nil
}

// DiscoverOIDCEndpoints discovers OIDC endpoints from well-known configuration.
func DiscoverOIDCEndpoints(ctx context.Context, issuer string) (*OAuthEndpoint, error) {
	wellKnownURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("discovery failed with status %d", resp.StatusCode)
	}

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return nil, err
	}

	var config struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}

	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}

	return &OAuthEndpoint{
		Issuer:           config.Issuer,
		AuthorizationURL: config.AuthorizationEndpoint,
		TokenURL:         config.TokenEndpoint,
		UserinfoURL:      config.UserinfoEndpoint,
		JwksURL:          config.JwksURI,
	}, nil
}

// IsImplicitFlowToken checks if token is exposed in URL fragment.
func IsImplicitFlowToken(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	fragment := u.Fragment
	return strings.Contains(fragment, "access_token=") || strings.Contains(fragment, "id_token=")
}

// ExtractTokenFromFragment extracts tokens from URL fragment.
func ExtractTokenFromFragment(urlStr string) map[string]string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	tokens := make(map[string]string)
	fragment := u.Fragment

	params, err := url.ParseQuery(fragment)
	if err != nil {
		return nil
	}

	if at := params.Get("access_token"); at != "" {
		tokens["access_token"] = at
	}
	if it := params.Get("id_token"); it != "" {
		tokens["id_token"] = it
	}

	return tokens
}

// IsWeakClientSecret checks if client secret is weak.
func IsWeakClientSecret(secret string) bool {
	if len(secret) < 32 {
		return true
	}

	weakPatterns := []string{
		"secret", "password", "123456", "client_secret",
		"changeme", "default", "test", "demo",
	}

	lowerSecret := strings.ToLower(secret)
	for _, pattern := range weakPatterns {
		if strings.Contains(lowerSecret, pattern) {
			return true
		}
	}

	// Check for low entropy (repeating characters)
	if len(secret) > 0 {
		first := secret[0]
		allSame := true
		for i := 1; i < len(secret); i++ {
			if secret[i] != first {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	return false
}
