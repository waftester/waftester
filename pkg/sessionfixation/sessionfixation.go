// Package sessionfixation provides Session Fixation vulnerability testing
package sessionfixation

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures session fixation testing
type Config struct {
	attackconfig.Base
	Headers map[string]string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Base: attackconfig.Base{
			Concurrency: defaults.ConcurrencyLow,
			Timeout:     httpclient.TimeoutScanning,
		},
	}
}

// Result represents a session fixation test result
type Result struct {
	URL                string
	SessionCookie      string
	PreAuthSession     string
	PostAuthSession    string
	SessionRegenerated bool
	Vulnerable         bool
	Evidence           string
	Severity           finding.Severity
	Timestamp          time.Time
}

// Scanner performs session fixation testing
type Scanner struct {
	config  Config
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new session fixation scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyLow
	}
	if config.Timeout <= 0 {
		config.Timeout = httpclient.TimeoutScanning
	}

	return &Scanner{
		config:  config,
		results: make([]Result, 0),
	}
}

// Scan tests for session fixation vulnerability
func (s *Scanner) Scan(ctx context.Context, loginURL string, credentials url.Values) (Result, error) {
	result := Result{
		URL:       loginURL,
		Timestamp: time.Now(),
	}

	jar, _ := cookiejar.New(nil)
	// Create a dedicated client for this scan — mutating httpclient.Default()'s
	// Jar field would be a data race affecting all concurrent HTTP callers.
	client := httpclient.New(httpclient.DefaultConfig())
	client.Jar = jar

	// Step 1: Get initial session (pre-auth)
	preReq, err := http.NewRequestWithContext(ctx, "GET", loginURL, nil)
	if err != nil {
		return result, err
	}
	for k, v := range s.config.Headers {
		preReq.Header.Set(k, v)
	}

	preResp, err := client.Do(preReq)
	if err != nil {
		return result, err
	}
	iohelper.DrainAndClose(preResp.Body)

	preAuthSession := s.extractSession(jar, loginURL)
	result.PreAuthSession = preAuthSession
	result.SessionCookie = s.getSessionCookieName(jar, loginURL)

	if preAuthSession == "" {
		// No session before auth, try to set one
		fixedSession := "FIXATED_SESSION_" + time.Now().Format("20060102150405")
		s.setSession(jar, loginURL, result.SessionCookie, fixedSession)
		result.PreAuthSession = fixedSession
	}

	// Step 2: Perform login
	loginReq, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(credentials.Encode()))
	if err != nil {
		return result, err
	}
	loginReq.Header.Set("Content-Type", defaults.ContentTypeForm)
	for k, v := range s.config.Headers {
		loginReq.Header.Set(k, v)
	}

	loginResp, err := client.Do(loginReq)
	if err != nil {
		return result, err
	}
	iohelper.ReadBodyDefault(loginResp.Body)
	iohelper.DrainAndClose(loginResp.Body)

	// Step 3: Check if session changed after auth
	postAuthSession := s.extractSession(jar, loginURL)
	result.PostAuthSession = postAuthSession

	// Check whether the server actually set a session cookie in the login response.
	// Without this check, we'd false-positive on sites that don't use session cookies
	// (our injected fixated session would remain unchanged in the jar).
	serverSetSession := s.responseSetSessionCookie(loginResp)

	// Determine if vulnerable
	if result.PreAuthSession != "" && result.PostAuthSession != "" {
		if result.PreAuthSession == result.PostAuthSession {
			if serverSetSession || preAuthSession != "" {
				// Session was NOT regenerated after authentication — vulnerable
				result.Vulnerable = true
				result.SessionRegenerated = false
				result.Evidence = "Session not regenerated after authentication"
				result.Severity = finding.High
				s.config.NotifyVulnerabilityFound()
			} else {
				// Server never sent a session cookie; our injected value
				// stayed in the jar but was never accepted by the server.
				result.SessionRegenerated = false
				result.Evidence = "Server did not set a session cookie; cannot confirm fixation"
			}
		} else {
			result.SessionRegenerated = true
			result.Evidence = "Session properly regenerated"
		}
	}

	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()

	return result, nil
}

// extractSession extracts session ID from cookies
func (s *Scanner) extractSession(jar *cookiejar.Jar, targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	for _, cookie := range jar.Cookies(u) {
		if s.isSessionCookie(cookie.Name) {
			return cookie.Value
		}
	}
	return ""
}

// getSessionCookieName returns the name of the session cookie
func (s *Scanner) getSessionCookieName(jar *cookiejar.Jar, targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "session"
	}

	for _, cookie := range jar.Cookies(u) {
		if s.isSessionCookie(cookie.Name) {
			return cookie.Name
		}
	}
	return "session"
}

// setSession manually sets a session cookie
func (s *Scanner) setSession(jar *cookiejar.Jar, targetURL, cookieName, value string) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	cookie := &http.Cookie{
		Name:  cookieName,
		Value: value,
	}
	jar.SetCookies(u, []*http.Cookie{cookie})
}

// isSessionCookie checks if cookie name looks like a session cookie
func (s *Scanner) isSessionCookie(name string) bool {
	nameLower := strings.ToLower(name)
	sessionPatterns := []string{
		"session",
		"sessid",
		"sid",
		"phpsessid",
		"jsessionid",
		"asp.net_sessionid",
		"aspsessionid",
		"connect.sid",
		"token",
		"auth",
	}

	for _, pattern := range sessionPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

// responseSetSessionCookie checks if the HTTP response included a Set-Cookie header
// for a session cookie. This distinguishes servers that actually manage sessions
// from those that never set session cookies (avoiding false positives).
func (s *Scanner) responseSetSessionCookie(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	for _, cookie := range resp.Cookies() {
		if s.isSessionCookie(cookie.Name) {
			return true
		}
	}
	return false
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// CommonSessionCookieNames returns common session cookie names
func CommonSessionCookieNames() []string {
	return []string{
		"PHPSESSID",
		"JSESSIONID",
		"ASP.NET_SessionId",
		"ASPSESSIONID",
		"CFID",
		"CFTOKEN",
		"connect.sid",
		"session",
		"sessionid",
		"session_id",
		"sid",
		"_session",
		"_session_id",
		"laravel_session",
		"rack.session",
		"_rails_session",
		"user_session",
		"express:sess",
	}
}

// FixationPayloads returns session fixation attack payloads
func FixationPayloads() []string {
	return []string{
		"FIXED_SESSION_123",
		"' OR '1'='1",
		"attacker_session",
		"../../etc/passwd",
		"<script>alert(1)</script>",
	}
}
