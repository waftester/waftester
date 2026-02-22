// Package brokenauth provides Broken Authentication testing
package brokenauth

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures broken authentication testing
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

// Result represents a broken authentication test result
type Result struct {
	URL          string
	TestType     string
	Description  string
	StatusCode   int
	ResponseSize int
	Vulnerable   bool
	Evidence     string
	Severity     string
	Timestamp    time.Time
}

// Scanner performs broken authentication testing
type Scanner struct {
	config  Config
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new broken authentication scanner
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

// TestSessionManagement tests for session management issues
func (s *Scanner) TestSessionManagement(ctx context.Context, loginURL string, credentials url.Values) ([]Result, error) {
	results := make([]Result, 0)

	jar, _ := cookiejar.New(nil)
	client := httpclient.Scanning()
	client.Jar = jar

	// Login
	loginReq, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(credentials.Encode()))
	if err != nil {
		return nil, err
	}
	loginReq.Header.Set("Content-Type", defaults.ContentTypeForm)
	for k, v := range s.config.Headers {
		loginReq.Header.Set(k, v)
	}

	loginResp, err := client.Do(loginReq)
	if err != nil {
		return nil, err
	}
	iohelper.ReadBodyDefault(loginResp.Body)
	iohelper.DrainAndClose(loginResp.Body)

	// Check for weak session tokens
	u, err := url.Parse(loginURL)
	if err == nil {
		for _, cookie := range jar.Cookies(u) {
			if isSessionCookie(cookie.Name) {
				result := s.analyzeSessionToken(cookie)
				results = append(results, result)
			}
		}
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

func (s *Scanner) analyzeSessionToken(cookie *http.Cookie) Result {
	result := Result{
		URL:         cookie.Name,
		TestType:    "session_analysis",
		Description: "Session token analysis",
		Timestamp:   time.Now(),
	}

	issues := make([]string, 0)

	// Check token length
	if len(cookie.Value) < 32 {
		issues = append(issues, "short token length")
	}

	// Check for HttpOnly flag
	if !cookie.HttpOnly {
		issues = append(issues, "missing HttpOnly flag")
	}

	// Check for Secure flag
	if !cookie.Secure {
		issues = append(issues, "missing Secure flag")
	}

	// Check SameSite
	if cookie.SameSite == http.SameSiteNoneMode || cookie.SameSite == 0 {
		issues = append(issues, "weak SameSite attribute")
	}

	if len(issues) > 0 {
		result.Vulnerable = true
		result.Evidence = strings.Join(issues, ", ")
		result.Severity = "high"
		s.config.NotifyVulnerabilityFound()
	}

	return result
}

// TestPasswordPolicy tests for weak password policy
func (s *Scanner) TestPasswordPolicy(ctx context.Context, registerURL string) ([]Result, error) {
	results := make([]Result, 0)

	weakPasswords := WeakPasswords()

	client := httpclient.Default()

	for _, pwd := range weakPasswords {
		result := Result{
			URL:         registerURL,
			TestType:    "weak_password",
			Description: "Testing weak password: " + pwd,
			Timestamp:   time.Now(),
		}

		data := url.Values{
			"username": {"testuser" + time.Now().Format("150405")},
			"password": {pwd},
			"email":    {"test@example.com"},
		}

		req, err := http.NewRequestWithContext(ctx, "POST", registerURL, strings.NewReader(data.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range s.config.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)

		result.StatusCode = resp.StatusCode
		result.ResponseSize = len(body)

		// If password was accepted
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			result.Vulnerable = true
			result.Evidence = "Weak password accepted: " + pwd
			result.Severity = "medium"
			s.config.NotifyVulnerabilityFound()
		}

		results = append(results, result)
	}

	s.mu.Lock()
	s.results = append(s.results, results...)
	s.mu.Unlock()

	return results, nil
}

// TestAccountLockout tests for account lockout mechanism
func (s *Scanner) TestAccountLockout(ctx context.Context, loginURL string, username string, attempts int) (Result, error) {
	result := Result{
		URL:         loginURL,
		TestType:    "account_lockout",
		Description: "Testing account lockout after " + strconv.Itoa(attempts) + " failed attempts",
		Timestamp:   time.Now(),
	}

	client := httpclient.Default()

	for i := 0; i < attempts; i++ {
		data := url.Values{
			"username": {username},
			"password": {"wrongpassword" + time.Now().Format("150405")},
		}

		req, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(data.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", defaults.ContentTypeForm)
		for k, v := range s.config.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)

		result.StatusCode = resp.StatusCode

		// Check if locked out
		if resp.StatusCode == 423 || resp.StatusCode == 429 {
			// Account lockout detected - good!
			result.Evidence = "Account lockout after " + strconv.Itoa(i+1) + " attempts"
			return result, nil
		}
	}

	// No lockout detected after all attempts
	result.Vulnerable = true
	result.Evidence = "No account lockout after " + strconv.Itoa(attempts) + " failed attempts"
	result.Severity = "high"
	s.config.NotifyVulnerabilityFound()

	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()

	return result, nil
}

func isSessionCookie(name string) bool {
	nameLower := strings.ToLower(name)
	patterns := []string{"session", "sid", "token", "auth"}
	for _, p := range patterns {
		if strings.Contains(nameLower, p) {
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

// WeakPasswords returns common weak passwords
func WeakPasswords() []string {
	return []string{
		"password",
		"123456",
		"admin",
		"12345678",
		"qwerty",
		"abc123",
		"password1",
		"test",
		"1234",
		"letmein",
	}
}

// DefaultCredentials returns common default credentials
func DefaultCredentials() map[string][]string {
	return map[string][]string{
		"admin":         {"admin", "password", "123456", "admin123"},
		"administrator": {"administrator", "password", "admin"},
		"root":          {"root", "toor", "password"},
		"user":          {"user", "password", "123456"},
		"test":          {"test", "test123", "password"},
	}
}

// AuthBypassPayloads returns authentication bypass payloads
func AuthBypassPayloads() []string {
	return []string{
		"' OR '1'='1",
		"' OR '1'='1' --",
		"admin'--",
		"' OR 1=1--",
		"admin' OR '1'='1",
		"') OR ('1'='1",
		"' OR ''='",
	}
}
