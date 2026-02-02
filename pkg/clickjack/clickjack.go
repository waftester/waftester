// Package clickjack provides Clickjacking testing
package clickjack

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Config configures clickjacking testing
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Concurrency: defaults.ConcurrencyMedium,
		Timeout:     httpclient.TimeoutProbing,
	}
}

// Result represents a clickjacking test result
type Result struct {
	URL            string
	XFrameOptions  string
	CSPFrameAncest string
	Frameable      bool
	Vulnerable     bool
	Evidence       string
	Severity       string
	Timestamp      time.Time
}

// Scanner performs clickjacking testing
type Scanner struct {
	config  Config
	client  *http.Client
	results []Result
	mu      sync.RWMutex
}

// NewScanner creates a new clickjacking scanner
func NewScanner(config Config) *Scanner {
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyMedium
	}
	if config.Timeout <= 0 {
		config.Timeout = httpclient.TimeoutProbing
	}

	return &Scanner{
		config:  config,
		client:  httpclient.Default(),
		results: make([]Result, 0),
	}
}

// Scan tests a URL for clickjacking vulnerabilities
func (s *Scanner) Scan(ctx context.Context, targetURL string) (Result, error) {
	result := Result{
		URL:       targetURL,
		Timestamp: time.Now(),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return result, err
	}

	for k, v := range s.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return result, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Check X-Frame-Options
	result.XFrameOptions = resp.Header.Get("X-Frame-Options")

	// Check CSP frame-ancestors
	csp := resp.Header.Get("Content-Security-Policy")
	if strings.Contains(csp, "frame-ancestors") {
		result.CSPFrameAncest = extractFrameAncestors(csp)
	}

	// Determine if frameable
	result.Frameable = s.isFrameable(result.XFrameOptions, result.CSPFrameAncest)
	result.Vulnerable = result.Frameable

	if result.Vulnerable {
		result.Severity = "MEDIUM"
		result.Evidence = s.buildEvidence(result)
	}

	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()

	return result, nil
}

// extractFrameAncestors extracts frame-ancestors directive from CSP
func extractFrameAncestors(csp string) string {
	parts := strings.Split(csp, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "frame-ancestors") {
			return strings.TrimPrefix(part, "frame-ancestors ")
		}
	}
	return ""
}

// isFrameable determines if the page can be framed
func (s *Scanner) isFrameable(xfo, frameAncestors string) bool {
	// If X-Frame-Options is set to DENY or SAMEORIGIN, not frameable
	xfoUpper := strings.ToUpper(xfo)
	if xfoUpper == "DENY" || xfoUpper == "SAMEORIGIN" {
		return false
	}

	// If CSP frame-ancestors is set restrictively, not frameable
	if frameAncestors != "" {
		fa := strings.ToLower(frameAncestors)
		if fa == "'none'" || fa == "'self'" {
			return false
		}
	}

	// No protection = frameable
	return true
}

// buildEvidence builds vulnerability evidence
func (s *Scanner) buildEvidence(result Result) string {
	if result.XFrameOptions == "" && result.CSPFrameAncest == "" {
		return "No X-Frame-Options or CSP frame-ancestors header"
	}
	if result.XFrameOptions != "" && strings.ToUpper(result.XFrameOptions) != "DENY" && strings.ToUpper(result.XFrameOptions) != "SAMEORIGIN" {
		return "Weak X-Frame-Options: " + result.XFrameOptions
	}
	return "Insufficient framing protection"
}

// GetResults returns all results
func (s *Scanner) GetResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Result{}, s.results...)
}

// GeneratePOC generates a clickjacking proof-of-concept
func GeneratePOC(targetURL string) string {
	return `<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        iframe {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.1;
            z-index: 2;
        }
        .decoy {
            position: absolute;
            top: 100px;
            left: 100px;
            z-index: 1;
        }
    </style>
</head>
<body>
    <div class="decoy">
        <h1>Win a Prize!</h1>
        <button>Click Here!</button>
    </div>
    <iframe src="` + targetURL + `"></iframe>
</body>
</html>`
}

// ScanMultiple scans multiple URLs
func (s *Scanner) ScanMultiple(ctx context.Context, urls []string) ([]Result, error) {
	results := make([]Result, 0, len(urls))
	for _, url := range urls {
		result, err := s.Scan(ctx, url)
		if err != nil {
			continue
		}
		results = append(results, result)
	}
	return results, nil
}

// CheckIframeLoad attempts to load the URL in an iframe (simulation)
func (s *Scanner) CheckIframeLoad(ctx context.Context, targetURL string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Read body to check for frame-busting scripts
	body, _ := iohelper.ReadBodyDefault(resp.Body)
	bodyStr := string(body)

	// Check for frame-busting JavaScript patterns
	frameBusters := []string{
		"top.location",
		"parent.location",
		"self !== top",
		"top !== self",
		"frameElement",
	}

	for _, fb := range frameBusters {
		if strings.Contains(bodyStr, fb) {
			return false // Has frame-busting
		}
	}

	return true // No frame-busting detected
}
