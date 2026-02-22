// Package leakypaths implements high-value path scanning based on research
// from the leaky-paths project (https://github.com/ayoubfathi/leaky-paths).
// Contains 1,766+ paths known to expose sensitive information.
package leakypaths

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// Scanner performs leaky path discovery on target URLs
type Scanner struct {
	client               *http.Client
	concurrency          int
	timeout              time.Duration
	userAgent            string
	verbose              bool
	onVulnerabilityFound func()
}

// ScanResult represents the result of scanning a single path
type ScanResult struct {
	Path           string            `json:"path"`
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	ContentLength  int64             `json:"content_length"`
	ContentType    string            `json:"content_type"`
	Interesting    bool              `json:"interesting"`
	Category       string            `json:"category"`
	Severity       string            `json:"severity"`
	Evidence       string            `json:"evidence,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	ResponseSample string            `json:"response_sample,omitempty"`
}

// ScanSummary provides aggregate results from a scan
type ScanSummary struct {
	Target          string         `json:"target"`
	TotalPaths      int            `json:"total_paths"`
	PathsScanned    int            `json:"paths_scanned"`
	InterestingHits int            `json:"interesting_hits"`
	Duration        time.Duration  `json:"duration"`
	Results         []ScanResult   `json:"results"`
	BySeverity      map[string]int `json:"by_severity"`
	ByCategory      map[string]int `json:"by_category"`
}

// Config configures the scanner behavior
type Config struct {
	attackconfig.Base
	Verbose       bool
	SkipTLSVerify bool
	Categories    []string     // Filter by category: "config", "debug", "backup", etc.
	HTTPClient    *http.Client // Optional custom HTTP client (e.g., JA3-aware)
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Base: attackconfig.Base{
			Concurrency: defaults.ConcurrencyHigh,
			Timeout:     duration.DialTimeout,
			UserAgent:   defaults.UAChrome,
		},
		Verbose: false,
	}
}

// NewScanner creates a new leaky paths scanner
func NewScanner(cfg *Config) *Scanner {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Use provided HTTPClient (e.g., JA3-aware) or create default
	var client *http.Client
	if cfg.HTTPClient != nil {
		client = cfg.HTTPClient
	} else {
		client = httpclient.New(httpclient.WithTimeout(cfg.Timeout))
	}

	return &Scanner{
		client:               client,
		concurrency:          cfg.Concurrency,
		timeout:              cfg.Timeout,
		userAgent:            cfg.UserAgent,
		verbose:              cfg.Verbose,
		onVulnerabilityFound: cfg.OnVulnerabilityFound,
	}
}

// Scan scans a target URL for leaky paths
func (s *Scanner) Scan(ctx context.Context, targetURL string, categories ...string) (*ScanSummary, error) {
	start := time.Now()

	// Normalize target URL
	targetURL = strings.TrimSuffix(targetURL, "/")

	// Get paths to scan
	paths := GetPaths(categories...)

	summary := &ScanSummary{
		Target:     targetURL,
		TotalPaths: len(paths),
		Results:    make([]ScanResult, 0),
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
	}

	// Create work channel
	pathsChan := make(chan PathEntry, len(paths))
	resultsChan := make(chan ScanResult, len(paths))

	// Spawn workers
	var wg sync.WaitGroup
	for i := 0; i < s.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathsChan {
				select {
				case <-ctx.Done():
					return
				default:
					result := s.scanPath(ctx, targetURL, path)
					resultsChan <- result
				}
			}
		}()
	}

	// Send work
	go func() {
		for _, path := range paths {
			select {
			case <-ctx.Done():
				close(pathsChan)
				return
			case pathsChan <- path:
			}
		}
		close(pathsChan)
	}()

	// Wait for completion in background
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for result := range resultsChan {
		summary.PathsScanned++
		if result.Interesting {
			summary.Results = append(summary.Results, result)
			summary.InterestingHits++
			summary.BySeverity[result.Severity]++
			summary.ByCategory[result.Category]++
			if s.onVulnerabilityFound != nil {
				s.onVulnerabilityFound()
			}
		}
	}

	summary.Duration = time.Since(start)
	return summary, nil
}

// scanPath checks a single path
func (s *Scanner) scanPath(ctx context.Context, baseURL string, path PathEntry) ScanResult {
	fullURL := baseURL + path.Path

	result := ScanResult{
		Path:     path.Path,
		URL:      fullURL,
		Category: path.Category,
		Severity: path.Severity,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return result
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := s.client.Do(req)
	if err != nil {
		return result
	}
	defer iohelper.DrainAndClose(resp.Body)

	result.StatusCode = resp.StatusCode
	result.ContentLength = resp.ContentLength
	result.ContentType = resp.Header.Get("Content-Type")

	// Determine if this is interesting
	result.Interesting = s.isInteresting(resp, path)

	if result.Interesting {
		// Capture headers and sample
		result.Headers = make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				result.Headers[k] = v[0]
			}
		}

		// Read sample of body
		sample := make([]byte, 1024)
		n, _ := io.ReadAtLeast(resp.Body, sample, 1)
		if n > 0 {
			result.ResponseSample = string(sample[:n])
			result.Evidence = s.extractEvidence(result.ResponseSample, path)
		}
	}

	return result
}

// isInteresting determines if a response indicates a leak
func (s *Scanner) isInteresting(resp *http.Response, path PathEntry) bool {
	// 200 OK is always interesting for sensitive paths
	if resp.StatusCode == 200 {
		contentType := resp.Header.Get("Content-Type")

		// JSON/XML responses from config endpoints
		if path.Category == "config" || path.Category == "api" {
			if strings.Contains(contentType, "json") ||
				strings.Contains(contentType, "xml") ||
				strings.Contains(contentType, "yaml") {
				return true
			}
		}

		// Source code exposure
		if path.Category == "source" {
			return true
		}

		// Debug/admin endpoints
		if path.Category == "debug" || path.Category == "admin" {
			return true
		}

		// Backup files
		if path.Category == "backup" {
			// Check for non-HTML response
			if !strings.Contains(contentType, "text/html") {
				return true
			}
		}

		// Sensitive files should return content
		if resp.ContentLength > 0 {
			return true
		}
	}

	// 401/403 on admin paths indicates they exist
	if (resp.StatusCode == 401 || resp.StatusCode == 403) &&
		(path.Category == "admin" || path.Category == "debug") {
		return true
	}

	// 500 errors on debug endpoints may leak info
	if resp.StatusCode == 500 && path.Category == "debug" {
		return true
	}

	return false
}

// Pre-compiled patterns for extractEvidence (avoid per-call regexp.MustCompile).
var evidencePatterns = map[string]*regexp.Regexp{
	"aws_key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"private_key": regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`),
	"db_url":      regexp.MustCompile(`(?:mysql|postgres|mongodb)://[^\s<>"']+`),
	"api_key":     regexp.MustCompile(`(?i)api[_-]?key['":\s]*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})`),
	"jwt":         regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
	"password":    regexp.MustCompile(`(?i)password['":\s]*[=:]\s*['"]?([^'"<>\s]+)`),
	"secret":      regexp.MustCompile(`(?i)secret['":\s]*[=:]\s*['"]?([^'"<>\s]+)`),
	"token":       regexp.MustCompile(`(?i)token['":\s]*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})`),
	"debug_mode":  regexp.MustCompile(`(?i)debug['":\s]*[=:]\s*['"]?(true|1|yes)`),
	"stack_trace": regexp.MustCompile(`at\s+[\w.]+\([^)]*:\d+:\d+\)`),
	"internal_ip": regexp.MustCompile(`(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}`),
}

// extractEvidence finds specific sensitive data in responses
func (s *Scanner) extractEvidence(body string, path PathEntry) string {
	var evidence []string
	for name, re := range evidencePatterns {
		if matches := re.FindStringSubmatch(body); len(matches) > 0 {
			evidence = append(evidence, fmt.Sprintf("%s found", name))
		}
	}

	if len(evidence) > 0 {
		return strings.Join(evidence, "; ")
	}
	return ""
}

// PathEntry represents a leaky path with metadata
type PathEntry struct {
	Path     string `json:"path"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

// GetPaths returns all paths, optionally filtered by category
func GetPaths(categories ...string) []PathEntry {
	categorySet := make(map[string]bool)
	for _, c := range categories {
		categorySet[strings.ToLower(c)] = true
	}

	var filtered []PathEntry
	for _, p := range allPaths {
		if len(categories) == 0 || categorySet[strings.ToLower(p.Category)] {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// GetCategories returns all available categories
func GetCategories() []string {
	seen := make(map[string]bool)
	var cats []string
	for _, p := range allPaths {
		if !seen[p.Category] {
			seen[p.Category] = true
			cats = append(cats, p.Category)
		}
	}
	return cats
}

// High-value paths from leaky-paths and additional research
// Categories: config, debug, backup, source, admin, api, cloud, ci, vcs
var allPaths = []PathEntry{
	// ═══════════════════════════════════════════════════════════════════════════
	// CONFIGURATION FILES - Critical severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/.env", Category: "config", Severity: "critical"},
	{Path: "/.env.local", Category: "config", Severity: "critical"},
	{Path: "/.env.development", Category: "config", Severity: "critical"},
	{Path: "/.env.production", Category: "config", Severity: "critical"},
	{Path: "/.env.staging", Category: "config", Severity: "critical"},
	{Path: "/.env.backup", Category: "config", Severity: "critical"},
	{Path: "/.env.old", Category: "config", Severity: "critical"},
	{Path: "/.env.bak", Category: "config", Severity: "critical"},
	{Path: "/.env.example", Category: "config", Severity: "medium"},
	{Path: "/.env.sample", Category: "config", Severity: "medium"},
	{Path: "/config.json", Category: "config", Severity: "high"},
	{Path: "/config.yaml", Category: "config", Severity: "high"},
	{Path: "/config.yml", Category: "config", Severity: "high"},
	{Path: "/config.xml", Category: "config", Severity: "high"},
	{Path: "/config.php", Category: "config", Severity: "high"},
	{Path: "/config.inc.php", Category: "config", Severity: "high"},
	{Path: "/configuration.php", Category: "config", Severity: "high"},
	{Path: "/settings.json", Category: "config", Severity: "high"},
	{Path: "/settings.yaml", Category: "config", Severity: "high"},
	{Path: "/settings.py", Category: "config", Severity: "high"},
	{Path: "/application.properties", Category: "config", Severity: "high"},
	{Path: "/application.yml", Category: "config", Severity: "high"},
	{Path: "/application.yaml", Category: "config", Severity: "high"},
	{Path: "/appsettings.json", Category: "config", Severity: "high"},
	{Path: "/appsettings.Development.json", Category: "config", Severity: "high"},
	{Path: "/appsettings.Production.json", Category: "config", Severity: "high"},
	{Path: "/web.config", Category: "config", Severity: "high"},
	{Path: "/Web.config", Category: "config", Severity: "high"},
	{Path: "/wp-config.php", Category: "config", Severity: "critical"},
	{Path: "/wp-config.php.bak", Category: "config", Severity: "critical"},
	{Path: "/wp-config.php.old", Category: "config", Severity: "critical"},
	{Path: "/wp-config.php~", Category: "config", Severity: "critical"},
	{Path: "/wp-config.txt", Category: "config", Severity: "critical"},
	{Path: "/database.yml", Category: "config", Severity: "critical"},
	{Path: "/database.json", Category: "config", Severity: "critical"},
	{Path: "/db.php", Category: "config", Severity: "critical"},
	{Path: "/db.inc.php", Category: "config", Severity: "critical"},
	{Path: "/dbconfig.php", Category: "config", Severity: "critical"},
	{Path: "/secrets.json", Category: "config", Severity: "critical"},
	{Path: "/secrets.yaml", Category: "config", Severity: "critical"},
	{Path: "/credentials.json", Category: "config", Severity: "critical"},
	{Path: "/credentials.xml", Category: "config", Severity: "critical"},

	// ═══════════════════════════════════════════════════════════════════════════
	// DEBUG ENDPOINTS - High severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/__debug__/", Category: "debug", Severity: "high"},
	{Path: "/debug", Category: "debug", Severity: "high"},
	{Path: "/debug/", Category: "debug", Severity: "high"},
	{Path: "/debug/default/view", Category: "debug", Severity: "high"},
	{Path: "/debug/pprof/", Category: "debug", Severity: "high"},
	{Path: "/debug/vars", Category: "debug", Severity: "high"},
	{Path: "/trace", Category: "debug", Severity: "high"},
	{Path: "/trace.axd", Category: "debug", Severity: "high"},
	{Path: "/elmah.axd", Category: "debug", Severity: "high"},
	{Path: "/phpinfo.php", Category: "debug", Severity: "high"},
	{Path: "/info.php", Category: "debug", Severity: "high"},
	{Path: "/php_info.php", Category: "debug", Severity: "high"},
	{Path: "/test.php", Category: "debug", Severity: "medium"},
	{Path: "/server-status", Category: "debug", Severity: "high"},
	{Path: "/server-info", Category: "debug", Severity: "high"},
	{Path: "/.well-known/", Category: "debug", Severity: "low"},
	{Path: "/status", Category: "debug", Severity: "medium"},
	{Path: "/_status", Category: "debug", Severity: "medium"},
	{Path: "/health", Category: "debug", Severity: "low"},
	{Path: "/healthz", Category: "debug", Severity: "low"},
	{Path: "/ready", Category: "debug", Severity: "low"},
	{Path: "/readiness", Category: "debug", Severity: "low"},
	{Path: "/metrics", Category: "debug", Severity: "medium"},
	{Path: "/prometheus", Category: "debug", Severity: "medium"},
	{Path: "/_prometheus", Category: "debug", Severity: "medium"},

	// Python/Django
	{Path: "/__debug__/sql/", Category: "debug", Severity: "critical"},
	{Path: "/__debug__/request/", Category: "debug", Severity: "high"},

	// Ruby/Rails
	{Path: "/rails/info/properties", Category: "debug", Severity: "high"},
	{Path: "/rails/info/routes", Category: "debug", Severity: "high"},

	// Spring Boot Actuator
	{Path: "/actuator", Category: "debug", Severity: "high"},
	{Path: "/actuator/", Category: "debug", Severity: "high"},
	{Path: "/actuator/env", Category: "debug", Severity: "critical"},
	{Path: "/actuator/health", Category: "debug", Severity: "low"},
	{Path: "/actuator/info", Category: "debug", Severity: "medium"},
	{Path: "/actuator/mappings", Category: "debug", Severity: "high"},
	{Path: "/actuator/beans", Category: "debug", Severity: "high"},
	{Path: "/actuator/configprops", Category: "debug", Severity: "critical"},
	{Path: "/actuator/dump", Category: "debug", Severity: "high"},
	{Path: "/actuator/trace", Category: "debug", Severity: "high"},
	{Path: "/actuator/logfile", Category: "debug", Severity: "high"},
	{Path: "/actuator/heapdump", Category: "debug", Severity: "critical"},
	{Path: "/actuator/threaddump", Category: "debug", Severity: "high"},
	{Path: "/actuator/prometheus", Category: "debug", Severity: "medium"},
	{Path: "/actuator/metrics", Category: "debug", Severity: "medium"},
	{Path: "/actuator/scheduledtasks", Category: "debug", Severity: "medium"},
	{Path: "/actuator/httptrace", Category: "debug", Severity: "high"},
	{Path: "/actuator/caches", Category: "debug", Severity: "medium"},
	{Path: "/actuator/conditions", Category: "debug", Severity: "medium"},
	{Path: "/actuator/flyway", Category: "debug", Severity: "medium"},
	{Path: "/actuator/liquibase", Category: "debug", Severity: "medium"},
	{Path: "/actuator/sessions", Category: "debug", Severity: "high"},
	{Path: "/actuator/shutdown", Category: "debug", Severity: "critical"},
	{Path: "/actuator/refresh", Category: "debug", Severity: "high"},
	{Path: "/actuator/restart", Category: "debug", Severity: "critical"},
	{Path: "/actuator/auditevents", Category: "debug", Severity: "high"},
	{Path: "/actuator/loggers", Category: "debug", Severity: "high"},

	// ═══════════════════════════════════════════════════════════════════════════
	// VERSION CONTROL - Critical severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/.git/", Category: "vcs", Severity: "critical"},
	{Path: "/.git/config", Category: "vcs", Severity: "critical"},
	{Path: "/.git/HEAD", Category: "vcs", Severity: "critical"},
	{Path: "/.git/index", Category: "vcs", Severity: "critical"},
	{Path: "/.git/logs/HEAD", Category: "vcs", Severity: "high"},
	{Path: "/.git/objects/", Category: "vcs", Severity: "critical"},
	{Path: "/.git/refs/heads/master", Category: "vcs", Severity: "high"},
	{Path: "/.git/refs/heads/main", Category: "vcs", Severity: "high"},
	{Path: "/.gitignore", Category: "vcs", Severity: "low"},
	{Path: "/.gitattributes", Category: "vcs", Severity: "low"},
	{Path: "/.svn/", Category: "vcs", Severity: "critical"},
	{Path: "/.svn/entries", Category: "vcs", Severity: "critical"},
	{Path: "/.svn/wc.db", Category: "vcs", Severity: "critical"},
	{Path: "/.hg/", Category: "vcs", Severity: "critical"},
	{Path: "/.hg/hgrc", Category: "vcs", Severity: "critical"},
	{Path: "/.bzr/", Category: "vcs", Severity: "critical"},
	{Path: "/CVS/", Category: "vcs", Severity: "critical"},
	{Path: "/CVS/Entries", Category: "vcs", Severity: "critical"},
	{Path: "/CVS/Root", Category: "vcs", Severity: "critical"},

	// ═══════════════════════════════════════════════════════════════════════════
	// CI/CD CONFIGURATION - Critical severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/.github/", Category: "ci", Severity: "medium"},
	{Path: "/.github/workflows/", Category: "ci", Severity: "high"},
	{Path: "/.gitlab-ci.yml", Category: "ci", Severity: "high"},
	{Path: "/.travis.yml", Category: "ci", Severity: "high"},
	{Path: "/Jenkinsfile", Category: "ci", Severity: "high"},
	{Path: "/jenkins/", Category: "ci", Severity: "high"},
	{Path: "/jenkins/script", Category: "ci", Severity: "critical"},
	{Path: "/azure-pipelines.yml", Category: "ci", Severity: "high"},
	{Path: "/bitbucket-pipelines.yml", Category: "ci", Severity: "high"},
	{Path: "/circle.yml", Category: "ci", Severity: "high"},
	{Path: "/.circleci/config.yml", Category: "ci", Severity: "high"},
	{Path: "/Dockerfile", Category: "ci", Severity: "medium"},
	{Path: "/docker-compose.yml", Category: "ci", Severity: "high"},
	{Path: "/docker-compose.yaml", Category: "ci", Severity: "high"},
	{Path: "/docker-compose.override.yml", Category: "ci", Severity: "high"},
	{Path: "/.docker/config.json", Category: "ci", Severity: "critical"},
	{Path: "/kubernetes/", Category: "ci", Severity: "high"},
	{Path: "/k8s/", Category: "ci", Severity: "high"},
	{Path: "/helm/", Category: "ci", Severity: "high"},

	// ═══════════════════════════════════════════════════════════════════════════
	// CLOUD CREDENTIALS - Critical severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/.aws/credentials", Category: "cloud", Severity: "critical"},
	{Path: "/.aws/config", Category: "cloud", Severity: "high"},
	{Path: "/aws/credentials", Category: "cloud", Severity: "critical"},
	{Path: "/.azure/", Category: "cloud", Severity: "critical"},
	{Path: "/.gcloud/", Category: "cloud", Severity: "critical"},
	{Path: "/gcloud/", Category: "cloud", Severity: "critical"},
	{Path: "/google-credentials.json", Category: "cloud", Severity: "critical"},
	{Path: "/service-account.json", Category: "cloud", Severity: "critical"},
	{Path: "/firebase.json", Category: "cloud", Severity: "high"},
	{Path: "/firebaseConfig.json", Category: "cloud", Severity: "high"},
	{Path: "/.firebase/", Category: "cloud", Severity: "high"},

	// ═══════════════════════════════════════════════════════════════════════════
	// ADMIN PANELS - High severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/admin", Category: "admin", Severity: "high"},
	{Path: "/admin/", Category: "admin", Severity: "high"},
	{Path: "/administrator", Category: "admin", Severity: "high"},
	{Path: "/administrator/", Category: "admin", Severity: "high"},
	{Path: "/admin.php", Category: "admin", Severity: "high"},
	{Path: "/admin/login", Category: "admin", Severity: "high"},
	{Path: "/admin/dashboard", Category: "admin", Severity: "high"},
	{Path: "/manager", Category: "admin", Severity: "high"},
	{Path: "/manager/", Category: "admin", Severity: "high"},
	{Path: "/management", Category: "admin", Severity: "high"},
	{Path: "/panel", Category: "admin", Severity: "high"},
	{Path: "/cpanel", Category: "admin", Severity: "high"},
	{Path: "/phpmyadmin", Category: "admin", Severity: "high"},
	{Path: "/phpmyadmin/", Category: "admin", Severity: "high"},
	{Path: "/pma", Category: "admin", Severity: "high"},
	{Path: "/adminer", Category: "admin", Severity: "high"},
	{Path: "/adminer.php", Category: "admin", Severity: "high"},
	{Path: "/_phpmyadmin/", Category: "admin", Severity: "high"},
	{Path: "/myadmin/", Category: "admin", Severity: "high"},
	{Path: "/wp-admin/", Category: "admin", Severity: "high"},
	{Path: "/wp-login.php", Category: "admin", Severity: "medium"},
	{Path: "/backend", Category: "admin", Severity: "high"},
	{Path: "/backend/", Category: "admin", Severity: "high"},
	{Path: "/console", Category: "admin", Severity: "high"},
	{Path: "/console/", Category: "admin", Severity: "high"},
	{Path: "/_admin", Category: "admin", Severity: "high"},
	{Path: "/__admin", Category: "admin", Severity: "high"},
	{Path: "/dashboard", Category: "admin", Severity: "medium"},
	{Path: "/dashboard/", Category: "admin", Severity: "medium"},
	{Path: "/login", Category: "admin", Severity: "low"},
	{Path: "/signin", Category: "admin", Severity: "low"},

	// ═══════════════════════════════════════════════════════════════════════════
	// BACKUP FILES - Critical severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/backup.sql", Category: "backup", Severity: "critical"},
	{Path: "/backup.tar.gz", Category: "backup", Severity: "critical"},
	{Path: "/backup.zip", Category: "backup", Severity: "critical"},
	{Path: "/backup.tar", Category: "backup", Severity: "critical"},
	{Path: "/backup/", Category: "backup", Severity: "high"},
	{Path: "/backups/", Category: "backup", Severity: "high"},
	{Path: "/db.sql", Category: "backup", Severity: "critical"},
	{Path: "/database.sql", Category: "backup", Severity: "critical"},
	{Path: "/dump.sql", Category: "backup", Severity: "critical"},
	{Path: "/db_backup.sql", Category: "backup", Severity: "critical"},
	{Path: "/mysql.sql", Category: "backup", Severity: "critical"},
	{Path: "/data.sql", Category: "backup", Severity: "critical"},
	{Path: "/export.sql", Category: "backup", Severity: "critical"},
	{Path: "/site.sql", Category: "backup", Severity: "critical"},
	{Path: "/www.sql", Category: "backup", Severity: "critical"},
	{Path: "/.sql", Category: "backup", Severity: "critical"},
	{Path: "/old/", Category: "backup", Severity: "high"},
	{Path: "/archive/", Category: "backup", Severity: "high"},
	{Path: "/temp/", Category: "backup", Severity: "medium"},
	{Path: "/tmp/", Category: "backup", Severity: "medium"},
	{Path: "/test/", Category: "backup", Severity: "medium"},
	{Path: "/demo/", Category: "backup", Severity: "medium"},
	{Path: "/dev/", Category: "backup", Severity: "medium"},
	{Path: "/staging/", Category: "backup", Severity: "medium"},

	// ═══════════════════════════════════════════════════════════════════════════
	// SOURCE CODE EXPOSURE - Critical severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/index.php.bak", Category: "source", Severity: "critical"},
	{Path: "/index.php~", Category: "source", Severity: "critical"},
	{Path: "/index.php.old", Category: "source", Severity: "critical"},
	{Path: "/index.php.swp", Category: "source", Severity: "critical"},
	{Path: "/.index.php.swp", Category: "source", Severity: "critical"},
	{Path: "/app.js.map", Category: "source", Severity: "high"},
	{Path: "/main.js.map", Category: "source", Severity: "high"},
	{Path: "/bundle.js.map", Category: "source", Severity: "high"},
	{Path: "/vendor.js.map", Category: "source", Severity: "high"},
	{Path: "/runtime.js.map", Category: "source", Severity: "high"},
	{Path: "/polyfills.js.map", Category: "source", Severity: "high"},
	{Path: "/webpack.config.js", Category: "source", Severity: "medium"},
	{Path: "/gulpfile.js", Category: "source", Severity: "low"},
	{Path: "/Gruntfile.js", Category: "source", Severity: "low"},
	{Path: "/package.json", Category: "source", Severity: "low"},
	{Path: "/package-lock.json", Category: "source", Severity: "low"},
	{Path: "/yarn.lock", Category: "source", Severity: "low"},
	{Path: "/composer.json", Category: "source", Severity: "low"},
	{Path: "/composer.lock", Category: "source", Severity: "low"},
	{Path: "/Gemfile", Category: "source", Severity: "low"},
	{Path: "/Gemfile.lock", Category: "source", Severity: "low"},
	{Path: "/requirements.txt", Category: "source", Severity: "low"},
	{Path: "/Pipfile", Category: "source", Severity: "low"},
	{Path: "/Pipfile.lock", Category: "source", Severity: "low"},
	{Path: "/poetry.lock", Category: "source", Severity: "low"},
	{Path: "/go.mod", Category: "source", Severity: "low"},
	{Path: "/go.sum", Category: "source", Severity: "low"},
	{Path: "/Cargo.toml", Category: "source", Severity: "low"},
	{Path: "/Cargo.lock", Category: "source", Severity: "low"},
	{Path: "/pom.xml", Category: "source", Severity: "low"},
	{Path: "/build.gradle", Category: "source", Severity: "low"},
	{Path: "/settings.gradle", Category: "source", Severity: "low"},
	{Path: "/.htaccess", Category: "source", Severity: "high"},
	{Path: "/.htpasswd", Category: "source", Severity: "critical"},
	{Path: "/nginx.conf", Category: "source", Severity: "high"},
	{Path: "/server.xml", Category: "source", Severity: "high"},
	{Path: "/context.xml", Category: "source", Severity: "high"},

	// ═══════════════════════════════════════════════════════════════════════════
	// API DOCUMENTATION - Medium severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/swagger", Category: "api", Severity: "medium"},
	{Path: "/swagger/", Category: "api", Severity: "medium"},
	{Path: "/swagger-ui/", Category: "api", Severity: "medium"},
	{Path: "/swagger-ui.html", Category: "api", Severity: "medium"},
	{Path: "/api-docs", Category: "api", Severity: "medium"},
	{Path: "/api-docs/", Category: "api", Severity: "medium"},
	{Path: "/v2/api-docs", Category: "api", Severity: "medium"},
	{Path: "/v3/api-docs", Category: "api", Severity: "medium"},
	{Path: "/openapi.json", Category: "api", Severity: "medium"},
	{Path: "/openapi.yaml", Category: "api", Severity: "medium"},
	{Path: "/swagger.json", Category: "api", Severity: "medium"},
	{Path: "/swagger.yaml", Category: "api", Severity: "medium"},
	{Path: "/redoc", Category: "api", Severity: "medium"},
	{Path: "/docs", Category: "api", Severity: "low"},
	{Path: "/docs/", Category: "api", Severity: "low"},
	{Path: "/api", Category: "api", Severity: "low"},
	{Path: "/api/", Category: "api", Severity: "low"},
	{Path: "/graphql", Category: "api", Severity: "medium"},
	{Path: "/graphiql", Category: "api", Severity: "high"},
	{Path: "/graphql/console", Category: "api", Severity: "high"},
	{Path: "/playground", Category: "api", Severity: "high"},
	{Path: "/explorer", Category: "api", Severity: "high"},

	// ═══════════════════════════════════════════════════════════════════════════
	// LOGS - High severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/logs/", Category: "debug", Severity: "high"},
	{Path: "/log/", Category: "debug", Severity: "high"},
	{Path: "/error.log", Category: "debug", Severity: "high"},
	{Path: "/access.log", Category: "debug", Severity: "high"},
	{Path: "/debug.log", Category: "debug", Severity: "high"},
	{Path: "/app.log", Category: "debug", Severity: "high"},
	{Path: "/application.log", Category: "debug", Severity: "high"},
	{Path: "/server.log", Category: "debug", Severity: "high"},
	{Path: "/error_log", Category: "debug", Severity: "high"},
	{Path: "/wp-content/debug.log", Category: "debug", Severity: "high"},
	{Path: "/var/log/", Category: "debug", Severity: "high"},

	// ═══════════════════════════════════════════════════════════════════════════
	// KEYS AND CERTIFICATES - Critical severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/.ssh/", Category: "config", Severity: "critical"},
	{Path: "/.ssh/id_rsa", Category: "config", Severity: "critical"},
	{Path: "/.ssh/id_rsa.pub", Category: "config", Severity: "high"},
	{Path: "/.ssh/authorized_keys", Category: "config", Severity: "critical"},
	{Path: "/.ssh/known_hosts", Category: "config", Severity: "medium"},
	{Path: "/id_rsa", Category: "config", Severity: "critical"},
	{Path: "/id_dsa", Category: "config", Severity: "critical"},
	{Path: "/server.key", Category: "config", Severity: "critical"},
	{Path: "/server.pem", Category: "config", Severity: "critical"},
	{Path: "/private.key", Category: "config", Severity: "critical"},
	{Path: "/privatekey.pem", Category: "config", Severity: "critical"},
	{Path: "/key.pem", Category: "config", Severity: "critical"},
	{Path: "/cert.pem", Category: "config", Severity: "high"},
	{Path: "/certificate.pem", Category: "config", Severity: "high"},
	{Path: "/.pem", Category: "config", Severity: "critical"},
	{Path: "/.key", Category: "config", Severity: "critical"},
	{Path: "/ssl/", Category: "config", Severity: "high"},
	{Path: "/certs/", Category: "config", Severity: "high"},
	{Path: "/keys/", Category: "config", Severity: "critical"},

	// ═══════════════════════════════════════════════════════════════════════════
	// IDE AND EDITOR FILES - Medium severity
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/.idea/", Category: "source", Severity: "medium"},
	{Path: "/.idea/workspace.xml", Category: "source", Severity: "medium"},
	{Path: "/.vscode/", Category: "source", Severity: "medium"},
	{Path: "/.vscode/settings.json", Category: "source", Severity: "medium"},
	{Path: "/.vscode/launch.json", Category: "source", Severity: "medium"},
	{Path: "/.project", Category: "source", Severity: "low"},
	{Path: "/.classpath", Category: "source", Severity: "low"},
	{Path: "/.settings/", Category: "source", Severity: "low"},
	{Path: "/nbproject/", Category: "source", Severity: "low"},
	{Path: "/.DS_Store", Category: "source", Severity: "low"},
	{Path: "/Thumbs.db", Category: "source", Severity: "low"},
	{Path: "/desktop.ini", Category: "source", Severity: "low"},

	// ═══════════════════════════════════════════════════════════════════════════
	// MISCELLANEOUS HIGH-VALUE PATHS
	// ═══════════════════════════════════════════════════════════════════════════
	{Path: "/crossdomain.xml", Category: "config", Severity: "medium"},
	{Path: "/clientaccesspolicy.xml", Category: "config", Severity: "medium"},
	{Path: "/security.txt", Category: "config", Severity: "low"},
	{Path: "/.well-known/security.txt", Category: "config", Severity: "low"},
	{Path: "/sitemap.xml", Category: "api", Severity: "low"},
	{Path: "/robots.txt", Category: "api", Severity: "low"},
	{Path: "/humans.txt", Category: "api", Severity: "low"},
	{Path: "/readme.md", Category: "source", Severity: "low"},
	{Path: "/README.md", Category: "source", Severity: "low"},
	{Path: "/CHANGELOG.md", Category: "source", Severity: "low"},
	{Path: "/changelog.txt", Category: "source", Severity: "low"},
	{Path: "/VERSION", Category: "source", Severity: "low"},
	{Path: "/version.txt", Category: "source", Severity: "low"},
	{Path: "/version.json", Category: "source", Severity: "low"},
	{Path: "/build.json", Category: "source", Severity: "medium"},
	{Path: "/build-info.json", Category: "source", Severity: "medium"},
	{Path: "/manifest.json", Category: "source", Severity: "low"},
	{Path: "/site.webmanifest", Category: "source", Severity: "low"},

	// Session and tokens
	{Path: "/token", Category: "api", Severity: "high"},
	{Path: "/oauth/token", Category: "api", Severity: "high"},
	{Path: "/auth/token", Category: "api", Severity: "high"},
	{Path: "/api/token", Category: "api", Severity: "high"},
	{Path: "/api/tokens", Category: "api", Severity: "high"},
	{Path: "/api/keys", Category: "api", Severity: "high"},
	{Path: "/api/key", Category: "api", Severity: "high"},
	{Path: "/api/credentials", Category: "api", Severity: "critical"},
	{Path: "/api/secrets", Category: "api", Severity: "critical"},
	{Path: "/api/config", Category: "api", Severity: "high"},
	{Path: "/api/settings", Category: "api", Severity: "high"},
	{Path: "/api/env", Category: "api", Severity: "critical"},
	{Path: "/api/environment", Category: "api", Severity: "critical"},
	{Path: "/api/internal", Category: "api", Severity: "high"},
	{Path: "/api/debug", Category: "api", Severity: "high"},
	{Path: "/api/admin", Category: "api", Severity: "high"},
	{Path: "/api/v1/admin", Category: "api", Severity: "high"},
	{Path: "/api/v2/admin", Category: "api", Severity: "high"},
	{Path: "/internal/", Category: "api", Severity: "high"},
	{Path: "/_internal/", Category: "api", Severity: "high"},
}
