// Package discovery - Content analysis (S3, subdomains, directory listings, secrets, fingerprinting, wildcards)
package discovery

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/regexcache"
)

// Pre-compiled regex for title extraction (used in fingerprinting)
var titleExtractRegex = regexcache.MustGet(`(?i)<title>([^<]+)</title>`)

// Content-hash based caches for expensive extraction functions
var (
	s3BucketsCache     sync.Map // map[string][]string (hash -> buckets)
	detectSecretsCache sync.Map // map[string][]Secret (hash -> secrets)
)

// ResetCaches clears all package-level content caches.
// Safe for concurrent use — uses Range+Delete rather than reassignment.
func ResetCaches() {
	s3BucketsCache.Range(func(key, _ any) bool {
		s3BucketsCache.Delete(key)
		return true
	})
	detectSecretsCache.Range(func(key, _ any) bool {
		detectSecretsCache.Delete(key)
		return true
	})
	jsURLsCache.Range(func(key, _ any) bool {
		jsURLsCache.Delete(key)
		return true
	})
}

// ==================== AWS S3 BUCKET EXTRACTION ====================
// From gospider - finds S3 buckets in responses

// S3 bucket regex patterns
var (
	// Match S3 bucket URLs and references
	s3BucketPatterns = []*regexp.Regexp{
		regexcache.MustGet(`[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com`),
		regexcache.MustGet(`[a-zA-Z0-9.\-_]+\.s3-[a-z0-9-]+\.amazonaws\.com`),
		regexcache.MustGet(`[a-zA-Z0-9.\-_]+\.s3\.[a-z0-9-]+\.amazonaws\.com`),
		regexcache.MustGet(`s3\.amazonaws\.com/[a-zA-Z0-9.\-_]+`),
		regexcache.MustGet(`s3-[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.\-_]+`),
		regexcache.MustGet(`s3\.[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.\-_]+`),
		regexcache.MustGet(`//[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com`),
		regexcache.MustGet(`arn:aws:s3:::[a-zA-Z0-9.\-_]+`),
	}
)

// ExtractS3Buckets finds AWS S3 bucket references in content
func ExtractS3Buckets(content string) []string {
	// Check cache first
	hash := contentHash(content)
	if cached, ok := s3BucketsCache.Load(hash); ok {
		return cached.([]string)
	}

	seen := make(map[string]bool, 16)
	buckets := make([]string, 0, 16)

	for _, pattern := range s3BucketPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			// Clean up the match
			match = strings.TrimPrefix(match, "//")
			match = strings.TrimPrefix(match, "arn:aws:s3:::")
			if !seen[match] {
				seen[match] = true
				buckets = append(buckets, match)
			}
		}
	}

	// Cache the result
	s3BucketsCache.Store(hash, buckets)
	return buckets
}

// ==================== SUBDOMAIN EXTRACTION ====================
// From gospider - finds subdomains in responses

// ExtractSubdomains finds subdomains of the target domain in content
func ExtractSubdomains(content string, baseDomain string) []string {
	seen := make(map[string]bool)
	var subdomains []string

	// Escape all regex metacharacters in domain
	escapedDomain := regexp.QuoteMeta(baseDomain)

	// Pattern to match subdomains
	subdomainRe, err := regexcache.Get(`(?i)([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+` + escapedDomain)
	if err != nil {
		return nil
	}

	matches := subdomainRe.FindAllString(content, -1)
	for _, match := range matches {
		match = strings.ToLower(match)
		// Skip if it's just the base domain
		if match == baseDomain {
			continue
		}
		if !seen[match] {
			seen[match] = true
			subdomains = append(subdomains, match)
		}
	}

	return subdomains
}

// ==================== DIRECTORY LISTING DETECTION ====================
// From feroxbuster - detects directory listings and extracts links

// DirectoryListing represents a detected directory listing
type DirectoryListing struct {
	URL     string   `json:"url"`
	Type    string   `json:"type"` // apache, nginx, iis, python, etc.
	Entries []string `json:"entries"`
}

// Directory listing detection patterns
var directoryListingPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"apache", regexcache.MustGet(`(?i)<title>Index of /`)},
	{"nginx", regexcache.MustGet(`(?i)<title>Index of /`)},
	{"nginx-autoindex", regexcache.MustGet(`(?i)autoindex on`)},
	{"lighttpd", regexcache.MustGet(`(?i)<title>Index of /`)},
	{"iis", regexcache.MustGet(`(?i)<title>.*- /</title>`)},
	{"python-http", regexcache.MustGet(`(?i)Directory listing for /`)},
	{"tomcat", regexcache.MustGet(`(?i)<title>Directory Listing For /`)},
	{"webdav", regexcache.MustGet(`(?i)<D:multistatus`)},
}

// Link extraction patterns for directory listings
var directoryLinkPatterns = []*regexp.Regexp{
	regexcache.MustGet(`<a\s+href="([^"?]+)"`),
	regexcache.MustGet(`<a\s+href='([^'?]+)'`),
}

// DetectDirectoryListing checks if content is a directory listing and extracts entries
func DetectDirectoryListing(content string, baseURL string) *DirectoryListing {
	// First check for sorting query params (strong indicator of directory listing)
	hasSorting := HasSortingQueryParams(content)

	for _, pattern := range directoryListingPatterns {
		if pattern.Pattern.MatchString(content) {
			listing := &DirectoryListing{
				URL:     baseURL,
				Type:    pattern.Name,
				Entries: make([]string, 0),
			}

			// Extract links
			seen := make(map[string]bool)
			for _, linkPattern := range directoryLinkPatterns {
				matches := linkPattern.FindAllStringSubmatch(content, -1)
				for _, match := range matches {
					if len(match) > 1 {
						link := match[1]
						// Skip parent directory and common non-file links
						if link == "../" || link == "./" || link == "/" ||
							strings.HasPrefix(link, "?") || strings.HasPrefix(link, "#") {
							continue
						}
						if !seen[link] {
							seen[link] = true
							listing.Entries = append(listing.Entries, link)
						}
					}
				}
			}

			return listing
		}
	}

	// If we have sorting params but no pattern match, it might still be a directory listing
	if hasSorting {
		listing := &DirectoryListing{
			URL:     baseURL,
			Type:    "unknown-with-sorting",
			Entries: make([]string, 0),
		}

		// Extract any links as potential directory entries
		seen := make(map[string]bool)
		for _, linkPattern := range directoryLinkPatterns {
			matches := linkPattern.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				if len(match) > 1 {
					link := match[1]
					if link == "../" || link == "./" || link == "/" ||
						strings.HasPrefix(link, "?") || strings.HasPrefix(link, "#") {
						continue
					}
					if !seen[link] {
						seen[link] = true
						listing.Entries = append(listing.Entries, link)
					}
				}
			}
		}

		if len(listing.Entries) > 0 {
			return listing
		}
	}

	return nil
}

// HasSortingQueryParams checks for directory listing sorting parameters
// From feroxbuster heuristics
func HasSortingQueryParams(content string) bool {
	sortPatterns := []string{
		"?C=N", "?C=M", "?C=S", "?C=D", // Apache mod_autoindex
		"?O=A", "?O=D", // Order
		"?N=A", "?N=D", // Name
		"?M=A", "?M=D", // Modified
		"?S=A", "?S=D", // Size
	}

	for _, pattern := range sortPatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}
	return false
}

// ==================== SECRET DETECTION ====================
// From jsluice - finds secrets in JavaScript/responses

// Secret represents a detected secret
type Secret struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Context  string `json:"context,omitempty"`
	Severity string `json:"severity"` // info, low, medium, high
}

// Secret detection patterns
var secretPatterns = []struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
}{
	// AWS
	{"aws_access_key", regexcache.MustGet(`AKIA[0-9A-Z]{16}`), "high"},
	{"aws_secret_key", regexcache.MustGet(`(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]`), "high"},

	// Google
	{"google_api_key", regexcache.MustGet(`AIza[0-9A-Za-z\-_]{35}`), "medium"},
	{"google_oauth", regexcache.MustGet(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), "medium"},

	// GitHub
	{"github_token", regexcache.MustGet(`gh[pousr]_[A-Za-z0-9_]{36,255}`), "high"},
	{"github_oauth", regexcache.MustGet(`gho_[A-Za-z0-9]{36}`), "high"},

	// Slack
	{"slack_token", regexcache.MustGet(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`), "high"},
	{"slack_webhook", regexcache.MustGet(`https://hooks\.slack\.com/services/[A-Za-z0-9+/]+`), "medium"},

	// JWT
	{"jwt_token", regexcache.MustGet(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`), "medium"},

	// Private keys
	{"private_key", regexcache.MustGet(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "high"},

	// Generic API keys
	{"api_key", regexcache.MustGet(`(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]`), "medium"},
	{"secret_key", regexcache.MustGet(`(?i)(?:secret[_-]?key|secretkey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]`), "medium"},
	{"auth_token", regexcache.MustGet(`(?i)(?:auth[_-]?token|access[_-]?token)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]`), "medium"},

	// Firebase
	{"firebase_config", regexcache.MustGet(`(?i)firebase[a-zA-Z]*\.json`), "low"},

	// Database URLs
	{"database_url", regexcache.MustGet(`(?i)(?:mongodb|postgres|mysql|redis)://[^\s'"]+`), "high"},

	// Stripe
	{"stripe_key", regexcache.MustGet(`sk_live_[0-9a-zA-Z]{24}`), "high"},
	{"stripe_publishable", regexcache.MustGet(`pk_live_[0-9a-zA-Z]{24}`), "low"},

	// Twilio
	{"twilio_sid", regexcache.MustGet(`AC[a-zA-Z0-9_\-]{32}`), "medium"},
	{"twilio_auth", regexcache.MustGet(`SK[a-zA-Z0-9_\-]{32}`), "high"},

	// SendGrid
	{"sendgrid_key", regexcache.MustGet(`SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`), "high"},

	// Mailgun
	{"mailgun_key", regexcache.MustGet(`key-[0-9a-zA-Z]{32}`), "high"},

	// Square
	{"square_token", regexcache.MustGet(`sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}`), "high"},

	// Heroku
	{"heroku_key", regexcache.MustGet(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`), "low"},
}

// DetectSecrets finds secrets in content
func DetectSecrets(content string) []Secret {
	// Check cache first
	hash := contentHash(content)
	if cached, ok := detectSecretsCache.Load(hash); ok {
		return cached.([]Secret)
	}

	secrets := make([]Secret, 0, 8)
	seen := make(map[string]bool, 16)

	for _, sp := range secretPatterns {
		matches := sp.Pattern.FindAllString(content, -1)
		for _, match := range matches {
			// Create a unique key to avoid duplicates
			key := sp.Name + ":" + match
			if !seen[key] {
				seen[key] = true
				secrets = append(secrets, Secret{
					Type:     sp.Name,
					Value:    truncateSecret(match),
					Severity: sp.Severity,
				})
			}
		}
	}

	// Cache the result
	detectSecretsCache.Store(hash, secrets)
	return secrets
}

func truncateSecret(s string) string {
	// Show first 10 and last 4 chars for secrets
	if len(s) > 20 {
		return s[:10] + "..." + s[len(s)-4:]
	}
	return s
}

// ==================== RESPONSE FINGERPRINTING ====================
// From feroxbuster - detect similar/duplicate responses

// ResponseFingerprint represents a response's unique characteristics
type ResponseFingerprint struct {
	StatusCode    int    `json:"status_code"`
	ContentLength int64  `json:"content_length"`
	WordCount     int    `json:"word_count"`
	LineCount     int    `json:"line_count"`
	ContentType   string `json:"content_type"`
	TitleHash     string `json:"title_hash,omitempty"`
}

// CalculateFingerprint creates a fingerprint from response data
func CalculateFingerprint(statusCode int, body []byte, contentType string) ResponseFingerprint {
	content := string(body)

	// Count words (simple split on whitespace)
	words := strings.Fields(content)
	wordCount := len(words)

	// Count lines
	lineCount := strings.Count(content, "\n") + 1

	// Extract title hash (using pre-compiled regex)
	titleHash := ""
	if match := titleExtractRegex.FindStringSubmatch(content); len(match) > 1 {
		titleHash = fmt.Sprintf("%x", simpleHash(match[1]))
	}

	return ResponseFingerprint{
		StatusCode:    statusCode,
		ContentLength: int64(len(body)),
		WordCount:     wordCount,
		LineCount:     lineCount,
		ContentType:   contentType,
		TitleHash:     titleHash,
	}
}

// IsSimilar checks if two fingerprints are similar (for filtering duplicates)
func (f ResponseFingerprint) IsSimilar(other ResponseFingerprint, threshold float64) bool {
	// Status codes must match
	if f.StatusCode != other.StatusCode {
		return false
	}

	// Content type should match
	if f.ContentType != other.ContentType {
		return false
	}

	// Calculate similarity score (0-1)
	var score float64

	// Content length similarity
	if f.ContentLength > 0 && other.ContentLength > 0 {
		lenDiff := float64(abs64(f.ContentLength-other.ContentLength)) / float64(max64(f.ContentLength, other.ContentLength))
		if lenDiff < 0.1 { // Within 10%
			score += 0.4
		}
	}

	// Word count similarity
	if f.WordCount > 0 && other.WordCount > 0 {
		wordDiff := float64(absInt(f.WordCount-other.WordCount)) / float64(maxInt(f.WordCount, other.WordCount))
		if wordDiff < 0.1 {
			score += 0.3
		}
	}

	// Line count similarity
	if f.LineCount > 0 && other.LineCount > 0 {
		lineDiff := float64(absInt(f.LineCount-other.LineCount)) / float64(maxInt(f.LineCount, other.LineCount))
		if lineDiff < 0.1 {
			score += 0.2
		}
	}

	// Title match
	if f.TitleHash != "" && f.TitleHash == other.TitleHash {
		score += 0.1
	}

	return score >= threshold
}

func simpleHash(s string) uint32 {
	var h uint32
	for _, c := range s {
		h = h*31 + uint32(c)
	}
	return h
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ==================== WILDCARD/404 DETECTION ====================
// From feroxbuster - detect wildcard/soft-404 responses

// WildcardDetector helps detect wildcard responses
type WildcardDetector struct {
	baselineFingerprints map[string]ResponseFingerprint // method -> fingerprint
}

// NewWildcardDetector creates a new wildcard detector
func NewWildcardDetector() *WildcardDetector {
	return &WildcardDetector{
		baselineFingerprints: make(map[string]ResponseFingerprint),
	}
}

// AddBaseline adds a baseline response for a method
func (w *WildcardDetector) AddBaseline(method string, fp ResponseFingerprint) {
	w.baselineFingerprints[method] = fp
}

// IsWildcard checks if a response matches the wildcard pattern
func (w *WildcardDetector) IsWildcard(method string, fp ResponseFingerprint) bool {
	baseline, exists := w.baselineFingerprints[method]
	if !exists {
		return false
	}
	return fp.IsSimilar(baseline, 0.7)
}
