// Package subtakeover provides subdomain takeover detection capabilities.
// It checks for dangling DNS records, unclaimed cloud resources,
// and other subdomain takeover vulnerabilities.
package subtakeover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// VulnerabilityType represents the type of subdomain takeover vulnerability
type VulnerabilityType string

const (
	VulnCNAME        VulnerabilityType = "dangling-cname"
	VulnCloudService VulnerabilityType = "unclaimed-cloud-service"
	VulnS3Bucket     VulnerabilityType = "unclaimed-s3-bucket"
	VulnAzureBlob    VulnerabilityType = "unclaimed-azure-blob"
	VulnGitHubPages  VulnerabilityType = "unclaimed-github-pages"
	VulnHeroku       VulnerabilityType = "unclaimed-heroku"
	VulnShopify      VulnerabilityType = "unclaimed-shopify"
	VulnFastly       VulnerabilityType = "unclaimed-fastly"
	VulnPantheon     VulnerabilityType = "unclaimed-pantheon"
	VulnNetlify      VulnerabilityType = "unclaimed-netlify"
	VulnNS           VulnerabilityType = "dangling-ns"
	VulnMX           VulnerabilityType = "dangling-mx"
)

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Vulnerability represents a detected subdomain takeover vulnerability
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Subdomain   string            `json:"subdomain"`
	Target      string            `json:"target"`
	Provider    string            `json:"provider"`
	Evidence    string            `json:"evidence"`
	Remediation string            `json:"remediation"`
	CVSS        float64           `json:"cvss"`
}

// Fingerprint represents a service fingerprint for detection
type Fingerprint struct {
	Name       string
	CNAMEs     []string
	Patterns   []*regexp.Regexp
	HTTPCode   int
	Vulnerable bool
	Provider   string
	VulnType   VulnerabilityType
}

// ScanResult contains the results of a subdomain takeover scan
type ScanResult struct {
	Subdomain       string          `json:"subdomain"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        time.Duration   `json:"duration"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	CNAMEChain      []string        `json:"cname_chain"`
	IsVulnerable    bool            `json:"is_vulnerable"`
}

// TesterConfig configures the subdomain takeover tester
type TesterConfig struct {
	Timeout     time.Duration
	UserAgent   string
	Concurrency int
	DNSResolver string
	CheckHTTP   bool
	FollowCNAME bool
	Client      *http.Client
}

// Tester performs subdomain takeover tests
type Tester struct {
	config       *TesterConfig
	client       *http.Client
	fingerprints []Fingerprint
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:     30 * time.Second,
		UserAgent:   "waf-tester/2.1.0",
		Concurrency: 10,
		DNSResolver: "",
		CheckHTTP:   true,
		FollowCNAME: true,
	}
}

// NewTester creates a new subdomain takeover tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return &Tester{
		config:       config,
		client:       client,
		fingerprints: GetFingerprints(),
	}
}

// GetFingerprints returns all service fingerprints
func GetFingerprints() []Fingerprint {
	return []Fingerprint{
		// AWS S3
		{
			Name:       "AWS S3",
			CNAMEs:     []string{".s3.amazonaws.com", ".s3-website", ".s3."},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)NoSuchBucket|The specified bucket does not exist`)},
			HTTPCode:   404,
			Vulnerable: true,
			Provider:   "Amazon AWS",
			VulnType:   VulnS3Bucket,
		},
		// GitHub Pages
		{
			Name:       "GitHub Pages",
			CNAMEs:     []string{".github.io", ".githubusercontent.com"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)There isn't a GitHub Pages site here`)},
			HTTPCode:   404,
			Vulnerable: true,
			Provider:   "GitHub",
			VulnType:   VulnGitHubPages,
		},
		// Heroku
		{
			Name:       "Heroku",
			CNAMEs:     []string{".herokuapp.com", ".herokussl.com", ".herokudns.com"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)No such app|heroku.*no.*app`)},
			HTTPCode:   404,
			Vulnerable: true,
			Provider:   "Heroku",
			VulnType:   VulnHeroku,
		},
		// Azure
		{
			Name:       "Azure",
			CNAMEs:     []string{".azurewebsites.net", ".cloudapp.azure.com", ".blob.core.windows.net", ".azure-api.net", ".azurefd.net"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)Azure Web App - Error|BlobNotFound|The specified blob does not exist`)},
			HTTPCode:   404,
			Vulnerable: true,
			Provider:   "Microsoft Azure",
			VulnType:   VulnAzureBlob,
		},
		// Shopify
		{
			Name:       "Shopify",
			CNAMEs:     []string{".myshopify.com"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)Sorry, this shop is currently unavailable|Only one step left`)},
			HTTPCode:   404,
			Vulnerable: true,
			Provider:   "Shopify",
			VulnType:   VulnShopify,
		},
		// Fastly
		{
			Name:       "Fastly",
			CNAMEs:     []string{".fastly.net", ".fastlylb.net"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)Fastly error: unknown domain`)},
			HTTPCode:   500,
			Vulnerable: true,
			Provider:   "Fastly",
			VulnType:   VulnFastly,
		},
		// Pantheon
		{
			Name:       "Pantheon",
			CNAMEs:     []string{".pantheonsite.io", ".pantheon.io"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)The gods are wise|404: Unknown site`)},
			HTTPCode:   404,
			Vulnerable: true,
			Provider:   "Pantheon",
			VulnType:   VulnPantheon,
		},
		// Netlify
		{
			Name:       "Netlify",
			CNAMEs:     []string{".netlify.app", ".netlify.com"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)Not Found.*Netlify`)},
			HTTPCode:   404,
			Vulnerable: true,
			Provider:   "Netlify",
			VulnType:   VulnNetlify,
		},
		// Zendesk
		{
			Name:       "Zendesk",
			CNAMEs:     []string{".zendesk.com"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)Help Center Closed`)},
			HTTPCode:   404,
			Vulnerable: true,
			Provider:   "Zendesk",
			VulnType:   VulnCloudService,
		},
		// Tumblr
		{
			Name:       "Tumblr",
			CNAMEs:     []string{".tumblr.com"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)There's nothing here|Whatever you were looking for doesn't currently exist`)},
			HTTPCode:   404,
			Vulnerable: true,
			Provider:   "Tumblr",
			VulnType:   VulnCloudService,
		},
		// WordPress
		{
			Name:       "WordPress",
			CNAMEs:     []string{".wordpress.com"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)Do you want to register`)},
			HTTPCode:   302,
			Vulnerable: true,
			Provider:   "WordPress",
			VulnType:   VulnCloudService,
		},
		// Cargo
		{
			Name:       "Cargo",
			CNAMEs:     []string{".cargo.site"},
			Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)404 Not Found`)},
			HTTPCode:   404,
			Vulnerable: true,
			Provider:   "Cargo",
			VulnType:   VulnCloudService,
		},
	}
}

// CheckSubdomain checks a subdomain for takeover vulnerabilities
func (t *Tester) CheckSubdomain(ctx context.Context, subdomain string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		Subdomain: subdomain,
		StartTime: startTime,
	}

	// Resolve CNAME chain
	cnameChain, err := t.resolveCNAMEChain(subdomain)
	if err != nil {
		// NXDOMAIN might indicate vulnerability
		if strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "NXDOMAIN") {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				Type:        VulnCNAME,
				Description: "Subdomain has dangling CNAME record",
				Severity:    SeverityHigh,
				Subdomain:   subdomain,
				Evidence:    fmt.Sprintf("DNS error: %v", err),
				Remediation: GetSubdomainTakeoverRemediation(),
				CVSS:        8.6,
			})
			result.IsVulnerable = true
		}
	}
	result.CNAMEChain = cnameChain

	// Check against fingerprints
	for _, cname := range cnameChain {
		for _, fp := range t.fingerprints {
			if t.matchesCNAME(cname, fp.CNAMEs) {
				// CNAME matches a known service, check HTTP
				if t.config.CheckHTTP {
					vuln := t.checkHTTPFingerprint(ctx, subdomain, fp)
					if vuln != nil {
						result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
						result.IsVulnerable = true
					}
				}
			}
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	return result, nil
}

// resolveCNAMEChain resolves the full CNAME chain for a domain
func (t *Tester) resolveCNAMEChain(domain string) ([]string, error) {
	var chain []string
	current := domain
	seen := make(map[string]bool)

	for i := 0; i < 10; i++ { // Max 10 levels
		if seen[current] {
			break // Circular reference
		}
		seen[current] = true

		cname, err := net.LookupCNAME(current)
		if err != nil {
			if len(chain) == 0 {
				return nil, err
			}
			break
		}

		// Trim trailing dot
		cname = strings.TrimSuffix(cname, ".")

		if cname == current {
			break
		}

		chain = append(chain, cname)
		current = cname
	}

	return chain, nil
}

// matchesCNAME checks if a CNAME matches any of the fingerprint patterns
func (t *Tester) matchesCNAME(cname string, patterns []string) bool {
	lower := strings.ToLower(cname)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// checkHTTPFingerprint checks HTTP response for service fingerprint
func (t *Tester) checkHTTPFingerprint(ctx context.Context, subdomain string, fp Fingerprint) *Vulnerability {
	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, targetURL := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", t.config.UserAgent)

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
		resp.Body.Close()

		bodyStr := string(body)

		// Check for fingerprint patterns
		for _, pattern := range fp.Patterns {
			if pattern.MatchString(bodyStr) {
				return &Vulnerability{
					Type:        fp.VulnType,
					Description: fmt.Sprintf("%s subdomain takeover possible", fp.Name),
					Severity:    SeverityHigh,
					Subdomain:   subdomain,
					Target:      targetURL,
					Provider:    fp.Provider,
					Evidence:    fmt.Sprintf("Pattern matched: %s", pattern.String()),
					Remediation: GetSubdomainTakeoverRemediation(),
					CVSS:        8.6,
				}
			}
		}
	}

	return nil
}

// CheckNS checks for dangling NS records
func (t *Tester) CheckNS(domain string) (*Vulnerability, error) {
	ns, err := net.LookupNS(domain)
	if err != nil {
		// No NS records might indicate issue
		return nil, err
	}

	for _, record := range ns {
		// Try to resolve each NS
		_, err := net.LookupHost(record.Host)
		if err != nil { //nolint:nilerr // intentional: DNS resolution failure IS the vulnerability
			return &Vulnerability{
				Type:        VulnNS,
				Description: "Dangling NS record detected",
				Severity:    SeverityCritical,
				Subdomain:   domain,
				Target:      record.Host,
				Evidence:    fmt.Sprintf("NS %s is not resolvable", record.Host),
				Remediation: GetSubdomainTakeoverRemediation(),
				CVSS:        9.8,
			}, nil
		}
	}

	return nil, nil
}

// CheckMX checks for dangling MX records
func (t *Tester) CheckMX(domain string) (*Vulnerability, error) {
	mx, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
	}

	for _, record := range mx {
		// Try to resolve each MX
		_, err := net.LookupHost(record.Host)
		if err != nil { //nolint:nilerr // intentional: DNS resolution failure IS the vulnerability
			return &Vulnerability{
				Type:        VulnMX,
				Description: "Dangling MX record detected",
				Severity:    SeverityMedium,
				Subdomain:   domain,
				Target:      record.Host,
				Evidence:    fmt.Sprintf("MX %s is not resolvable", record.Host),
				Remediation: GetSubdomainTakeoverRemediation(),
				CVSS:        5.3,
			}, nil
		}
	}

	return nil, nil
}

// BatchCheck checks multiple subdomains concurrently
func (t *Tester) BatchCheck(ctx context.Context, subdomains []string) ([]ScanResult, error) {
	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, t.config.Concurrency)

	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(sd string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			result, err := t.CheckSubdomain(ctx, sd)
			if err != nil {
				return
			}

			mu.Lock()
			results = append(results, *result)
			mu.Unlock()
		}(subdomain)
	}

	wg.Wait()
	return results, nil
}

// Helper functions

func getSeverity(vulnType VulnerabilityType) Severity {
	switch vulnType {
	case VulnNS:
		return SeverityCritical
	case VulnCNAME, VulnS3Bucket, VulnAzureBlob, VulnGitHubPages:
		return SeverityHigh
	case VulnMX:
		return SeverityMedium
	case VulnCloudService, VulnHeroku, VulnShopify, VulnFastly, VulnPantheon, VulnNetlify:
		return SeverityHigh
	}
	return SeverityHigh // default for unknown types
}

// Remediation guidance

// GetSubdomainTakeoverRemediation returns remediation guidance
func GetSubdomainTakeoverRemediation() string {
	return `To fix subdomain takeover vulnerabilities:
1. Remove dangling DNS records (CNAME, A, AAAA, NS, MX)
2. Claim the unclaimed cloud resource (S3 bucket, GitHub Pages, etc.)
3. Regularly audit DNS records for unused entries
4. Implement DNS monitoring and alerting
5. Use DNS CAA records to restrict certificate issuance
6. Document all DNS records and their purpose
7. Implement change management for DNS modifications
8. Consider using wildcard DNS entries with caution`
}

// AllVulnerabilityTypes returns all subdomain takeover vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnCNAME,
		VulnCloudService,
		VulnS3Bucket,
		VulnAzureBlob,
		VulnGitHubPages,
		VulnHeroku,
		VulnShopify,
		VulnFastly,
		VulnPantheon,
		VulnNetlify,
		VulnNS,
		VulnMX,
	}
}

// GetProviders returns all supported cloud providers
func GetProviders() []string {
	return []string{
		"Amazon AWS",
		"Microsoft Azure",
		"GitHub",
		"Heroku",
		"Shopify",
		"Fastly",
		"Pantheon",
		"Netlify",
		"Zendesk",
		"Tumblr",
		"WordPress",
	}
}

// VulnerabilityToJSON converts vulnerability to JSON
func VulnerabilityToJSON(v Vulnerability) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// IsKnownVulnerableService checks if a CNAME points to a known vulnerable service
func IsKnownVulnerableService(cname string) (bool, string) {
	fingerprints := GetFingerprints()
	lower := strings.ToLower(cname)

	for _, fp := range fingerprints {
		for _, pattern := range fp.CNAMEs {
			if strings.Contains(lower, strings.ToLower(pattern)) {
				return true, fp.Name
			}
		}
	}

	return false, ""
}
