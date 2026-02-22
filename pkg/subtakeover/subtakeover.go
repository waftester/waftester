// Package subtakeover provides subdomain takeover detection capabilities.
// It checks for dangling DNS records, unclaimed cloud resources,
// and other subdomain takeover vulnerabilities.
package subtakeover

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/runner"
	"github.com/waftester/waftester/pkg/ui"
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

// Vulnerability represents a detected subdomain takeover vulnerability
type Vulnerability struct {
	finding.Vulnerability
	Type      VulnerabilityType `json:"type"`
	Subdomain string            `json:"subdomain"`
	Target    string            `json:"target"`
	Provider  string            `json:"provider"`
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
	attackconfig.Base
	DNSResolver string
	CheckHTTP   bool
	FollowCNAME bool
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
		Base: attackconfig.Base{
			Timeout:     duration.HTTPFuzzing,
			UserAgent:   ui.UserAgent(),
			Concurrency: defaults.ConcurrencyMedium,
		},
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
		client = httpclient.New(httpclient.WithTimeout(config.Timeout))
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
				Vulnerability: finding.Vulnerability{
					Description: "Subdomain has dangling CNAME record",
					Severity:    finding.High,
					Evidence:    fmt.Sprintf("DNS error: %v", err),
					Remediation: GetSubdomainTakeoverRemediation(),
					CVSS:        8.6,
				},
				Type:      VulnCNAME,
				Subdomain: subdomain,
			})
			result.IsVulnerable = true
		} else {
			// Non-NXDOMAIN DNS errors should not be silently swallowed
			return result, fmt.Errorf("DNS resolution for %s: %w", subdomain, err)
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
		if vuln := t.checkSingleURL(ctx, subdomain, targetURL, fp); vuln != nil {
			return vuln
		}
	}

	return nil
}

// checkSingleURL checks a single URL against a fingerprint, properly scoping defer.
func (t *Tester) checkSingleURL(ctx context.Context, subdomain, targetURL string, fp Fingerprint) *Vulnerability {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, _ := iohelper.ReadBody(resp.Body, iohelper.MediumMaxBodySize)

	bodyStr := string(body)

	// Check for fingerprint patterns
	for _, pattern := range fp.Patterns {
		if pattern.MatchString(bodyStr) {
			t.config.NotifyVulnerabilityFound()
			return &Vulnerability{
				Vulnerability: finding.Vulnerability{
					Description: fmt.Sprintf("%s subdomain takeover possible", fp.Name),
					Severity:    finding.High,
					Evidence:    fmt.Sprintf("Pattern matched: %s", pattern.String()),
					Remediation: GetSubdomainTakeoverRemediation(),
					CVSS:        8.6,
				},
				Type:      fp.VulnType,
				Subdomain: subdomain,
				Target:    targetURL,
				Provider:  fp.Provider,
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
			t.config.NotifyVulnerabilityFound()
			return &Vulnerability{
				Vulnerability: finding.Vulnerability{
					Description: "Dangling NS record detected",
					Severity:    finding.Critical,
					Evidence:    fmt.Sprintf("NS %s is not resolvable", record.Host),
					Remediation: GetSubdomainTakeoverRemediation(),
					CVSS:        9.8,
				},
				Type:      VulnNS,
				Subdomain: domain,
				Target:    record.Host,
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
			t.config.NotifyVulnerabilityFound()
			return &Vulnerability{
				Vulnerability: finding.Vulnerability{
					Description: "Dangling MX record detected",
					Severity:    finding.Medium,
					Evidence:    fmt.Sprintf("MX %s is not resolvable", record.Host),
					Remediation: GetSubdomainTakeoverRemediation(),
					CVSS:        5.3,
				},
				Type:      VulnMX,
				Subdomain: domain,
				Target:    record.Host,
			}, nil
		}
	}

	return nil, nil
}

// BatchCheck checks multiple subdomains concurrently using runner.Runner[T].
func (t *Tester) BatchCheck(ctx context.Context, subdomains []string) ([]ScanResult, error) {
	r := runner.NewRunner[ScanResult]()
	r.Concurrency = t.config.Concurrency

	results := r.Run(ctx, subdomains, func(ctx context.Context, target string) (ScanResult, error) {
		result, err := t.CheckSubdomain(ctx, target)
		if err != nil {
			return ScanResult{}, err
		}
		return *result, nil
	})

	out := make([]ScanResult, 0, len(results))
	for _, res := range results {
		if res.Error == nil {
			out = append(out, res.Data)
		}
	}
	return out, nil
}

// Helper functions

func getSeverity(vulnType VulnerabilityType) finding.Severity {
	switch vulnType {
	case VulnNS:
		return finding.Critical
	case VulnCNAME, VulnS3Bucket, VulnAzureBlob, VulnGitHubPages:
		return finding.High
	case VulnMX:
		return finding.Medium
	case VulnCloudService, VulnHeroku, VulnShopify, VulnFastly, VulnPantheon, VulnNetlify:
		return finding.High
	}
	return finding.High // default for unknown types
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
