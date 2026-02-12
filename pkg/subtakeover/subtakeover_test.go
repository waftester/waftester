package subtakeover

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/finding"
)

func TestNewTester(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		tester := NewTester(nil)
		if tester == nil {
			t.Fatal("expected tester, got nil")
		}
		if tester.config.Concurrency != 10 {
			t.Errorf("expected concurrency 10, got %d", tester.config.Concurrency)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &TesterConfig{
			Base: attackconfig.Base{Timeout: 60 * time.Second, Concurrency: 20},
		}
		tester := NewTester(config)
		if tester.config.Concurrency != 20 {
			t.Errorf("expected concurrency 20, got %d", tester.config.Concurrency)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", config.Timeout)
	}

	if !config.CheckHTTP {
		t.Error("expected CheckHTTP to be true")
	}

	if !config.FollowCNAME {
		t.Error("expected FollowCNAME to be true")
	}
}

func TestGetFingerprints(t *testing.T) {
	fingerprints := GetFingerprints()

	if len(fingerprints) == 0 {
		t.Fatal("expected fingerprints")
	}

	// Check for some known services
	services := make(map[string]bool)
	for _, fp := range fingerprints {
		services[fp.Name] = true
	}

	if !services["AWS S3"] {
		t.Error("expected AWS S3 fingerprint")
	}
	if !services["GitHub Pages"] {
		t.Error("expected GitHub Pages fingerprint")
	}
	if !services["Heroku"] {
		t.Error("expected Heroku fingerprint")
	}
}

func TestMatchesCNAME(t *testing.T) {
	tester := NewTester(nil)

	tests := []struct {
		cname    string
		patterns []string
		expected bool
	}{
		{"example.s3.amazonaws.com", []string{".s3.amazonaws.com"}, true},
		{"example.github.io", []string{".github.io"}, true},
		{"example.herokuapp.com", []string{".herokuapp.com"}, true},
		{"example.com", []string{".s3.amazonaws.com"}, false},
		{"test.netlify.app", []string{".netlify.app"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.cname, func(t *testing.T) {
			result := tester.matchesCNAME(tt.cname, tt.patterns)
			if result != tt.expected {
				t.Errorf("matchesCNAME(%s, %v) = %v, want %v", tt.cname, tt.patterns, result, tt.expected)
			}
		})
	}
}

func TestIsKnownVulnerableService(t *testing.T) {
	tests := []struct {
		cname      string
		expectVuln bool
		expectName string
	}{
		{"example.s3.amazonaws.com", true, "AWS S3"},
		{"example.github.io", true, "GitHub Pages"},
		{"example.herokuapp.com", true, "Heroku"},
		{"example.com", false, ""},
		{"test.azurewebsites.net", true, "Azure"},
	}

	for _, tt := range tests {
		t.Run(tt.cname, func(t *testing.T) {
			vuln, name := IsKnownVulnerableService(tt.cname)
			if vuln != tt.expectVuln {
				t.Errorf("IsKnownVulnerableService(%s) vulnerable = %v, want %v", tt.cname, vuln, tt.expectVuln)
			}
			if tt.expectVuln && name != tt.expectName {
				t.Errorf("IsKnownVulnerableService(%s) name = %s, want %s", tt.cname, name, tt.expectName)
			}
		})
	}
}

func TestCheckSubdomain(t *testing.T) {
	// Note: This test requires DNS resolution, so we use a known domain
	tester := NewTester(&TesterConfig{
		Base:      attackconfig.Base{Timeout: 5 * time.Second},
		CheckHTTP: false, // Skip HTTP check for faster test
	})

	ctx := context.Background()

	// Test with a domain that likely exists
	result, err := tester.CheckSubdomain(ctx, "example.com")
	if err != nil {
		t.Logf("DNS resolution may have failed (expected in some environments): %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if result.Subdomain != "example.com" {
		t.Errorf("expected subdomain example.com, got %s", result.Subdomain)
	}
}

func TestBatchCheck(t *testing.T) {
	tester := NewTester(&TesterConfig{
		Base:      attackconfig.Base{Timeout: 5 * time.Second, Concurrency: 5},
		CheckHTTP: false,
	})

	ctx := context.Background()

	subdomains := []string{"example.com", "google.com"}

	results, err := tester.BatchCheck(ctx, subdomains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have some results (may be 0 if DNS fails)
	_ = results
}

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		expected finding.Severity
	}{
		{VulnNS, finding.Critical},
		{VulnCNAME, finding.High},
		{VulnS3Bucket, finding.High},
		{VulnAzureBlob, finding.High},
		{VulnGitHubPages, finding.High},
		{VulnMX, finding.Medium},
	}

	for _, tt := range tests {
		t.Run(string(tt.vulnType), func(t *testing.T) {
			result := getSeverity(tt.vulnType)
			if result != tt.expected {
				t.Errorf("getSeverity(%s) = %s, want %s", tt.vulnType, result, tt.expected)
			}
		})
	}
}

func TestGetSubdomainTakeoverRemediation(t *testing.T) {
	remediation := GetSubdomainTakeoverRemediation()
	if remediation == "" {
		t.Error("expected remediation text")
	}

	if !strings.Contains(remediation, "DNS") {
		t.Error("remediation should mention DNS")
	}
	if !strings.Contains(remediation, "dangling") {
		t.Error("remediation should mention dangling records")
	}
}

func TestAllVulnerabilityTypes(t *testing.T) {
	types := AllVulnerabilityTypes()

	if len(types) != 12 {
		t.Errorf("expected 12 vulnerability types, got %d", len(types))
	}
}

func TestGetProviders(t *testing.T) {
	providers := GetProviders()

	if len(providers) == 0 {
		t.Fatal("expected providers")
	}

	// Check for some known providers
	hasAWS := false
	hasAzure := false
	hasGitHub := false

	for _, p := range providers {
		if strings.Contains(p, "AWS") {
			hasAWS = true
		}
		if strings.Contains(p, "Azure") {
			hasAzure = true
		}
		if strings.Contains(p, "GitHub") {
			hasGitHub = true
		}
	}

	if !hasAWS {
		t.Error("expected AWS provider")
	}
	if !hasAzure {
		t.Error("expected Azure provider")
	}
	if !hasGitHub {
		t.Error("expected GitHub provider")
	}
}

func TestVulnerabilityToJSON(t *testing.T) {
	vuln := Vulnerability{
		Vulnerability: finding.Vulnerability{
			Description: "S3 bucket takeover",
			Severity:    finding.High,
			Evidence:    "NoSuchBucket error",
			CVSS:        8.6,
		},
		Type:      VulnS3Bucket,
		Subdomain: "static.example.com",
		Target:    "static.example.com.s3.amazonaws.com",
		Provider:  "Amazon AWS",
	}

	jsonStr, err := VulnerabilityToJSON(vuln)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(jsonStr, "unclaimed-s3-bucket") {
		t.Error("expected vulnerability type in JSON")
	}
}

func TestVulnerability(t *testing.T) {
	vuln := Vulnerability{
		Vulnerability: finding.Vulnerability{
			Description: "GitHub Pages takeover",
			Severity:    finding.High,
			Evidence:    "No GitHub Pages site",
			Remediation: "Remove DNS record",
			CVSS:        8.6,
		},
		Type:      VulnGitHubPages,
		Subdomain: "docs.example.com",
		Target:    "example.github.io",
		Provider:  "GitHub",
	}

	data, err := json.Marshal(vuln)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded Vulnerability
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Type != vuln.Type {
		t.Errorf("type mismatch")
	}
	if decoded.Provider != vuln.Provider {
		t.Errorf("provider mismatch")
	}
}

func TestScanResult(t *testing.T) {
	result := ScanResult{
		Subdomain:    "test.example.com",
		StartTime:    time.Now(),
		EndTime:      time.Now().Add(5 * time.Second),
		Duration:     5 * time.Second,
		CNAMEChain:   []string{"example.s3.amazonaws.com"},
		IsVulnerable: true,
		Vulnerabilities: []Vulnerability{
			{Type: VulnS3Bucket},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !decoded.IsVulnerable {
		t.Error("expected IsVulnerable to be true")
	}
	if len(decoded.CNAMEChain) != 1 {
		t.Errorf("expected 1 CNAME, got %d", len(decoded.CNAMEChain))
	}
}

func TestFingerprint(t *testing.T) {
	fp := Fingerprint{
		Name:       "Test Service",
		CNAMEs:     []string{".testservice.com"},
		Patterns:   []*regexp.Regexp{regexp.MustCompile(`(?i)test error`)},
		HTTPCode:   404,
		Vulnerable: true,
		Provider:   "Test Provider",
		VulnType:   VulnCloudService,
	}

	if !fp.Vulnerable {
		t.Error("expected vulnerable to be true")
	}
	if len(fp.CNAMEs) == 0 {
		t.Error("expected CNAMEs")
	}
	if len(fp.Patterns) == 0 {
		t.Error("expected patterns")
	}
}

func TestFingerprintPatterns(t *testing.T) {
	fingerprints := GetFingerprints()

	// Test some patterns
	testCases := []struct {
		name    string
		body    string
		service string
	}{
		{"S3 bucket", "NoSuchBucket", "AWS S3"},
		{"GitHub Pages", "There isn't a GitHub Pages site here", "GitHub Pages"},
		{"Heroku", "No such app", "Heroku"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, fp := range fingerprints {
				if fp.Name != tc.service {
					continue
				}
				for _, pattern := range fp.Patterns {
					if pattern.MatchString(tc.body) {
						found = true
						break
					}
				}
			}
			if !found {
				t.Errorf("expected pattern to match for %s", tc.service)
			}
		})
	}
}

func TestTesterConfig(t *testing.T) {
	config := &TesterConfig{
		Base:        attackconfig.Base{Timeout: 10 * time.Second, UserAgent: "custom-agent/1.0", Concurrency: 5},
		DNSResolver: "8.8.8.8:53",
		CheckHTTP:   true,
		FollowCNAME: true,
	}

	if config.Timeout != 10*time.Second {
		t.Error("timeout mismatch")
	}
	if config.UserAgent != "custom-agent/1.0" {
		t.Error("user agent mismatch")
	}
	if config.DNSResolver != "8.8.8.8:53" {
		t.Error("DNS resolver mismatch")
	}
}
