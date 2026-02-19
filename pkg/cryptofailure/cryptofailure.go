// Package cryptofailure provides testing for Cryptographic Failures (OWASP A02:2021)
package cryptofailure

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
)

// VulnerabilityType represents cryptographic vulnerability types
type VulnerabilityType string

const (
	WeakTLSVersion     VulnerabilityType = "weak_tls_version"
	WeakCipherSuite    VulnerabilityType = "weak_cipher_suite"
	ExpiredCertificate VulnerabilityType = "expired_certificate"
	SelfSignedCert     VulnerabilityType = "self_signed_certificate"
	WeakKeySize        VulnerabilityType = "weak_key_size"
	MissingHSTS        VulnerabilityType = "missing_hsts"
	InsecureTransport  VulnerabilityType = "insecure_transport"
	HardcodedSecrets   VulnerabilityType = "hardcoded_secrets"
	WeakHashing        VulnerabilityType = "weak_hashing"
	InsecureRandomness VulnerabilityType = "insecure_randomness"
)

// TestResult represents a cryptographic test result
type TestResult struct {
	VulnType    VulnerabilityType `json:"vuln_type"`
	Target      string            `json:"target"`
	Vulnerable  bool              `json:"vulnerable"`
	Description string            `json:"description"`
	Evidence    string            `json:"evidence,omitempty"`
	Severity    finding.Severity  `json:"severity"`
	Remediation string            `json:"remediation"`
}

// TLSInfo contains TLS connection information
type TLSInfo struct {
	Version               uint16
	CipherSuite           uint16
	CertificateExpiry     time.Time
	CertificateIssuer     string
	CertificateSubject    string
	KeySize               int
	IsSelfSigned          bool
	SupportedVersions     []uint16
	SupportedCipherSuites []uint16
}

// Tester performs cryptographic vulnerability testing
type Tester struct {
	target  string
	timeout time.Duration
}

// NewTester creates a new cryptographic failure tester
func NewTester(target string, timeout time.Duration) *Tester {
	if timeout == 0 {
		timeout = httpclient.TimeoutProbing
	}
	return &Tester{
		target:  target,
		timeout: timeout,
	}
}

// WeakTLSVersions returns deprecated/weak TLS versions
func WeakTLSVersions() map[uint16]string {
	return map[uint16]string{
		tls.VersionSSL30: "SSL 3.0",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
	}
}

// WeakCipherSuites returns known weak cipher suites
func WeakCipherSuites() map[uint16]string {
	return map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "TLS_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	}
}

// SecretPatterns returns regex patterns for detecting hardcoded secrets
func SecretPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"AWS Access Key":   regexcache.MustGet(`AKIA[0-9A-Z]{16}`),
		"AWS Secret Key":   regexcache.MustGet(`(?i)aws_secret_access_key[\"'=:\s]+[A-Za-z0-9/+=]{40}`),
		"Private Key":      regexcache.MustGet(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		"Generic Secret":   regexcache.MustGet(`(?i)(password|secret|api_key|apikey|auth_token|authtoken)[\"'=:\s]+[\"']?[A-Za-z0-9+/=]{8,}[\"']?`),
		"JWT":              regexcache.MustGet(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		"GitHub Token":     regexcache.MustGet(`gh[pousr]_[A-Za-z0-9_]{36,}`),
		"Slack Token":      regexcache.MustGet(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
		"Google API Key":   regexcache.MustGet(`AIza[0-9A-Za-z_-]{35}`),
		"Stripe Key":       regexcache.MustGet(`(?i)sk_live_[0-9a-zA-Z]{24,}`),
		"RSA Key Fragment": regexcache.MustGet(`(?i)(rsa_private|id_rsa|ssh_key)[\"'=:\s]`),
		"Database URL":     regexcache.MustGet(`(?i)(mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@`),
		"Bearer Token":     regexcache.MustGet(`(?i)bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
	}
}

// WeakHashPatterns returns patterns for weak hashing algorithms
func WeakHashPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"MD5 Hash":   regexcache.MustGet(`(?i)\b[a-f0-9]{32}\b`),
		"SHA1 Hash":  regexcache.MustGet(`(?i)\b[a-f0-9]{40}\b`),
		"MD5 Usage":  regexcache.MustGet(`(?i)(md5|MD5)\s*\(`),
		"SHA1 Usage": regexcache.MustGet(`(?i)(sha1|SHA1)\s*\(`),
	}
}

// TestTLSVersion tests for weak TLS versions
func (t *Tester) TestTLSVersion(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	host := strings.TrimPrefix(t.target, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	weakVersions := WeakTLSVersions()

	for version, name := range weakVersions {
		config := &tls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			InsecureSkipVerify: true,
		}

		dialer := &net.Dialer{Timeout: t.timeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", host, config)

		result := TestResult{
			VulnType: WeakTLSVersion,
			Target:   t.target,
			Severity: finding.High,
		}

		if err == nil {
			conn.Close()
			result.Vulnerable = true
			result.Description = fmt.Sprintf("Server accepts deprecated %s", name)
			result.Evidence = fmt.Sprintf("Successfully negotiated %s connection", name)
			result.Remediation = "Disable TLS 1.0, TLS 1.1, and SSL 3.0. Only allow TLS 1.2+"
		} else {
			result.Vulnerable = false
			result.Description = fmt.Sprintf("Server correctly rejects %s", name)
		}

		results = append(results, result)
	}

	return results, nil
}

// TestCipherSuites tests for weak cipher suites
func (t *Tester) TestCipherSuites(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	host := strings.TrimPrefix(t.target, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	weakCiphers := WeakCipherSuites()

	for cipher, name := range weakCiphers {
		config := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{cipher},
			InsecureSkipVerify: true,
		}

		dialer := &net.Dialer{Timeout: t.timeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", host, config)

		result := TestResult{
			VulnType: WeakCipherSuite,
			Target:   t.target,
			Severity: finding.Medium,
		}

		if err == nil {
			conn.Close()
			result.Vulnerable = true
			result.Description = fmt.Sprintf("Server accepts weak cipher: %s", name)
			result.Evidence = fmt.Sprintf("Successfully negotiated with %s", name)
			result.Remediation = "Configure server to only accept strong cipher suites"
		} else {
			result.Vulnerable = false
			result.Description = fmt.Sprintf("Server correctly rejects %s", name)
		}

		results = append(results, result)
	}

	return results, nil
}

// TestCertificate tests certificate validity
func (t *Tester) TestCertificate(ctx context.Context) ([]TestResult, error) {
	var results []TestResult

	host := strings.TrimPrefix(t.target, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	dialer := &net.Dialer{Timeout: t.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
	if err != nil {
		return results, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return results, fmt.Errorf("no certificates found")
	}

	cert := state.PeerCertificates[0]

	// Check for expired certificate
	if time.Now().After(cert.NotAfter) {
		results = append(results, TestResult{
			VulnType:    ExpiredCertificate,
			Target:      t.target,
			Vulnerable:  true,
			Description: "Certificate has expired",
			Evidence:    fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC3339)),
			Severity:    finding.Critical,
			Remediation: "Renew the SSL/TLS certificate immediately",
		})
	} else if time.Until(cert.NotAfter) < 30*24*time.Hour {
		results = append(results, TestResult{
			VulnType:    ExpiredCertificate,
			Target:      t.target,
			Vulnerable:  true,
			Description: "Certificate expires soon",
			Evidence:    fmt.Sprintf("Certificate expires on %s (less than 30 days)", cert.NotAfter.Format(time.RFC3339)),
			Severity:    finding.Medium,
			Remediation: "Plan certificate renewal before expiry",
		})
	}

	// Check for self-signed certificate
	isSelfSigned := cert.Issuer.String() == cert.Subject.String()
	if isSelfSigned {
		results = append(results, TestResult{
			VulnType:    SelfSignedCert,
			Target:      t.target,
			Vulnerable:  true,
			Description: "Certificate is self-signed",
			Evidence:    fmt.Sprintf("Issuer matches Subject: %s", cert.Issuer.String()),
			Severity:    finding.High,
			Remediation: "Use a certificate from a trusted Certificate Authority",
		})
	}

	// Check key size
	if cert.PublicKeyAlgorithm == x509.RSA {
		if rsaKey, ok := cert.PublicKey.(interface{ Size() int }); ok {
			keySize := rsaKey.Size() * 8
			if keySize < 2048 {
				results = append(results, TestResult{
					VulnType:    WeakKeySize,
					Target:      t.target,
					Vulnerable:  true,
					Description: "Certificate uses weak key size",
					Evidence:    fmt.Sprintf("RSA key size: %d bits (minimum recommended: 2048)", keySize),
					Severity:    finding.High,
					Remediation: "Use at least 2048-bit RSA keys or switch to ECDSA",
				})
			}
		}
	}

	return results, nil
}

// TestHSTS tests for HSTS header
func (t *Tester) TestHSTS(ctx context.Context) (*TestResult, error) {
	client := httpclient.Default()

	req, err := http.NewRequestWithContext(ctx, "GET", t.target, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	hstsHeader := resp.Header.Get("Strict-Transport-Security")

	result := &TestResult{
		VulnType: MissingHSTS,
		Target:   t.target,
		Severity: finding.Medium,
	}

	if hstsHeader == "" {
		result.Vulnerable = true
		result.Description = "Missing Strict-Transport-Security header"
		result.Remediation = "Add HSTS header with appropriate max-age (e.g., 31536000)"
	} else {
		result.Vulnerable = false
		result.Description = "HSTS header present"
		result.Evidence = hstsHeader

		// Check for suboptimal configuration
		if !strings.Contains(hstsHeader, "includeSubDomains") {
			result.Evidence += " (missing includeSubDomains)"
		}
		if !strings.Contains(hstsHeader, "preload") {
			result.Evidence += " (missing preload)"
		}
	}

	return result, nil
}

// TestHTTPDowngrade tests for HTTP downgrade vulnerability
func (t *Tester) TestHTTPDowngrade(ctx context.Context) (*TestResult, error) {
	httpTarget := strings.Replace(t.target, "https://", "http://", 1)

	client := httpclient.Default()

	req, err := http.NewRequestWithContext(ctx, "GET", httpTarget, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		// Connection refused is good - HTTP disabled
		return &TestResult{
			VulnType:    InsecureTransport,
			Target:      httpTarget,
			Vulnerable:  false,
			Description: "HTTP endpoint not accessible (good)",
			Severity:    finding.Low,
		}, nil
	}
	defer iohelper.DrainAndClose(resp.Body)

	result := &TestResult{
		VulnType: InsecureTransport,
		Target:   httpTarget,
		Severity: finding.Medium,
	}

	if resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 308 {
		location := resp.Header.Get("Location")
		if strings.HasPrefix(location, "https://") {
			result.Vulnerable = false
			result.Description = "HTTP properly redirects to HTTPS"
			result.Evidence = fmt.Sprintf("Redirects to: %s", location)
		} else {
			result.Vulnerable = true
			result.Description = "HTTP redirect does not use HTTPS"
			result.Evidence = fmt.Sprintf("Redirects to: %s", location)
			result.Remediation = "Ensure all HTTP requests redirect to HTTPS"
		}
	} else if resp.StatusCode == 200 {
		result.Vulnerable = true
		result.Description = "HTTP endpoint serves content without redirecting to HTTPS"
		result.Evidence = fmt.Sprintf("HTTP %d on insecure endpoint", resp.StatusCode)
		result.Remediation = "Force redirect all HTTP traffic to HTTPS"
	}

	return result, nil
}

// ScanForSecrets scans content for hardcoded secrets
func ScanForSecrets(content string) []TestResult {
	var results []TestResult

	patterns := SecretPatterns()

	for name, pattern := range patterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			// Mask the actual secret
			maskedEvidence := make([]string, len(matches))
			for i, m := range matches {
				if len(m) > 20 {
					maskedEvidence[i] = m[:10] + "..." + m[len(m)-5:]
				} else if len(m) > 8 {
					maskedEvidence[i] = m[:4] + "..." + m[len(m)-2:]
				} else {
					maskedEvidence[i] = "***"
				}
			}

			results = append(results, TestResult{
				VulnType:    HardcodedSecrets,
				Vulnerable:  true,
				Description: fmt.Sprintf("Detected potential %s in content", name),
				Evidence:    fmt.Sprintf("Found %d instances: %v", len(matches), maskedEvidence),
				Severity:    finding.Critical,
				Remediation: "Remove hardcoded secrets and use environment variables or secret management",
			})
		}
	}

	return results
}

// ScanForWeakHashing scans content for weak hashing usage
func ScanForWeakHashing(content string) []TestResult {
	var results []TestResult

	patterns := WeakHashPatterns()

	for name, pattern := range patterns {
		if pattern.MatchString(content) {
			results = append(results, TestResult{
				VulnType:    WeakHashing,
				Vulnerable:  true,
				Description: fmt.Sprintf("Detected %s usage", name),
				Severity:    finding.Medium,
				Remediation: "Use strong hashing algorithms like bcrypt, Argon2, or SHA-256+",
			})
		}
	}

	return results
}

// ScanResponseForSecrets scans an HTTP response for secrets
func (t *Tester) ScanResponseForSecrets(ctx context.Context, path string) ([]TestResult, error) {
	client := httpclient.Default()

	fullURL := t.target + path

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, err := iohelper.ReadBody(resp.Body, iohelper.DefaultMaxBodySize) // 1MB limit
	if err != nil {
		return nil, err
	}

	results := ScanForSecrets(string(body))
	for i := range results {
		results[i].Target = fullURL
	}

	return results, nil
}

// RunAllTests runs all cryptographic tests
func (t *Tester) RunAllTests(ctx context.Context) ([]TestResult, error) {
	var allResults []TestResult

	// TLS version tests
	if results, err := t.TestTLSVersion(ctx); err == nil {
		allResults = append(allResults, results...)
	}

	// Cipher suite tests (limited to avoid too many)
	// Skip cipher tests in RunAll to keep it fast

	// Certificate tests
	if results, err := t.TestCertificate(ctx); err == nil {
		allResults = append(allResults, results...)
	}

	// HSTS test
	if result, err := t.TestHSTS(ctx); err == nil && result != nil {
		allResults = append(allResults, *result)
	}

	// HTTP downgrade test
	if result, err := t.TestHTTPDowngrade(ctx); err == nil && result != nil {
		allResults = append(allResults, *result)
	}

	return allResults, nil
}

// SummarizeResults summarizes test results
func SummarizeResults(results []TestResult) map[string]int {
	summary := map[string]int{
		"total":      len(results),
		"vulnerable": 0,
		"safe":       0,
		"critical":   0,
		"high":       0,
		"medium":     0,
	}

	for _, r := range results {
		if r.Vulnerable {
			summary["vulnerable"]++
			switch r.Severity {
			case finding.Critical:
				summary["critical"]++
			case finding.High:
				summary["high"]++
			case finding.Medium:
				summary["medium"]++
			}
		} else {
			summary["safe"]++
		}
	}

	return summary
}
