// Package probes provides protocol-level probing functionality
// Based on httpx's TLS fingerprinting, CSP extraction, and pipeline probing
package probes

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/duration"
)

// TLSInfo contains TLS connection information
type TLSInfo struct {
	Version               string            `json:"tls_version"`
	CipherSuite           string            `json:"cipher_suite"`
	Protocol              string            `json:"protocol,omitempty"` // ALPN negotiated
	ServerName            string            `json:"server_name,omitempty"`
	SubjectDN             string            `json:"subject_dn,omitempty"`
	IssuerDN              string            `json:"issuer_dn,omitempty"`
	SubjectCN             string            `json:"subject_cn,omitempty"`
	SubjectAN             []string          `json:"subject_an,omitempty"` // Subject Alt Names
	Serial                string            `json:"serial,omitempty"`
	NotBefore             time.Time         `json:"not_before,omitempty"`
	NotAfter              time.Time         `json:"not_after,omitempty"`
	Fingerprint           string            `json:"fingerprint,omitempty"` // SHA256
	JA3Fingerprint        string            `json:"ja3,omitempty"`
	JARMFingerprint       string            `json:"jarm,omitempty"` // Active TLS fingerprint
	OCSPStapling          bool              `json:"ocsp_stapling"`
	SCTList               bool              `json:"sct_list"`
	TLSExtensions         []uint16          `json:"tls_extensions,omitempty"`
	SupportedVersions     []string          `json:"supported_versions,omitempty"`
	SupportedCipherSuites []string          `json:"supported_cipher_suites,omitempty"`
	CertificateChain      []CertificateInfo `json:"certificate_chain,omitempty"`
	Errors                []string          `json:"errors,omitempty"`
	Mismatched            bool              `json:"mismatched"` // Host doesn't match cert
	SelfSigned            bool              `json:"self_signed"`
	Expired               bool              `json:"expired"`
	Revoked               bool              `json:"revoked,omitempty"`
}

// CertificateInfo contains certificate details
type CertificateInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"` // SHA256
	IsCA        bool      `json:"is_ca"`
}

// TLSProber probes TLS connections for information
type TLSProber struct {
	Timeout     time.Duration
	MaxVersions []uint16
	MinVersions []uint16
	DialTimeout time.Duration
}

// NewTLSProber creates a new TLS prober with defaults
func NewTLSProber() *TLSProber {
	return &TLSProber{
		Timeout:     duration.DialTimeout,
		DialTimeout: duration.HTTPProbing,
		MaxVersions: []uint16{
			tls.VersionTLS13,
			tls.VersionTLS12,
			tls.VersionTLS11,
			tls.VersionTLS10,
		},
		MinVersions: []uint16{
			tls.VersionTLS10,
			tls.VersionTLS11,
			tls.VersionTLS12,
			tls.VersionTLS13,
		},
	}
}

// Probe performs a TLS handshake and extracts information
func (p *TLSProber) Probe(ctx context.Context, host string, port int) (*TLSInfo, error) {
	if port == 0 {
		port = 443
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	info := &TLSInfo{
		ServerName: host,
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // We validate ourselves
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	// Dial with timeout
	dialer := &net.Dialer{
		Timeout: p.DialTimeout,
	}

	netConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	// Set deadline
	if deadline, ok := ctx.Deadline(); ok {
		netConn.SetDeadline(deadline)
	} else {
		netConn.SetDeadline(time.Now().Add(p.Timeout))
	}

	// TLS handshake
	tlsConn := tls.Client(netConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		netConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close() // also closes underlying netConn

	// Extract connection state
	state := tlsConn.ConnectionState()

	// Version
	info.Version = versionToString(state.Version)

	// Cipher suite
	info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// ALPN negotiated protocol
	info.Protocol = state.NegotiatedProtocol

	// Process certificates
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		info.SubjectDN = cert.Subject.String()
		info.IssuerDN = cert.Issuer.String()
		info.SubjectCN = cert.Subject.CommonName
		info.SubjectAN = append([]string(nil), cert.DNSNames...)
		info.Serial = cert.SerialNumber.String()
		info.NotBefore = cert.NotBefore
		info.NotAfter = cert.NotAfter

		// SHA256 fingerprint
		fingerprint := sha256.Sum256(cert.Raw)
		info.Fingerprint = hex.EncodeToString(fingerprint[:])

		// Check validity
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			info.Expired = true
		}

		// Check if self-signed
		if cert.Subject.String() == cert.Issuer.String() {
			info.SelfSigned = true
		}

		// Check hostname match
		if err := cert.VerifyHostname(host); err != nil {
			info.Mismatched = true
		}

		// Build certificate chain
		for _, c := range state.PeerCertificates {
			fp := sha256.Sum256(c.Raw)
			info.CertificateChain = append(info.CertificateChain, CertificateInfo{
				Subject:     c.Subject.String(),
				Issuer:      c.Issuer.String(),
				Serial:      c.SerialNumber.String(),
				NotBefore:   c.NotBefore,
				NotAfter:    c.NotAfter,
				Fingerprint: hex.EncodeToString(fp[:]),
				IsCA:        c.IsCA,
			})
		}
	}

	// OCSP Stapling
	if len(state.OCSPResponse) > 0 {
		info.OCSPStapling = true
	}

	// SCT (Signed Certificate Timestamps)
	if len(state.SignedCertificateTimestamps) > 0 {
		info.SCTList = true
	}

	return info, nil
}

// ProbeSupportedVersions probes for all supported TLS versions
func (p *TLSProber) ProbeSupportedVersions(ctx context.Context, host string, port int) ([]string, error) {
	if port == 0 {
		port = 443
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var supported []string

	versions := []uint16{
		tls.VersionSSL30, // 0x0300 (deprecated)
		tls.VersionTLS10, // 0x0301
		tls.VersionTLS11, // 0x0302
		tls.VersionTLS12, // 0x0303
		tls.VersionTLS13, // 0x0304
	}

	for _, ver := range versions {
		select {
		case <-ctx.Done():
			return supported, ctx.Err()
		default:
		}

		// Go doesn't support SSL 3.0 client, skip it
		if ver == tls.VersionSSL30 {
			continue
		}

		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         ver,
			MaxVersion:         ver,
		}

		dialer := &net.Dialer{
			Timeout: p.DialTimeout,
		}

		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}

		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			conn.Close()
		} else {
			tlsConn.Close() // also closes conn
			supported = append(supported, versionToString(ver))
		}
	}

	return supported, nil
}

// ProbeCipherSuites probes for supported cipher suites
func (p *TLSProber) ProbeCipherSuites(ctx context.Context, host string, port int) ([]string, error) {
	if port == 0 {
		port = 443
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var supported []string

	// Get all cipher suites
	ciphers := tls.CipherSuites()
	insecure := tls.InsecureCipherSuites()

	allCiphers := make([]uint16, 0, len(ciphers)+len(insecure))
	for _, c := range ciphers {
		allCiphers = append(allCiphers, c.ID)
	}
	for _, c := range insecure {
		allCiphers = append(allCiphers, c.ID)
	}

	for _, cipher := range allCiphers {
		select {
		case <-ctx.Done():
			return supported, ctx.Err()
		default:
		}

		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{cipher},
		}

		dialer := &net.Dialer{
			Timeout: p.DialTimeout,
		}

		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}

		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			conn.Close()
		} else {
			tlsConn.Close() // also closes conn
			supported = append(supported, tls.CipherSuiteName(cipher))
		}
	}

	return supported, nil
}

// GenerateJARMFingerprint generates JARM fingerprint (simplified)
// JARM sends 10 TLS client hello probes and combines responses
func (p *TLSProber) GenerateJARMFingerprint(ctx context.Context, host string, port int) (string, error) {
	if port == 0 {
		port = 443
	}

	// JARM uses specific TLS configurations to fingerprint servers
	// This is a simplified implementation
	probes := []struct {
		minVer     uint16
		maxVer     uint16
		ciphers    []uint16
		extensions []uint16
	}{
		{tls.VersionTLS12, tls.VersionTLS12, nil, nil},
		{tls.VersionTLS13, tls.VersionTLS13, nil, nil},
		{tls.VersionTLS11, tls.VersionTLS11, nil, nil},
		{tls.VersionTLS10, tls.VersionTLS10, nil, nil},
	}

	var results []string

	for _, probe := range probes {
		result := p.jarmProbe(ctx, host, port, probe.minVer, probe.maxVer)
		results = append(results, result)
	}

	// Combine results into fingerprint
	combined := strings.Join(results, "")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:32]), nil
}

func (p *TLSProber) jarmProbe(ctx context.Context, host string, port int, minVer, maxVer uint16) string {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         minVer,
		MaxVersion:         maxVer,
	}

	dialer := &net.Dialer{
		Timeout: p.DialTimeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "000"
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return "000"
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	return fmt.Sprintf("%03x", state.CipherSuite&0xFFF)
}

// versionToString converts TLS version to string
func versionToString(ver uint16) string {
	switch ver {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", ver)
	}
}

// GetWeakCiphers returns list of weak cipher suites if present
func (info *TLSInfo) GetWeakCiphers() []string {
	weakPatterns := []string{
		"NULL", "EXPORT", "DES", "RC4", "MD5", "CBC",
		"3DES", "ANON", "PSK", "SRP", "CAMELLIA",
	}

	var weak []string
	for _, cipher := range info.SupportedCipherSuites {
		upper := strings.ToUpper(cipher)
		for _, pattern := range weakPatterns {
			if strings.Contains(upper, pattern) {
				weak = append(weak, cipher)
				break
			}
		}
	}

	return weak
}

// GetSecurityGrade returns a security grade based on TLS config
func (info *TLSInfo) GetSecurityGrade() string {
	// Grade based on httpx-style grading
	score := 100

	// Deductions for issues
	if info.Expired {
		score -= 50
	}
	if info.SelfSigned {
		score -= 20
	}
	if info.Mismatched {
		score -= 30
	}

	// Version checks
	switch info.Version {
	case "SSLv3":
		score -= 50
	case "TLS1.0":
		score -= 30
	case "TLS1.1":
		score -= 20
	case "TLS1.2":
		// OK
	case "TLS1.3":
		score += 10 // Bonus for TLS 1.3
	}

	// Cipher suite checks
	if strings.Contains(strings.ToUpper(info.CipherSuite), "NULL") ||
		strings.Contains(strings.ToUpper(info.CipherSuite), "EXPORT") ||
		strings.Contains(strings.ToUpper(info.CipherSuite), "RC4") {
		score -= 40
	}

	// Calculate grade
	switch {
	case score >= 95:
		return "A+"
	case score >= 85:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// TLSInfoSummary provides a quick text summary
func (info *TLSInfo) TLSInfoSummary() string {
	var parts []string
	parts = append(parts, info.Version)

	if info.Protocol != "" {
		parts = append(parts, info.Protocol)
	}

	if info.Expired {
		parts = append(parts, "EXPIRED")
	}
	if info.SelfSigned {
		parts = append(parts, "SELF-SIGNED")
	}
	if info.Mismatched {
		parts = append(parts, "HOSTNAME-MISMATCH")
	}

	parts = append(parts, fmt.Sprintf("[%s]", info.GetSecurityGrade()))

	return strings.Join(parts, " | ")
}

// SANContains checks if the Subject Alternative Names contain a domain
func (info *TLSInfo) SANContains(domain string) bool {
	domain = strings.ToLower(domain)
	for _, san := range info.SubjectAN {
		san = strings.ToLower(san)
		if san == domain {
			return true
		}
		// Check wildcard — RFC 6125: wildcards match exactly one label
		if strings.HasPrefix(san, "*.") {
			baseDomain := san[2:] // Remove *.
			if idx := strings.Index(domain, "."); idx != -1 && domain[idx+1:] == baseDomain {
				return true
			}
		}
	}
	return false
}

// GetAllDomains returns all domains from CN and SANs
func (info *TLSInfo) GetAllDomains() []string {
	domains := make(map[string]bool)

	if info.SubjectCN != "" && !strings.Contains(info.SubjectCN, " ") {
		domains[strings.ToLower(info.SubjectCN)] = true
	}

	for _, san := range info.SubjectAN {
		domains[strings.ToLower(san)] = true
	}

	result := make([]string, 0, len(domains))
	for d := range domains {
		result = append(result, d)
	}

	sort.Strings(result)
	return result
}
