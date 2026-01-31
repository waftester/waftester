package probes

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/ui"
)

// HTTPProbeResult contains HTTP probing results
type HTTPProbeResult struct {
	Host              string        `json:"host"`
	Port              int           `json:"port"`
	HTTP2Supported    bool          `json:"http2_supported"`
	H2CSupported      bool          `json:"h2c_supported"` // HTTP/2 cleartext
	PipelineSupported bool          `json:"pipeline_supported"`
	KeepAliveWorks    bool          `json:"keep_alive_works"`
	Methods           []string      `json:"methods,omitempty"` // Allowed methods
	MaxConnections    int           `json:"max_connections,omitempty"`
	ResponseTime      time.Duration `json:"response_time"`
	ServerPush        bool          `json:"server_push,omitempty"`
	ALPN              []string      `json:"alpn,omitempty"`
	Errors            []string      `json:"errors,omitempty"`
}

// HTTPProber probes HTTP capabilities
type HTTPProber struct {
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxRedirects int
	UserAgent    string
}

// NewHTTPProber creates a new HTTP prober with defaults
func NewHTTPProber() *HTTPProber {
	return &HTTPProber{
		DialTimeout:  5 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 5 * time.Second,
		MaxRedirects: 5,
		UserAgent:    ui.UserAgentWithContext("prober"),
	}
}

// ProbeHTTP2 checks if HTTP/2 is supported
func (p *HTTPProber) ProbeHTTP2(ctx context.Context, host string, port int) (bool, string, error) {
	if port == 0 {
		port = 443
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// TLS config with ALPN
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	dialer := &net.Dialer{
		Timeout: p.DialTimeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return false, "", err
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	proto := state.NegotiatedProtocol

	return proto == "h2", proto, nil
}

// ProbeH2C checks if HTTP/2 over cleartext is supported
func (p *HTTPProber) ProbeH2C(ctx context.Context, host string, port int) (bool, error) {
	if port == 0 {
		port = 80
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{
		Timeout: p.DialTimeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.ReadTimeout))

	// Send HTTP/1.1 Upgrade request
	req := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: Upgrade, HTTP2-Settings\r\n"+
			"Upgrade: h2c\r\n"+
			"HTTP2-Settings: \r\n"+
			"\r\n",
		host,
	)

	if _, err := conn.Write([]byte(req)); err != nil {
		return false, err
	}

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	// Check for 101 Switching Protocols
	return strings.Contains(resp, "101"), nil
}

// ProbePipeline checks if HTTP pipelining is supported
func (p *HTTPProber) ProbePipeline(ctx context.Context, host string, port int, useTLS bool) (bool, error) {
	if port == 0 {
		if useTLS {
			port = 443
		} else {
			port = 80
		}
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{
		Timeout: p.DialTimeout,
	}

	var conn net.Conn
	var err error

	if useTLS {
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return false, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.ReadTimeout))

	// Send multiple pipelined requests
	requests := ""
	for i := 0; i < 3; i++ {
		requests += fmt.Sprintf(
			"GET /?pipeline=%d HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Connection: keep-alive\r\n"+
				"User-Agent: %s\r\n"+
				"\r\n",
			i, host, p.UserAgent,
		)
	}

	if _, err := conn.Write([]byte(requests)); err != nil {
		return false, err
	}

	// Read responses
	reader := bufio.NewReader(conn)
	responseCount := 0

	for responseCount < 3 {
		// Read status line
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		if strings.HasPrefix(line, "HTTP/") {
			responseCount++

			// Read headers until empty line
			for {
				header, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				if header == "\r\n" {
					break
				}
			}
		}
	}

	// If we got all 3 responses, pipelining works
	return responseCount >= 3, nil
}

// ProbeKeepAlive checks if Keep-Alive works
func (p *HTTPProber) ProbeKeepAlive(ctx context.Context, host string, port int, useTLS bool) (bool, int, error) {
	if port == 0 {
		if useTLS {
			port = 443
		} else {
			port = 80
		}
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{
		Timeout: p.DialTimeout,
	}

	var conn net.Conn
	var err error

	if useTLS {
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return false, 0, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.ReadTimeout))

	successfulRequests := 0

	for i := 0; i < 5; i++ {
		req := fmt.Sprintf(
			"GET / HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Connection: keep-alive\r\n"+
				"User-Agent: %s\r\n"+
				"\r\n",
			host, p.UserAgent,
		)

		if _, err := conn.Write([]byte(req)); err != nil {
			break
		}

		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		if strings.HasPrefix(line, "HTTP/") {
			successfulRequests++

			// Read headers and body
			contentLength := 0
			chunked := false
			for {
				header, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				if header == "\r\n" {
					break
				}
				lower := strings.ToLower(header)
				if strings.HasPrefix(lower, "content-length:") {
					fmt.Sscanf(lower, "content-length: %d", &contentLength)
				}
				if strings.Contains(lower, "transfer-encoding:") && strings.Contains(lower, "chunked") {
					chunked = true
				}
			}

			// Drain body
			if contentLength > 0 {
				io.CopyN(io.Discard, reader, int64(contentLength))
			} else if chunked {
				// Simple chunked reading
				for {
					sizeLine, _ := reader.ReadString('\n')
					sizeLine = strings.TrimSpace(sizeLine)
					size, _ := strconv.ParseInt(sizeLine, 16, 64)
					if size == 0 {
						reader.ReadString('\n') // trailing CRLF
						break
					}
					io.CopyN(io.Discard, reader, size+2) // +2 for CRLF
				}
			}
		}
	}

	return successfulRequests > 1, successfulRequests, nil
}

// ProbeMethods checks which HTTP methods are allowed
func (p *HTTPProber) ProbeMethods(ctx context.Context, host string, port int, useTLS bool, path string) ([]string, error) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	if port == 0 {
		if useTLS {
			port = 443
		} else {
			port = 80
		}
	}

	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)

	client := &http.Client{
		Timeout: p.ReadTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// First try OPTIONS
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", url, nil)
	if err == nil {
		req.Header.Set("User-Agent", p.UserAgent)

		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if allow := resp.Header.Get("Allow"); allow != "" {
				methods := strings.Split(allow, ",")
				for i := range methods {
					methods[i] = strings.TrimSpace(methods[i])
				}
				return methods, nil
			}
		}
	}

	// Fall back to probing each method
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
	var allowed []string

	for _, method := range methods {
		select {
		case <-ctx.Done():
			return allowed, ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", p.UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Not 405 Method Not Allowed means it's probably allowed
		if resp.StatusCode != 405 {
			allowed = append(allowed, method)
		}
	}

	return allowed, nil
}

// VHostProbeResult contains virtual host probing results
type VHostProbeResult struct {
	Host          string `json:"host"`
	VHost         string `json:"vhost"`
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	Title         string `json:"title,omitempty"`
	Valid         bool   `json:"valid"` // Different from base
}

// VHostProber probes for virtual hosts
type VHostProber struct {
	Timeout   time.Duration
	UserAgent string
}

// NewVHostProber creates a new vhost prober
func NewVHostProber() *VHostProber {
	return &VHostProber{
		Timeout:   10 * time.Second,
		UserAgent: ui.UserAgentWithContext("vhost-prober"),
	}
}

// ProbeVHosts probes for virtual hosts using a wordlist
func (p *VHostProber) ProbeVHosts(ctx context.Context, targetIP string, port int, domain string, wordlist []string) ([]VHostProbeResult, error) {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}

	baseURL := fmt.Sprintf("%s://%s:%d/", scheme, targetIP, port)

	client := &http.Client{
		Timeout: p.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Get baseline with original domain
	baseReq, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return nil, err
	}
	baseReq.Host = domain
	baseReq.Header.Set("User-Agent", p.UserAgent)

	baseResp, err := client.Do(baseReq)
	if err != nil {
		return nil, err
	}
	baseBody, _ := io.ReadAll(baseResp.Body)
	baseResp.Body.Close()

	baseStatus := baseResp.StatusCode
	baseLen := len(baseBody)

	var results []VHostProbeResult

	for _, word := range wordlist {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		vhost := word + "." + domain

		req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
		if err != nil {
			continue
		}
		req.Host = vhost
		req.Header.Set("User-Agent", p.UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		result := VHostProbeResult{
			Host:          targetIP,
			VHost:         vhost,
			StatusCode:    resp.StatusCode,
			ContentLength: len(body),
		}

		// Extract title
		result.Title = extractTitle(body)

		// Check if different from baseline
		if resp.StatusCode != baseStatus || !similarLength(len(body), baseLen) {
			result.Valid = true
		}

		// Also check for content differences
		if !bytes.Equal(body, baseBody) && result.ContentLength > 0 {
			// Simple similarity check
			similarity := contentSimilarity(baseBody, body)
			if similarity < 0.95 { // Less than 95% similar
				result.Valid = true
			}
		}

		if result.Valid {
			results = append(results, result)
		}
	}

	return results, nil
}

// extractTitle extracts title from HTML
func extractTitle(body []byte) string {
	html := string(body)
	start := strings.Index(strings.ToLower(html), "<title>")
	if start == -1 {
		return ""
	}
	start += 7

	end := strings.Index(strings.ToLower(html[start:]), "</title>")
	if end == -1 {
		return ""
	}

	title := strings.TrimSpace(html[start : start+end])
	if len(title) > 100 {
		title = title[:100]
	}
	return title
}

// similarLength checks if two lengths are within 10% of each other
func similarLength(a, b int) bool {
	if a == b {
		return true
	}
	if a == 0 || b == 0 {
		return false
	}

	ratio := float64(a) / float64(b)
	return ratio > 0.9 && ratio < 1.1
}

// contentSimilarity calculates simple content similarity
func contentSimilarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// Simple approach: count matching bytes
	shorter, longer := a, b
	if len(a) > len(b) {
		shorter, longer = b, a
	}

	matches := 0
	for i := range shorter {
		if shorter[i] == longer[i] {
			matches++
		}
	}

	return float64(matches) / float64(len(longer))
}

// GenerateVHostWordlist generates common vhost prefixes
func GenerateVHostWordlist() []string {
	return []string{
		"www", "mail", "remote", "blog", "webmail", "server",
		"ns1", "ns2", "smtp", "secure", "vpn", "m", "shop",
		"ftp", "mail2", "test", "portal", "ns", "ww1", "host",
		"support", "dev", "web", "bbs", "ww42", "mx", "email",
		"cloud", "1", "mail1", "2", "forum", "owa", "www2",
		"gw", "admin", "store", "mx1", "cdn", "api", "exchange",
		"app", "gov", "2tty", "vps", "govyty", "hgfgdf", "news",
		"1rer", "lkjkui", "internal", "intranet", "corp", "local",
		"staging", "stage", "demo", "sandbox", "beta", "alpha",
		"pre", "preprod", "uat", "qa", "ci", "cd", "jenkins",
		"gitlab", "github", "bitbucket", "jira", "confluence",
		"grafana", "kibana", "prometheus", "elk", "log", "logs",
		"monitor", "metrics", "status", "health", "dashboard",
	}
}
