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
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
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
		DialTimeout:  duration.HTTPProbing,
		ReadTimeout:  duration.DialTimeout,
		WriteTimeout: duration.HTTPProbing,
		MaxRedirects: defaults.MaxRedirects,
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
		rawConn, dialErr := dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			err = dialErr
		} else {
			tlsConn := tls.Client(rawConn, tlsConfig)
			if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
				rawConn.Close()
				err = hsErr
			} else {
				conn = tlsConn
			}
		}
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

			// Read headers until empty line, track body size
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

			// Drain response body before reading next response
			if contentLength > 0 {
				io.CopyN(io.Discard, reader, int64(contentLength))
			} else if chunked {
				// Read chunked body until terminal 0-length chunk
				for {
					sizeLine, err := reader.ReadString('\n')
					if err != nil {
						break
					}
					sizeLine = strings.TrimSpace(sizeLine)
					// Strip chunk extensions (RFC 7230 sec 4.1.1)
					if semi := strings.IndexByte(sizeLine, ';'); semi >= 0 {
						sizeLine = sizeLine[:semi]
					}
					var chunkSize int64
					fmt.Sscanf(sizeLine, "%x", &chunkSize)
					if chunkSize == 0 {
						reader.ReadString('\n') // trailing CRLF
						break
					}
					io.CopyN(io.Discard, reader, chunkSize)
					reader.ReadString('\n') // chunk-terminating CRLF
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
		rawConn, dialErr := dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			err = dialErr
		} else {
			tlsConn := tls.Client(rawConn, tlsConfig)
			if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
				rawConn.Close()
				err = hsErr
			} else {
				conn = tlsConn
			}
		}
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return false, 0, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(p.ReadTimeout))

	successfulRequests := 0
	reader := bufio.NewReader(conn)

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
					sizeLine, readErr := reader.ReadString('\n')
					if readErr != nil {
						break
					}
					sizeLine = strings.TrimSpace(sizeLine)
					size, parseErr := strconv.ParseInt(sizeLine, 16, 64)
					if parseErr != nil || size == 0 {
						reader.ReadString('\n') // trailing CRLF
						break
					}
					io.CopyN(io.Discard, reader, size)
					reader.ReadString('\n') // chunk-terminating CRLF
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

	client := httpclient.Default()

	// First try OPTIONS
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", url, nil)
	if err == nil {
		req.Header.Set("User-Agent", p.UserAgent)

		resp, err := client.Do(req)
		if err == nil {
			allow := resp.Header.Get("Allow")
			iohelper.DrainAndClose(resp.Body) // Close immediately, not defer
			if allow != "" {
				methods := strings.Split(allow, ",")
				for i := range methods {
					methods[i] = strings.TrimSpace(methods[i])
				}
				return methods, nil
			}
		}
	}

	// Check context before falling back to probing each method
	if ctx.Err() != nil {
		return nil, ctx.Err()
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
		iohelper.DrainAndClose(resp.Body)

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
		Timeout:   duration.DialTimeout,
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

	client := httpclient.Default()

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
	baseBody, _ := iohelper.ReadBodyDefault(baseResp.Body)
	iohelper.DrainAndClose(baseResp.Body)

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

		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)

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
	html := strings.ToLower(string(body))
	start := strings.Index(html, "<title>")
	if start == -1 {
		return ""
	}
	start += 7

	end := strings.Index(html[start:], "</title>")
	if end == -1 {
		return ""
	}

	title := strings.TrimSpace(html[start : start+end])
	titleRunes := []rune(title)
	if len(titleRunes) > 100 {
		title = string(titleRunes[:100])
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

// defaultVHostPrefixes are common subdomain prefixes found during vhost enumeration.
var defaultVHostPrefixes = []string{
	"www", "mail", "remote", "blog", "webmail", "server",
	"ns1", "ns2", "smtp", "secure", "vpn", "m", "shop",
	"ftp", "mail2", "test", "portal", "ns", "ww1", "host",
	"support", "dev", "web", "bbs", "mx", "email",
	"cloud", "mail1", "forum", "owa", "www2",
	"gw", "admin", "store", "mx1", "cdn", "api", "exchange",
	"app", "gov", "vps", "news", "proxy", "cache", "backup",
	"db", "sql", "mysql", "postgres", "redis", "mongo",
	"internal", "intranet", "corp", "local",
	"staging", "stage", "demo", "sandbox", "beta", "alpha",
	"pre", "preprod", "uat", "qa", "ci", "cd", "jenkins",
	"gitlab", "github", "bitbucket", "jira", "confluence",
	"grafana", "kibana", "prometheus", "elk", "log", "logs",
	"monitor", "metrics", "status", "health", "dashboard",
}

// GenerateVHostWordlist returns the default vhost prefixes.
// Deprecated: Use VHostWordlistGenerator for target-aware wordlist generation.
func GenerateVHostWordlist() []string {
	cp := make([]string, len(defaultVHostPrefixes))
	copy(cp, defaultVHostPrefixes)
	return cp
}

// VHostWordlistGenerator builds vhost wordlists from multiple sources:
// base prefixes, external wordlist files, and target-derived domains
// (TLS certificate SANs, CSP headers).
type VHostWordlistGenerator struct {
	domain string
	seen   map[string]bool
	extra  []string
}

// NewVHostWordlistGenerator creates a generator for the given target domain.
func NewVHostWordlistGenerator(domain string) *VHostWordlistGenerator {
	return &VHostWordlistGenerator{
		domain: strings.ToLower(domain),
		seen:   make(map[string]bool),
	}
}

// AddFromFile loads newline-delimited prefixes from a wordlist file.
// Blank lines and lines starting with '#' are skipped.
func (g *VHostWordlistGenerator) AddFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("vhost wordlist: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		g.addPrefix(strings.ToLower(line))
	}
	return scanner.Err()
}

// AddFromTLS extracts subdomain prefixes from TLS certificate SANs.
func (g *VHostWordlistGenerator) AddFromTLS(info *TLSInfo) {
	if info == nil {
		return
	}
	for _, d := range info.GetAllDomains() {
		g.addDomain(d)
	}
}

// AddFromCSP extracts subdomain prefixes from a Content-Security-Policy header.
func (g *VHostWordlistGenerator) AddFromCSP(csp string) {
	if csp == "" {
		return
	}
	for _, d := range ExtractDomainsFromCSP(csp) {
		g.addDomain(d)
	}
}

// AddPrefixes adds arbitrary prefixes (e.g. from user input).
func (g *VHostWordlistGenerator) AddPrefixes(prefixes ...string) {
	for _, p := range prefixes {
		g.addPrefix(strings.ToLower(p))
	}
}

// Generate returns the deduplicated wordlist: base defaults + all added sources.
func (g *VHostWordlistGenerator) Generate() []string {
	// Start with defaults.
	for _, p := range defaultVHostPrefixes {
		g.addPrefix(p)
	}

	// Sort extras for deterministic output.
	sort.Strings(g.extra)
	return g.extra
}

// addDomain extracts the first subdomain label relative to g.domain and adds it.
// For SANs/CSP domains that share the target's base domain, this turns
// "staging.example.com" into the prefix "staging".
// Domains that don't share the base domain are added whole as prefixes.
func (g *VHostWordlistGenerator) addDomain(d string) {
	d = strings.ToLower(strings.TrimPrefix(d, "*."))
	if d == "" || d == g.domain {
		return
	}

	suffix := "." + g.domain
	if strings.HasSuffix(d, suffix) {
		prefix := strings.TrimSuffix(d, suffix)
		// Could be multi-level (e.g. "a.b"); split and add each segment.
		for _, part := range strings.Split(prefix, ".") {
			if part != "" {
				g.addPrefix(part)
			}
		}
		return
	}

	// Different base domain — add first label as a prefix (it may be a
	// common environment name like "cdn" or "api").
	parts := strings.SplitN(d, ".", 2)
	if len(parts) > 0 && parts[0] != "" {
		g.addPrefix(parts[0])
	}
}

func (g *VHostWordlistGenerator) addPrefix(p string) {
	if g.seen[p] {
		return
	}
	g.seen[p] = true
	g.extra = append(g.extra, p)
}
