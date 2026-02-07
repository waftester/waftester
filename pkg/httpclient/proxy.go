// Package httpclient provides proxy support including SOCKS4, SOCKS5, and HTTP proxies.
// This file implements proxy URL parsing, validation, and SOCKS dialer creation.
//
// Supported proxy schemes:
//   - http:// - HTTP CONNECT proxy
//   - https:// - HTTPS CONNECT proxy
//   - socks4:// - SOCKS4 proxy
//   - socks5:// - SOCKS5 proxy (local DNS resolution)
//   - socks5h:// - SOCKS5 proxy with remote DNS resolution (DNS over proxy)
//
// Based on patterns from nuclei, ffuf, httpx, and fastdialer.
package httpclient

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Supported proxy schemes - validated during URL parsing
var supportedProxySchemes = map[string]bool{
	"http":    true,
	"https":   true,
	"socks4":  true,
	"socks5":  true,
	"socks5h": true, // SOCKS5 with remote DNS resolution (no DNS leaks)
}

// ProxyConfig holds parsed proxy configuration
type ProxyConfig struct {
	URL         *url.URL
	Scheme      string
	Host        string
	Port        string
	Username    string
	Password    string
	IsSOCKS     bool
	IsDNSRemote bool // For socks5h - resolve DNS on proxy side
}

// ParseProxyURL validates and parses a proxy URL string.
// Returns nil, nil if proxyURL is empty (no proxy configured).
// Returns nil, error if the URL is malformed or uses an unsupported scheme.
//
// Supported formats:
//   - http://host:port
//   - http://user:pass@host:port
//   - socks5://host:port
//   - socks5h://host:port (DNS resolved on proxy side)
func ParseProxyURL(proxyURL string) (*ProxyConfig, error) {
	if proxyURL == "" {
		return nil, nil
	}

	// Handle shorthand formats (user convenience)
	if !strings.Contains(proxyURL, "://") {
		// Default to http:// if no scheme provided
		proxyURL = "http://" + proxyURL
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if !supportedProxySchemes[scheme] {
		return nil, fmt.Errorf("unsupported proxy scheme '%s', supported: http, https, socks4, socks5, socks5h", scheme)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if host == "" {
		return nil, fmt.Errorf("proxy URL missing host")
	}
	if port == "" {
		// Default ports based on scheme
		switch scheme {
		case "http":
			port = "8080"
		case "https":
			port = "8443"
		case "socks4", "socks5", "socks5h":
			port = "1080"
		}
	}

	config := &ProxyConfig{
		URL:         parsed,
		Scheme:      scheme,
		Host:        host,
		Port:        port,
		IsSOCKS:     scheme == "socks4" || scheme == "socks5" || scheme == "socks5h",
		IsDNSRemote: scheme == "socks5h",
	}

	// Extract authentication if present
	if parsed.User != nil {
		config.Username = parsed.User.Username()
		config.Password, _ = parsed.User.Password()
	}

	return config, nil
}

// IsSOCKS returns true if the proxy uses a SOCKS protocol
func (p *ProxyConfig) IsSOCKS4() bool {
	return p != nil && p.Scheme == "socks4"
}

// IsSOCKS5 returns true if the proxy uses SOCKS5 protocol
func (p *ProxyConfig) IsSOCKS5() bool {
	return p != nil && (p.Scheme == "socks5" || p.Scheme == "socks5h")
}

// Address returns the proxy address in host:port format
func (p *ProxyConfig) Address() string {
	if p == nil {
		return ""
	}
	return net.JoinHostPort(p.Host, p.Port)
}

// ContextDialer is an interface for dialers that support context
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// TimeoutDialer wraps a proxy.Dialer with timeout support
// This is needed because SOCKS dialers don't natively support timeouts
// Based on fastdialer pattern
type TimeoutDialer struct {
	dialer  proxy.Dialer
	timeout time.Duration
}

// DialContext implements ContextDialer with timeout support
func (t *TimeoutDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Create timeout context if not already set
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}

	// Use channel-based pattern for timeout handling (fastdialer pattern)
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)

	go func() {
		var conn net.Conn
		var err error

		// Check if dialer supports context
		if ctxDialer, ok := t.dialer.(proxy.ContextDialer); ok {
			conn, err = ctxDialer.DialContext(ctx, network, address)
		} else {
			// Fallback: use non-context dial
			conn, err = t.dialer.Dial(network, address)
		}

		if err != nil {
			errCh <- err
			return
		}

		// Try to send conn; if context already cancelled, close it to prevent leak
		select {
		case connCh <- conn:
		case <-ctx.Done():
			conn.Close()
		}
	}()

	select {
	case <-ctx.Done():
		// Goroutine will close conn if it completes after this point
		return nil, fmt.Errorf("proxy dial timeout: %w", ctx.Err())
	case conn := <-connCh:
		return conn, nil
	case err := <-errCh:
		return nil, err
	}
}

// CreateSOCKSDialer creates a SOCKS dialer from ProxyConfig
// Supports SOCKS4, SOCKS5, and SOCKS5h (DNS over proxy)
// Returns a ContextDialer that can be used as transport.DialContext
func CreateSOCKSDialer(config *ProxyConfig, timeout time.Duration) (ContextDialer, error) {
	if config == nil {
		return nil, fmt.Errorf("proxy config is nil")
	}

	// Build auth if present
	var auth *proxy.Auth
	if config.Username != "" {
		auth = &proxy.Auth{
			User:     config.Username,
			Password: config.Password,
		}
	}

	// For socks5h, we need to use "socks5" scheme but ensure DNS is resolved remotely
	// This is handled by the SOCKS5 proxy itself when we pass hostnames instead of IPs
	dialerScheme := config.Scheme
	if dialerScheme == "socks5h" {
		dialerScheme = "socks5"
	}

	// Create proxy URL for golang.org/x/net/proxy
	proxyURL := &url.URL{
		Scheme: dialerScheme,
		Host:   config.Address(),
	}
	if auth != nil {
		proxyURL.User = url.UserPassword(auth.User, auth.Password)
	}

	// Create the SOCKS dialer
	dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS dialer: %w", err)
	}

	// Wrap with timeout support
	return &TimeoutDialer{
		dialer:  dialer,
		timeout: timeout,
	}, nil
}

// BurpProxyURL is the default Burp Suite proxy URL
// Used by --burp shortcut flag (feroxbuster pattern)
const BurpProxyURL = "http://127.0.0.1:8080"

// ZAPProxyURL is the default OWASP ZAP proxy URL
const ZAPProxyURL = "http://127.0.0.1:8081"

// CommonProxyPorts are typical proxy ports for validation hints
var CommonProxyPorts = []string{"8080", "8081", "8443", "1080", "9050"}

// ValidateProxyURL checks if a proxy URL is valid and provides hints
func ValidateProxyURL(proxyURL string) error {
	_, err := ParseProxyURL(proxyURL)
	return err
}
