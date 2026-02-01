// Package httpclient provides a shared, optimized HTTP client factory.
// It enables connection pooling and reuse across all packages,
// significantly improving performance for security scanning workloads.
package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Config holds HTTP client configuration options.
type Config struct {
	// Timeout is the total request timeout (default: 30s)
	Timeout time.Duration

	// InsecureSkipVerify skips TLS certificate verification (default: true for security scanning)
	InsecureSkipVerify bool

	// Proxy is the HTTP/HTTPS proxy URL (optional)
	Proxy string

	// MaxIdleConns is the maximum number of idle connections across all hosts (default: 100)
	MaxIdleConns int

	// MaxConnsPerHost is the maximum connections per host (default: 25)
	MaxConnsPerHost int

	// IdleConnTimeout is how long idle connections stay in pool (default: 90s)
	IdleConnTimeout time.Duration

	// DisableKeepAlives disables HTTP keep-alives if true (default: false)
	DisableKeepAlives bool

	// DialTimeout is the timeout for establishing connections (default: 10s)
	DialTimeout time.Duration

	// TLSHandshakeTimeout is the timeout for TLS handshake (default: 10s)
	TLSHandshakeTimeout time.Duration
}

// DefaultConfig returns sensible defaults optimized for security scanning workloads.
// These values are tuned for high-throughput scanning with connection reuse.
func DefaultConfig() Config {
	return Config{
		Timeout:             30 * time.Second,
		InsecureSkipVerify:  true, // Security scanners often need this
		MaxIdleConns:        100,
		MaxConnsPerHost:     25,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DialTimeout:         10 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

var (
	defaultClient *http.Client
	defaultOnce   sync.Once
)

// Default returns a shared, pre-configured HTTP client.
// This client is safe for concurrent use and employs connection pooling.
// All packages should prefer Default() over creating their own clients.
//
// The default client:
//   - Uses connection pooling (100 idle, 25 per host)
//   - Has 30s timeout
//   - Skips TLS verification (common for security scanning)
//   - Does NOT follow redirects (returns http.ErrUseLastResponse)
//   - Enables HTTP/2
func Default() *http.Client {
	defaultOnce.Do(func() {
		defaultClient = New(DefaultConfig())
	})
	return defaultClient
}

// New creates a new HTTP client with the given configuration.
// Use this when you need a client with non-default settings.
// For most cases, prefer Default() for connection reuse benefits.
func New(cfg Config) *http.Client {
	// Apply sensible defaults for zero values
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 100
	}
	if cfg.MaxConnsPerHost == 0 {
		cfg.MaxConnsPerHost = 25
	}
	if cfg.IdleConnTimeout == 0 {
		cfg.IdleConnTimeout = 90 * time.Second
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.TLSHandshakeTimeout == 0 {
		cfg.TLSHandshakeTimeout = 10 * time.Second
	}

	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		// Connection pooling - key for performance
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxConnsPerHost,
		MaxConnsPerHost:     cfg.MaxConnsPerHost,
		IdleConnTimeout:     cfg.IdleConnTimeout,
		DisableKeepAlives:   cfg.DisableKeepAlives,

		// Performance tuning
		ForceAttemptHTTP2:     true,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,

		// Dialer with timeouts
		DialContext: dialer.DialContext,

		// TLS configuration
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	// Proxy support (optional)
	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil && proxyURL != nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
		// Silently ignore malformed proxy URLs - continue without proxy
	}

	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects - security scanners need to see the redirect response
			return http.ErrUseLastResponse
		},
	}
}

// WithTimeout returns a new Config based on DefaultConfig with the specified timeout.
// Convenience function for the common case of only needing to change timeout.
func WithTimeout(timeout time.Duration) Config {
	cfg := DefaultConfig()
	cfg.Timeout = timeout
	return cfg
}

// WithProxy returns a new Config based on DefaultConfig with the specified proxy.
// Convenience function for the common case of only needing to add a proxy.
func WithProxy(proxyURL string) Config {
	cfg := DefaultConfig()
	cfg.Proxy = proxyURL
	return cfg
}
