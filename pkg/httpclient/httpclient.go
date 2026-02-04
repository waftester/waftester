// Package httpclient provides a shared, optimized HTTP client factory.
// It enables connection pooling and reuse across all packages,
// significantly improving performance for security scanning workloads.
package httpclient

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/sockopt"
)

// ============================================================================
// CANONICAL TIMEOUT CONSTANTS
// ============================================================================
//
// These are the ONLY timeout values that should be used across the codebase.
// All package Config structs should reference these constants, NOT hardcoded
// time.Duration values.
//
// Usage in other packages:
//   Timeout: httpclient.TimeoutProbing,  // NOT: 10 * time.Second
// ============================================================================

const (
	// TimeoutProbing is for quick fingerprinting and health checks (5s)
	TimeoutProbing = 5 * time.Second

	// TimeoutScanning is for WAF detection and security scanning (15s)
	TimeoutScanning = 15 * time.Second

	// TimeoutFuzzing is for deep payload testing (30s) - the default
	TimeoutFuzzing = 30 * time.Second

	// TimeoutLongOps is for crawling, uploads, and authenticated flows (5min)
	TimeoutLongOps = 5 * time.Minute

	// TimeoutAPI is for external API calls like AI services (60s)
	TimeoutAPI = 60 * time.Second
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

	// UseDNSCache enables DNS caching for improved performance (default: false)
	// Enable this for high-throughput scanning of the same hosts
	UseDNSCache bool
}

// DefaultConfig returns sensible defaults optimized for security scanning workloads.
// These values are tuned for high-throughput scanning with connection reuse.
// Based on industry patterns from fasthttp, Caddy, Traefik, and ProjectDiscovery tools.
func DefaultConfig() Config {
	return Config{
		Timeout:             30 * time.Second,
		InsecureSkipVerify:  true, // Security scanners often need this
		MaxIdleConns:        100,
		MaxConnsPerHost:     100, // Increased from 25 to match industry (Nuclei, HTTPx use 100)
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DialTimeout:         10 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		UseDNSCache:         true, // Enable DNS caching for scanning
	}
}

// SprayingConfig returns configuration optimized for scanning many different hosts.
// Disables keep-alives since connections won't be reused across different hosts.
// Use this for reconnaissance and multi-target discovery.
func SprayingConfig() Config {
	return Config{
		Timeout:             30 * time.Second,
		InsecureSkipVerify:  true,
		MaxIdleConns:        0,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     0,
		DisableKeepAlives:   true, // No connection reuse for spraying
		DialTimeout:         10 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// Spraying returns a shared HTTP client optimized for scanning many different hosts.
// Unlike Default(), this client does not maintain connection pools.
var (
	sprayingClient *http.Client
	sprayingOnce   sync.Once
)

func Spraying() *http.Client {
	sprayingOnce.Do(func() {
		sprayingClient = New(SprayingConfig())
	})
	return sprayingClient
}

var (
	defaultClient *http.Client
	defaultOnce   sync.Once
)

// TransportWrapper is a function that wraps an http.RoundTripper.
// Used by detection and other systems to inject middleware.
type TransportWrapper func(http.RoundTripper) http.RoundTripper

var (
	transportWrapper TransportWrapper
	wrapperMu        sync.RWMutex
)

// RegisterTransportWrapper registers a function to wrap all transports.
// This should be called once at startup before creating clients.
// Used by detection package to inject connection drop/ban detection.
func RegisterTransportWrapper(wrapper TransportWrapper) {
	wrapperMu.Lock()
	defer wrapperMu.Unlock()
	transportWrapper = wrapper
}

// wrapTransport applies the registered wrapper if one exists.
func wrapTransport(transport http.RoundTripper) http.RoundTripper {
	wrapperMu.RLock()
	defer wrapperMu.RUnlock()
	if transportWrapper != nil {
		return transportWrapper(transport)
	}
	return transport
}

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

	// Create dialer - use caching dialer if DNS caching is enabled
	// Also apply platform-specific socket optimizations (TCP_NODELAY, larger buffers, etc.)
	var dialContext func(ctx context.Context, network, address string) (net.Conn, error)

	if cfg.UseDNSCache {
		cachingDialer := NewCachingDialer(GetDNSCache(), cfg.DialTimeout)
		// Wrap with socket optimization
		dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := cachingDialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			// Apply platform-specific optimizations (TCP_NODELAY, buffers, etc.)
			// Errors are non-fatal - continue with unoptimized connection
			_ = sockopt.OptimizeConn(conn)
			return conn, nil
		}
	} else {
		dialer := &net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: 30 * time.Second,
			Control:   sockopt.DialControl(), // Apply socket opts at dial time (Linux only)
		}
		dialContext = dialer.DialContext
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

		// Buffer sizes for improved throughput (matches fasthttp/gnet patterns)
		// These reduce syscall overhead for larger payloads
		WriteBufferSize: 32 * 1024, // 32KB write buffer
		ReadBufferSize:  32 * 1024, // 32KB read buffer

		// Dialer with timeouts (uses DNS caching if enabled)
		DialContext: dialContext,

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

	// Apply registered transport wrapper (e.g., detection)
	wrappedTransport := wrapTransport(transport)

	return &http.Client{
		Transport: wrappedTransport,
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

// ============================================================================
// SEMANTIC PRESETS - The canonical way to get HTTP clients
// ============================================================================
//
// These presets eliminate configuration drift by providing purpose-driven
// clients. Each preset is tuned for specific use cases and shares connection
// pools via sync.Once singletons.
//
// Usage:
//   client := httpclient.Probing()   // Quick fingerprinting
//   client := httpclient.Scanning()  // WAF detection
//   client := httpclient.Fuzzing()   // Deep payload testing
//   client := httpclient.LongOps()   // Crawling, uploads
//
// DO NOT create &http.Client{} directly - use these presets instead.
// ============================================================================

// ProbingConfig returns configuration for quick fingerprinting operations.
// Fast timeout (5s), used for initial recon and quick checks.
func ProbingConfig() Config {
	return Config{
		Timeout:             5 * time.Second,
		InsecureSkipVerify:  true,
		MaxIdleConns:        100,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DialTimeout:         5 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
}

// ScanningConfig returns configuration for WAF detection and security scanning.
// Medium timeout (15s), balanced for accuracy and speed.
func ScanningConfig() Config {
	return Config{
		Timeout:             15 * time.Second,
		InsecureSkipVerify:  true,
		MaxIdleConns:        100,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DialTimeout:         10 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// FuzzingConfig returns configuration for deep payload testing.
// Standard timeout (30s), allows for complex responses.
func FuzzingConfig() Config {
	return Config{
		Timeout:             30 * time.Second,
		InsecureSkipVerify:  true,
		MaxIdleConns:        100,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DialTimeout:         10 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// LongOpsConfig returns configuration for long-running operations.
// Extended timeout (5min), for crawling, file uploads, authenticated flows.
func LongOpsConfig() Config {
	return Config{
		Timeout:             5 * time.Minute,
		InsecureSkipVerify:  true,
		MaxIdleConns:        100,
		MaxConnsPerHost:     50, // Lower for long ops - fewer concurrent connections
		IdleConnTimeout:     120 * time.Second,
		DisableKeepAlives:   false,
		DialTimeout:         30 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
}

// Singleton clients for each preset
var (
	probingClient  *http.Client
	probingOnce    sync.Once
	scanningClient *http.Client
	scanningOnce   sync.Once
	fuzzingClient  *http.Client
	fuzzingOnce    sync.Once
	longOpsClient  *http.Client
	longOpsOnce    sync.Once
)

// Probing returns a shared HTTP client for quick fingerprinting (5s timeout).
// Use for: initial recon, health checks, quick probes, WAF presence detection.
func Probing() *http.Client {
	probingOnce.Do(func() {
		probingClient = New(ProbingConfig())
	})
	return probingClient
}

// Scanning returns a shared HTTP client for security scanning (15s timeout).
// Use for: WAF detection, vulnerability scanning, bypass testing.
func Scanning() *http.Client {
	scanningOnce.Do(func() {
		scanningClient = New(ScanningConfig())
	})
	return scanningClient
}

// Fuzzing returns a shared HTTP client for payload testing (30s timeout).
// Use for: injection testing, payload delivery, deep fuzzing.
// This is equivalent to Default() but with semantic naming.
func Fuzzing() *http.Client {
	fuzzingOnce.Do(func() {
		fuzzingClient = New(FuzzingConfig())
	})
	return fuzzingClient
}

// LongOps returns a shared HTTP client for long operations (5min timeout).
// Use for: crawling, file uploads, authenticated flows, browser operations.
func LongOps() *http.Client {
	longOpsOnce.Do(func() {
		longOpsClient = New(LongOpsConfig())
	})
	return longOpsClient
}
