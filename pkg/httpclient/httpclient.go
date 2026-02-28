// Package httpclient provides a shared, optimized HTTP client factory.
// It enables connection pooling and reuse across all packages,
// significantly improving performance for security scanning workloads.
package httpclient

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
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

	// Proxy is the HTTP/HTTPS/SOCKS proxy URL (optional)
	// Supported schemes: http://, https://, socks4://, socks5://, socks5h://
	Proxy string

	// ReplayProxy is a secondary proxy for matched/interesting requests (ffuf/feroxbuster pattern)
	// Useful for sending only relevant findings to Burp/ZAP
	ReplayProxy string

	// SNI is the TLS Server Name Indication override (optional)
	// When set, overrides the Host header value in TLS handshake
	// Essential for testing hosts via IP address or CDN bypass
	SNI string

	// ProxyDNS controls DNS resolution for SOCKS5 proxies
	// "local" = resolve locally (default for socks5://)
	// "remote" = resolve on proxy (default for socks5h://)
	ProxyDNS string

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

	// CustomResolvers is a list of DNS resolver addresses (e.g., "8.8.8.8:53").
	// When set, DNS resolution uses these resolvers instead of system defaults.
	// Useful for split-horizon DNS bypass in WAF testing.
	CustomResolvers []string

	// AuthHeaders are HTTP headers added to every request (e.g., Authorization).
	// These headers are NOT forwarded on cross-origin redirects to prevent
	// credential leakage.
	AuthHeaders http.Header

	// ForceHTTPVersion forces a specific HTTP protocol version.
	// "1.1" disables HTTP/2, "2" forces HTTP/2, "" uses default negotiation.
	// Useful for bypassing WAFs that only inspect one protocol version.
	ForceHTTPVersion string

	// RetryCount is the number of retry attempts after the initial request (default: 0).
	// Retries on transport errors and HTTP 429/503 responses.
	RetryCount int

	// RetryDelay is the delay between retry attempts (default: 0).
	RetryDelay time.Duration

	// RandomUserAgent rotates User-Agent headers across requests using
	// realistic browser fingerprints to evade UA-based WAF detection.
	RandomUserAgent bool

	// UserAgent sets a fixed User-Agent header on all requests.
	// Ignored if RandomUserAgent is true.
	UserAgent string

	// CipherSuites specifies TLS cipher suites for JA3 fingerprint control.
	// When empty, Go's default cipher suite selection is used.
	CipherSuites []uint16

	// MinTLSVersion sets the minimum TLS version (e.g., tls.VersionTLS12).
	// When zero, the Go default minimum is used.
	MinTLSVersion uint16

	// MaxTLSVersion sets the maximum TLS version (e.g., tls.VersionTLS13).
	// When zero, the Go default maximum is used.
	// Set both Min and Max to tls.VersionTLS13 to force TLS 1.3 only.
	MaxTLSVersion uint16

	// TLSConfig provides a complete TLS configuration.
	// When set, this replaces the auto-built TLS config entirely —
	// InsecureSkipVerify, SNI, CipherSuites, MinTLSVersion, and MaxTLSVersion
	// are ignored. Use this for browser-profile TLS fingerprinting.
	TLSConfig *tls.Config

	// CookieJar enables automatic cookie handling across requests.
	// When true, a net/http/cookiejar.Jar is attached to the client,
	// allowing stateful sessions (e.g., OAuth2 flows, authenticated scanning).
	CookieJar bool

	// TransportWrapper is an optional per-client transport wrapper.
	// When set, this wrapper is applied INSTEAD of the global
	// RegisterTransportWrapper wrapper, giving callers explicit control
	// over transport middleware without relying on global state.
	// This is preferred over RegisterTransportWrapper for testability.
	TransportWrapper TransportWrapper
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

// RegisterTransportWrapper registers a global function to wrap all transports.
// This should be called once at startup before creating clients.
// Used by detection package to inject connection drop/ban detection.
//
// Deprecated: Prefer setting Config.TransportWrapper for per-client wrappers.
// The global wrapper remains for backward compatibility but per-client wrappers
// take precedence when set, enabling testable, non-global configuration.
func RegisterTransportWrapper(wrapper TransportWrapper) {
	wrapperMu.Lock()
	defer wrapperMu.Unlock()
	transportWrapper = wrapper
}

// wrapTransport applies the per-client wrapper if set, otherwise falls back
// to the global registered wrapper. Per-client wrappers take precedence
// to enable testing without mutating global state.
func wrapTransport(transport http.RoundTripper) http.RoundTripper {
	wrapperMu.RLock()
	defer wrapperMu.RUnlock()
	if transportWrapper != nil {
		return transportWrapper(transport)
	}
	return transport
}

// wrapTransportWithConfig applies a per-client wrapper if provided in Config,
// otherwise falls back to the global registered wrapper.
func wrapTransportWithConfig(transport http.RoundTripper, cfg Config) http.RoundTripper {
	if cfg.TransportWrapper != nil {
		return cfg.TransportWrapper(transport)
	}
	return wrapTransport(transport)
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
	// Only apply pool defaults when keep-alives are enabled.
	// SprayingConfig() sets these to 0 intentionally to disable pooling.
	if !cfg.DisableKeepAlives {
		if cfg.MaxIdleConns == 0 {
			cfg.MaxIdleConns = 100
		}
		if cfg.MaxConnsPerHost == 0 {
			cfg.MaxConnsPerHost = 25
		}
		if cfg.IdleConnTimeout == 0 {
			cfg.IdleConnTimeout = 90 * time.Second
		}
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

	// Build TLS configuration
	var tlsConfig *tls.Config
	if cfg.TLSConfig != nil {
		// Use caller-provided TLS config directly (e.g., browser profile fingerprinting)
		tlsConfig = cfg.TLSConfig
	} else {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}
		// Apply SNI override if configured
		if cfg.SNI != "" {
			tlsConfig.ServerName = cfg.SNI
		}
		// Apply custom cipher suites for JA3 fingerprint control
		if len(cfg.CipherSuites) > 0 {
			tlsConfig.CipherSuites = cfg.CipherSuites
		}
		// Apply TLS version constraints
		if cfg.MinTLSVersion != 0 {
			tlsConfig.MinVersion = cfg.MinTLSVersion
		}
		if cfg.MaxTLSVersion != 0 {
			tlsConfig.MaxVersion = cfg.MaxTLSVersion
		}
	}

	// Parse proxy configuration if provided
	var proxyConfig *ProxyConfig
	if cfg.Proxy != "" {
		var err error
		proxyConfig, err = ParseProxyURL(cfg.Proxy)
		if err != nil {
			slog.Warn("httpclient: ignoring malformed proxy URL", "proxy", cfg.Proxy, "error", err)
			proxyConfig = nil
		}
	}

	// Determine dial context based on DNS caching and proxy type
	if proxyConfig != nil && proxyConfig.IsSOCKS {
		// SOCKS proxy requires custom dialer
		socksDialer, err := CreateSOCKSDialer(proxyConfig, cfg.DialTimeout)
		if err != nil {
			slog.Warn("httpclient: SOCKS proxy dialer failed, traffic will route directly", "proxy", cfg.Proxy, "error", err)
			dialer := &net.Dialer{
				Timeout:   cfg.DialTimeout,
				KeepAlive: 30 * time.Second,
				Control:   sockopt.DialControl(),
			}
			dialContext = dialer.DialContext
		} else {
			dialContext = socksDialer.DialContext
		}
	} else if len(cfg.CustomResolvers) > 0 {
		// Custom DNS resolvers for split-horizon DNS bypass
		resolver := cfg.CustomResolvers[0]
		if !containsPort(resolver) {
			// Bare IPv6 needs brackets: "::1" → "[::1]:53"
			if strings.Count(resolver, ":") > 1 && !strings.Contains(resolver, "[") {
				resolver = "[" + resolver + "]:53"
			} else {
				resolver = resolver + ":53"
			}
		}
		baseDialer := &net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: 30 * time.Second,
			Control:   sockopt.DialControl(),
		}
		dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return baseDialer.DialContext(ctx, network, address)
			}
			customResolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					d := net.Dialer{Timeout: cfg.DialTimeout}
					return d.DialContext(ctx, "udp", resolver)
				},
			}
			ips, err := customResolver.LookupIPAddr(ctx, host)
			if err != nil || len(ips) == 0 {
				return baseDialer.DialContext(ctx, network, address)
			}
			return baseDialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		}
	} else if cfg.UseDNSCache {
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

	// Determine HTTP/2 settings based on ForceHTTPVersion
	forceHTTP2 := true // default: allow HTTP/2
	var tlsNextProto map[string]func(authority string, c *tls.Conn) http.RoundTripper
	switch cfg.ForceHTTPVersion {
	case "1.1":
		forceHTTP2 = false
		// Empty map disables HTTP/2 via ALPN
		tlsNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	case "2":
		forceHTTP2 = true
	}

	transport := &http.Transport{
		// Connection pooling - key for performance
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxConnsPerHost,
		MaxConnsPerHost:     cfg.MaxConnsPerHost,
		IdleConnTimeout:     cfg.IdleConnTimeout,
		DisableKeepAlives:   cfg.DisableKeepAlives,

		// Performance tuning
		ForceAttemptHTTP2:     forceHTTP2,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		TLSNextProto:          tlsNextProto,

		// Buffer sizes for improved throughput (matches fasthttp/gnet patterns)
		// These reduce syscall overhead for larger payloads
		WriteBufferSize: 32 * 1024, // 32KB write buffer
		ReadBufferSize:  32 * 1024, // 32KB read buffer

		// Dialer with timeouts (uses DNS caching if enabled, or SOCKS dialer)
		DialContext: dialContext,

		// TLS configuration with SNI support
		TLSClientConfig: tlsConfig,
	}

	// HTTP/HTTPS Proxy support (SOCKS is handled via DialContext above)
	if proxyConfig != nil && !proxyConfig.IsSOCKS {
		transport.Proxy = http.ProxyURL(proxyConfig.URL)
	}

	// Apply transport wrapper: per-client Config.TransportWrapper takes
	// precedence over the global RegisterTransportWrapper.
	var finalTransport http.RoundTripper = wrapTransportWithConfig(transport, cfg)

	// Wrap with middleware transport for UA, auth headers, and retries
	if needsMiddleware(cfg) {
		finalTransport = &middlewareTransport{
			base:        finalTransport,
			userAgent:   cfg.UserAgent,
			randomUA:    cfg.RandomUserAgent,
			authHeaders: cfg.AuthHeaders,
			retryCount:  cfg.RetryCount,
			retryDelay:  cfg.RetryDelay,
		}
	}

	// Determine redirect policy
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if len(cfg.AuthHeaders) > 0 {
		checkRedirect = redirectPolicyWithAuthStrip(cfg.AuthHeaders)
	}

	// Cookie jar for stateful sessions (OAuth2, authenticated scanning).
	var jar http.CookieJar
	if cfg.CookieJar {
		// cookiejar.New with nil options uses the public suffix list,
		// which is the safe default for cross-domain cookie handling.
		var jarErr error
		jar, jarErr = cookiejar.New(nil)
		if jarErr != nil {
			slog.Warn("httpclient: failed to create cookie jar", "error", jarErr)
		}
	}

	return &http.Client{
		Transport:     finalTransport,
		Timeout:       cfg.Timeout,
		CheckRedirect: checkRedirect,
		Jar:           jar,
	}
}

// containsPort reports whether the address string contains a port suffix.
// Handles IPv4 ("1.2.3.4:53"), bracketed IPv6 ("[::1]:53"), and bare IPv6 ("::1").
func containsPort(addr string) bool {
	// IPv6 with brackets: "[::1]:53" has port, "[::1]" does not
	if strings.Contains(addr, "[") {
		return strings.Contains(addr, "]:")
	}
	// Bare IPv6 without brackets (contains multiple colons): never has a port.
	// A host:port pair has exactly one colon for IPv4/hostname.
	if strings.Count(addr, ":") > 1 {
		return false
	}
	return strings.Contains(addr, ":")
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

// WithSNI returns a new Config based on DefaultConfig with the specified SNI.
// Convenience function for testing hosts via IP address with custom SNI.
func WithSNI(sni string) Config {
	cfg := DefaultConfig()
	cfg.SNI = sni
	return cfg
}

// WithProxyAndSNI returns a new Config with both proxy and SNI configured.
// Convenience function for the common case of proxied scanning with SNI override.
func WithProxyAndSNI(proxyURL, sni string) Config {
	cfg := DefaultConfig()
	cfg.Proxy = proxyURL
	cfg.SNI = sni
	return cfg
}

// WithBurp returns a Config pre-configured for Burp Suite integration.
// Uses default Burp proxy (127.0.0.1:8080) with TLS verification disabled.
// Based on feroxbuster's --burp flag pattern.
func WithBurp() Config {
	cfg := DefaultConfig()
	cfg.Proxy = BurpProxyURL
	cfg.InsecureSkipVerify = true
	return cfg
}

// WithZAP returns a Config pre-configured for OWASP ZAP integration.
// Uses default ZAP proxy (127.0.0.1:8081) with TLS verification disabled.
func WithZAP() Config {
	cfg := DefaultConfig()
	cfg.Proxy = ZAPProxyURL
	cfg.InsecureSkipVerify = true
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
