// cmd_probe_http.go - HTTP request helpers for probe command
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/ui"
)

// ProbeHTTPOptions contains options for probe HTTP requests
type ProbeHTTPOptions struct {
	Method           string
	FollowRedirects  bool
	MaxRedirects     int
	RandomAgent      bool
	CustomHeaders    string
	RequestBody      string
	ProxyURL         string
	Retries          int
	SkipVerify       bool
	Delay            time.Duration
	SNI              string            // Custom SNI hostname
	AutoReferer      bool              // Automatically set Referer header
	UnsafeMode       bool              // Disable security checks
	FollowHostOnly   bool              // Only follow same-host redirects
	RespectHSTS      bool              // Respect HSTS headers
	StreamMode       bool              // Stream response body
	NoDedupe         bool              // Don't deduplicate results
	LeaveDefaultPort bool              // Keep :80 or :443 in URLs
	UseZTLS          bool              // Use ZTLS library
	NoDecode         bool              // Don't decode response
	TLSImpersonate   bool              // Impersonate browser TLS
	NoFallback       bool              // Don't fall back to HTTP
	NoFallbackScheme bool              // Don't try alternate scheme
	MaxHostErrors    int               // Skip host after N errors
	MaxResponseRead  int               // Max bytes to read from response
	MaxResponseSave  int               // Max bytes to save from response
	VHostHeader      string            // Override Host header for vhost probing
	TrackRedirects   bool              // Track redirect chain
	RedirectChain    *[]string         // Pointer to redirect chain slice
	ForceHTTP2       bool              // Force HTTP/2 protocol
	ForceHTTP11      bool              // Force HTTP/1.1 protocol
	AuthSecrets      map[string]string // Authentication secrets (key=value)
	ExcludeFields    map[string]bool   // Fields to exclude from output
	CustomResolvers  []string          // Custom DNS resolvers
}

// makeProbeHTTPRequest performs a simple HTTP GET request for probe command
func makeProbeHTTPRequest(ctx context.Context, target string, timeout time.Duration) (*http.Response, error) {
	client := httpclient.New(httpclient.WithTimeout(timeout))
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ui.UserAgent())
	return client.Do(req)
}

// makeProbeHTTPRequestWithOptions performs HTTP request with full options
func makeProbeHTTPRequestWithOptions(ctx context.Context, target string, timeout time.Duration, opts ProbeHTTPOptions) (*http.Response, error) {
	maxRedirects := opts.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 10
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if !opts.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= maxRedirects {
			return fmt.Errorf("too many redirects")
		}
		// Follow same-host redirects only
		if opts.FollowHostOnly && len(via) > 0 {
			originalHost := via[0].URL.Host
			if req.URL.Host != originalHost {
				return http.ErrUseLastResponse
			}
		}
		// Respect HSTS - upgrade http to https
		if opts.RespectHSTS && req.URL.Scheme == "http" {
			// Check if response had Strict-Transport-Security header
			if len(via) > 0 {
				lastResp := via[len(via)-1].Response
				if lastResp != nil && lastResp.Header.Get("Strict-Transport-Security") != "" {
					req.URL.Scheme = "https"
				}
			}
		}
		// Track redirect chain if enabled
		if opts.TrackRedirects && opts.RedirectChain != nil {
			*opts.RedirectChain = append(*opts.RedirectChain, req.URL.String())
		}
		return nil
	}

	// Build HTTP version for httpclient.Config
	var httpVersion string
	if opts.ForceHTTP2 {
		httpVersion = "2"
	} else if opts.ForceHTTP11 {
		httpVersion = "1.1"
	}

	// Build cipher suites for TLS impersonation
	var cipherSuites []uint16
	if opts.TLSImpersonate {
		cipherSuites = []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}
	}

	// Use httpclient.Config for transport, retries, and UA
	cfg := httpclient.Config{
		Timeout:            timeout,
		InsecureSkipVerify: opts.SkipVerify,
		SNI:                opts.SNI,
		Proxy:              opts.ProxyURL,
		CustomResolvers:    opts.CustomResolvers,
		ForceHTTPVersion:   httpVersion,
		CipherSuites:       cipherSuites,
		RetryCount:         opts.Retries,
		RetryDelay:         opts.Delay,
		RandomUserAgent:    opts.RandomAgent,
		UserAgent:          ui.UserAgent(),
	}
	// UseZTLS forces TLS 1.3 only
	if opts.UseZTLS {
		cfg.MinTLSVersion = tls.VersionTLS13
		cfg.MaxTLSVersion = tls.VersionTLS13
	}
	client := httpclient.New(cfg)
	// Override redirect policy with probe-specific handling
	client.CheckRedirect = checkRedirect

	// Prepare request body if provided
	var bodyReader io.Reader
	if opts.RequestBody != "" {
		bodyReader = strings.NewReader(opts.RequestBody)
	}

	method := opts.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, err
	}

	// Parse and set custom headers
	if opts.CustomHeaders != "" {
		headers := strings.Split(opts.CustomHeaders, ";")
		for _, h := range headers {
			parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}

	// VHost header override
	if opts.VHostHeader != "" {
		req.Host = opts.VHostHeader
	}

	// Auto Referer header
	if opts.AutoReferer {
		parsedURL, err := url.Parse(target)
		if err == nil {
			req.Header.Set("Referer", fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host))
		}
	}

	// Apply auth secrets as headers
	if opts.AuthSecrets != nil {
		for key, value := range opts.AuthSecrets {
			// Common auth secret keys
			switch strings.ToLower(key) {
			case "authorization", "auth":
				req.Header.Set("Authorization", value)
			case "bearer", "token":
				req.Header.Set("Authorization", "Bearer "+value)
			case "api_key", "apikey", "x-api-key":
				req.Header.Set("X-API-Key", value)
			case "cookie":
				req.Header.Set("Cookie", value)
			default:
				// Set as custom header
				req.Header.Set(key, value)
			}
		}
	}

	// Content-Type for POST/PUT with body
	if opts.RequestBody != "" && (method == "POST" || method == "PUT") {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	return client.Do(req)
}
