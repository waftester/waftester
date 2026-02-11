package httpclient

import (
	"net/http"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
)

// middlewareTransport wraps a base RoundTripper to add request-level
// middleware: user-agent rotation, auth headers, and retry logic.
//
// Features:
//   - Fixed or random User-Agent header per request
//   - Auth headers on initial request (stripped on cross-origin redirects)
//   - Retry on transport errors and HTTP 429/503 responses
type middlewareTransport struct {
	base        http.RoundTripper
	userAgent   string
	randomUA    bool
	authHeaders http.Header
	retryCount  int
	retryDelay  time.Duration
}

// retryableStatusCodes are HTTP status codes that trigger automatic retry.
// 429 = Too Many Requests (rate limiting), 503 = Service Unavailable (WAF DDoS protection).
var retryableStatusCodes = map[int]bool{
	http.StatusTooManyRequests:    true,
	http.StatusServiceUnavailable: true,
}

// RoundTrip implements http.RoundTripper with middleware.
func (m *middlewareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid mutating the caller's request.
	r := req.Clone(req.Context())

	// Set User-Agent.
	if m.randomUA {
		r.Header.Set("User-Agent", RandomUserAgent())
	} else if m.userAgent != "" {
		r.Header.Set("User-Agent", m.userAgent)
	}

	// Set auth headers (only on the initial request host).
	for key, vals := range m.authHeaders {
		for _, v := range vals {
			r.Header.Add(key, v)
		}
	}

	// Execute with retry logic.
	attempts := m.retryCount + 1
	if attempts < 1 {
		attempts = 1
	}

	var resp *http.Response
	var err error

	for i := 0; i < attempts; i++ {
		if i > 0 {
			if m.retryDelay > 0 {
				time.Sleep(m.retryDelay)
			}
			// Reset body for retry if possible.
			if r.GetBody != nil {
				r.Body, _ = r.GetBody()
			}
		}

		resp, err = m.base.RoundTrip(r)
		if err != nil {
			continue // Transport error — retry.
		}

		// Check for retryable HTTP status codes.
		if retryableStatusCodes[resp.StatusCode] && i < attempts-1 {
			// Drain and close the body before retry.
			iohelper.DrainAndClose(resp.Body)
			continue
		}

		return resp, nil
	}

	return resp, err
}

// needsMiddleware reports whether the config requires the middleware transport.
func needsMiddleware(cfg Config) bool {
	return cfg.UserAgent != "" ||
		cfg.RandomUserAgent ||
		len(cfg.AuthHeaders) > 0 ||
		cfg.RetryCount > 0
}

// redirectPolicyWithAuthStrip returns a CheckRedirect function that strips
// auth headers on cross-origin redirects to prevent credential leakage.
func redirectPolicyWithAuthStrip(authHeaders http.Header) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return http.ErrUseLastResponse
		}

		// Security scanners don't follow redirects by default.
		// If the first request's host differs from the redirect target,
		// strip auth headers to prevent credential leakage.
		originalHost := via[0].URL.Host
		if req.URL.Host != originalHost {
			for key := range authHeaders {
				req.Header.Del(key)
			}
		}

		return http.ErrUseLastResponse
	}
}
