// Package detection provides connection drop and silent ban detection.
package detection

import (
	"net/http"
	"sync/atomic"
	"time"
)

// disabled is a global flag to disable detection. Use Disable() and Enable().
var disabled int32

// Disable turns off detection globally. All transport wrappers become pass-through.
func Disable() {
	atomic.StoreInt32(&disabled, 1)
}

// Enable turns on detection globally (the default).
func Enable() {
	atomic.StoreInt32(&disabled, 0)
}

// IsEnabled returns true if detection is enabled.
func IsEnabled() bool {
	return atomic.LoadInt32(&disabled) == 0
}

// Transport wraps an http.RoundTripper to automatically feed
// request results to the detection system. This enables detection
// for any HTTP client that uses this transport.
type Transport struct {
	// Base is the underlying RoundTripper. If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// Detector is the detection system to notify. If nil, Default() is used.
	Detector *Detector
}

// RoundTrip implements http.RoundTripper. It executes the request and
// records the result (error or response) to the detection system.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	// If detection is disabled, just pass through
	if !IsEnabled() {
		return base.RoundTrip(req)
	}

	detector := t.Detector
	if detector == nil {
		detector = Default()
	}

	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	// Check if we should skip this host due to detected drops/bans
	if skip, reason := detector.ShouldSkipHost(host); skip {
		return nil, &SkipHostError{Host: host, Reason: reason}
	}

	// Execute the request and measure latency
	start := time.Now()
	resp, err := base.RoundTrip(req)
	latency := time.Since(start)

	// Record the result to the detection system
	if err != nil {
		detector.RecordError(host, err)
	} else {
		// Estimate body size from Content-Length header
		bodySize := int(resp.ContentLength)
		if bodySize < 0 {
			bodySize = 0
		}
		detector.RecordResponse(host, resp, latency, bodySize)
	}

	return resp, err
}

// SkipHostError is returned when a host is skipped due to detected issues.
type SkipHostError struct {
	Host   string
	Reason string
}

func (e *SkipHostError) Error() string {
	if e.Reason != "" {
		return "host skipped due to detected issues (" + e.Reason + "): " + e.Host
	}
	return "host skipped due to detected connection drops or silent ban: " + e.Host
}

// WrapTransport wraps an existing http.RoundTripper with detection capabilities.
// If base is nil, http.DefaultTransport is used.
func WrapTransport(base http.RoundTripper) *Transport {
	return &Transport{
		Base:     base,
		Detector: Default(),
	}
}

// WrapRoundTripper is a convenience function that returns http.RoundTripper
// instead of *Transport. This matches the TransportWrapper signature used
// by httpclient.RegisterTransportWrapper().
func WrapRoundTripper(base http.RoundTripper) http.RoundTripper {
	return WrapTransport(base)
}

// WrapClient returns a new http.Client with the same settings as the original,
// but with the transport wrapped for detection. This is a convenience function
// for quickly adding detection to an existing client.
func WrapClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}

	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}

	return &http.Client{
		Transport:     WrapTransport(base),
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}
}
