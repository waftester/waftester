package main

import (
	"net/http"
	"strings"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// headerSlice implements flag.Value for repeated -H flags.
// Does not split on commas since header values may contain them.
type headerSlice []string

func (h *headerSlice) String() string { return strings.Join(*h, "; ") }

func (h *headerSlice) Set(value string) error {
	*h = append(*h, value)
	return nil
}

// countingTransport wraps an http.RoundTripper and atomically increments
// a counter on every request. This feeds the LiveProgress rate display
// so it shows real HTTP req/s instead of 0.0/s while scanners run.
type countingTransport struct {
	inner   http.RoundTripper
	counter *int64
}

func (ct *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt64(ct.counter, 1)
	return ct.inner.RoundTrip(req)
}

// rateLimitTransport enforces a per-request rate limit at the HTTP
// transport level so all scanners share a single token bucket.
// This replaces the per-scanner-launch limiter that only gated scanner
// starts, not actual HTTP traffic.
type rateLimitTransport struct {
	inner   http.RoundTripper
	limiter *rate.Limiter
}

func (rt *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := rt.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	return rt.inner.RoundTrip(req)
}

// tamperTransport applies WAF evasion tampers to every outgoing HTTP
// request via the tamper engine's TransformRequest method. This ensures
// all scanners benefit from --tamper/--tamper-auto without individual
// scanner changes.
type tamperTransport struct {
	inner  http.RoundTripper
	engine interface {
		TransformRequest(req *http.Request) *http.Request
	}
}

func (tt *tamperTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return tt.inner.RoundTrip(tt.engine.TransformRequest(req))
}
