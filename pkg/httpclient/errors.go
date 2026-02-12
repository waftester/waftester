package httpclient

import "errors"

// Sentinel errors for HTTP client failure modes.
// Callers should use errors.Is() to check for these.
var (
	// ErrProxyConnect indicates the client failed to connect through
	// the configured proxy (SOCKS4/5, HTTP).
	ErrProxyConnect = errors.New("httpclient: proxy connection failed")

	// ErrDNS indicates a DNS resolution failure for the target host.
	ErrDNS = errors.New("httpclient: DNS resolution failed")

	// ErrTLS indicates a TLS handshake or certificate verification failure.
	ErrTLS = errors.New("httpclient: TLS handshake failed")
)
