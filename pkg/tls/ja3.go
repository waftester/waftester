// Package tls provides JA3/JA3S fingerprint rotation capabilities
// for evading TLS fingerprinting-based WAF detection.
//
// Based on research from:
// - https://github.com/salesforce/ja3
// - https://github.com/CUCyber/ja3transport
// - https://github.com/refraction-networking/utls
package tls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/waftester/waftester/pkg/duration"
)

// JA3Profile represents a TLS fingerprint profile
type JA3Profile struct {
	Name        string `json:"name"`
	JA3Hash     string `json:"ja3_hash"`
	UserAgent   string `json:"user_agent"`
	Description string `json:"description"`
	ClientHello *utls.ClientHelloID
}

// Transport provides HTTP transport with JA3 fingerprint rotation
type Transport struct {
	profiles     []*JA3Profile
	currentIndex int
	rotateEvery  int
	requestCount int
	mu           sync.RWMutex
	timeout      time.Duration
	skipVerify   bool
	verbose      bool
}

// Config configures the TLS transport
type Config struct {
	Profiles    []*JA3Profile // Custom profiles (uses defaults if nil)
	RotateEvery int           // Rotate after N requests (0 = random each request)
	Timeout     time.Duration
	SkipVerify  bool
	Verbose     bool
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Profiles:    DefaultProfiles(),
		RotateEvery: 25, // Rotate every 25 requests
		Timeout:     duration.HTTPFuzzing,
		SkipVerify:  false,
		Verbose:     false,
	}
}

// NewTransport creates a new JA3-rotating HTTP transport
func NewTransport(cfg *Config) *Transport {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	profiles := cfg.Profiles
	if len(profiles) == 0 {
		profiles = DefaultProfiles()
	}

	t := &Transport{
		profiles:     profiles,
		currentIndex: 0,
		rotateEvery:  cfg.RotateEvery,
		timeout:      cfg.Timeout,
		skipVerify:   cfg.SkipVerify,
		verbose:      cfg.Verbose,
	}

	// Set initial random index using crypto/rand for unpredictability
	if len(profiles) > 0 {
		if n, err := rand.Int(rand.Reader, big.NewInt(int64(len(profiles)))); err == nil {
			t.currentIndex = int(n.Int64())
		}
	}

	return t
}

// RoundTrip implements http.RoundTripper
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	if len(t.profiles) == 0 {
		t.mu.Unlock()
		return nil, fmt.Errorf("no TLS profiles configured")
	}
	profile := t.profiles[t.currentIndex]
	t.requestCount++

	// Rotate profile if needed
	if t.rotateEvery > 0 && t.requestCount >= t.rotateEvery {
		t.requestCount = 0
		t.currentIndex = (t.currentIndex + 1) % len(t.profiles)
	} else if t.rotateEvery == 0 {
		// Random selection for each request using crypto/rand
		if n, err := rand.Int(rand.Reader, big.NewInt(int64(len(t.profiles)))); err == nil {
			t.currentIndex = int(n.Int64())
		}
	}
	t.mu.Unlock()

	// profile is already a local copy - no additional lock needed
	currentProfile := profile

	// Create a single-use transport for this profile's fingerprint.
	// DisableKeepAlives=true ensures connections are closed after use,
	// so the transport holds no long-lived resources.
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return t.dialTLSWithProfile(ctx, network, addr, currentProfile)
		},
		DisableKeepAlives: true,
	}

	// Set matching User-Agent
	if profile.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}

	resp, err := transport.RoundTrip(req)

	// Close idle connections to prevent goroutine/FD leaks.
	// With DisableKeepAlives=true this is fast (no idle conns to track),
	// but it ensures internal goroutines are cleaned up.
	transport.CloseIdleConnections()

	return resp, err
}

// dialTLSWithProfile establishes a TLS connection with the specified JA3 fingerprint
func (t *Transport) dialTLSWithProfile(ctx context.Context, network, addr string, profile *JA3Profile) (net.Conn, error) {
	// Extract host for SNI
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// Dial TCP connection
	dialer := &net.Dialer{
		Timeout: t.timeout,
	}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Create uTLS connection with the fingerprint
	tlsConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: t.skipVerify,
	}

	uConn := utls.UClient(conn, tlsConfig, *profile.ClientHello)
	if err := uConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return uConn, nil
}

// getCurrentProfile returns the current active profile
func (t *Transport) getCurrentProfile() *JA3Profile {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.profiles[t.currentIndex]
}

// GetCurrentJA3 returns the current JA3 fingerprint info
func (t *Transport) GetCurrentJA3() (name, hash string) {
	profile := t.getCurrentProfile()
	return profile.Name, profile.JA3Hash
}

// SetProfile sets a specific profile by name
func (t *Transport) SetProfile(name string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for i, p := range t.profiles {
		if strings.EqualFold(p.Name, name) {
			t.currentIndex = i
			return nil
		}
	}
	return fmt.Errorf("profile not found: %s", name)
}

// CreateClient creates an HTTP client with JA3 fingerprint rotation
func CreateClient(cfg *Config) *http.Client {
	transport := NewTransport(cfg)
	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}
}

// DefaultProfiles returns a set of common browser fingerprints
func DefaultProfiles() []*JA3Profile {
	return []*JA3Profile{
		// Chrome profiles
		{
			Name:        "Chrome 120 Windows",
			JA3Hash:     "b32309a26951912be7dba376398abc3b",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			Description: "Chrome 120 on Windows 10/11",
			ClientHello: &utls.HelloChrome_120,
		},
		{
			Name:        "Chrome 120 macOS",
			JA3Hash:     "b32309a26951912be7dba376398abc3b",
			UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			Description: "Chrome 120 on macOS",
			ClientHello: &utls.HelloChrome_120,
		},
		{
			Name:        "Chrome 120 Linux",
			JA3Hash:     "b32309a26951912be7dba376398abc3b",
			UserAgent:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			Description: "Chrome 120 on Linux",
			ClientHello: &utls.HelloChrome_120,
		},
		{
			Name:        "Chrome 112",
			JA3Hash:     "8e1f6dd365d1e6d38c98c7903f6cbb1d",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
			Description: "Chrome 112 with PSK",
			ClientHello: &utls.HelloChrome_112_PSK_Shuf,
		},
		{
			Name:        "Chrome 106",
			JA3Hash:     "e3e2c2ae93562f0b7d2c27c0b9a8c4e0",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
			Description: "Chrome 106 with Shuffle",
			ClientHello: &utls.HelloChrome_106_Shuffle,
		},

		// Firefox profiles
		{
			Name:        "Firefox 121 Windows",
			JA3Hash:     "aa56c057389e0c3b2c0d6d3e3e97e50d",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			Description: "Firefox 121 on Windows",
			ClientHello: &utls.HelloFirefox_120,
		},
		{
			Name:        "Firefox 120 macOS",
			JA3Hash:     "aa56c057389e0c3b2c0d6d3e3e97e50d",
			UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
			Description: "Firefox 120 on macOS",
			ClientHello: &utls.HelloFirefox_120,
		},
		{
			Name:        "Firefox 110",
			JA3Hash:     "e3e2c2ae93562f0b7d2c27c0b9a8c4e0",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0",
			Description: "Firefox 110",
			ClientHello: &utls.HelloFirefox_105,
		},

		// Safari profiles
		{
			Name:        "Safari 17 macOS",
			JA3Hash:     "7c8e4c4d43e0bbafcdea0cfa34f95936",
			UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			Description: "Safari 17 on macOS Sonoma",
			ClientHello: &utls.HelloSafari_16_0,
		},
		{
			Name:        "Safari iOS 17",
			JA3Hash:     "7c8e4c4d43e0bbafcdea0cfa34f95936",
			UserAgent:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			Description: "Safari on iOS 17",
			ClientHello: &utls.HelloIOS_14,
		},

		// Edge profiles
		{
			Name:        "Edge 120 Windows",
			JA3Hash:     "b32309a26951912be7dba376398abc3b",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			Description: "Microsoft Edge 120 on Windows",
			ClientHello: &utls.HelloEdge_106,
		},

		// Android profiles
		{
			Name:        "Chrome Android",
			JA3Hash:     "6e5e58e4d7c5f2a0f5a5e0d5b0c5f0e2",
			UserAgent:   "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36",
			Description: "Chrome on Android 14",
			ClientHello: &utls.HelloChrome_120,
		},

		// Randomized profile
		{
			Name:        "Randomized",
			JA3Hash:     "randomized",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			Description: "Randomized fingerprint to evade detection",
			ClientHello: &utls.HelloRandomized,
		},
	}
}

// ListProfiles returns names of all available profiles
func ListProfiles() []string {
	profiles := DefaultProfiles()
	names := make([]string, len(profiles))
	for i, p := range profiles {
		names[i] = p.Name
	}
	return names
}

// GetProfileByName returns a profile by name
func GetProfileByName(name string) (*JA3Profile, error) {
	for _, p := range DefaultProfiles() {
		if strings.EqualFold(p.Name, name) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("profile not found: %s", name)
}

// FallbackTransport provides a standard TLS transport when utls is unavailable
// This is used when the utls library fails or for compatibility
type FallbackTransport struct {
	profiles     []*JA3Profile
	currentIndex int
	rotateEvery  int
	requestCount int
	mu           sync.RWMutex
	timeout      time.Duration
	skipVerify   bool
}

// NewFallbackTransport creates a transport using standard crypto/tls
func NewFallbackTransport(cfg *Config) *FallbackTransport {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	profiles := cfg.Profiles
	if len(profiles) == 0 {
		profiles = DefaultProfiles()
	}

	t := &FallbackTransport{
		profiles:     profiles,
		currentIndex: 0,
		rotateEvery:  cfg.RotateEvery,
		timeout:      cfg.Timeout,
		skipVerify:   cfg.SkipVerify,
	}

	// Set initial random index using crypto/rand for unpredictability
	if len(profiles) > 0 {
		if n, err := rand.Int(rand.Reader, big.NewInt(int64(len(profiles)))); err == nil {
			t.currentIndex = int(n.Int64())
		}
	}

	return t
}

// RoundTrip implements http.RoundTripper with User-Agent rotation
func (t *FallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	profile := t.profiles[t.currentIndex]
	t.requestCount++

	if t.rotateEvery > 0 && t.requestCount >= t.rotateEvery {
		t.requestCount = 0
		t.currentIndex = (t.currentIndex + 1) % len(t.profiles)
	} else if t.rotateEvery == 0 {
		if n, err := rand.Int(rand.Reader, big.NewInt(int64(len(t.profiles)))); err == nil {
			t.currentIndex = int(n.Int64())
		}
	}
	t.mu.Unlock()

	// Set User-Agent from profile
	if profile.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}

	// Add browser-like headers
	addBrowserHeaders(req)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: t.skipVerify,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
		},
		DisableKeepAlives: true, // Prevent idle connection accumulation
	}

	resp, err := transport.RoundTrip(req)

	// Close idle connections to prevent goroutine/FD leaks
	transport.CloseIdleConnections()

	return resp, err
}

// addBrowserHeaders adds realistic browser headers
func addBrowserHeaders(req *http.Request) {
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}
	if req.Header.Get("Cache-Control") == "" {
		req.Header.Set("Cache-Control", "no-cache")
	}
	if req.Header.Get("Sec-Ch-Ua") == "" {
		req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	}
	if req.Header.Get("Sec-Ch-Ua-Mobile") == "" {
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	}
	if req.Header.Get("Sec-Ch-Ua-Platform") == "" {
		req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	}
	if req.Header.Get("Sec-Fetch-Dest") == "" {
		req.Header.Set("Sec-Fetch-Dest", "document")
	}
	if req.Header.Get("Sec-Fetch-Mode") == "" {
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	if req.Header.Get("Sec-Fetch-Site") == "" {
		req.Header.Set("Sec-Fetch-Site", "none")
	}
	if req.Header.Get("Sec-Fetch-User") == "" {
		req.Header.Set("Sec-Fetch-User", "?1")
	}
	if req.Header.Get("Upgrade-Insecure-Requests") == "" {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}
}

// CreateFallbackClient creates an HTTP client with User-Agent rotation
// when full JA3 spoofing is not available
func CreateFallbackClient(cfg *Config) *http.Client {
	transport := NewFallbackTransport(cfg)
	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}
}

// DetectJA3Support checks if JA3 fingerprint rotation is available
func DetectJA3Support() bool {
	// Try to create a uTLS connection to check support
	// This is a compile-time check essentially
	return true // utls is imported
}

// JA3Info provides information about the current JA3 fingerprint
type JA3Info struct {
	ProfileName string `json:"profile_name"`
	JA3Hash     string `json:"ja3_hash"`
	UserAgent   string `json:"user_agent"`
	Description string `json:"description"`
	RotateEvery int    `json:"rotate_every"`
	RequestNum  int    `json:"request_num"`
}

// GetJA3Info returns current JA3 information from a transport
func (t *Transport) GetJA3Info() *JA3Info {
	t.mu.RLock()
	defer t.mu.RUnlock()

	profile := t.profiles[t.currentIndex]
	return &JA3Info{
		ProfileName: profile.Name,
		JA3Hash:     profile.JA3Hash,
		UserAgent:   profile.UserAgent,
		Description: profile.Description,
		RotateEvery: t.rotateEvery,
		RequestNum:  t.requestCount,
	}
}
