// Package hosterrors provides a thread-safe cache for tracking hosts that have
// failed connectivity checks. This prevents repeatedly trying hosts that are
// known to be down, significantly improving scan performance.
//
// Inspired by projectdiscovery/httpx and projectdiscovery/nuclei.
//
// Usage:
//
//	if hosterrors.Check("example.com") {
//	    // Skip this host, it's known to be unreachable
//	    return
//	}
//	err := makeRequest("example.com")
//	if isNetworkError(err) {
//	    hosterrors.Mark("example.com")
//	}
package hosterrors

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/duration"
)

// Default configuration
const (
	// DefaultMaxErrors is the max errors before marking a host as failed.
	// Matches DropDetectConsecutiveThreshold so both systems trip together.
	DefaultMaxErrors = 5
)

// DefaultExpiry is how long to cache a failed host
var DefaultExpiry = duration.CacheMedium

// hostState tracks the error count and expiration for a host
type hostState struct {
	mu        sync.RWMutex
	count     int32
	markedAt  time.Time
	permanent bool
}

// Cache stores hosts that have failed connectivity checks
type Cache struct {
	hosts     sync.Map // map[string]*hostState
	maxErrors int32
	expiry    time.Duration
	hits      atomic.Int64
	misses    atomic.Int64
}

// global default cache
var defaultCache = NewCache(DefaultMaxErrors, DefaultExpiry)

// NewCache creates a new host error cache with custom settings.
func NewCache(maxErrors int, expiry time.Duration) *Cache {
	return &Cache{
		maxErrors: int32(maxErrors),
		expiry:    expiry,
	}
}

// MarkError records an error for a host. Returns true if the host has been
// marked as failed (reached maxErrors threshold).
func (c *Cache) MarkError(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}

	var state *hostState
	if v, ok := c.hosts.Load(host); ok {
		state, _ = v.(*hostState)
		if state == nil {
			state = &hostState{}
		}
	} else {
		state = &hostState{}
		actual, _ := c.hosts.LoadOrStore(host, state)
		state, _ = actual.(*hostState)
		if state == nil {
			state = &hostState{}
		}
	}

	// All state modifications under lock to prevent TOCTOU race
	state.mu.Lock()
	defer state.mu.Unlock()

	// Check if expired and reset if so
	if !state.permanent && !state.markedAt.IsZero() && time.Since(state.markedAt) > c.expiry {
		state.count = 0
		state.markedAt = time.Time{}
	}

	state.count++
	if state.count >= c.maxErrors {
		// Only set markedAt on first time reaching threshold
		if state.markedAt.IsZero() {
			state.markedAt = time.Now()
		}
		return true
	}
	return false
}

// MarkPermanent permanently marks a host as failed (won't expire).
// Use for DNS failures or other permanent issues.
func (c *Cache) MarkPermanent(host string) {
	host = normalizeHost(host)
	if host == "" {
		return
	}

	// Update existing state in-place to avoid racing with MarkError
	if v, ok := c.hosts.Load(host); ok {
		if existing, _ := v.(*hostState); existing != nil {
			existing.mu.Lock()
			existing.count = c.maxErrors
			existing.markedAt = time.Now()
			existing.permanent = true
			existing.mu.Unlock()
			return
		}
	}
	c.hosts.Store(host, &hostState{
		count:     c.maxErrors,
		markedAt:  time.Now(),
		permanent: true,
	})
}

// Check returns true if the host should be skipped (has exceeded error threshold).
func (c *Cache) Check(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}

	v, ok := c.hosts.Load(host)
	if !ok {
		c.misses.Add(1)
		return false
	}

	state, _ := v.(*hostState)
	if state == nil {
		c.misses.Add(1)
		return false
	}

	// Fast read path - use RLock for the common case
	state.mu.RLock()
	count := state.count
	permanent := state.permanent
	markedAt := state.markedAt

	if count >= c.maxErrors {
		// Check expiry for non-permanent entries
		if !permanent && time.Since(markedAt) > c.expiry {
			// Need write lock for expiry reset - upgrade lock
			state.mu.RUnlock()
			state.mu.Lock()
			// Double-check under write lock (another goroutine may have reset)
			if state.count >= c.maxErrors && !state.permanent && time.Since(state.markedAt) > c.expiry {
				state.count = 0
				state.markedAt = time.Time{}
			}
			state.mu.Unlock()
			c.misses.Add(1)
			return false
		}
		state.mu.RUnlock()
		c.hits.Add(1)
		return true
	}
	state.mu.RUnlock()

	c.misses.Add(1)
	return false
}

// Clear removes a specific host from the cache (e.g., after successful request).
func (c *Cache) Clear(host string) {
	host = normalizeHost(host)
	if host != "" {
		c.hosts.Delete(host)
	}
}

// ClearAll removes all hosts from the cache.
func (c *Cache) ClearAll() {
	c.hosts.Range(func(key, value interface{}) bool {
		c.hosts.Delete(key)
		return true
	})
	c.hits.Store(0)
	c.misses.Store(0)
}

// Size returns the number of hosts in the cache.
func (c *Cache) Size() int {
	count := 0
	c.hosts.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// Stats returns cache hit/miss statistics.
func (c *Cache) Stats() (hits, misses int64) {
	return c.hits.Load(), c.misses.Load()
}

// Package-level functions using the default cache

// MarkError records an error for a host using the default cache.
func MarkError(host string) bool {
	return defaultCache.MarkError(host)
}

// MarkPermanent permanently marks a host as failed using the default cache.
func MarkPermanent(host string) {
	defaultCache.MarkPermanent(host)
}

// Check returns true if the host should be skipped using the default cache.
func Check(host string) bool {
	return defaultCache.Check(host)
}

// Clear removes a specific host from the default cache.
func Clear(host string) {
	defaultCache.Clear(host)
}

// ClearAll removes all hosts from the default cache.
func ClearAll() {
	defaultCache.ClearAll()
}

// Size returns the number of hosts in the default cache.
func Size() int {
	return defaultCache.Size()
}

// Stats returns cache statistics from the default cache.
func Stats() (hits, misses int64) {
	return defaultCache.Stats()
}

// normalizeHost extracts and normalizes the host from a URL or host string.
func normalizeHost(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	// If it looks like a URL, parse it
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Host != "" {
			input = u.Host
		}
	}

	// Remove port if present
	host, _, err := net.SplitHostPort(input)
	if err != nil {
		// No port present, use as-is
		host = input
	}

	return strings.ToLower(host)
}

// IsNetworkError returns true if the error is a network-level error that
// indicates the host may be unreachable.
func IsNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific network errors
	var netErr net.Error
	if isNetErr := errorAs(err, &netErr); isNetErr {
		if netErr.Timeout() {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	return false
	}

	// Check error message for common network failures
	errStr := strings.ToLower(err.Error())
	networkIndicators := []string{
		"connection refused",
		"no such host",
		"no route to host",
		"network is unreachable",
		"i/o timeout",
		"dial tcp",
		"dial udp",
		"tls handshake timeout",
		"context deadline exceeded",
		"connection reset",
		"eof",
	}

	for _, indicator := range networkIndicators {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}

	return false
}

// errorAs is a helper to check error types using errors.As for proper unwrapping.
func errorAs(err error, target interface{}) bool {
	if err == nil {
		return false
	}

	switch t := target.(type) {
	case *net.Error:
		return errors.As(err, t)
	}

	return false
}
