// Package httpclient provides a shared, optimized HTTP client factory.
// This file implements DNS caching to avoid repeated lookups during
// high-throughput scanning operations.
package httpclient

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// DNSCache provides thread-safe caching of DNS lookups.
// This significantly reduces latency when making many requests to the same hosts.
type DNSCache struct {
	// cache stores resolved IP addresses keyed by hostname
	cache sync.Map // map[string]*cacheEntry

	// resolver is the underlying DNS resolver
	resolver *net.Resolver

	// ttl is how long entries remain valid
	ttl time.Duration

	// negativeTTL is how long failed lookups are cached
	negativeTTL time.Duration

	// stopEviction signals the background eviction goroutine to stop
	stopEviction chan struct{}
}

// cacheEntry holds cached DNS results
type cacheEntry struct {
	ips       []net.IP
	err       error
	expiresAt time.Time
	mu        sync.RWMutex
}

// DefaultDNSCache is the global DNS cache instance
var (
	defaultDNSCache *DNSCache
	dnsCacheOnce    sync.Once
)

// GetDNSCache returns the shared DNS cache instance
func GetDNSCache() *DNSCache {
	dnsCacheOnce.Do(func() {
		defaultDNSCache = NewDNSCache(5*time.Minute, 30*time.Second)
	})
	return defaultDNSCache
}

// NewDNSCache creates a new DNS cache with the specified TTL.
// - ttl: how long successful lookups are cached
// - negativeTTL: how long failed lookups are cached
//
// The cache starts a background goroutine that evicts expired entries
// every 2*ttl. Call Close() to stop it when done.
func NewDNSCache(ttl, negativeTTL time.Duration) *DNSCache {
	d := &DNSCache{
		resolver: &net.Resolver{
			PreferGo: true, // Use Go's resolver for better control
		},
		ttl:          ttl,
		negativeTTL:  negativeTTL,
		stopEviction: make(chan struct{}),
	}

	// Background eviction of expired entries to prevent unbounded memory growth
	go d.evictionLoop(2 * ttl)

	return d
}

// Close stops the background eviction goroutine.
func (d *DNSCache) Close() {
	select {
	case <-d.stopEviction:
		// already closed
	default:
		close(d.stopEviction)
	}
}

// evictionLoop periodically removes expired cache entries.
func (d *DNSCache) evictionLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopEviction:
			return
		case <-ticker.C:
			now := time.Now()
			d.cache.Range(func(key, value interface{}) bool {
				entry, ok := value.(*cacheEntry)
				if !ok {
					d.cache.Delete(key)
					return true
				}
				entry.mu.RLock()
				expired := now.After(entry.expiresAt)
				entry.mu.RUnlock()
				if expired {
					d.cache.Delete(key)
				}
				return true
			})
		}
	}
}

// LookupHost returns cached IP addresses for the given host.
// If not cached or expired, performs a fresh lookup and caches the result.
func (d *DNSCache) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	// Check cache first
	if entry, ok := d.cache.Load(host); ok {
		e, eOk := entry.(*cacheEntry)
		if !eOk {
			return nil, fmt.Errorf("dnscache: corrupt entry type %T for host %s", entry, host)
		}
		e.mu.RLock()
		if time.Now().Before(e.expiresAt) {
			ips := e.ips
			err := e.err
			e.mu.RUnlock()
			return ips, err
		}
		e.mu.RUnlock()
	}

	// Cache miss or expired - perform lookup
	return d.refresh(ctx, host)
}

// refresh performs a DNS lookup and updates the cache
func (d *DNSCache) refresh(ctx context.Context, host string) ([]net.IP, error) {
	// Create or get existing entry for synchronization
	entryI, _ := d.cache.LoadOrStore(host, &cacheEntry{})
	entry, ok := entryI.(*cacheEntry)
	if !ok {
		return nil, fmt.Errorf("dnscache: corrupt entry type %T for host %s", entryI, host)
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Double-check if another goroutine already refreshed
	if time.Now().Before(entry.expiresAt) {
		return entry.ips, entry.err
	}

	// Perform the actual lookup
	addrs, err := d.resolver.LookupHost(ctx, host)

	if err != nil {
		// If the context was canceled, do NOT cache the error — a subsequent
		// lookup with a fresh context should retry DNS, not get a stale
		// "context canceled" / "deadline exceeded" error.
		if ctx.Err() != nil {
			return nil, err
		}
		// Cache negative result with shorter TTL
		entry.ips = nil
		entry.err = err
		entry.expiresAt = time.Now().Add(d.negativeTTL)
		return nil, err
	}

	// Parse and cache successful result
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil {
			ips = append(ips, ip)
		}
	}

	// All addresses failed to parse — treat as lookup failure
	if len(ips) == 0 {
		noIPErr := fmt.Errorf("dnscache: no valid IPs for host %s (%d addresses unparseable)", host, len(addrs))
		entry.ips = nil
		entry.err = noIPErr
		entry.expiresAt = time.Now().Add(d.negativeTTL)
		return nil, noIPErr
	}

	entry.ips = ips
	entry.err = nil
	entry.expiresAt = time.Now().Add(d.ttl)

	return ips, nil
}

// LookupHostString returns cached IP addresses as strings.
// Convenience method for dialers that expect string addresses.
func (d *DNSCache) LookupHostString(ctx context.Context, host string) ([]string, error) {
	ips, err := d.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}

	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = ip.String()
	}
	return addrs, nil
}

// Invalidate removes a host from the cache.
// Use this when you know DNS has changed (e.g., after a connection error).
func (d *DNSCache) Invalidate(host string) {
	d.cache.Delete(host)
}

// Clear removes all entries from the cache.
func (d *DNSCache) Clear() {
	d.cache.Range(func(key, _ interface{}) bool {
		d.cache.Delete(key)
		return true
	})
}

// Stats returns cache statistics for monitoring.
func (d *DNSCache) Stats() DNSCacheStats {
	var stats DNSCacheStats
	now := time.Now()

	d.cache.Range(func(key, value interface{}) bool {
		stats.TotalEntries++
		entry, ok := value.(*cacheEntry)
		if !ok {
			return true
		}
		entry.mu.RLock()
		if now.Before(entry.expiresAt) {
			stats.ValidEntries++
		} else {
			stats.ExpiredEntries++
		}
		entry.mu.RUnlock()
		return true
	})

	return stats
}

// DNSCacheStats holds cache statistics
type DNSCacheStats struct {
	TotalEntries   int
	ValidEntries   int
	ExpiredEntries int
}

// CachingDialer wraps a dialer with DNS caching.
// Use this to inject DNS caching into http.Transport.
type CachingDialer struct {
	cache   *DNSCache
	dialer  *net.Dialer
	timeout time.Duration
}

// NewCachingDialer creates a dialer that uses DNS caching.
func NewCachingDialer(cache *DNSCache, timeout time.Duration) *CachingDialer {
	return &CachingDialer{
		cache:   cache,
		timeout: timeout,
		dialer: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		},
	}
}

// DialContext connects to the address using cached DNS.
// This method is compatible with http.Transport.DialContext.
func (d *CachingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// Address might not have a port, try direct dial
		return d.dialer.DialContext(ctx, network, address)
	}

	// Check if it's already an IP address
	if ip := net.ParseIP(host); ip != nil {
		return d.dialer.DialContext(ctx, network, address)
	}

	// Lookup with cache
	ips, err := d.cache.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}

	// Try each IP until one works
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), port)
		conn, err := d.dialer.DialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	// All IPs failed, invalidate cache entry
	d.cache.Invalidate(host)
	if lastErr == nil {
		lastErr = fmt.Errorf("dnscache: no IPs to dial for host %s", host)
	}
	return nil, lastErr
}
