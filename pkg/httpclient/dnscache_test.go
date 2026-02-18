package httpclient

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDNSCache_LookupHost(t *testing.T) {
	cache := NewDNSCache(5*time.Minute, 30*time.Second)

	// Lookup a well-known host
	ips, err := cache.LookupHost(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("LookupHost failed: %v", err)
	}
	if len(ips) == 0 {
		t.Error("Expected at least one IP for localhost")
	}

	// Second lookup should use cache
	ips2, err := cache.LookupHost(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("Cached LookupHost failed: %v", err)
	}
	if len(ips) != len(ips2) {
		t.Error("Cached result differs from original")
	}
}

func TestDNSCache_Invalidate(t *testing.T) {
	cache := NewDNSCache(5*time.Minute, 30*time.Second)

	// Populate cache
	_, err := cache.LookupHost(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("LookupHost failed: %v", err)
	}

	stats := cache.Stats()
	if stats.TotalEntries != 1 {
		t.Errorf("Expected 1 entry, got %d", stats.TotalEntries)
	}

	// Invalidate
	cache.Invalidate("localhost")

	stats = cache.Stats()
	if stats.TotalEntries != 0 {
		t.Errorf("Expected 0 entries after invalidate, got %d", stats.TotalEntries)
	}
}

func TestDNSCache_Clear(t *testing.T) {
	cache := NewDNSCache(5*time.Minute, 30*time.Second)

	// Populate cache with multiple entries
	hosts := []string{"localhost", "127.0.0.1"}
	for _, host := range hosts {
		cache.LookupHost(context.Background(), host)
	}

	cache.Clear()

	stats := cache.Stats()
	if stats.TotalEntries != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", stats.TotalEntries)
	}
}

func TestDNSCache_NegativeTTL(t *testing.T) {
	// Short TTLs for testing
	cache := NewDNSCache(100*time.Millisecond, 50*time.Millisecond)

	// Lookup non-existent host
	_, err := cache.LookupHost(context.Background(), "definitely-not-a-real-host-12345.invalid")
	if err == nil {
		t.Skip("Expected error for non-existent host, but got none (DNS might have wildcard)")
	}

	// Error should be cached
	stats := cache.Stats()
	if stats.TotalEntries != 1 {
		t.Errorf("Expected negative result to be cached")
	}

	// Wait for negative TTL to expire
	time.Sleep(60 * time.Millisecond)

	stats = cache.Stats()
	if stats.ExpiredEntries != 1 {
		t.Logf("Negative TTL expiry: %+v", stats)
	}
}

func TestDNSCache_Concurrency(t *testing.T) {
	cache := NewDNSCache(5*time.Minute, 30*time.Second)

	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				cache.LookupHost(context.Background(), "localhost")
			}
		}()
	}

	wg.Wait()

	// Should still have just one entry
	stats := cache.Stats()
	if stats.TotalEntries != 1 {
		t.Errorf("Expected 1 entry after concurrent access, got %d", stats.TotalEntries)
	}
}

func TestCachingDialer_DialContext(t *testing.T) {
	cache := NewDNSCache(5*time.Minute, 30*time.Second)
	dialer := NewCachingDialer(cache, 5*time.Second)

	// Start a local listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Dial using the caching dialer
	addr := listener.Addr().String()
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	conn.Close()
}

func TestCachingDialer_IPAddress(t *testing.T) {
	cache := NewDNSCache(5*time.Minute, 30*time.Second)
	dialer := NewCachingDialer(cache, 5*time.Second)

	// Start a local listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	// Dial using IP address directly (should skip DNS lookup)
	addr := listener.Addr().String()
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("DialContext with IP failed: %v", err)
	}
	conn.Close()

	// Cache should be empty (no DNS lookup needed)
	stats := cache.Stats()
	if stats.TotalEntries != 0 {
		t.Errorf("Expected 0 entries for IP dial, got %d", stats.TotalEntries)
	}
}

func BenchmarkDNSCache_LookupHost(b *testing.B) {
	cache := NewDNSCache(5*time.Minute, 30*time.Second)

	// Prime the cache
	cache.LookupHost(context.Background(), "localhost")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.LookupHost(context.Background(), "localhost")
		}
	})
}

func BenchmarkDNSCache_vs_Direct(b *testing.B) {
	cache := NewDNSCache(5*time.Minute, 30*time.Second)
	resolver := &net.Resolver{}

	// Prime cache
	cache.LookupHost(context.Background(), "localhost")

	b.Run("cached", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				cache.LookupHost(context.Background(), "localhost")
			}
		})
	})

	b.Run("direct", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				resolver.LookupHost(context.Background(), "localhost")
			}
		})
	})
}

func TestDNSCache_BackgroundEviction(t *testing.T) {
	// Use a very short TTL so the eviction goroutine fires quickly.
	// TTL=50ms → eviction interval=100ms.
	cache := NewDNSCache(50*time.Millisecond, 50*time.Millisecond)
	defer cache.Close()

	// Prime the cache with a lookup.
	_, err := cache.LookupHost(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("LookupHost failed: %v", err)
	}

	// Confirm it's cached.
	stats := cache.Stats()
	if stats.TotalEntries == 0 {
		t.Fatal("expected at least one cached entry after lookup")
	}

	// Wait for TTL + eviction interval + margin (50ms + 100ms + 100ms = 250ms).
	time.Sleep(300 * time.Millisecond)

	// The background eviction goroutine should have removed the expired entry.
	stats = cache.Stats()
	if stats.TotalEntries > 0 {
		t.Errorf("expected 0 entries after background eviction, got %d (expired: %d)",
			stats.TotalEntries, stats.ExpiredEntries)
	}
}

func TestDNSCache_CloseStopsEviction(t *testing.T) {
	cache := NewDNSCache(50*time.Millisecond, 50*time.Millisecond)

	// Close should be safe to call multiple times.
	cache.Close()
	cache.Close() // double-close must not panic
}

func TestDNSCache_CorruptEntry(t *testing.T) {
	// The type assertion guard in LookupHost must return an error — not panic —
	// when an entry in the sync.Map has the wrong type.
	cache := NewDNSCache(5*time.Minute, 30*time.Second)
	defer cache.Close()

	// Inject a corrupt entry directly into the underlying sync.Map.
	cache.cache.Store("corrupt-host", "not-a-cacheEntry")

	_, err := cache.LookupHost(context.Background(), "corrupt-host")
	if err == nil {
		t.Fatal("LookupHost should return error for corrupt cache entry, not panic")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error should mention corrupt entry, got: %v", err)
	}
}
