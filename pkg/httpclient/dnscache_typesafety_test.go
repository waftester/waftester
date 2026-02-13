package httpclient

// Type safety tests for DNSCache sync.Map — verifies corrupt cache entries
// don't cause panics. Would have caught A-03 (Round 4).

import (
	"context"
	"testing"
	"time"
)

// TestDNSCache_CorruptEntry_NoPanic stores a wrong type in the internal cache
// and verifies LookupHost returns an error instead of panicking.
func TestDNSCache_CorruptEntry_NoPanic(t *testing.T) {
	t.Parallel()

	cache := NewDNSCache(5*time.Minute, 1*time.Minute)

	// Poison the internal sync.Map with a non-*cacheEntry value
	cache.cache.Store("example.com", "not-a-cache-entry")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("LookupHost panicked on corrupt cache entry: %v", r)
		}
	}()

	_, err := cache.LookupHost(context.Background(), "example.com")
	if err == nil {
		// Either error or fallback to real lookup — both acceptable.
		// The key thing is no panic.
		t.Log("LookupHost succeeded (fell through to real lookup)")
	}
}

// TestDNSCache_CorruptEntry_Stats verifies Stats() doesn't panic on corrupt entries.
func TestDNSCache_CorruptEntry_Stats(t *testing.T) {
	t.Parallel()

	cache := NewDNSCache(5*time.Minute, 1*time.Minute)
	cache.cache.Store("bad-host", 12345) // integer, not *cacheEntry

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Stats panicked on corrupt cache entry: %v", r)
		}
	}()

	stats := cache.Stats()
	// Corrupt entry should be skipped, not counted
	if stats.TotalEntries < 0 {
		t.Error("negative TotalEntries")
	}
}

// TestDNSCache_NilEntry verifies nil stored as cache entry doesn't panic.
func TestDNSCache_NilEntry(t *testing.T) {
	t.Parallel()

	cache := NewDNSCache(5*time.Minute, 1*time.Minute)
	cache.cache.Store("nil-host", nil)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("LookupHost panicked on nil cache entry: %v", r)
		}
	}()

	_, _ = cache.LookupHost(context.Background(), "nil-host")
}
