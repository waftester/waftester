package hosterrors

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestMarkError_SingleHost(t *testing.T) {
	cache := NewCache(3, time.Minute)

	// First two errors should not mark as failed
	if cache.MarkError("example.com") {
		t.Error("host should not be marked after first error")
	}
	if cache.MarkError("example.com") {
		t.Error("host should not be marked after second error")
	}
	// Third error should mark as failed
	if !cache.MarkError("example.com") {
		t.Error("host should be marked after third error")
	}
}

func TestCheck(t *testing.T) {
	cache := NewCache(2, time.Minute)

	// Unknown host should not be blocked
	if cache.Check("unknown.com") {
		t.Error("unknown host should not be blocked")
	}

	// Mark errors
	cache.MarkError("blocked.com")
	cache.MarkError("blocked.com")

	// Now should be blocked
	if !cache.Check("blocked.com") {
		t.Error("host should be blocked after reaching threshold")
	}
}

func TestCheck_Expiry(t *testing.T) {
	cache := NewCache(2, 50*time.Millisecond)

	cache.MarkError("expiring.com")
	cache.MarkError("expiring.com")

	if !cache.Check("expiring.com") {
		t.Error("host should be blocked initially")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	if cache.Check("expiring.com") {
		t.Error("host should not be blocked after expiry")
	}
}

func TestMarkPermanent(t *testing.T) {
	cache := NewCache(2, 50*time.Millisecond)

	cache.MarkPermanent("permanent.com")

	if !cache.Check("permanent.com") {
		t.Error("permanently marked host should be blocked")
	}

	// Should still be blocked after normal expiry time
	time.Sleep(100 * time.Millisecond)

	if !cache.Check("permanent.com") {
		t.Error("permanently marked host should still be blocked after expiry time")
	}
}

func TestClear(t *testing.T) {
	cache := NewCache(2, time.Minute)

	cache.MarkError("clear-test.com")
	cache.MarkError("clear-test.com")

	if !cache.Check("clear-test.com") {
		t.Fatal("host should be blocked")
	}

	cache.Clear("clear-test.com")

	if cache.Check("clear-test.com") {
		t.Error("host should not be blocked after clear")
	}
}

func TestClearAll(t *testing.T) {
	cache := NewCache(2, time.Minute)

	hosts := []string{"host1.com", "host2.com", "host3.com"}
	for _, h := range hosts {
		cache.MarkError(h)
		cache.MarkError(h)
	}

	if cache.Size() != 3 {
		t.Errorf("expected 3 hosts, got %d", cache.Size())
	}

	cache.ClearAll()

	if cache.Size() != 0 {
		t.Errorf("expected 0 hosts after clear, got %d", cache.Size())
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com:443", "example.com"},
		{"https://example.com", "example.com"},
		{"https://example.com:8080/path", "example.com"},
		{"http://EXAMPLE.COM/path?query=1", "example.com"},
		{"  example.com  ", "example.com"},
		{"", ""},
		{"[::1]:8080", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeHost(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeHost(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestStats(t *testing.T) {
	cache := NewCache(2, time.Minute)

	// Generate some hits and misses
	cache.Check("miss1.com") // miss
	cache.Check("miss2.com") // miss

	cache.MarkError("blocked.com")
	cache.MarkError("blocked.com")

	cache.Check("blocked.com") // hit
	cache.Check("blocked.com") // hit
	cache.Check("miss3.com")   // miss

	hits, misses := cache.Stats()
	if hits != 2 {
		t.Errorf("expected 2 hits, got %d", hits)
	}
	if misses != 3 {
		t.Errorf("expected 3 misses, got %d", misses)
	}
}

func TestConcurrentAccess(t *testing.T) {
	cache := NewCache(5, time.Minute)
	hosts := []string{"host1.com", "host2.com", "host3.com", "host4.com", "host5.com"}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			host := hosts[idx%len(hosts)]
			for j := 0; j < 10; j++ {
				cache.MarkError(host)
				cache.Check(host)
			}
		}(i)
	}
	wg.Wait()

	// All hosts should be marked as failed
	for _, h := range hosts {
		if !cache.Check(h) {
			t.Errorf("host %s should be blocked", h)
		}
	}
}

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"generic error", errors.New("some error"), false},
		{"connection refused", errors.New("dial tcp: connection refused"), true},
		{"no such host", errors.New("lookup host: no such host"), true},
		{"timeout", errors.New("i/o timeout"), true},
		{"context deadline", errors.New("context deadline exceeded"), true},
		{"connection reset", errors.New("connection reset by peer"), true},
		{"EOF", errors.New("unexpected EOF"), true},
		{"tls timeout", errors.New("tls handshake timeout"), true},
		{"network unreachable", errors.New("network is unreachable"), true},
		{"random error", errors.New("random validation error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNetworkError(tt.err)
			if result != tt.expected {
				t.Errorf("IsNetworkError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

// Mock net.Error for testing
type mockNetError struct {
	timeout   bool
	temporary bool
}

func (e *mockNetError) Error() string   { return "mock network error" }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

var _ net.Error = (*mockNetError)(nil)

func TestIsNetworkError_NetError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"timeout error", &mockNetError{timeout: true, temporary: false}, true},
		{"permanent error", &mockNetError{timeout: false, temporary: false}, true},
		{"temporary error", &mockNetError{timeout: false, temporary: true}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNetworkError(tt.err)
			if result != tt.expected {
				t.Errorf("IsNetworkError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestDefaultCache(t *testing.T) {
	ClearAll()

	// Test package-level functions
	for i := 0; i < DefaultMaxErrors; i++ {
		MarkError("default-test.com")
	}

	if !Check("default-test.com") {
		t.Error("host should be blocked via default cache")
	}

	Clear("default-test.com")

	if Check("default-test.com") {
		t.Error("host should not be blocked after clear")
	}
}

// Benchmarks

func BenchmarkCheck_Miss(b *testing.B) {
	cache := NewCache(3, time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Check("unknown.com")
	}
}

func BenchmarkCheck_Hit(b *testing.B) {
	cache := NewCache(3, time.Minute)
	cache.MarkPermanent("blocked.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Check("blocked.com")
	}
}

func BenchmarkMarkError(b *testing.B) {
	cache := NewCache(1000000, time.Minute) // High threshold to avoid blocking
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.MarkError("test.com")
	}
}

func BenchmarkConcurrentCheck(b *testing.B) {
	cache := NewCache(3, time.Minute)
	hosts := []string{"h1.com", "h2.com", "h3.com", "h4.com", "h5.com"}
	for _, h := range hosts {
		cache.MarkPermanent(h)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.Check(hosts[i%len(hosts)])
			i++
		}
	})
}

func BenchmarkNormalizeHost(b *testing.B) {
	inputs := []string{
		"example.com",
		"https://example.com/path",
		"example.com:443",
		"EXAMPLE.COM",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		normalizeHost(inputs[i%len(inputs)])
	}
}
