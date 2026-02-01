package bufpool

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestGet_ReturnsBuffer(t *testing.T) {
	buf := Get()
	if buf == nil {
		t.Fatal("Get() returned nil")
	}
	Put(buf)
}

func TestGet_ReturnsEmptyBuffer(t *testing.T) {
	buf := Get()
	defer Put(buf)
	if buf.Len() != 0 {
		t.Errorf("Expected empty buffer, got len=%d", buf.Len())
	}
}

func TestPut_ResetsBuffer(t *testing.T) {
	buf := Get()
	buf.WriteString("test data that should be cleared")
	Put(buf)

	// Get another buffer - may or may not be the same one from pool
	// but it should be empty
	buf2 := Get()
	defer Put(buf2)
	if buf2.Len() != 0 {
		t.Error("Buffer from pool not empty after Put")
	}
}

func TestPut_NilSafe(t *testing.T) {
	// Should not panic
	Put(nil)
}

func TestGetSized_ReturnsBufferWithCapacity(t *testing.T) {
	buf := GetSized(1024)
	defer Put(buf)
	if buf == nil {
		t.Fatal("GetSized() returned nil")
	}
	if buf.Cap() < 1024 {
		t.Errorf("Expected capacity >= 1024, got %d", buf.Cap())
	}
}

func TestGetSized_ReturnsEmptyBuffer(t *testing.T) {
	buf := GetSized(1024)
	defer Put(buf)
	if buf.Len() != 0 {
		t.Errorf("Expected empty buffer, got len=%d", buf.Len())
	}
}

func TestPool_ConcurrentSafe(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := Get()
			buf.WriteString("concurrent test data")
			Put(buf)
		}()
	}
	wg.Wait()
}

func TestPool_ConcurrentSafeWithSized(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := GetSized(512)
			buf.WriteString("concurrent test data with sized buffer")
			Put(buf)
		}()
	}
	wg.Wait()
}

func TestPut_LargeBufferNotReturned(t *testing.T) {
	// This tests the behavior that very large buffers are not returned to pool
	// to prevent memory bloat. We can't directly test pool internals,
	// but we can verify the function doesn't crash with large buffers.
	buf := Get()
	buf.Grow(128 * 1024) // 128KB - above threshold
	buf.WriteString("some data")
	Put(buf) // Should not panic, buffer just won't be returned to pool
}

func TestGetString_ReturnsBuilder(t *testing.T) {
	sb := GetString()
	if sb == nil {
		t.Fatal("GetString() returned nil")
	}
	PutString(sb)
}

func TestGetString_ReturnsEmptyBuilder(t *testing.T) {
	sb := GetString()
	defer PutString(sb)
	if sb.Len() != 0 {
		t.Errorf("Expected empty builder, got len=%d", sb.Len())
	}
}

func TestPutString_NilSafe(t *testing.T) {
	// Should not panic
	PutString(nil)
}

func TestStringPool_ConcurrentSafe(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sb := GetString()
			sb.WriteString("concurrent string builder test")
			PutString(sb)
		}()
	}
	wg.Wait()
}

// Benchmarks - comparing pooled vs non-pooled allocations

func BenchmarkGet(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := Get()
		buf.WriteString("benchmark test data for buffer pool performance testing")
		Put(buf)
	}
}

func BenchmarkNewBuffer(b *testing.B) {
	// Baseline: creating new buffer each time (no pooling)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := new(bytes.Buffer)
		buf.WriteString("benchmark test data for buffer pool performance testing")
		_ = buf
	}
}

func BenchmarkGetSized(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := GetSized(1024)
		buf.WriteString("benchmark test data for buffer pool performance testing")
		Put(buf)
	}
}

func BenchmarkGetString(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sb := GetString()
		sb.WriteString("benchmark test data for string builder pool performance testing")
		PutString(sb)
	}
}

func BenchmarkNewStringBuilder(b *testing.B) {
	// Baseline: creating new builder each time (no pooling)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sb := new(strings.Builder)
		sb.WriteString("benchmark test data for string builder pool performance testing")
		_ = sb
	}
}
