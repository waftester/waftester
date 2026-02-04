package bufpool

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/waftester/waftester/pkg/defaults"
)

func TestGetSlice(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		wantCap  int // Expected minimum capacity (power of 2)
		wantPool bool
	}{
		{"zero", 0, 0, false},
		{"tiny_64", 64, 64, true},
		{"small_100", 100, 128, true},
		{"small_1KB", 1024, 1024, true},
		{"medium_4KB", 4096, 4096, true},
		{"large_32KB", 32768, 32768, true},
		{"max_64KB", 65536, 65536, true},
		{"too_large_128KB", 131072, 131072, false}, // Not pooled
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := GetSlice(tt.size)

			if tt.size == 0 {
				if buf != nil {
					t.Error("Expected nil for size 0")
				}
				return
			}

			if len(buf) != tt.size {
				t.Errorf("Length = %d, want %d", len(buf), tt.size)
			}

			if cap(buf) < tt.wantCap {
				t.Errorf("Capacity = %d, want >= %d", cap(buf), tt.wantCap)
			}

			// Return to pool (if applicable)
			PutSlice(buf)
		})
	}
}

func TestSlicePoolReuse(t *testing.T) {
	// Get a slice, write to it, return it
	buf1 := GetSlice(1024)
	copy(buf1, []byte("test data"))
	originalCap := cap(buf1)
	PutSlice(buf1)

	// Get another slice of the same size - should reuse
	buf2 := GetSlice(1024)
	if cap(buf2) != originalCap {
		t.Logf("Buffer was not reused (original cap: %d, new cap: %d)", originalCap, cap(buf2))
	}
	PutSlice(buf2)
}

func TestSlicePoolConcurrency(t *testing.T) {
	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				buf := GetSlice(4096)
				buf[0] = byte(j % 256)
				PutSlice(buf)
			}
		}()
	}

	wg.Wait()
}

func TestGetResponse(t *testing.T) {
	resp := GetResponse()
	defer PutResponse(resp)

	if resp.Body == nil {
		t.Error("Body should not be nil")
	}
	if resp.Body.Cap() < defaults.BufferLarge {
		t.Errorf("Body capacity = %d, want >= %d", resp.Body.Cap(), defaults.BufferLarge)
	}
	if resp.chunk == nil {
		t.Error("chunk should not be nil")
	}
	if len(resp.chunk) != defaults.BufferMedium {
		t.Errorf("chunk length = %d, want %d", len(resp.chunk), defaults.BufferMedium)
	}
}

func TestResponseReadFrom(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "value")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	}))
	defer server.Close()

	// Make request
	httpResp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer httpResp.Body.Close()

	// Use pooled response
	resp := GetResponse()
	defer PutResponse(resp)

	n, err := resp.ReadFrom(httpResp)
	if err != nil {
		t.Fatal(err)
	}

	if n != 13 {
		t.Errorf("Read %d bytes, want 13", n)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if resp.String() != "Hello, World!" {
		t.Errorf("Body = %q, want %q", resp.String(), "Hello, World!")
	}
	if resp.Headers.Get("X-Test") != "value" {
		t.Errorf("Header X-Test = %q, want %q", resp.Headers.Get("X-Test"), "value")
	}
}

func TestResponseReadFromReader(t *testing.T) {
	resp := GetResponse()
	defer PutResponse(resp)

	reader := strings.NewReader("test data from reader")
	n, err := resp.ReadFromReader(reader)
	if err != nil {
		t.Fatalf("ReadFromReader() error = %v", err)
	}
	if n != 21 {
		t.Errorf("ReadFromReader() n = %d, want 21", n)
	}
	if resp.String() != "test data from reader" {
		t.Errorf("Body = %q, want %q", resp.String(), "test data from reader")
	}
}

func TestResponseReadFromReaderNil(t *testing.T) {
	resp := GetResponse()
	defer PutResponse(resp)

	n, err := resp.ReadFromReader(nil)
	if err != nil {
		t.Fatalf("ReadFromReader(nil) error = %v", err)
	}
	if n != 0 {
		t.Errorf("ReadFromReader(nil) n = %d, want 0", n)
	}
}

func TestResponseReadFromLimited(t *testing.T) {
	resp := GetResponse()
	defer PutResponse(resp)

	// Create mock HTTP response
	body := "This is a long response body that exceeds the limit"
	httpResp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"X-Test": []string{"limited"}},
	}
	defer httpResp.Body.Close()

	// Limit to 10 bytes
	n, err := resp.ReadFromLimited(httpResp, 10)
	if err != nil {
		t.Fatalf("ReadFromLimited() error = %v", err)
	}
	if n != 10 {
		t.Errorf("ReadFromLimited() n = %d, want 10", n)
	}
	if resp.String() != "This is a " {
		t.Errorf("Body = %q, want %q", resp.String(), "This is a ")
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestResponsePoolReuse(t *testing.T) {
	resp1 := GetResponse()
	resp1.Body.WriteString("test data")
	resp1.StatusCode = 200
	resp1.Headers.Set("X-Test", "value")
	PutResponse(resp1)

	// Get another response - should be reset
	resp2 := GetResponse()
	defer PutResponse(resp2)

	if resp2.Body.Len() != 0 {
		t.Error("Body should be reset")
	}
	if resp2.StatusCode != 0 {
		t.Error("StatusCode should be reset")
	}
	if len(resp2.Headers) != 0 {
		t.Error("Headers should be reset")
	}
}

func TestResponsePoolConcurrency(t *testing.T) {
	const goroutines = 100
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				resp := GetResponse()
				resp.Body.WriteString("test data")
				resp.StatusCode = 200
				PutResponse(resp)
			}
		}()
	}

	wg.Wait()
}

// Benchmarks

func BenchmarkGetSlice(b *testing.B) {
	b.Run("pooled/4KB", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := GetSlice(4096)
			PutSlice(buf)
		}
	})

	b.Run("direct/4KB", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = make([]byte, 4096)
		}
	})

	b.Run("pooled/32KB", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := GetSlice(32768)
			PutSlice(buf)
		}
	})

	b.Run("direct/32KB", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = make([]byte, 32768)
		}
	})
}

func BenchmarkGetResponse(b *testing.B) {
	b.Run("pooled", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			resp := GetResponse()
			resp.Body.WriteString("test data for benchmarking purposes")
			PutResponse(resp)
		}
	})

	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := bytes.NewBuffer(make([]byte, 0, 65536))
			buf.WriteString("test data for benchmarking purposes")
		}
	})
}

func BenchmarkParallelSlicePool(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := GetSlice(4096)
			buf[0] = 1
			PutSlice(buf)
		}
	})
}

func BenchmarkParallelResponsePool(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp := GetResponse()
			resp.Body.WriteString("test data")
			PutResponse(resp)
		}
	})
}
