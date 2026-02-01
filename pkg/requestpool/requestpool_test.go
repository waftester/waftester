package requestpool

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
)

func TestGet(t *testing.T) {
	req := Get()
	if req == nil {
		t.Fatal("Get() returned nil")
	}
	if req.Header == nil {
		t.Error("Get() returned request with nil Header")
	}
	Put(req)
}

func TestGetWithMethod(t *testing.T) {
	tests := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	for _, method := range tests {
		t.Run(method, func(t *testing.T) {
			req := GetWithMethod(method)
			if req.Method != method {
				t.Errorf("GetWithMethod(%q) returned request with method %q", method, req.Method)
			}
			Put(req)
		})
	}
}

func TestPutResetsRequest(t *testing.T) {
	req := Get()

	// Set various fields
	req.Method = "POST"
	req.URL, _ = url.Parse("https://example.com/path?query=value")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Host = "example.com"
	req.ContentLength = 100
	req.Close = true

	Put(req)

	// Get a new request (might be the same one from pool)
	req2 := Get()

	// Verify it's been reset
	if req2.Method != "" {
		t.Errorf("Method not reset, got %q", req2.Method)
	}
	if req2.URL != nil {
		t.Errorf("URL not reset, got %v", req2.URL)
	}
	if len(req2.Header) != 0 {
		t.Errorf("Header not reset, got %v", req2.Header)
	}
	if req2.Host != "" {
		t.Errorf("Host not reset, got %q", req2.Host)
	}
	if req2.ContentLength != 0 {
		t.Errorf("ContentLength not reset, got %d", req2.ContentLength)
	}
	if req2.Close {
		t.Error("Close not reset")
	}

	Put(req2)
}

func TestPutNil(t *testing.T) {
	// Should not panic
	Put(nil)
}

func TestConcurrentGetPut(t *testing.T) {
	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				req := Get()
				req.Method = "GET"
				req.Header.Set("X-Request-ID", "test")
				Put(req)
			}
		}(i)
	}

	wg.Wait()
}

func TestHeaderIsolation(t *testing.T) {
	// Ensure headers don't leak between pooled requests
	req1 := Get()
	req1.Header.Set("Secret", "should-not-leak")
	Put(req1)

	req2 := Get()
	if req2.Header.Get("Secret") != "" {
		t.Error("Header leaked between pooled requests")
	}
	Put(req2)
}

func TestPoolReuse(t *testing.T) {
	// Get and put the same request multiple times
	for i := 0; i < 100; i++ {
		req := Get()
		if req == nil {
			t.Fatalf("Get() returned nil on iteration %d", i)
		}
		if req.Header == nil {
			t.Fatalf("Header was nil on iteration %d", i)
		}
		req.Method = "POST"
		req.Header.Set("X-Test", "value")
		Put(req)
	}
}

// Benchmarks

func BenchmarkGetPut(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := Get()
		Put(req)
	}
}

func BenchmarkNewRequest(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := &http.Request{
			Header: make(http.Header),
		}
		_ = req
	}
}

func BenchmarkGetPutWithHeaders(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := Get()
		req.Method = "POST"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("User-Agent", "WAFtester/1.0")
		Put(req)
	}
}

func BenchmarkNewRequestWithHeaders(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := &http.Request{
			Method: "POST",
			Header: make(http.Header),
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("User-Agent", "WAFtester/1.0")
		_ = req
	}
}

func BenchmarkConcurrentGetPut(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := Get()
			req.Method = "GET"
			req.Header.Set("X-Test", "value")
			Put(req)
		}
	})
}
