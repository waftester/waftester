// Regression tests for crawler context lifecycle.
package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCrawl_ContextCancelledOnNormalCompletion verifies that the derived context
// is cancelled when crawling finishes normally (not via Stop()).
// Regression: cancel() was only called by Stop(), leaving the child context
// registered with the parent on normal completion — a context/resource leak.
func TestCrawl_ContextCancelledOnNormalCompletion(t *testing.T) {
	t.Parallel()

	// Simple server with one page, no outbound links
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Solo</title></head><body>No links here</body></html>`))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:       1,
		MaxPages:       5,
		MaxConcurrency: 2,
		UserAgent:      "test-crawler",
		Timeout:        5 * time.Second,
	}
	c := NewCrawler(config)

	parentCtx, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()

	results, err := c.Crawl(parentCtx, server.URL)
	if err != nil {
		t.Fatalf("Crawl error: %v", err)
	}

	// Drain all results
	var count int
	for range results {
		count++
	}

	if count == 0 {
		t.Error("expected at least 1 crawl result")
	}

	// After results channel is closed, the internal context should be cancelled.
	// Give a brief moment for the goroutine to complete cancel().
	time.Sleep(50 * time.Millisecond)

	// Verify the internal context is done
	select {
	case <-c.ctx.Done():
		// Success — context was properly cancelled
	default:
		t.Error("internal context was NOT cancelled after normal crawl completion — context leak")
	}
}

// TestCrawl_StopCancelsContext verifies Stop() still works as before.
func TestCrawl_StopCancelsContext(t *testing.T) {
	t.Parallel()

	// Server that responds slowly to keep crawler busy
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Slow</title></head><body>
			<a href="/page1">1</a><a href="/page2">2</a><a href="/page3">3</a>
		</body></html>`))
	}))
	defer server.Close()

	config := &Config{
		MaxDepth:       3,
		MaxPages:       100,
		MaxConcurrency: 2,
		UserAgent:      "test-crawler",
		Timeout:        5 * time.Second,
	}
	c := NewCrawler(config)

	ctx := context.Background()
	results, err := c.Crawl(ctx, server.URL)
	if err != nil {
		t.Fatalf("Crawl error: %v", err)
	}

	// Read one result then stop
	select {
	case _, ok := <-results:
		if !ok {
			t.Fatal("results channel closed before Stop()")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first result")
	}

	c.Stop()

	// Drain remaining
	for range results {
	}

	// Context should be cancelled after Stop()
	time.Sleep(50 * time.Millisecond)
	select {
	case <-c.ctx.Done():
		// Success
	default:
		t.Error("context not cancelled after Stop()")
	}
}

// TestCrawl_MaxPagesCloseOnce_NoPanic exercises the closeOnce guard on the
// queue channel. When MaxPages is low and concurrency is high, multiple
// workers may hit the page limit and decrement inFlight to zero concurrently.
// Without closeOnce, this causes a double-close panic.
// Regression: both close(c.queue) call sites now use c.closeOnce.Do().
func TestCrawl_MaxPagesCloseOnce_NoPanic(t *testing.T) {
	t.Parallel()

	// Server returns pages with many links to maximize concurrent worker activity
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
			<a href="/a">A</a><a href="/b">B</a><a href="/c">C</a>
			<a href="/d">D</a><a href="/e">E</a><a href="/f">F</a>
		</body></html>`))
	}))
	defer server.Close()

	// Low MaxPages + high concurrency = multiple workers hitting the limit simultaneously
	config := &Config{
		MaxDepth:       2,
		MaxPages:       2,
		MaxConcurrency: 8,
		UserAgent:      "test-crawler",
		Timeout:        5 * time.Second,
	}

	c := NewCrawler(config)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := c.Crawl(ctx, server.URL)
	if err != nil {
		t.Fatalf("Crawl failed: %v", err)
	}

	// Drain results — the test passes if no panic occurs
	for range results {
	}
}
