package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestActiveDiscoveryDemo demonstrates active discovery finding real endpoints
// Uses a minimal setup to avoid goroutine leaks during tests
func TestActiveDiscoveryDemo(t *testing.T) {
	// Create a mock server with various endpoints
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "nginx")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><a href="/api">API</a></body></html>`))
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
		case "/api":
			w.WriteHeader(http.StatusOK)
		case "/login":
			w.WriteHeader(http.StatusOK)
		case "/health":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	// Don''t use defer server.Close() - we close manually after discovery

	t.Run("active discovery finds endpoints", func(t *testing.T) {
		// Use short timeout for the HTTP client
		ad := NewActiveDiscoverer(server.URL, 2*time.Second, false)

		// Use a context with reasonable timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Run discovery with low concurrency
		results := ad.DiscoverAll(ctx, 5)

		t.Logf("=== DISCOVERED %d ENDPOINTS ===", len(results))
		for _, ep := range results {
			t.Logf("  [%d] %s %s (%s)", ep.StatusCode, ep.Method, ep.Path, ep.Category)
		}

		// Verify we found some endpoints
		if len(results) == 0 {
			t.Error("Expected to find some endpoints")
		}

		// Check for specific paths
		foundPaths := make(map[string]bool)
		for _, ep := range results {
			foundPaths[ep.Path] = true
		}

		// These paths are in the hardcoded wordlist and should be found
		expectedPaths := []string{"/admin", "/api", "/login", "/health"}
		found := 0
		for _, path := range expectedPaths {
			if foundPaths[path] {
				found++
			}
		}

		if found < 2 {
			t.Errorf("Expected to find at least 2 of %v, got %d", expectedPaths, found)
		}

		// Close server AFTER discovery completes to avoid goroutine leaks
		server.Close()
	})
}
