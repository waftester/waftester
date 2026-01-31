package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestActiveDiscoveryPhases verifies all 6 phases execute with proper progress reporting
func TestActiveDiscoveryPhases(t *testing.T) {
	// Create a realistic mock server with various endpoint types
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		method := r.Method

		// Simulate different responses based on path
		switch {
		case path == "/":
			w.Header().Set("Server", "nginx")
			w.Header().Set("X-Powered-By", "Express")
			w.WriteHeader(200)
			w.Write([]byte(`<html><head></head><body>
				<a href="/dashboard">Dashboard</a>
				<a href="/settings">Settings</a>
				<script src="/static/app.js"></script>
			</body></html>`))

		case path == "/login" || path == "/signin":
			if method == "GET" {
				w.WriteHeader(200)
				w.Write([]byte(`<form action="/login" method="POST">
					<input name="username" type="text"/>
					<input name="password" type="password"/>
				</form>`))
			} else if method == "POST" {
				w.WriteHeader(200)
			} else {
				w.WriteHeader(200) // Accept all methods for auth endpoints
			}

		case path == "/admin" || path == "/dashboard":
			w.WriteHeader(403)

		case strings.HasPrefix(path, "/api"):
			w.Header().Set("Content-Type", "application/json")
			if method == "GET" {
				w.WriteHeader(200)
				w.Write([]byte(`{"status":"ok","endpoints":["/api/users","/api/data"]}`))
			} else {
				w.WriteHeader(200) // API accepts all methods
			}

		case path == "/health" || path == "/healthz":
			w.WriteHeader(200)
			w.Write([]byte(`{"healthy":true}`))

		case path == "/webhook" || strings.HasPrefix(path, "/rest"):
			w.WriteHeader(200)
			w.Write([]byte(`ok`))

		case strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css"):
			w.WriteHeader(200)
			w.Write([]byte(`/* static */`))

		default:
			// Return 404 for unknown paths
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	t.Run("all_6_phases_execute_with_progress", func(t *testing.T) {
		ad := NewActiveDiscoverer(server.URL, 5*time.Second, false)

		// Track which phases were called and their progress
		var mu sync.Mutex
		phasesSeen := make(map[string]bool)
		phaseCounts := make(map[string]int)
		phaseMaxProgress := make(map[string]int)

		progress := func(p PhaseProgress) {
			mu.Lock()
			defer mu.Unlock()
			phasesSeen[p.PhaseName] = true
			phaseCounts[p.PhaseName]++
			if p.Done > phaseMaxProgress[p.PhaseName] {
				phaseMaxProgress[p.PhaseName] = p.Done
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		endpoints := ad.DiscoverAllWithPhaseProgress(ctx, 10, progress)

		// Verify all 6 phases executed
		expectedPhases := []string{"fingerprint", "path-bruteforce", "link-extraction", "param-discovery", "method-enum", "dedupe"}
		for _, phase := range expectedPhases {
			if !phasesSeen[phase] {
				t.Errorf("Phase %q was not executed", phase)
			}
		}

		// Verify we got progress callbacks for key phases
		if phaseCounts["path-bruteforce"] < 5 {
			t.Errorf("Expected multiple progress callbacks for path-bruteforce, got %d", phaseCounts["path-bruteforce"])
		}

		// Verify endpoints were discovered
		if len(endpoints) == 0 {
			t.Fatal("Expected at least some endpoints to be discovered")
		}

		// Log what we found
		t.Logf("=== PHASE EXECUTION SUMMARY ===")
		for _, phase := range expectedPhases {
			t.Logf("  %s: %d callbacks, max progress: %d", phase, phaseCounts[phase], phaseMaxProgress[phase])
		}
		t.Logf("=== DISCOVERED %d ENDPOINTS ===", len(endpoints))

		// Verify endpoint variety
		methodCounts := make(map[string]int)
		categoryCounts := make(map[string]int)
		for _, ep := range endpoints {
			methodCounts[ep.Method]++
			categoryCounts[ep.Category]++
		}

		t.Logf("By Method: %v", methodCounts)
		t.Logf("By Category: %v", categoryCounts)

		// Should have multiple methods (method enumeration worked)
		if len(methodCounts) < 2 {
			t.Errorf("Expected multiple HTTP methods, got %v", methodCounts)
		}

		// Should have found high-value endpoints
		highValueFound := categoryCounts["api"] > 0 || categoryCounts["auth"] > 0 || categoryCounts["admin"] > 0 || categoryCounts["protected"] > 0
		if !highValueFound {
			t.Errorf("Expected to find high-value endpoints (api/auth/admin), got categories: %v", categoryCounts)
		}
	})

	t.Run("phases_respect_context_cancellation", func(t *testing.T) {
		ad := NewActiveDiscoverer(server.URL, 5*time.Second, false)

		// Cancel immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		endpoints := ad.DiscoverAllWithPhaseProgress(ctx, 10, nil)

		// Should return early with minimal/no results
		if len(endpoints) > 10 {
			t.Errorf("Expected early termination to limit endpoints, got %d", len(endpoints))
		}
	})

	t.Run("high_value_filtering_works", func(t *testing.T) {
		// Test the isHighValueEndpoint function
		testCases := []struct {
			ep       Endpoint
			expected bool
		}{
			{Endpoint{Path: "/api/users", Category: "api"}, true},
			{Endpoint{Path: "/login", Category: "auth"}, true},
			{Endpoint{Path: "/admin", Category: "admin"}, true},
			{Endpoint{Path: "/webhook", Category: "page"}, true}, // webhook in path
			{Endpoint{Path: "/about", Category: "page"}, false},
			{Endpoint{Path: "/static/style.css", Category: "static"}, false},
		}

		for _, tc := range testCases {
			result := isHighValueEndpoint(tc.ep)
			if result != tc.expected {
				t.Errorf("isHighValueEndpoint(%v) = %v, want %v", tc.ep.Path, result, tc.expected)
			}
		}
	})

	t.Run("static_asset_filtering_works", func(t *testing.T) {
		testCases := []struct {
			path     string
			expected bool
		}{
			{"/app.js", true},
			{"/style.css", true},
			{"/logo.png", true},
			{"/api/data", false},
			{"/login", false},
		}

		for _, tc := range testCases {
			result := isStaticAsset(tc.path)
			if result != tc.expected {
				t.Errorf("isStaticAsset(%q) = %v, want %v", tc.path, result, tc.expected)
			}
		}
	})
}

// TestActiveDiscoveryPerformance verifies the discovery completes in reasonable time
func TestActiveDiscoveryPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// Create a slow server to simulate real-world latency
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond) // Simulate network latency

		path := r.URL.Path
		if path == "/" || path == "/api" || path == "/login" || path == "/health" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	t.Run("completes_within_timeout", func(t *testing.T) {
		ad := NewActiveDiscoverer(server.URL, 2*time.Second, false)

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		start := time.Now()
		endpoints := ad.DiscoverAllWithPhaseProgress(ctx, 20, nil)
		duration := time.Since(start)

		t.Logf("Discovery completed in %v, found %d endpoints", duration, len(endpoints))

		// Should complete reasonably fast even with slow server (worker pool helps)
		if duration > 45*time.Second {
			t.Errorf("Discovery took too long: %v", duration)
		}

		// Should still find the valid endpoints
		if len(endpoints) == 0 {
			t.Error("Expected to find at least some endpoints")
		}
	})
}
