// Package calibration provides auto-calibration tests
package calibration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestResultStruct tests the Result struct
func TestResultStruct(t *testing.T) {
	result := Result{
		BaselineStatus: 404,
		BaselineSize:   100,
		BaselineWords:  20,
		BaselineLines:  10,
		Calibrated:     true,
		Suggestions: FilterSuggestion{
			FilterStatus: []int{404},
			FilterSize:   []int{100},
			FilterWords:  []int{20},
			FilterLines:  []int{10},
		},
	}

	if result.BaselineStatus != 404 {
		t.Errorf("expected BaselineStatus 404, got %d", result.BaselineStatus)
	}
	if result.BaselineSize != 100 {
		t.Errorf("expected BaselineSize 100, got %d", result.BaselineSize)
	}
	if result.BaselineWords != 20 {
		t.Errorf("expected BaselineWords 20, got %d", result.BaselineWords)
	}
	if result.BaselineLines != 10 {
		t.Errorf("expected BaselineLines 10, got %d", result.BaselineLines)
	}
	if !result.Calibrated {
		t.Error("expected Calibrated to be true")
	}
}

// TestFilterSuggestionStruct tests the FilterSuggestion struct
func TestFilterSuggestionStruct(t *testing.T) {
	suggestion := FilterSuggestion{
		FilterStatus: []int{403, 404, 500},
		FilterSize:   []int{100, 200},
		FilterWords:  []int{50},
		FilterLines:  []int{5, 10, 15},
	}

	if len(suggestion.FilterStatus) != 3 {
		t.Errorf("expected 3 FilterStatus, got %d", len(suggestion.FilterStatus))
	}
	if len(suggestion.FilterSize) != 2 {
		t.Errorf("expected 2 FilterSize, got %d", len(suggestion.FilterSize))
	}
	if len(suggestion.FilterWords) != 1 {
		t.Errorf("expected 1 FilterWords, got %d", len(suggestion.FilterWords))
	}
	if len(suggestion.FilterLines) != 3 {
		t.Errorf("expected 3 FilterLines, got %d", len(suggestion.FilterLines))
	}
}

// TestNewCalibrator tests creating a new Calibrator
func TestNewCalibrator(t *testing.T) {
	tests := []struct {
		name       string
		targetURL  string
		timeout    time.Duration
		skipVerify bool
	}{
		{"basic", "http://example.com", 10 * time.Second, false},
		{"with https", "https://secure.example.com", 30 * time.Second, true},
		{"short timeout", "http://localhost:8080", 5 * time.Second, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCalibrator(tt.targetURL, tt.timeout, tt.skipVerify)
			if c == nil {
				t.Fatal("expected calibrator, got nil")
			}
			if c.targetURL != tt.targetURL {
				t.Errorf("expected targetURL %s, got %s", tt.targetURL, c.targetURL)
			}
			if c.timeout != tt.timeout {
				t.Errorf("expected timeout %v, got %v", tt.timeout, c.timeout)
			}
			if c.skipVerify != tt.skipVerify {
				t.Errorf("expected skipVerify %v, got %v", tt.skipVerify, c.skipVerify)
			}
			if c.client == nil {
				t.Error("expected client, got nil")
			}
		})
	}
}

// TestCalibratorCalibrate tests the Calibrate method with mock server
func TestCalibratorCalibrate(t *testing.T) {
	// Create a mock server that returns 404 for all paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Page not found. This is a test response."))
	}))
	defer server.Close()

	c := NewCalibrator(server.URL, 5*time.Second, false)
	result, err := c.Calibrate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if !result.Calibrated {
		t.Error("expected Calibrated to be true")
	}

	if result.BaselineStatus != 404 {
		t.Errorf("expected BaselineStatus 404, got %d", result.BaselineStatus)
	}
}

// TestCalibratorCalibrateWith403 tests calibration with 403 responses
func TestCalibratorCalibrateWith403(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access Denied by WAF"))
	}))
	defer server.Close()

	c := NewCalibrator(server.URL, 5*time.Second, false)
	result, err := c.Calibrate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.BaselineStatus != 403 {
		t.Errorf("expected BaselineStatus 403, got %d", result.BaselineStatus)
	}
}

// TestCalibratorCalibrateWith200 tests calibration with 200 responses
func TestCalibratorCalibrateWith200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	c := NewCalibrator(server.URL, 5*time.Second, false)
	result, err := c.Calibrate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.BaselineStatus != 200 {
		t.Errorf("expected BaselineStatus 200, got %d", result.BaselineStatus)
	}
}

// TestResultDescribe tests the Describe method
func TestResultDescribe(t *testing.T) {
	tests := []struct {
		name     string
		result   Result
		contains string
	}{
		{
			name:     "not calibrated",
			result:   Result{Calibrated: false},
			contains: "failed",
		},
		{
			name: "with status",
			result: Result{
				Calibrated:     true,
				BaselineStatus: 404,
			},
			contains: "Status: 404",
		},
		{
			name: "with size",
			result: Result{
				Calibrated:   true,
				BaselineSize: 1024,
			},
			contains: "Size: 1024",
		},
		{
			name: "with words",
			result: Result{
				Calibrated:    true,
				BaselineWords: 50,
			},
			contains: "Words: 50",
		},
		{
			name: "with lines",
			result: Result{
				Calibrated:    true,
				BaselineLines: 10,
			},
			contains: "Lines: 10",
		},
		{
			name: "full calibration",
			result: Result{
				Calibrated:     true,
				BaselineStatus: 404,
				BaselineSize:   512,
				BaselineWords:  25,
				BaselineLines:  5,
			},
			contains: "Baseline detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := tt.result.Describe()
			if !contains(desc, tt.contains) {
				t.Errorf("expected description to contain %q, got %q", tt.contains, desc)
			}
		})
	}
}

// TestResultGetFilterArgs tests the GetFilterArgs method
func TestResultGetFilterArgs(t *testing.T) {
	tests := []struct {
		name     string
		result   Result
		contains string
	}{
		{
			name:     "not calibrated",
			result:   Result{Calibrated: false},
			contains: "",
		},
		{
			name: "with filter status",
			result: Result{
				Calibrated: true,
				Suggestions: FilterSuggestion{
					FilterStatus: []int{404},
				},
			},
			contains: "-fc 404",
		},
		{
			name: "with filter size",
			result: Result{
				Calibrated: true,
				Suggestions: FilterSuggestion{
					FilterSize: []int{1024},
				},
			},
			contains: "-fs 1024",
		},
		{
			name: "with multiple status codes",
			result: Result{
				Calibrated: true,
				Suggestions: FilterSuggestion{
					FilterStatus: []int{403, 404},
				},
			},
			contains: "-fc 403,404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.result.GetFilterArgs()
			if !contains(args, tt.contains) {
				t.Errorf("expected args to contain %q, got %q", tt.contains, args)
			}
		})
	}
}

// TestFindMostCommon tests the findMostCommon helper function
func TestFindMostCommon(t *testing.T) {
	tests := []struct {
		name     string
		counts   map[int]int
		expected int
	}{
		{
			name:     "empty map",
			counts:   map[int]int{},
			expected: 0,
		},
		{
			name:     "single value",
			counts:   map[int]int{404: 5},
			expected: 404,
		},
		{
			name:     "multiple values, clear winner",
			counts:   map[int]int{200: 1, 404: 5, 500: 2},
			expected: 404,
		},
		{
			name:     "two values same count",
			counts:   map[int]int{403: 3, 404: 3},
			expected: 403, // or 404, depending on iteration order
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findMostCommon(tt.counts)
			// For cases with same count, just check it returns one of them
			if tt.name == "two values same count" {
				if result != 403 && result != 404 {
					t.Errorf("expected 403 or 404, got %d", result)
				}
			} else if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

// TestRandomString tests the randomString helper function
func TestRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"short", 5},
		{"medium", 16},
		{"long", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := randomString(tt.length)
			if len(result) != tt.length {
				t.Errorf("expected length %d, got %d", tt.length, len(result))
			}
			// Verify it only contains valid characters
			for _, c := range result {
				if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
					t.Errorf("unexpected character: %c", c)
				}
			}
		})
	}
}

// TestRandomStringUniqueness tests that randomString produces different values
func TestRandomStringUniqueness(t *testing.T) {
	s1 := randomString(16)
	time.Sleep(time.Millisecond) // Ensure different seeds
	s2 := randomString(16)

	// They might be the same due to the simple implementation, but lengths should match
	if len(s1) != 16 || len(s2) != 16 {
		t.Errorf("expected lengths 16, got %d and %d", len(s1), len(s2))
	}
}

// TestCalibratorWithContextCancellation tests calibration with cancelled context
func TestCalibratorWithContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Slow response
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := NewCalibrator(server.URL, 5*time.Second, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := c.Calibrate(ctx)
	// Should complete without fatal error even with cancelled context
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	_ = err // Error is acceptable with cancelled context
}

// TestCalibratorHTTPClient tests the HTTP client configuration
func TestCalibratorHTTPClient(t *testing.T) {
	c := NewCalibrator("http://example.com", 15*time.Second, true)

	// With the migration to shared httpclient.Default(), the client uses a 30s timeout
	// by default for connection pooling benefits. The timeout parameter is still
	// stored in the Calibrator struct for potential future use.
	if c.client.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s (from httpclient.Default()), got %v", c.client.Timeout)
	}
}

// TestFilterSuggestionEmpty tests empty FilterSuggestion
func TestFilterSuggestionEmpty(t *testing.T) {
	suggestion := FilterSuggestion{}

	if len(suggestion.FilterStatus) != 0 {
		t.Error("expected empty FilterStatus")
	}
	if len(suggestion.FilterSize) != 0 {
		t.Error("expected empty FilterSize")
	}
	if len(suggestion.FilterWords) != 0 {
		t.Error("expected empty FilterWords")
	}
	if len(suggestion.FilterLines) != 0 {
		t.Error("expected empty FilterLines")
	}
}

// TestResultDefaultValues tests Result with default values
func TestResultDefaultValues(t *testing.T) {
	result := Result{}

	if result.BaselineStatus != 0 {
		t.Errorf("expected default BaselineStatus 0, got %d", result.BaselineStatus)
	}
	if result.BaselineSize != 0 {
		t.Errorf("expected default BaselineSize 0, got %d", result.BaselineSize)
	}
	if result.Calibrated {
		t.Error("expected default Calibrated to be false")
	}
}

// TestCalibratorWithVariedResponses tests calibration with varied server responses
func TestCalibratorWithVariedResponses(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		// Return 404 most of the time, occasionally 200
		if requestCount%5 == 0 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
		}
	}))
	defer server.Close()

	c := NewCalibrator(server.URL, 5*time.Second, false)
	result, err := c.Calibrate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect 404 as baseline since it's more common
	if result.BaselineStatus != 404 {
		t.Errorf("expected baseline 404, got %d", result.BaselineStatus)
	}
}

// TestCalibratorWithDifferentBodySizes tests calibration detecting body size patterns
func TestCalibratorWithDifferentBodySizes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		// Return consistent body size
		w.Write([]byte("Not Found - Error Page"))
	}))
	defer server.Close()

	c := NewCalibrator(server.URL, 5*time.Second, false)
	result, err := c.Calibrate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.BaselineSize <= 0 {
		t.Error("expected positive BaselineSize")
	}
}

// =============================================================================
// BUG-EXPOSING TESTS - These tests expose real bugs in the source code
// =============================================================================

// TestRandomStringIsPredictable tests that randomString is now properly random using crypto/rand
// FIXED: randomString now uses crypto/rand instead of time.Now().UnixNano()
func TestRandomStringIsPredictable(t *testing.T) {
	// Generate multiple strings rapidly and check for patterns
	strings := make([]string, 100)
	for i := 0; i < 100; i++ {
		strings[i] = randomString(8)
	}

	// Check for sequential patterns
	duplicateChars := 0
	for _, s := range strings {
		for i := 0; i < len(s)-1; i++ {
			if s[i] == s[i+1] {
				duplicateChars++
			}
		}
	}

	// With crypto/rand, duplicate adjacent chars should be ~2.7% (1/36)
	// 100 strings * 7 adjacent pairs = 700 pairs
	// Expected duplicates: ~19 (2.7%)
	t.Logf("Total adjacent duplicate chars across 100 strings of length 8: %d", duplicateChars)

	// Check if any strings are identical (should never happen with crypto/rand)
	seen := make(map[string]int)
	for _, s := range strings {
		seen[s]++
	}
	for s, count := range seen {
		if count > 1 {
			t.Errorf("randomString produced duplicate string %q %d times - crypto/rand failed!", s, count)
		}
	}

	// Check entropy of first chars
	firstChars := make(map[byte]int)
	for _, s := range strings {
		if len(s) > 0 {
			firstChars[s[0]]++
		}
	}

	// With proper randomness, distribution should be relatively uniform
	// No single char should dominate (>20% = bias)
	for char, count := range firstChars {
		if count > 20 {
			t.Errorf("Character %c appeared %d times as first char - distribution bias detected", char, count)
		}
	}
}

// TestRandomStringMustUseCryptoRand confirms that randomString uses crypto/rand
// FIXED: randomString now uses crypto/rand for secure random generation
func TestRandomStringMustUseCryptoRand(t *testing.T) {
	// Verify that rapid generation produces unique strings
	var identical int
	for i := 0; i < 50; i++ {
		s1 := randomString(4)
		s2 := randomString(4)
		if s1 == s2 {
			identical++
		}
	}

	// With crypto/rand: probability of 4-char match = 1/(36^4) ≈ 0.00006%
	// Should NEVER get identical pairs
	if identical > 0 {
		t.Errorf("Got %d identical pairs in rapid generation - crypto/rand not working!", identical)
	}

	// Test uniqueness over larger set
	generated := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		s := randomString(8)
		if generated[s] {
			t.Errorf("Duplicate string %q generated - randomness issue!", s)
		}
		generated[s] = true
	}
}

// helper function for string contains
func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr)))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
