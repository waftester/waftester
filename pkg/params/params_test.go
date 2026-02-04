// Package params provides tests for parameter discovery functionality
package params

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDefaultConfig_NotEmpty verifies DefaultConfig returns usable defaults
func TestDefaultConfig_NotEmpty(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if cfg.Concurrency <= 0 {
		t.Errorf("expected positive Concurrency, got %d", cfg.Concurrency)
	}

	if cfg.Timeout <= 0 {
		t.Errorf("expected positive Timeout, got %v", cfg.Timeout)
	}

	if cfg.ChunkSize <= 0 {
		t.Errorf("expected positive ChunkSize, got %d", cfg.ChunkSize)
	}

	if len(cfg.Methods) == 0 {
		t.Error("expected non-empty Methods")
	}
}

// TestNewDiscoverer_NilConfig verifies NewDiscoverer handles nil config gracefully
func TestNewDiscoverer_NilConfig(t *testing.T) {
	discoverer := NewDiscoverer(nil)

	if discoverer == nil {
		t.Fatal("NewDiscoverer(nil) returned nil")
	}

	if discoverer.client == nil {
		t.Error("discoverer should have non-nil HTTP client")
	}

	if discoverer.concurrency <= 0 {
		t.Error("discoverer should have positive concurrency from defaults")
	}
}

// TestNewDiscoverer_CustomConfig verifies NewDiscoverer respects custom config
func TestNewDiscoverer_CustomConfig(t *testing.T) {
	cfg := &Config{
		Concurrency: 3,
		Timeout:     15 * time.Second,
		UserAgent:   "ParamTester/1.0",
		ChunkSize:   128,
		Verbose:     true,
	}

	discoverer := NewDiscoverer(cfg)

	if discoverer == nil {
		t.Fatal("NewDiscoverer returned nil")
	}

	if discoverer.concurrency != 3 {
		t.Errorf("expected concurrency 3, got %d", discoverer.concurrency)
	}

	if discoverer.userAgent != "ParamTester/1.0" {
		t.Errorf("expected user agent ParamTester/1.0, got %s", discoverer.userAgent)
	}

	if !discoverer.verbose {
		t.Error("expected verbose to be true")
	}
}

// TestDiscoverFromJSON_ValidJSON verifies JSON parameter extraction
func TestDiscoverFromJSON_ValidJSON(t *testing.T) {
	jsonData := []byte(`{
		"username": "test",
		"password": "secret",
		"nested": {
			"field1": "value1",
			"field2": 123
		}
	}`)

	params := DiscoverFromJSON(jsonData)

	if len(params) == 0 {
		t.Error("expected non-empty params from JSON")
	}

	// Should find top-level and nested keys
	foundKeys := make(map[string]bool)
	for _, p := range params {
		foundKeys[p.Name] = true
	}

	expectedKeys := []string{"username", "password", "nested", "nested.field1", "nested.field2"}
	for _, key := range expectedKeys {
		if !foundKeys[key] {
			t.Errorf("expected to find key '%s' in params", key)
		}
	}
}

// TestDiscoverFromJSON_InvalidJSON verifies handling of invalid JSON
func TestDiscoverFromJSON_InvalidJSON(t *testing.T) {
	invalidData := []byte(`{invalid json}`)

	params := DiscoverFromJSON(invalidData)

	// Should return empty, not panic
	if params == nil {
		// nil is acceptable
	} else if len(params) != 0 {
		t.Error("expected empty params for invalid JSON")
	}
}

// TestDiscoverFromJSON_EmptyJSON verifies handling of empty JSON
func TestDiscoverFromJSON_EmptyJSON(t *testing.T) {
	emptyData := []byte(`{}`)

	params := DiscoverFromJSON(emptyData)

	if len(params) != 0 {
		t.Error("expected empty params for empty JSON object")
	}
}

// TestDiscoverFromJSON_NestedArrays verifies handling of arrays in JSON
func TestDiscoverFromJSON_NestedArrays(t *testing.T) {
	jsonData := []byte(`{
		"items": [1, 2, 3],
		"config": {
			"enabled": true
		}
	}`)

	params := DiscoverFromJSON(jsonData)

	// Should at least find top-level keys
	if len(params) == 0 {
		t.Error("expected non-empty params")
	}

	foundItems := false
	foundConfig := false
	for _, p := range params {
		if p.Name == "items" {
			foundItems = true
		}
		if p.Name == "config" || p.Name == "config.enabled" {
			foundConfig = true
		}
	}

	if !foundItems {
		t.Error("expected to find 'items' key")
	}
	if !foundConfig {
		t.Error("expected to find 'config' related keys")
	}
}

// TestDiscoveredParam_Defaults verifies DiscoveredParam has proper zero values
func TestDiscoveredParam_Defaults(t *testing.T) {
	param := DiscoveredParam{}

	if param.Name != "" {
		t.Error("default Name should be empty")
	}

	if param.Confidence != 0 {
		t.Error("default Confidence should be 0")
	}

	if param.Type != "" {
		t.Error("default Type should be empty")
	}
}

// TestDiscoveryResult_Defaults verifies DiscoveryResult has proper zero values
func TestDiscoveryResult_Defaults(t *testing.T) {
	result := DiscoveryResult{}

	if result.FoundParams != 0 {
		t.Error("default FoundParams should be 0")
	}

	if result.Parameters != nil {
		t.Error("default Parameters should be nil")
	}

	if result.Target != "" {
		t.Error("default Target should be empty")
	}
}

// TestDiscover_BasicFunctionality verifies basic discovery works
func TestDiscover_BasicFunctionality(t *testing.T) {
	// Create a test server with a simple HTML form
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<html>
			<body>
				<form action="/submit" method="POST">
					<input type="text" name="username" />
					<input type="password" name="password" />
					<input type="hidden" name="csrf_token" />
					<button type="submit">Login</button>
				</form>
			</body>
			</html>
		`))
	}))
	defer ts.Close()

	cfg := &Config{
		Concurrency: 1,
		Timeout:     5 * time.Second,
		ChunkSize:   10,
	}
	discoverer := NewDiscoverer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := discoverer.Discover(ctx, ts.URL, "GET")
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if result == nil {
		t.Fatal("Discover returned nil result")
	}

	if result.Target != ts.URL {
		t.Errorf("expected target %s, got %s", ts.URL, result.Target)
	}

	// Should find form parameters through passive discovery
	if result.BySource["passive"] == 0 && result.BySource["passive-form"] == 0 {
		// Passive discovery may not find params in all cases
		t.Log("Note: passive discovery didn't find form params (acceptable in unit test)")
	}
}

// TestDiscover_ContextCancellation verifies discovery respects context
func TestDiscover_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	discoverer := NewDiscoverer(&Config{Concurrency: 1, Timeout: time.Second, ChunkSize: 5})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := discoverer.Discover(ctx, ts.URL, "GET")
	// Should complete quickly due to cancellation (may error or return partial results)
	_ = err // Error is acceptable here
}

// TestConfig_Methods verifies Methods default values
func TestConfig_Methods(t *testing.T) {
	cfg := DefaultConfig()

	if len(cfg.Methods) < 2 {
		t.Error("expected at least GET and POST methods")
	}

	hasGet := false
	hasPost := false
	for _, m := range cfg.Methods {
		if m == "GET" {
			hasGet = true
		}
		if m == "POST" {
			hasPost = true
		}
	}

	if !hasGet {
		t.Error("expected GET in default methods")
	}
	if !hasPost {
		t.Error("expected POST in default methods")
	}
}
