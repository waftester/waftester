package httpclient

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDefaultClient_ReturnsHTTPClient(t *testing.T) {
	client := Default()
	if client == nil {
		t.Fatal("Default() returned nil")
	}
	if _, ok := interface{}(client).(*http.Client); !ok {
		t.Fatal("Default() did not return *http.Client")
	}
}

func TestDefaultClient_IsSingleton(t *testing.T) {
	c1 := Default()
	c2 := Default()
	if c1 != c2 {
		t.Error("Default() should return same instance")
	}
}

func TestNewClient_WithDefaultConfig(t *testing.T) {
	client := New(DefaultConfig())
	if client == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNewClient_RespectsTimeout(t *testing.T) {
	client := New(Config{Timeout: 5 * time.Second})
	if client == nil {
		t.Fatal("New() returned nil")
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", client.Timeout)
	}
}

func TestNewClient_RespectsInsecureSkipVerify(t *testing.T) {
	client := New(Config{InsecureSkipVerify: true})
	if client == nil {
		t.Fatal("New() returned nil")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify not set to true")
	}
}

func TestNewClient_DoesNotFollowRedirects(t *testing.T) {
	client := New(DefaultConfig())
	// Create a request - we can't test redirect behavior without a server,
	// but we can verify the CheckRedirect function is set
	if client.CheckRedirect == nil {
		t.Error("CheckRedirect function not set")
	}
}

func TestNewClient_ZeroConfigUsesDefaults(t *testing.T) {
	// Zero config should still produce a working client with sensible defaults
	client := New(Config{})
	if client == nil {
		t.Fatal("New(Config{}) returned nil")
	}
	if client.Timeout == 0 {
		t.Error("Expected non-zero default timeout")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if transport.MaxIdleConns == 0 {
		t.Error("Expected non-zero MaxIdleConns")
	}
}

func TestNewClient_WithProxy(t *testing.T) {
	client := New(Config{
		Proxy: "http://localhost:8080",
	})
	if client == nil {
		t.Fatal("New() with proxy returned nil")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}
	if transport.Proxy == nil {
		t.Error("Proxy function not set")
	}
}

func TestNewClient_InvalidProxyIgnored(t *testing.T) {
	// Invalid proxy URL should not crash, just be ignored
	client := New(Config{
		Proxy: "not-a-valid-url-://bad",
	})
	if client == nil {
		t.Fatal("New() with invalid proxy returned nil")
	}
	// Should still work
}

func TestDefaultConfig_HasSensibleDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 30*time.Second {
		t.Errorf("Expected 30s timeout, got %v", cfg.Timeout)
	}
	if cfg.MaxIdleConns < 50 {
		t.Errorf("Expected MaxIdleConns >= 50, got %d", cfg.MaxIdleConns)
	}
	if cfg.MaxConnsPerHost < 10 {
		t.Errorf("Expected MaxConnsPerHost >= 10, got %d", cfg.MaxConnsPerHost)
	}
	if cfg.IdleConnTimeout < 30*time.Second {
		t.Errorf("Expected IdleConnTimeout >= 30s, got %v", cfg.IdleConnTimeout)
	}
}

func TestNewClient_ConcurrentAccess(t *testing.T) {
	// Verify thread safety of Default()
	done := make(chan *http.Client, 100)
	for i := 0; i < 100; i++ {
		go func() {
			done <- Default()
		}()
	}

	var first *http.Client
	for i := 0; i < 100; i++ {
		c := <-done
		if first == nil {
			first = c
		} else if c != first {
			t.Error("Default() returned different instances concurrently")
		}
	}
}

// Benchmarks

func BenchmarkDefault(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Default()
	}
}

func BenchmarkNew(b *testing.B) {
	cfg := DefaultConfig()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = New(cfg)
	}
}

func BenchmarkDefaultConfig(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = DefaultConfig()
	}
}

// ============================================================================
// TRANSPORT WRAPPER TESTS
// ============================================================================

func TestRegisterTransportWrapper(t *testing.T) {
	// Save original state
	wrapperMu.Lock()
	origWrapper := transportWrapper
	wrapperMu.Unlock()

	// Clean up after test
	defer func() {
		wrapperMu.Lock()
		transportWrapper = origWrapper
		wrapperMu.Unlock()
	}()

	// Test registering a wrapper
	called := false
	testWrapper := func(rt http.RoundTripper) http.RoundTripper {
		called = true
		return rt
	}

	RegisterTransportWrapper(testWrapper)

	// Create a new client - wrapper should be applied
	client := New(DefaultConfig())
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	// The wrapper was called during New()
	if !called {
		t.Error("expected wrapper to be called during New()")
	}
}

func TestTransportWrapperNil(t *testing.T) {
	// Save original state
	wrapperMu.Lock()
	origWrapper := transportWrapper
	wrapperMu.Unlock()

	// Set wrapper to nil
	wrapperMu.Lock()
	transportWrapper = nil
	wrapperMu.Unlock()

	// Clean up after test
	defer func() {
		wrapperMu.Lock()
		transportWrapper = origWrapper
		wrapperMu.Unlock()
	}()

	// Should still work without wrapper
	client := New(DefaultConfig())
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

// ============================================================================
// ENFORCEMENT TESTS - Detect raw http.Client creation
// ============================================================================

// TestNoRawHTTPClient ensures code uses httpclient.New() instead of &http.Client{}
func TestNoRawHTTPClient(t *testing.T) {
	violations := findRawHTTPClients(t)

	if len(violations) > 0 {
		t.Errorf("Found %d raw &http.Client{} literals. Use httpclient.New() or httpclient.Default() instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

func findRawHTTPClients(t *testing.T) []string {
	t.Helper()

	var violations []string
	root := findProjectRoot(t)

	// Files that legitimately need custom http.Client configuration
	excludePatterns := []string{
		"httpclient.go", // The factory itself
		"_test.go",      // All tests can create clients for testing
		"ja3.go",        // JA3 fingerprinting needs custom transport
		"transport.go",  // detection/transport.go wraps existing transports
	}

	for _, dir := range []string{"pkg", "cmd"} {
		dirPath := filepath.Join(root, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}

			for _, pattern := range excludePatterns {
				if strings.Contains(path, pattern) {
					return nil
				}
			}

			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil
			}

			ast.Inspect(node, func(n ast.Node) bool {
				// Look for &http.Client{} or http.Client{}
				if unary, ok := n.(*ast.UnaryExpr); ok {
					if comp, ok := unary.X.(*ast.CompositeLit); ok {
						if isHTTPClientType(comp.Type) {
							pos := fset.Position(comp.Pos())
							relPath, _ := filepath.Rel(root, pos.Filename)
							violations = append(violations,
								relPath+":"+strconv.Itoa(pos.Line)+": &http.Client{}")
						}
					}
				}
				return true
			})

			return nil
		})
	}

	return violations
}

func isHTTPClientType(expr ast.Expr) bool {
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok {
			return ident.Name == "http" && sel.Sel.Name == "Client"
		}
	}
	return false
}

// TestNoRawHTTPTransport ensures code uses httpclient.New() instead of raw &http.Transport{}.
// Raw transports bypass centralized middleware (UA rotation, retries, auth headers)
// and detection wrapping.
func TestNoRawHTTPTransport(t *testing.T) {
	violations := findRawHTTPTransports(t)

	if len(violations) > 0 {
		t.Errorf("Found %d raw &http.Transport{} literals. Use httpclient.New() instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

func findRawHTTPTransports(t *testing.T) []string {
	t.Helper()

	var violations []string
	root := findProjectRoot(t)

	// Files that legitimately need custom http.Transport
	excludePatterns := []string{
		"httpclient.go", // The factory itself builds transports
		"_test.go",      // Tests can create transports for testing
		"ja3.go",        // JA3 fingerprinting needs custom transport config
		"transport.go",  // detection/transport.go wraps transports
	}

	for _, dir := range []string{"pkg", "cmd"} {
		dirPath := filepath.Join(root, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}

			for _, pattern := range excludePatterns {
				if strings.Contains(path, pattern) {
					return nil
				}
			}

			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil
			}

			ast.Inspect(node, func(n ast.Node) bool {
				if unary, ok := n.(*ast.UnaryExpr); ok {
					if comp, ok := unary.X.(*ast.CompositeLit); ok {
						if isHTTPTransportType(comp.Type) {
							pos := fset.Position(comp.Pos())
							relPath, _ := filepath.Rel(root, pos.Filename)
							violations = append(violations,
								relPath+":"+strconv.Itoa(pos.Line)+": &http.Transport{}")
						}
					}
				}
				return true
			})

			return nil
		})
	}

	return violations
}

func isHTTPTransportType(expr ast.Expr) bool {
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok {
			return ident.Name == "http" && sel.Sel.Name == "Transport"
		}
	}
	return false
}

func findProjectRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("Could not find project root (go.mod)")
		}
		dir = parent
	}
}
