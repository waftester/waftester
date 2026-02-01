package httpclient

import (
	"net/http"
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
