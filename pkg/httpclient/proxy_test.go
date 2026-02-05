package httpclient

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseProxyURL(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		wantScheme  string
		wantHost    string
		wantPort    string
		wantIsSOCKS bool
	}{
		{
			name:       "empty URL returns nil",
			input:      "",
			wantErr:    false,
			wantScheme: "",
		},
		{
			name:        "HTTP proxy",
			input:       "http://proxy.example.com:8080",
			wantErr:     false,
			wantScheme:  "http",
			wantHost:    "proxy.example.com",
			wantPort:    "8080",
			wantIsSOCKS: false,
		},
		{
			name:        "HTTPS proxy",
			input:       "https://proxy.example.com:8443",
			wantErr:     false,
			wantScheme:  "https",
			wantHost:    "proxy.example.com",
			wantPort:    "8443",
			wantIsSOCKS: false,
		},
		{
			name:        "SOCKS4 proxy",
			input:       "socks4://proxy.example.com:1080",
			wantErr:     false,
			wantScheme:  "socks4",
			wantHost:    "proxy.example.com",
			wantPort:    "1080",
			wantIsSOCKS: true,
		},
		{
			name:        "SOCKS5 proxy",
			input:       "socks5://proxy.example.com:1080",
			wantErr:     false,
			wantScheme:  "socks5",
			wantHost:    "proxy.example.com",
			wantPort:    "1080",
			wantIsSOCKS: true,
		},
		{
			name:        "SOCKS5h proxy (DNS over proxy)",
			input:       "socks5h://proxy.example.com:1080",
			wantErr:     false,
			wantScheme:  "socks5h",
			wantHost:    "proxy.example.com",
			wantPort:    "1080",
			wantIsSOCKS: true,
		},
		{
			name:        "HTTP proxy with auth",
			input:       "http://user:pass@proxy.example.com:8080",
			wantErr:     false,
			wantScheme:  "http",
			wantHost:    "proxy.example.com",
			wantPort:    "8080",
			wantIsSOCKS: false,
		},
		{
			name:        "Shorthand without scheme defaults to http",
			input:       "proxy.example.com:8080",
			wantErr:     false,
			wantScheme:  "http",
			wantHost:    "proxy.example.com",
			wantPort:    "8080",
			wantIsSOCKS: false,
		},
		{
			name:        "HTTP proxy without port defaults to 8080",
			input:       "http://proxy.example.com",
			wantErr:     false,
			wantScheme:  "http",
			wantHost:    "proxy.example.com",
			wantPort:    "8080",
			wantIsSOCKS: false,
		},
		{
			name:        "SOCKS5 without port defaults to 1080",
			input:       "socks5://proxy.example.com",
			wantErr:     false,
			wantScheme:  "socks5",
			wantHost:    "proxy.example.com",
			wantPort:    "1080",
			wantIsSOCKS: true,
		},
		{
			name:    "Unsupported scheme returns error",
			input:   "ftp://proxy.example.com:21",
			wantErr: true,
		},
		{
			name:    "Invalid URL returns error",
			input:   "://invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := ParseProxyURL(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseProxyURL(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseProxyURL(%q) unexpected error: %v", tt.input, err)
				return
			}

			// Empty input should return nil config
			if tt.input == "" {
				if config != nil {
					t.Errorf("ParseProxyURL(%q) expected nil config, got %+v", tt.input, config)
				}
				return
			}

			if config == nil {
				t.Errorf("ParseProxyURL(%q) got nil config, expected non-nil", tt.input)
				return
			}

			if config.Scheme != tt.wantScheme {
				t.Errorf("ParseProxyURL(%q).Scheme = %q, want %q", tt.input, config.Scheme, tt.wantScheme)
			}
			if config.Host != tt.wantHost {
				t.Errorf("ParseProxyURL(%q).Host = %q, want %q", tt.input, config.Host, tt.wantHost)
			}
			if config.Port != tt.wantPort {
				t.Errorf("ParseProxyURL(%q).Port = %q, want %q", tt.input, config.Port, tt.wantPort)
			}
			if config.IsSOCKS != tt.wantIsSOCKS {
				t.Errorf("ParseProxyURL(%q).IsSOCKS = %v, want %v", tt.input, config.IsSOCKS, tt.wantIsSOCKS)
			}
		})
	}
}

func TestProxyConfigAddress(t *testing.T) {
	config, _ := ParseProxyURL("socks5://proxy.example.com:1080")
	if config.Address() != "proxy.example.com:1080" {
		t.Errorf("Address() = %q, want %q", config.Address(), "proxy.example.com:1080")
	}

	var nilConfig *ProxyConfig
	if nilConfig.Address() != "" {
		t.Errorf("nil Address() = %q, want empty", nilConfig.Address())
	}
}

func TestProxyConfigAuth(t *testing.T) {
	config, _ := ParseProxyURL("http://user:pass@proxy.example.com:8080")
	if config.Username != "user" {
		t.Errorf("Username = %q, want %q", config.Username, "user")
	}
	if config.Password != "pass" {
		t.Errorf("Password = %q, want %q", config.Password, "pass")
	}
}

func TestProxyConfigDNSRemote(t *testing.T) {
	tests := []struct {
		input         string
		wantDNSRemote bool
	}{
		{"socks5://proxy:1080", false},
		{"socks5h://proxy:1080", true},
		{"http://proxy:8080", false},
	}

	for _, tt := range tests {
		config, _ := ParseProxyURL(tt.input)
		if config.IsDNSRemote != tt.wantDNSRemote {
			t.Errorf("ParseProxyURL(%q).IsDNSRemote = %v, want %v", tt.input, config.IsDNSRemote, tt.wantDNSRemote)
		}
	}
}

func TestValidateProxyURL(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"http://proxy:8080", false},
		{"socks5://proxy:1080", false},
		{"ftp://proxy:21", true},
		{"", false}, // Empty is valid (no proxy)
	}

	for _, tt := range tests {
		err := ValidateProxyURL(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateProxyURL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
	}
}

func TestTimeoutDialerContext(t *testing.T) {
	// Create a mock dialer that simulates a slow connection
	slowDialer := &mockSlowDialer{delay: 100 * time.Millisecond}

	// Create a timeout dialer with a shorter timeout than the dialer delay
	td := &TimeoutDialer{
		dialer:  slowDialer,
		timeout: 10 * time.Millisecond,
	}

	ctx := context.Background()
	_, err := td.DialContext(ctx, "tcp", "example.com:80")

	if err == nil {
		t.Error("Expected timeout error from slow dialer")
	}

	// Verify it's a timeout error
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

// mockSlowDialer simulates a slow dialer for testing timeout behavior
type mockSlowDialer struct {
	delay time.Duration
}

func (d *mockSlowDialer) Dial(network, addr string) (net.Conn, error) {
	time.Sleep(d.delay)
	return nil, fmt.Errorf("mock dial completed after %v", d.delay)
}

func TestBurpProxyURL(t *testing.T) {
	if BurpProxyURL != "http://127.0.0.1:8080" {
		t.Errorf("BurpProxyURL = %q, want %q", BurpProxyURL, "http://127.0.0.1:8080")
	}
}

func TestZAPProxyURL(t *testing.T) {
	if ZAPProxyURL != "http://127.0.0.1:8081" {
		t.Errorf("ZAPProxyURL = %q, want %q", ZAPProxyURL, "http://127.0.0.1:8081")
	}
}
