package httpclient

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors_Wrapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrProxyConnect", ErrProxyConnect, "httpclient: proxy connection failed"},
		{"ErrDNS", ErrDNS, "httpclient: DNS resolution failed"},
		{"ErrTLS", ErrTLS, "httpclient: TLS handshake failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatalf("%s must not be nil", tt.name)
			}
			if got := tt.err.Error(); got != tt.msg {
				t.Errorf("%s.Error() = %q, want %q", tt.name, got, tt.msg)
			}

			wrapped := fmt.Errorf("request: %w", tt.err)
			if !errors.Is(wrapped, tt.err) {
				t.Errorf("errors.Is must work through wrapping for %s", tt.name)
			}
		})
	}
}

func TestSentinelErrors_Distinct(t *testing.T) {
	sentinels := []error{ErrProxyConnect, ErrDNS, ErrTLS}
	for i := 0; i < len(sentinels); i++ {
		for j := i + 1; j < len(sentinels); j++ {
			if errors.Is(sentinels[i], sentinels[j]) {
				t.Errorf("sentinel %d and %d must be distinct", i, j)
			}
		}
	}
}
