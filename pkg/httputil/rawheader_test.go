package httputil

import (
	"context"
	"net/http"
	"testing"
)

func TestSetPayloadCookie_PreservesSpecialChars(t *testing.T) {
	tests := []struct {
		name     string
		cookie   string
		value    string
		contains string // substring that must appear in Cookie header
	}{
		{"double quote", "test", `<script>"alert(1)</script>`, `"`},
		{"semicolon", "test", "val;ue", ";"},
		{"backslash", "test", `val\ue`, `\`},
		{"carriage return", "test", "val\rue", "\r"},
		{"null byte", "test", "val\x00ue", "\x00"},
		{"crlf injection", "test", "val\r\nX-Injected: true", "\r\n"},
		{"sql injection", "sid", "' OR 1=1--", "'"},
		{"xss payload", "data", "<img src=x onerror=alert(1)>", "<img"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
			SetPayloadCookie(req, tt.cookie, tt.value)
			got := req.Header.Get("Cookie")
			if got == "" {
				t.Fatal("Cookie header is empty")
			}
			// Verify the special characters are preserved
			expected := tt.cookie + "=" + tt.value
			if got != expected {
				t.Errorf("Cookie header = %q, want %q", got, expected)
			}
		})
	}
}

func TestSetPayloadCookie_AppendsToExisting(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)

	// Add a legitimate cookie first
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

	// Add a payload cookie
	SetPayloadCookie(req, "attack", "<script>alert(1)</script>")

	got := req.Header.Get("Cookie")
	if got != "session=abc123; attack=<script>alert(1)</script>" {
		t.Errorf("Cookie header = %q, want both cookies present", got)
	}
}

func TestSetPayloadCookie_GoAddCookieStripsChars(t *testing.T) {
	// This test documents the Go stdlib behavior we're working around.
	// If this test starts failing, Go changed its cookie sanitization
	// and SetPayloadCookie may need updating.
	specialChars := []struct {
		name  string
		value string
	}{
		{"double quote", `val"ue`},
		{"backslash", `val\ue`},
		{"semicolon", "val;ue"},
	}

	for _, tt := range specialChars {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
			req.AddCookie(&http.Cookie{Name: "test", Value: tt.value})
			got := req.Header.Get("Cookie")
			// Go's AddCookie should strip or modify the value
			if got == "test="+tt.value {
				t.Errorf("Go's AddCookie did NOT sanitize %q — check if Go changed behavior", tt.value)
			}
		})
	}
}

func TestSetPayloadHeader_PreservesCRLF(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		value  string
		expect string
	}{
		{"crlf injection", "X-Custom", "value\r\nInjected: true", "value\r\nInjected: true"},
		{"carriage return", "X-Test", "val\rue", "val\rue"},
		{"newline only", "X-Test", "val\nue", "val\nue"},
		{"normal value", "X-Test", "normalvalue", "normalvalue"},
		{"xss in header", "X-Custom", "<script>alert(1)</script>", "<script>alert(1)</script>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
			SetPayloadHeader(req, tt.key, tt.value)
			got := req.Header.Get(tt.key)
			if got != tt.expect {
				t.Errorf("Header[%s] = %q, want %q", tt.key, got, tt.expect)
			}
		})
	}
}

func TestSetPayloadHeader_CanonicalKey(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	SetPayloadHeader(req, "x-forwarded-for", "127.0.0.1\r\nX-Injected: true")

	// Should be accessible via canonical key
	got := req.Header.Get("X-Forwarded-For")
	if got != "127.0.0.1\r\nX-Injected: true" {
		t.Errorf("Header value = %q, want CRLF preserved", got)
	}
}
