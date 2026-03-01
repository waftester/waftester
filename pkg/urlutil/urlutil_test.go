package urlutil

import "testing"

func TestStripScheme(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"https", "https://example.com/path", "example.com/path"},
		{"http", "http://example.com/path", "example.com/path"},
		{"no scheme", "example.com/path", "example.com/path"},
		{"empty", "", ""},
		{"double scheme", "https://http://evil.com", "evil.com"},
		{"ftp untouched", "ftp://example.com", "ftp://example.com"},
		{"scheme only", "https://", ""},
		{"with port", "https://example.com:8443/api", "example.com:8443/api"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripScheme(tt.input)
			if got != tt.want {
				t.Errorf("StripScheme(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct {
		name string
		base string
		path string
		want string
	}{
		{"basic", "https://example.com", "/api/v1", "https://example.com/api/v1"},
		{"trailing slash on base", "https://example.com/", "/api/v1", "https://example.com/api/v1"},
		{"no leading slash on path", "https://example.com", "api/v1", "https://example.com/api/v1"},
		{"both slashes", "https://example.com/", "api/v1", "https://example.com/api/v1"},
		{"empty path", "https://example.com", "", "https://example.com"},
		{"empty base", "", "/api", "/api"},
		{"root path", "https://example.com", "/", "https://example.com/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := JoinPath(tt.base, tt.path)
			if got != tt.want {
				t.Errorf("JoinPath(%q, %q) = %q, want %q", tt.base, tt.path, got, tt.want)
			}
		})
	}
}
