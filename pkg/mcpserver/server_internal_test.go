package mcpserver

import "testing"

func TestIsCloudMetadataHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		// Direct IPv4 metadata endpoints
		{"169.254.169.254", true},
		{"100.100.100.200", true},
		{"metadata.google.internal", true},

		// IPv6-mapped IPv4 bypass attempts
		{"::ffff:169.254.169.254", true},
		{"::ffff:a9fe:a9fe", true},
		{"0:0:0:0:0:ffff:169.254.169.254", true},
		{"::ffff:100.100.100.200", true},

		// Safe hosts
		{"example.com", false},
		{"10.0.0.1", false},
		{"localhost", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := isCloudMetadataHost(tt.host); got != tt.want {
				t.Errorf("isCloudMetadataHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestValidateTargetURL_CloudMetadata(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"direct metadata", "http://169.254.169.254/latest/meta-data/", true},
		{"ipv6-mapped metadata", "http://[::ffff:169.254.169.254]/latest/meta-data/", true},
		{"google metadata", "http://metadata.google.internal/computeMetadata/v1/", true},
		{"alibaba metadata", "http://100.100.100.200/latest/meta-data/", true},
		{"normal target", "https://example.com/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTargetURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTargetURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestIsLocalhostOrigin(t *testing.T) {
	tests := []struct {
		origin string
		want   bool
	}{
		{"http://localhost:3000", true},
		{"http://127.0.0.1:8080", true},
		{"http://[::1]:5173", true},
		{"https://localhost", true},
		{"https://evil.example.com", false},
		{"http://localhost.evil.com:3000", false},
		{"", false},
		{"not-a-url", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			if got := isLocalhostOrigin(tt.origin); got != tt.want {
				t.Errorf("isLocalhostOrigin(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}
