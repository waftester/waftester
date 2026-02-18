package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestIsCloudMetadataHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		// Direct IPv4 metadata endpoints
		{"169.254.169.254", true},
		{"100.100.100.200", true},
		{"metadata.google.internal", true},

		// Cloud provider metadata IPs added in security review
		{"192.0.0.192", true},   // Oracle Cloud IMDS
		{"168.63.129.16", true}, // Azure Wire Server
		{"fd00:ec2::254", true}, // AWS IMDSv2 IPv6

		// Link-local range (169.254.0.0/16) — not just .169.254
		{"169.254.0.1", true},
		{"169.254.1.1", true},
		{"169.254.255.255", true},

		// ULA range (fd00::/8) — covers all fd** addresses
		{"fd00::1", true},
		{"fdff::1", true},
		{"fd12:3456:789a::1", true},

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
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"fc00::1", false}, // fc00::/7 but NOT fd00::/8
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
		{"oracle cloud IMDS", "http://192.0.0.192/opc/v2/", true},
		{"azure wire server", "http://168.63.129.16/metadata/instance", true},
		{"link-local other", "http://169.254.1.1/anything", true},
		{"ula address", "http://[fd12:3456::1]/path", true},
		{"normal target", "https://example.com/", false},
		{"empty URL", "", true},
		{"no scheme", "example.com", true},
		{"ftp scheme", "ftp://example.com", true},
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

func TestParseArgs_RejectsUnknownFields(t *testing.T) {
	t.Parallel()

	type args struct {
		Target string `json:"target"`
	}

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Arguments: json.RawMessage(`{"target":"https://example.com","typo_flag":true}`),
		},
	}

	var got args
	err := parseArgs(req, &got)
	if err == nil {
		t.Fatal("expected parseArgs to reject unknown fields")
	}
}

func TestParseArgs_AllowsKnownFields(t *testing.T) {
	t.Parallel()

	type args struct {
		Target string `json:"target"`
	}

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Arguments: json.RawMessage(`{"target":"https://example.com"}`),
		},
	}

	var got args
	err := parseArgs(req, &got)
	if err != nil {
		t.Fatalf("unexpected parseArgs error: %v", err)
	}
	if got.Target != "https://example.com" {
		t.Fatalf("target mismatch: got %q", got.Target)
	}
}
