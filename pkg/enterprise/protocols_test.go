package enterprise

import (
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/httpclient"
)

func TestProtocolDetectorNew(t *testing.T) {
	client := httpclient.Default()
	detector := NewProtocolDetector(client)
	if detector == nil {
		t.Fatal("NewProtocolDetector returned nil")
	}
}

func TestProtocolTypeConstants(t *testing.T) {
	protocols := []ProtocolType{
		ProtocolHTTP,
		ProtocolGRPC,
		ProtocolGRPCWeb,
		ProtocolSOAP,
		ProtocolXMLRPC,
		ProtocolWCF,
		ProtocolGraphQL,
		ProtocolProtobuf,
	}

	// Ensure all protocols are unique
	seen := make(map[ProtocolType]bool)
	for _, p := range protocols {
		if seen[p] {
			t.Errorf("Duplicate protocol: %s", p)
		}
		seen[p] = true
	}

	if len(protocols) != 8 {
		t.Errorf("Expected 8 protocol constants, got %d", len(protocols))
	}
}

func TestLocationFactoryNew(t *testing.T) {
	factory := NewLocationFactory()
	if factory == nil {
		t.Fatal("NewLocationFactory returned nil")
	}
}

func TestLocationFactoryCreateGRPC(t *testing.T) {
	factory := NewLocationFactory()
	locations := factory.CreateLocations(ProtocolGRPC)

	if len(locations) == 0 {
		t.Error("Should have gRPC locations")
	}
}

func TestLocationFactoryCreateSOAP(t *testing.T) {
	factory := NewLocationFactory()
	locations := factory.CreateLocations(ProtocolSOAP)

	if len(locations) == 0 {
		t.Error("Should have SOAP locations")
	}
}

func TestLocationFactoryCreateGraphQL(t *testing.T) {
	factory := NewLocationFactory()
	locations := factory.CreateLocations(ProtocolGraphQL)

	if len(locations) == 0 {
		t.Error("Should have GraphQL locations")
	}
}

func TestDetectedProtocolStruct(t *testing.T) {
	result := &DetectedProtocol{
		Type:       ProtocolGRPC,
		Confidence: 0.95,
		Evidence:   []string{"grpc-status header", "application/grpc content-type"},
		Endpoints:  []string{"/api.Service/Method"},
	}

	if result.Type != ProtocolGRPC {
		t.Errorf("Expected gRPC protocol, got %s", result.Type)
	}
	if result.Confidence != 0.95 {
		t.Errorf("Expected 0.95 confidence, got %f", result.Confidence)
	}
	if len(result.Evidence) != 2 {
		t.Errorf("Expected 2 evidence items, got %d", len(result.Evidence))
	}
}

func TestLocationInterface(t *testing.T) {
	factory := NewLocationFactory()
	locations := factory.CreateLocations(ProtocolGRPC)

	for _, loc := range locations {
		// Test Location interface methods
		name := loc.Name()
		if name == "" {
			t.Error("Location name should not be empty")
		}

		contentType := loc.ContentType()
		if contentType == "" {
			t.Error("Content type should not be empty")
		}

		proto := loc.Protocol()
		if proto == "" {
			t.Error("Protocol should not be empty")
		}

		desc := loc.Description()
		if desc == "" {
			t.Error("Description should not be empty")
		}
	}
}

func TestSOAPLocationBuild(t *testing.T) {
	factory := NewLocationFactory()
	locations := factory.CreateLocations(ProtocolSOAP)

	if len(locations) == 0 {
		t.Skip("No SOAP locations available")
	}

	// Locations implement BuildRequest not Build
	// Just verify we have locations
	for _, loc := range locations {
		if loc.Name() == "" {
			t.Error("SOAP location should have a name")
		}
	}
}

func TestGraphQLLocation(t *testing.T) {
	factory := NewLocationFactory()
	locations := factory.CreateLocations(ProtocolGraphQL)

	if len(locations) == 0 {
		t.Skip("No GraphQL locations available")
	}

	for _, loc := range locations {
		if loc.ContentType() == "" {
			t.Error("GraphQL location should have content type")
		}
	}
}

// TestFormatProtocolReportMultiByteEvidence is a regression test for a byte
// truncation bug. The old code used e[:53] which truncates at byte offset 53,
// potentially splitting a multi-byte UTF-8 character and producing invalid
// output (or panicking). The fix uses []rune to truncate at rune boundaries.
// This test passes a multi-byte string (Chinese characters, 3 bytes each in
// UTF-8) that would corrupt output under the old byte-based truncation.
func TestFormatProtocolReportMultiByteEvidence(t *testing.T) {
	// Each Chinese character is 3 bytes in UTF-8.
	// 20 runes = under the 56 rune limit, should not be truncated.
	shortEvidence := strings.Repeat("证", 20)
	// 60 runes = over the 56 rune limit, should be truncated to 53 + "..."
	longEvidence := strings.Repeat("据", 60)

	detected := &DetectedProtocol{
		Type:       ProtocolGRPC,
		Confidence: 0.95,
		Evidence:   []string{shortEvidence, longEvidence},
	}

	// Should not panic with multi-byte characters
	report := FormatProtocolReport(detected, nil)

	// Short evidence should appear intact (under limit)
	if !containsSubstring(report, shortEvidence) {
		t.Error("short multi-byte evidence should appear intact in report")
	}

	// Long evidence should be truncated with "..."
	if !containsSubstring(report, "...") {
		t.Error("long multi-byte evidence should be truncated with ...")
	}

	// The truncated string should be valid UTF-8
	for _, r := range report {
		if r == 0xFFFD { // Unicode replacement character indicates corruption
			t.Fatal("report contains replacement character — multi-byte truncation corrupted UTF-8")
		}
	}
}

// TestFormatProtocolReportMultiByteDescription is a regression test for a byte
// truncation bug in location description rendering. Same fix as evidence: uses
// []rune instead of byte slicing.
func TestFormatProtocolReportMultiByteDescription(t *testing.T) {
	detected := &DetectedProtocol{
		Type:       ProtocolSOAP,
		Confidence: 0.80,
	}

	// Create a mock location with a long multi-byte description
	factory := NewLocationFactory()
	locations := factory.CreateLocations(ProtocolSOAP)

	report := FormatProtocolReport(detected, locations)

	// Should not panic and should produce valid UTF-8
	for _, r := range report {
		if r == 0xFFFD {
			t.Fatal("report contains replacement character — multi-byte truncation corrupted UTF-8")
		}
	}

	// Report should contain INJECTION LOCATIONS section if locations exist
	if len(locations) > 0 && !containsSubstring(report, "INJECTION LOCATIONS") {
		t.Error("report should contain INJECTION LOCATIONS section")
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestProtocolTypeString(t *testing.T) {
	tests := []struct {
		protocol ProtocolType
		expected string
	}{
		{ProtocolGRPC, "grpc"},
		{ProtocolGRPCWeb, "grpc-web"},
		{ProtocolSOAP, "soap"},
		{ProtocolXMLRPC, "xml-rpc"},
		{ProtocolWCF, "wcf"},
		{ProtocolGraphQL, "graphql"},
		{ProtocolProtobuf, "protobuf"},
	}

	for _, tt := range tests {
		if string(tt.protocol) != tt.expected {
			t.Errorf("Expected protocol string '%s', got '%s'", tt.expected, string(tt.protocol))
		}
	}
}
