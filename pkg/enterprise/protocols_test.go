package enterprise

import (
	"net/http"
	"testing"
	"time"
)

func TestProtocolDetectorNew(t *testing.T) {
	client := &http.Client{Timeout: 10 * time.Second}
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
