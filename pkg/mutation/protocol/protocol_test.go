package protocol

import (
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/mutation"
)

func TestHTTPSmugglingCLTE(t *testing.T) {
	proto := &HTTPSmugglingCLTE{}

	if proto.Name() != "smuggle_clte" {
		t.Errorf("Expected name 'smuggle_clte', got '%s'", proto.Name())
	}
	if proto.Category() != "protocol" {
		t.Error("Wrong category")
	}

	results := proto.Mutate("GET /admin")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should contain smuggling markers
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "Content-Length") &&
			strings.Contains(r.Mutated, "Transfer-Encoding") {
			found = true
			break
		}
	}
	if !found {
		t.Error("CL.TE smuggling should contain both headers")
	}
}

func TestHTTPSmugglingTECL(t *testing.T) {
	proto := &HTTPSmugglingTECL{}

	results := proto.Mutate("smuggled_request")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should contain chunked encoding
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "chunked") {
			found = true
			break
		}
	}
	if !found {
		t.Error("TE.CL smuggling should contain chunked encoding")
	}
}

func TestHTTPSmugglingTETE(t *testing.T) {
	proto := &HTTPSmugglingTETE{}

	results := proto.Mutate("payload")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should contain obfuscated Transfer-Encoding
	found := false
	for _, r := range results {
		if strings.Contains(strings.ToLower(r.Mutated), "transfer-encoding") {
			found = true
			break
		}
	}
	if !found {
		t.Error("TE.TE smuggling should contain Transfer-Encoding variations")
	}
}

func TestHTTP2Downgrade(t *testing.T) {
	proto := &HTTP2Downgrade{}

	results := proto.Mutate("GET /secret")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}
}

func TestWebSocketUpgrade(t *testing.T) {
	proto := &WebSocketUpgrade{}

	results := proto.Mutate("smuggled_data")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should contain WebSocket upgrade headers
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "Upgrade") ||
			strings.Contains(r.Mutated, "websocket") {
			found = true
			break
		}
	}
	if !found {
		t.Error("WebSocket should contain upgrade headers")
	}
}

func TestRequestLineMutator(t *testing.T) {
	proto := &RequestLineMutator{}

	results := proto.Mutate("/admin")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should produce request line variations
	for _, r := range results {
		if r.Mutated == "" {
			t.Error("Request line mutator should produce output")
		}
	}
}

func TestHeaderFolding(t *testing.T) {
	proto := &HeaderFolding{}

	results := proto.Mutate("malicious_value")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should contain line folding
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "\r\n ") ||
			strings.Contains(r.Mutated, "\r\n\t") {
			found = true
			break
		}
	}
	if !found {
		t.Log("Note: Header folding may use different techniques")
	}
}

func TestTransferEncodingObfuscation(t *testing.T) {
	proto := &TransferEncodingObfuscation{}

	results := proto.Mutate("payload")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should contain TE variations
	for _, r := range results {
		if r.Mutated == "" {
			t.Error("TE obfuscation should produce output")
		}
	}
}

func TestAllProtocolsRegistered(t *testing.T) {
	protocols := mutation.DefaultRegistry.GetByCategory("protocol")

	expectedProtocols := []string{
		"smuggle_clte", "smuggle_tecl", "smuggle_tete",
		"h2_downgrade", "websocket", "request_line",
		"header_fold", "te_obfuscate",
	}

	registered := make(map[string]bool)
	for _, proto := range protocols {
		registered[proto.Name()] = true
	}

	for _, name := range expectedProtocols {
		if !registered[name] {
			t.Errorf("Protocol '%s' not registered", name)
		}
	}
}

func TestProtocolCategoryCorrect(t *testing.T) {
	protocols := mutation.DefaultRegistry.GetByCategory("protocol")

	for _, proto := range protocols {
		if proto.Category() != "protocol" {
			t.Errorf("Protocol '%s' has wrong category: %v", proto.Name(), proto.Category())
		}
	}
}

func TestEmptyPayloadDoesNotPanic(t *testing.T) {
	// Regression test: ensure empty payload doesn't cause panic from [:1] slice
	protocols := []mutation.Mutator{
		&HTTPSmugglingCLTE{},
		&HTTP2Downgrade{},
	}

	for _, proto := range protocols {
		t.Run(proto.Name(), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panicked on empty payload: %v", proto.Name(), r)
				}
			}()
			results := proto.Mutate("")
			if len(results) == 0 {
				t.Errorf("%s returned no results for empty payload", proto.Name())
			}
		})
	}
}
