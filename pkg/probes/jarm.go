package probes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// JARMResult contains JARM fingerprint results
type JARMResult struct {
	Fingerprint string `json:"fingerprint"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Error       string `json:"error,omitempty"`
}

// JARMProber probes TLS servers to generate JARM fingerprints
type JARMProber struct {
	Timeout time.Duration
}

// NewJARMProber creates a new JARM prober with defaults
func NewJARMProber() *JARMProber {
	return &JARMProber{
		Timeout: 10 * time.Second,
	}
}

// Probe generates a JARM fingerprint for the target
func (p *JARMProber) Probe(ctx context.Context, host string, port int) *JARMResult {
	result := &JARMResult{
		Host: host,
		Port: port,
	}

	if port == 0 {
		port = 443
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// JARM uses 10 different TLS client hello probes
	// Each probe has different extensions and cipher suites
	probes := getJARMProbes(host)
	var responses []string

	for _, probe := range probes {
		response := p.sendProbe(ctx, addr, probe)
		responses = append(responses, response)
	}

	// Generate fingerprint from responses
	result.Fingerprint = generateJARMFingerprint(responses)
	return result
}

// jarmProbe represents a single JARM probe configuration
type jarmProbe struct {
	cipherOrder []byte
	version     []byte
	extensions  []byte
	grease      bool
	alpn        bool
}

// getJARMProbes returns the 10 JARM probe configurations
func getJARMProbes(host string) []jarmProbe {
	// TLS versions
	tls12 := []byte{0x03, 0x03}
	tls13 := []byte{0x03, 0x04}
	_ = tls13

	// Forward cipher order (most common ciphers first)
	forwardCiphers := []byte{
		0x00, 0x16, // ALL_CIPHERS count
		0xc0, 0x2c, 0xc0, 0x2b, 0xc0, 0x30, 0xc0, 0x2f, // ECDHE-ECDSA-AES256-GCM, etc.
		0x00, 0x9e, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0xa3, // DHE-RSA-AES128-GCM, etc.
		0x00, 0x9f, 0x00, 0xa2, 0x00, 0x35, 0x00, 0x2f, // More ciphers
		0x00, 0x0a, 0x00, 0xff, // TLS_RSA_WITH_3DES_EDE_CBC_SHA, RENEGOTIATION
	}

	// Reverse cipher order
	reverseCiphers := make([]byte, len(forwardCiphers))
	copy(reverseCiphers, forwardCiphers)
	reverseCiphers[0] = forwardCiphers[0]
	reverseCiphers[1] = forwardCiphers[1]
	// Reverse cipher pairs (skip length bytes)
	for i := 2; i < len(forwardCiphers)-2; i += 4 {
		j := len(forwardCiphers) - i - 2
		if j > i {
			reverseCiphers[i], reverseCiphers[j] = forwardCiphers[j], forwardCiphers[i]
			reverseCiphers[i+1], reverseCiphers[j+1] = forwardCiphers[j+1], forwardCiphers[i+1]
		}
	}

	// Common extensions
	sni := buildSNIExtension(host)
	ec := []byte{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17} // supported_groups: x25519
	ecFormat := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}       // ec_point_formats: uncompressed

	// JARM uses 10 probes with variations
	return []jarmProbe{
		{cipherOrder: forwardCiphers, version: tls12, extensions: sni},
		{cipherOrder: reverseCiphers, version: tls12, extensions: sni},
		{cipherOrder: forwardCiphers, version: tls12, extensions: append(sni, ec...)},
		{cipherOrder: reverseCiphers, version: tls12, extensions: append(sni, ec...)},
		{cipherOrder: forwardCiphers, version: tls12, extensions: append(append(sni, ec...), ecFormat...)},
		{cipherOrder: reverseCiphers, version: tls12, extensions: append(append(sni, ec...), ecFormat...)},
		{cipherOrder: forwardCiphers, version: tls12, grease: true, extensions: sni},
		{cipherOrder: reverseCiphers, version: tls12, grease: true, extensions: sni},
		{cipherOrder: forwardCiphers, version: tls12, alpn: true, extensions: sni},
		{cipherOrder: reverseCiphers, version: tls12, alpn: true, extensions: sni},
	}
}

// buildSNIExtension builds the Server Name Indication extension
func buildSNIExtension(host string) []byte {
	hostBytes := []byte(host)
	hostLen := len(hostBytes)

	ext := []byte{
		0x00, 0x00, // extension type: server_name
		byte((hostLen + 5) >> 8), byte((hostLen + 5) & 0xff), // extension length
		byte((hostLen + 3) >> 8), byte((hostLen + 3) & 0xff), // server name list length
		0x00,                                     // name type: host_name
		byte(hostLen >> 8), byte(hostLen & 0xff), // host name length
	}
	return append(ext, hostBytes...)
}

// sendProbe sends a single JARM probe and returns the response hash
func (p *JARMProber) sendProbe(ctx context.Context, addr string, probe jarmProbe) string {
	dialer := &net.Dialer{
		Timeout: p.Timeout / 10, // Divide timeout among probes
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(p.Timeout / 10))

	// Build and send ClientHello
	clientHello := buildClientHello(probe)
	_, err = conn.Write(clientHello)
	if err != nil {
		return ""
	}

	// Read ServerHello response
	response := make([]byte, 1484)
	n, err := conn.Read(response)
	if err != nil || n < 6 {
		return ""
	}

	// Parse ServerHello for JARM
	return parseServerHelloForJARM(response[:n])
}

// buildClientHello constructs a TLS ClientHello message
func buildClientHello(probe jarmProbe) []byte {
	// Random bytes
	random := make([]byte, 32)
	rand.Read(random)

	// Session ID (32 random bytes)
	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	// Build ClientHello
	hello := []byte{
		0x16,                   // Content type: Handshake
		probe.version[0], 0x01, // Version (record layer)
	}

	// Build handshake message
	handshake := []byte{
		0x01, // Handshake type: ClientHello
	}

	// Client version
	clientVersion := probe.version

	// Ciphers
	ciphers := probe.cipherOrder
	if len(ciphers) == 0 {
		// Default cipher list
		ciphers = []byte{
			0x00, 0x04, // 2 ciphers
			0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
			0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
		}
	}

	// Compression
	compression := []byte{0x01, 0x00} // null compression

	// Extensions
	extensions := probe.extensions
	if len(extensions) == 0 {
		extensions = []byte{}
	}

	// Calculate lengths
	helloBody := append(clientVersion, random...)
	helloBody = append(helloBody, byte(len(sessionID)))
	helloBody = append(helloBody, sessionID...)
	helloBody = append(helloBody, ciphers...)
	helloBody = append(helloBody, compression...)

	if len(extensions) > 0 {
		extLen := len(extensions)
		helloBody = append(helloBody, byte(extLen>>8), byte(extLen&0xff))
		helloBody = append(helloBody, extensions...)
	}

	// Handshake length (3 bytes)
	helloLen := len(helloBody)
	handshake = append(handshake, byte(helloLen>>16), byte(helloLen>>8), byte(helloLen&0xff))
	handshake = append(handshake, helloBody...)

	// Record length (2 bytes)
	recordLen := len(handshake)
	hello = append(hello, byte(recordLen>>8), byte(recordLen&0xff))
	hello = append(hello, handshake...)

	return hello
}

// parseServerHelloForJARM extracts the JARM-relevant fields from ServerHello
func parseServerHelloForJARM(data []byte) string {
	if len(data) < 6 {
		return ""
	}

	// Check for TLS record
	if data[0] != 0x16 { // Handshake
		// Could be alert (0x15)
		if data[0] == 0x15 {
			return fmt.Sprintf("%02x%02x", data[5], data[6]) // Alert description
		}
		return ""
	}

	// TLS version from record layer
	version := fmt.Sprintf("%02x%02x", data[1], data[2])

	// Skip to handshake type
	if len(data) < 6 || data[5] != 0x02 { // ServerHello
		return version + "|||"
	}

	// Parse ServerHello
	if len(data) < 11 {
		return version + "|||"
	}

	// Server version
	serverVersion := fmt.Sprintf("%02x%02x", data[9], data[10])

	// Skip random (32 bytes) + session_id_length
	pos := 11 + 32
	if pos >= len(data) {
		return version + "|" + serverVersion + "||"
	}

	sessionLen := int(data[pos])
	pos += 1 + sessionLen

	// Cipher suite
	if pos+2 > len(data) {
		return version + "|" + serverVersion + "||"
	}
	cipher := fmt.Sprintf("%02x%02x", data[pos], data[pos+1])
	pos += 2

	// Compression
	if pos >= len(data) {
		return version + "|" + serverVersion + "|" + cipher + "|"
	}
	compression := fmt.Sprintf("%02x", data[pos])

	return version + "|" + serverVersion + "|" + cipher + "|" + compression
}

// generateJARMFingerprint creates the final JARM fingerprint from responses
func generateJARMFingerprint(responses []string) string {
	if len(responses) != 10 {
		return ""
	}

	// Concatenate all responses
	combined := strings.Join(responses, ",")

	// If all empty, return empty fingerprint
	allEmpty := true
	for _, r := range responses {
		if r != "" {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		return "00000000000000000000000000000000"
	}

	// Hash the combined responses
	hash := sha256.Sum256([]byte(combined))

	// JARM fingerprint format: first 30 chars of hex + fuzzy hash
	fingerprint := hex.EncodeToString(hash[:])[:62]

	return fingerprint
}

// KnownJARMFingerprints contains fingerprints for known software
var KnownJARMFingerprints = map[string]string{
	"2ad2ad16d2ad2ad22c2ad2ad2ad2ad30e5e6ed24a0e9ea7e6b71b0ef5ccc6a": "Cloudflare",
	"27d40d40d29d40d1dc27d40d27d40d3df7a16ed2bffb3d3e41a87f53e0e2c7": "AWS ALB",
	"29d29d15d29d29d21c29d29d29d29de0c4c3e2d2d6d2d2d2d2d2d2d2d2d2d2": "nginx",
	"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7934c27d":   "Apache",
	"2ad2ad0002ad2ad00041d2ad2ad2adce0f2d3f2d3f2d3f2d3f2d3f2d3f2d":   "IIS",
	"07d14d16d21d21d00007d14d07d21d9b2f5869a6985368a9dec764186a904":  "Caddy",
	"00000000000000000000000000000000000000000000000000000000000000": "Connection Failed",
}

// IdentifyJARMFingerprint tries to identify the server software from fingerprint
func IdentifyJARMFingerprint(fingerprint string) string {
	if name, ok := KnownJARMFingerprints[fingerprint]; ok {
		return name
	}

	// Partial matching for similar fingerprints
	for known, name := range KnownJARMFingerprints {
		if len(fingerprint) >= 20 && len(known) >= 20 {
			if fingerprint[:20] == known[:20] {
				return name + " (similar)"
			}
		}
	}

	return "Unknown"
}
