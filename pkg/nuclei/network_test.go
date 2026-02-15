package nuclei

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkRequest_TCPBanner(t *testing.T) {
	// Start a TCP server that sends a banner
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	}()

	engine := NewEngine()
	req := &NetworkRequest{
		ID:   "ssh-banner",
		Host: listener.Addr().String(),
		Type: "tcp",
		Matchers: []Matcher{
			{Type: "word", Words: []string{"SSH-2.0"}},
		},
	}

	vars := map[string]string{}
	matched, _, err := engine.executeNetworkRequest(context.Background(), req, vars)
	require.NoError(t, err)
	assert.True(t, matched, "should match SSH banner")
}

func TestNetworkRequest_TCPSendReceive(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		// Echo back what was received
		conn.Write([]byte(fmt.Sprintf("ECHO: %s", buf[:n])))
	}()

	engine := NewEngine()
	req := &NetworkRequest{
		ID:   "echo",
		Host: listener.Addr().String(),
		Type: "tcp",
		Inputs: []NetworkInput{
			{Data: "HELLO\r\n"},
		},
		Matchers: []Matcher{
			{Type: "word", Words: []string{"ECHO: HELLO"}},
		},
	}

	vars := map[string]string{}
	matched, _, err := engine.executeNetworkRequest(context.Background(), req, vars)
	require.NoError(t, err)
	assert.True(t, matched, "should match echoed response")
}

func TestNetworkRequest_Extractor(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("Server: MyApp/3.2.1\r\n"))
	}()

	engine := NewEngine()
	req := &NetworkRequest{
		ID:   "version",
		Host: listener.Addr().String(),
		Extractors: []Extractor{
			{
				Type:  "regex",
				Name:  "version",
				Regex: []string{`MyApp/(\d+\.\d+\.\d+)`},
				Group: 1,
			},
		},
	}

	vars := map[string]string{}
	_, extracted, err := engine.executeNetworkRequest(context.Background(), req, vars)
	require.NoError(t, err)
	assert.Contains(t, extracted["version"], "3.2.1")
}

func TestNetworkRequest_HexInput(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		// Respond based on received hex data
		if n >= 2 && buf[0] == 0x00 && buf[1] == 0x01 {
			conn.Write([]byte("HEX_OK"))
		}
	}()

	engine := NewEngine()
	req := &NetworkRequest{
		ID:   "hex-test",
		Host: listener.Addr().String(),
		Inputs: []NetworkInput{
			{Hex: "0001"},
		},
		Matchers: []Matcher{
			{Type: "word", Words: []string{"HEX_OK"}},
		},
	}

	vars := map[string]string{}
	matched, _, err := engine.executeNetworkRequest(context.Background(), req, vars)
	require.NoError(t, err)
	assert.True(t, matched)
}

func TestNetworkRequest_DefaultType(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("banner"))
	}()

	engine := NewEngine()
	req := &NetworkRequest{
		ID:   "default",
		Host: listener.Addr().String(),
		// Type intentionally empty — should default to tcp
	}

	vars := map[string]string{}
	_, _, err = engine.executeNetworkRequest(context.Background(), req, vars)
	assert.NoError(t, err)
}

func TestNetworkRequest_VariableExpansion(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Must read client data before closing to avoid RST on Windows
		buf := make([]byte, 1024)
		conn.Read(buf) //nolint:errcheck // test helper
		conn.Write([]byte("OK"))
	}()

	engine := NewEngine()
	req := &NetworkRequest{
		ID:   "var-expand",
		Host: "{{target_host}}",
		Inputs: []NetworkInput{
			{Data: "GET {{path}}\r\n"},
		},
	}

	vars := map[string]string{
		"target_host": listener.Addr().String(),
		"path":        "/test",
	}
	_, _, err = engine.executeNetworkRequest(context.Background(), req, vars)
	assert.NoError(t, err)
}

func TestNetworkRequest_ConnectionRefused(t *testing.T) {
	engine := NewEngine()
	req := &NetworkRequest{
		ID:      "refused",
		Host:    "127.0.0.1:1", // Almost certainly not listening
		Timeout: "1s",
	}

	vars := map[string]string{}
	_, _, err := engine.executeNetworkRequest(context.Background(), req, vars)
	assert.Error(t, err)
}

func TestParseTemplate_WithDNS(t *testing.T) {
	tmplData := `
id: dns-test
info:
  name: DNS Test
  severity: info
dns:
  - id: lookup
    name: example.com
    type: A
    matchers:
      - type: regex
        regex: ['\d+\.\d+\.\d+\.\d+']
`
	tmpl, err := ParseTemplate([]byte(tmplData))
	require.NoError(t, err)
	require.Len(t, tmpl.DNS, 1)
	assert.Equal(t, "lookup", tmpl.DNS[0].ID)
	assert.Equal(t, "A", tmpl.DNS[0].Type)
}

func TestParseTemplate_WithNetwork(t *testing.T) {
	tmplData := `
id: net-test
info:
  name: Network Test
  severity: info
network:
  - id: banner
    host: "{{Hostname}}:22"
    type: tcp
    inputs:
      - data: "HEAD / HTTP/1.0\r\n\r\n"
    matchers:
      - type: word
        words: ["SSH"]
`
	tmpl, err := ParseTemplate([]byte(tmplData))
	require.NoError(t, err)
	require.Len(t, tmpl.Network, 1)
	assert.Equal(t, "banner", tmpl.Network[0].ID)
	assert.Len(t, tmpl.Network[0].Inputs, 1)
}
