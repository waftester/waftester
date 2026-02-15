package nuclei

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// NetworkRequest represents a TCP/UDP network request in a template.
type NetworkRequest struct {
	ID                string         `yaml:"id,omitempty"`
	Host              string         `yaml:"host"`                         // host:port (supports {{variables}})
	Type              string         `yaml:"type,omitempty"`               // tcp (default) or udp
	Inputs            []NetworkInput `yaml:"inputs,omitempty"`             // Data to send
	ReadSize          int            `yaml:"read-size,omitempty"`          // Bytes to read (default 4096)
	ReadAll           bool           `yaml:"read-all,omitempty"`           // Read until EOF
	Timeout           string         `yaml:"timeout,omitempty"`            // Connection timeout
	MatchersCondition string         `yaml:"matchers-condition,omitempty"` // "and" or "or" (default: "or")
	Matchers          []Matcher      `yaml:"matchers,omitempty"`
	Extractors        []Extractor    `yaml:"extractors,omitempty"`
}

// NetworkInput represents data to send over a network connection.
type NetworkInput struct {
	Data string `yaml:"data"`          // Text data (supports \r\n escapes and {{variables}})
	Hex  string `yaml:"hex,omitempty"` // Hex-encoded binary data
}

// executeNetworkRequest runs a TCP/UDP request and evaluates matchers/extractors.
func (e *Engine) executeNetworkRequest(ctx context.Context, req *NetworkRequest, vars map[string]string) (bool, map[string][]string, error) {
	extracted := make(map[string][]string)

	host := expandVariables(req.Host, vars)
	netType := strings.ToLower(req.Type)
	if netType == "" {
		netType = "tcp"
	}

	readSize := req.ReadSize
	if readSize <= 0 {
		readSize = 4096
	}

	timeout := 10 * time.Second
	if req.Timeout != "" {
		if d, err := time.ParseDuration(req.Timeout); err == nil {
			timeout = d
		}
	}

	// Dial with context-aware timeout
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, netType, host)
	if err != nil {
		return false, extracted, fmt.Errorf("connect to %s (%s): %w", host, netType, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	var responseData []byte

	// If no inputs, just read the banner
	if len(req.Inputs) == 0 {
		buf := make([]byte, readSize)
		n, readErr := conn.Read(buf)
		if n > 0 {
			responseData = buf[:n]
		}
		if readErr != nil && readErr != io.EOF && n == 0 {
			return false, extracted, fmt.Errorf("read banner: %w", readErr)
		}
	} else {
		// Send each input and collect response
		for _, input := range req.Inputs {
			var data []byte
			if input.Hex != "" {
				var decErr error
				data, decErr = hex.DecodeString(strings.ReplaceAll(input.Hex, " ", ""))
				if decErr != nil {
					return false, extracted, fmt.Errorf("decode hex: %w", decErr)
				}
			} else {
				// Expand variables and unescape
				expanded := expandVariables(input.Data, vars)
				expanded = strings.ReplaceAll(expanded, `\r\n`, "\r\n")
				expanded = strings.ReplaceAll(expanded, `\n`, "\n")
				expanded = strings.ReplaceAll(expanded, `\r`, "\r")
				expanded = strings.ReplaceAll(expanded, `\t`, "\t")
				data = []byte(expanded)
			}

			if _, err := conn.Write(data); err != nil {
				return false, extracted, fmt.Errorf("write: %w", err)
			}
		}

		// Read response
		if req.ReadAll {
			responseData, err = io.ReadAll(io.LimitReader(conn, 1024*1024)) // 1MB limit
			if err != nil && err != io.EOF {
				return false, extracted, fmt.Errorf("read all: %w", err)
			}
		} else {
			buf := make([]byte, readSize)
			n, readErr := conn.Read(buf)
			if n > 0 {
				responseData = buf[:n]
			}
			if readErr != nil && readErr != io.EOF && n == 0 {
				return false, extracted, fmt.Errorf("read: %w", readErr)
			}
		}
	}

	respData := &ResponseData{
		StatusCode: len(responseData), // Byte count, not HTTP status — status matchers are not meaningful for network
		Body:       responseData,
	}

	condition := "or"
	if req.MatchersCondition != "" {
		condition = req.MatchersCondition
	}

	matched := evaluateMatchers(req.Matchers, condition, respData)

	for _, extractor := range req.Extractors {
		values := runExtractor(&extractor, respData)
		name := extractor.Name
		if name == "" {
			name = "extracted"
		}
		extracted[name] = append(extracted[name], values...)
	}

	return matched, extracted, nil
}
