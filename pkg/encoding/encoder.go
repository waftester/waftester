// Package encoding provides payload encoding/decoding capabilities for WAF testing.
// It supports 12+ encoding methods and chained encoding for evasion testing.
package encoding

import (
	"fmt"
	"strings"
)

// Encoder defines the interface for payload encoding
type Encoder interface {
	// Name returns the encoder identifier
	Name() string
	// Encode transforms the payload
	Encode(payload string) (string, error)
	// Decode reverses the encoding (if possible)
	Decode(encoded string) (string, error)
}

// ChainEncoder applies multiple encoders in sequence
type ChainEncoder struct {
	name     string
	encoders []Encoder
}

func (c *ChainEncoder) Name() string { return c.name }

func (c *ChainEncoder) Encode(payload string) (string, error) {
	result := payload
	var err error
	for _, enc := range c.encoders {
		result, err = enc.Encode(result)
		if err != nil {
			return "", fmt.Errorf("encoder %s failed: %w", enc.Name(), err)
		}
	}
	return result, nil
}

func (c *ChainEncoder) Decode(encoded string) (string, error) {
	result := encoded
	var err error
	// Decode in reverse order
	for i := len(c.encoders) - 1; i >= 0; i-- {
		result, err = c.encoders[i].Decode(result)
		if err != nil {
			return "", fmt.Errorf("decoder %s failed: %w", c.encoders[i].Name(), err)
		}
	}
	return result, nil
}

// Registry of available encoders
var registry = make(map[string]Encoder)

// Register adds an encoder to the registry
func Register(enc Encoder) {
	registry[strings.ToLower(enc.Name())] = enc
}

// Get retrieves an encoder by name
func Get(name string) Encoder {
	return registry[strings.ToLower(name)]
}

// List returns all registered encoder names
func List() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// Chain creates a chained encoder from multiple encoder names
func Chain(names ...string) Encoder {
	encoders := make([]Encoder, 0, len(names))
	for _, name := range names {
		if enc := Get(name); enc != nil {
			encoders = append(encoders, enc)
		}
	}
	if len(encoders) == 0 {
		return nil
	}
	return &ChainEncoder{
		name:     strings.Join(names, "+"),
		encoders: encoders,
	}
}

// EncodeAll applies an encoder to multiple payloads
func EncodeAll(encoderName string, payloads []string) ([]string, error) {
	enc := Get(encoderName)
	if enc == nil {
		return nil, fmt.Errorf("encoder not found: %s", encoderName)
	}

	results := make([]string, len(payloads))
	for i, p := range payloads {
		encoded, err := enc.Encode(p)
		if err != nil {
			return nil, fmt.Errorf("encoding payload %d: %w", i, err)
		}
		results[i] = encoded
	}
	return results, nil
}

// EncodeWithAll applies all registered encoders to a single payload
func EncodeWithAll(payload string) map[string]string {
	results := make(map[string]string)
	for name, enc := range registry {
		if encoded, err := enc.Encode(payload); err == nil {
			results[name] = encoded
		}
	}
	return results
}
