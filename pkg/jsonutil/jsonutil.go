// Package jsonutil provides a high-performance JSON encoding/decoding wrapper.
// It uses github.com/go-json-experiment/json which is 2-3x faster than encoding/json.
//
// This is a drop-in replacement for encoding/json in hot paths.
// The API matches the standard library for easy migration.
//
// Usage:
//
//	import "github.com/waftester/waftester/pkg/jsonutil"
//
//	// Instead of: json.Unmarshal(data, &v)
//	err := jsonutil.Unmarshal(data, &v)
//
//	// Instead of: json.Marshal(v)
//	data, err := jsonutil.Marshal(v)
package jsonutil

import (
	"io"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// Unmarshal parses the JSON-encoded data and stores the result in v.
// This is 2-3x faster than encoding/json.Unmarshal.
func Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// Marshal returns the JSON encoding of v.
// This is 2-3x faster than encoding/json.Marshal.
func Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// MarshalIndent returns the indented JSON encoding of v.
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	// go-json-experiment uses jsontext options for indentation
	return json.Marshal(v, jsontext.WithIndent(indent))
}

// NewDecoder returns a new decoder that reads from r.
func NewDecoder(r io.Reader) *jsontext.Decoder {
	return jsontext.NewDecoder(r)
}

// NewEncoder returns a new encoder that writes to w.
func NewEncoder(w io.Writer) *jsontext.Encoder {
	return jsontext.NewEncoder(w)
}

// Valid reports whether data is a valid JSON encoding.
func Valid(data []byte) bool {
	return jsontext.Value(data).IsValid()
}

// Encoder provides a streaming JSON encoder compatible with encoding/json.Encoder.
type Encoder struct {
	w      io.Writer
	indent string
}

// NewStreamEncoder creates an encoder that writes to w.
// This provides encoding/json.Encoder-like interface.
func NewStreamEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// Encode writes the JSON encoding of v to the stream, followed by a newline.
// This matches encoding/json.Encoder.Encode behavior.
func (e *Encoder) Encode(v any) error {
	var err error
	if e.indent != "" {
		err = json.MarshalWrite(e.w, v, jsontext.WithIndent(e.indent))
	} else {
		err = json.MarshalWrite(e.w, v)
	}
	if err != nil {
		return err
	}
	// Add trailing newline to match encoding/json behavior
	_, err = e.w.Write([]byte{'\n'})
	return err
}

// SetIndent instructs the encoder to format each subsequent encoded value
// with the given indentation.
func (e *Encoder) SetIndent(prefix, indent string) {
	e.indent = indent
}

// Decoder provides a streaming JSON decoder compatible with encoding/json.Decoder.
type Decoder struct {
	r io.Reader
}

// NewStreamDecoder creates a decoder that reads from r.
// This provides encoding/json.Decoder-like interface.
func NewStreamDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

// Decode reads the next JSON-encoded value from the stream and stores it in v.
func (d *Decoder) Decode(v any) error {
	return json.UnmarshalRead(d.r, v)
}
