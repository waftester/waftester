// Package iohelper provides helper functions for I/O operations,
// particularly for safely reading HTTP response bodies with limits.
package iohelper

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// WriteAtomic writes data to path atomically via a temp file + rename.
// The caller is responsible for creating parent directories if needed.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

// WriteAtomicJSON marshals v as indented JSON and writes it atomically to path.
// The caller is responsible for creating parent directories if needed.
func WriteAtomicJSON(path string, v any, perm os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	return WriteAtomic(path, data, perm)
}

// ReadJSON reads a JSON file from disk and unmarshals it into v.
// This is the read-side counterpart to WriteAtomicJSON.
func ReadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Standard body size limits for different use cases
const (
	// SmallMaxBodySize is for headers, status pages, etc. (8KB)
	SmallMaxBodySize int64 = 8 * 1024

	// MediumMaxBodySize is for typical HTML responses (100KB)
	MediumMaxBodySize int64 = 100 * 1024

	// DefaultMaxBodySize is for general responses (1MB)
	DefaultMaxBodySize int64 = 1024 * 1024

	// LargeMaxBodySize is for downloads, assets (10MB)
	LargeMaxBodySize int64 = 10 * 1024 * 1024
)

// ReadBody reads from an io.Reader with a size limit.
// If r is nil, returns empty slice and no error.
// This prevents memory exhaustion from maliciously large responses.
//
// Usage:
//
//	body, err := iohelper.ReadBody(resp.Body, iohelper.DefaultMaxBodySize)
//	defer resp.Body.Close()
func ReadBody(r io.Reader, maxSize int64) ([]byte, error) {
	if r == nil {
		return []byte{}, nil
	}
	return io.ReadAll(io.LimitReader(r, maxSize))
}

// ReadBodyDefault reads from an io.Reader with the default 1MB limit.
// Convenience wrapper around ReadBody with DefaultMaxBodySize.
func ReadBodyDefault(r io.Reader) ([]byte, error) {
	return ReadBody(r, DefaultMaxBodySize)
}

// ReadBodySmall reads from an io.Reader with an 8KB limit.
// Suitable for headers, error pages, status responses.
func ReadBodySmall(r io.Reader) ([]byte, error) {
	return ReadBody(r, SmallMaxBodySize)
}

// ReadBodyOrLog reads the response body using ReadBodyDefault and logs any errors.
// It returns the body bytes (which may be nil on error).
func ReadBodyOrLog(r io.Reader, logger *slog.Logger) []byte {
	data, err := ReadBodyDefault(r)
	if err != nil && logger != nil {
		logger.Warn("body read failed", slog.String("error", err.Error()))
	}
	return data
}

// CountWords returns the number of whitespace-separated words in data.
func CountWords(data []byte) int {
	count := 0
	inWord := false
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			inWord = false
		} else if !inWord {
			count++
			inWord = true
		}
	}
	return count
}

// CountLines returns the number of lines in data.
// An empty input returns 0; non-empty input without newlines returns 1.
func CountLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	count := 1
	for _, b := range data {
		if b == '\n' {
			count++
		}
	}
	return count
}

// DrainAndClose reads any remaining data from r and closes it if it's a ReadCloser.
// This ensures the connection can be reused for HTTP keep-alive.
// Always returns nil error to allow use in defer.
func DrainAndClose(r io.Reader) error {
	if r == nil {
		return nil
	}

	// Drain remaining data (limited to 64KB to prevent DoS)
	_, _ = io.Copy(io.Discard, io.LimitReader(r, 64*1024))

	// Close if possible
	if rc, ok := r.(io.ReadCloser); ok {
		rc.Close()
	}
	return nil
}
