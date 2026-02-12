// Package iohelper provides helper functions for I/O operations,
// particularly for safely reading HTTP response bodies with limits.
package iohelper

import (
	"io"
	"log/slog"
)

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
