//go:build !linux

// Package iouring provides io_uring-based async I/O for Linux 5.1+.
// This file provides a stub implementation for non-Linux platforms.
package iouring

import "errors"

// ErrNotSupported indicates io_uring is not available on this platform
var ErrNotSupported = errors.New("io_uring not supported on this platform")

// ErrRingClosed indicates the ring has been closed
var ErrRingClosed = errors.New("io_uring ring is closed")

// Ring is a stub for non-Linux platforms
type Ring struct{}

// Supported returns false on non-Linux platforms
func Supported() bool {
	return false
}

// New returns ErrNotSupported on non-Linux platforms
func New(size uint32) (*Ring, error) {
	return nil, ErrNotSupported
}

// Close is a no-op on non-Linux platforms
func (r *Ring) Close() error {
	return nil
}

// Read returns ErrNotSupported on non-Linux platforms
func (r *Ring) Read(fd int, buf []byte) (int, error) {
	return 0, ErrNotSupported
}

// Write returns ErrNotSupported on non-Linux platforms
func (r *Ring) Write(fd int, buf []byte) (int, error) {
	return 0, ErrNotSupported
}
