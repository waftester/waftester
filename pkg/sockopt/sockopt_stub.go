//go:build !linux

// Package sockopt provides platform-specific socket optimizations.
// This stub provides no-op implementations for non-Linux platforms.
package sockopt

import (
	"net"
	"syscall"
)

// OptimizeConn is a no-op on non-Linux platforms.
func OptimizeConn(conn net.Conn) error {
	return nil
}

// OptimizeListener is a no-op on non-Linux platforms.
func OptimizeListener(listener net.Listener) error {
	return nil
}

// DialControl returns nil on non-Linux platforms.
// Usage:
//
//	dialer := &net.Dialer{
//	    Control: sockopt.DialControl(), // nil is valid
//	}
func DialControl() func(network, address string, c syscall.RawConn) error {
	return nil
}
