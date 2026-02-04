//go:build linux

// Package sockopt provides platform-specific socket optimizations.
// On Linux, this enables high-performance network settings.
package sockopt

import (
	"net"
	"syscall"
)

// OptimizeConn applies high-performance socket options to a connection.
// This includes:
// - TCP_NODELAY: Disable Nagle's algorithm for lower latency
// - SO_RCVBUF/SO_SNDBUF: Larger buffers for higher throughput
// - TCP_QUICKACK: Send ACKs immediately
// - TCP_KEEPALIVE: Enable keep-alive for long connections
func OptimizeConn(conn net.Conn) error {
	if conn == nil {
		return nil
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil // Not a TCP connection, skip
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		// Disable Nagle's algorithm for lower latency
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
			setErr = err
			return
		}

		// Set larger receive buffer (256KB)
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 262144); err != nil {
			// Non-fatal, continue
		}

		// Set larger send buffer (256KB)
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 262144); err != nil {
			// Non-fatal, continue
		}

		// Enable TCP_QUICKACK for faster ACKs
		const TCP_QUICKACK = 12
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_QUICKACK, 1); err != nil {
			// Non-fatal, continue
		}

		// Enable keep-alive
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
			// Non-fatal, continue
		}

		// Set TCP keep-alive idle time to 60 seconds
		const TCP_KEEPIDLE = 4
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_KEEPIDLE, 60); err != nil {
			// Non-fatal, continue
		}

		// Set TCP keep-alive interval to 10 seconds
		const TCP_KEEPINTVL = 5
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_KEEPINTVL, 10); err != nil {
			// Non-fatal, continue
		}

		// Set TCP keep-alive probe count to 6
		const TCP_KEEPCNT = 6
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_KEEPCNT, 6); err != nil {
			// Non-fatal, continue
		}
	})

	if err != nil {
		return err
	}
	return setErr
}

// OptimizeListener applies high-performance socket options to a listener.
// This enables faster connection acceptance.
func OptimizeListener(listener net.Listener) error {
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return nil
	}

	rawConn, err := tcpListener.SyscallConn()
	if err != nil {
		return err
	}

	return rawConn.Control(func(fd uintptr) {
		// Enable SO_REUSEPORT for better load balancing across cores
		const SO_REUSEPORT = 15
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)

		// Set larger accept queue
		const TCP_FASTOPEN = 23
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN, 256)
	})
}

// DialControl returns a control function for net.Dialer that optimizes sockets.
// Usage:
//
//	dialer := &net.Dialer{
//	    Control: sockopt.DialControl(),
//	}
func DialControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			// TCP_NODELAY
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)

			// Larger buffers
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 262144)
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 262144)

			// TCP_QUICKACK
			const TCP_QUICKACK = 12
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_QUICKACK, 1)
		})
	}
}
