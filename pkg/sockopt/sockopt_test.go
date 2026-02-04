package sockopt

import (
	"net"
	"runtime"
	"testing"
)

func TestOptimizeConn(t *testing.T) {
	// Create a simple listener for testing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept in background
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	// Connect
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// Test OptimizeConn
	err = OptimizeConn(conn)
	if runtime.GOOS == "linux" {
		// On Linux, should succeed
		if err != nil {
			t.Errorf("OptimizeConn() on Linux should succeed, got: %v", err)
		}
	} else {
		// On other platforms, should be a no-op
		if err != nil {
			t.Errorf("OptimizeConn() should be no-op, got: %v", err)
		}
	}
}

func TestOptimizeListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	err = OptimizeListener(listener)
	if err != nil {
		t.Errorf("OptimizeListener() should not error: %v", err)
	}
}

func TestDialControl(t *testing.T) {
	ctrl := DialControl()

	if runtime.GOOS == "linux" {
		if ctrl == nil {
			t.Error("DialControl() on Linux should return a function")
		}
	}
	// On other platforms, ctrl may be nil which is valid
}

func TestOptimizeNilConn(t *testing.T) {
	// Should handle nil gracefully
	err := OptimizeConn(nil)
	if err != nil {
		t.Errorf("OptimizeConn(nil) should return nil, got: %v", err)
	}
}

func BenchmarkOptimizeConn(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept connections in background
	done := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				close(done)
				return
			}
			conn.Close()
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			b.Fatalf("Failed to dial: %v", err)
		}
		OptimizeConn(conn)
		conn.Close()
	}
}
