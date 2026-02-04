package iouring

import (
	"runtime"
	"testing"
)

func TestSupported(t *testing.T) {
	supported := Supported()
	
	if runtime.GOOS == "linux" {
		// On Linux, io_uring may or may not be supported depending on kernel version
		// Just verify the function runs without panic
		t.Logf("io_uring supported: %v", supported)
	} else {
		// On non-Linux platforms, should always return false
		if supported {
			t.Error("Supported() should return false on non-Linux platforms")
		}
	}
}

func TestNewNotSupported(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Skipping on Linux - io_uring may be available")
	}

	ring, err := New(256)
	if err != ErrNotSupported {
		t.Errorf("New() on non-Linux should return ErrNotSupported, got: %v", err)
	}
	if ring != nil {
		t.Error("New() should return nil ring on non-Linux")
	}
}

func TestRingStubMethods(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Skipping stub tests on Linux")
	}

	r := &Ring{}
	
	// Test Read
	buf := make([]byte, 100)
	n, err := r.Read(0, buf)
	if err != ErrNotSupported {
		t.Errorf("Read() should return ErrNotSupported, got: %v", err)
	}
	if n != 0 {
		t.Errorf("Read() should return 0 bytes, got: %d", n)
	}

	// Test Write
	n, err = r.Write(0, buf)
	if err != ErrNotSupported {
		t.Errorf("Write() should return ErrNotSupported, got: %v", err)
	}
	if n != 0 {
		t.Errorf("Write() should return 0 bytes, got: %d", n)
	}

	// Test Close
	if err := r.Close(); err != nil {
		t.Errorf("Close() should return nil, got: %v", err)
	}
}

func TestRingEmptyBuffer(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Skipping stub tests on Linux")
	}

	r := &Ring{}

	// Test Read with empty buffer - should not panic
	emptyBuf := make([]byte, 0)
	n, err := r.Read(0, emptyBuf)
	// On stub, returns ErrNotSupported; on Linux impl, returns 0, nil
	if err != nil && err != ErrNotSupported {
		t.Errorf("Read(empty) should return nil or ErrNotSupported, got: %v", err)
	}
	if n != 0 {
		t.Errorf("Read(empty) should return 0 bytes, got: %d", n)
	}

	// Test Write with empty buffer
	n, err = r.Write(0, emptyBuf)
	if err != nil && err != ErrNotSupported {
		t.Errorf("Write(empty) should return nil or ErrNotSupported, got: %v", err)
	}
	if n != 0 {
		t.Errorf("Write(empty) should return 0 bytes, got: %d", n)
	}

	// Test with nil buffer
	n, err = r.Read(0, nil)
	if err != nil && err != ErrNotSupported {
		t.Errorf("Read(nil) should return nil or ErrNotSupported, got: %v", err)
	}
	if n != 0 {
		t.Errorf("Read(nil) should return 0 bytes, got: %d", n)
	}
}

func BenchmarkSupported(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Supported()
	}
}
