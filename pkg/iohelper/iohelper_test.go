package iohelper

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadBody_NilReader(t *testing.T) {
	body, err := ReadBody(nil, DefaultMaxBodySize)
	if err != nil {
		t.Errorf("Expected no error for nil reader, got %v", err)
	}
	if len(body) != 0 {
		t.Errorf("Expected empty body for nil reader, got %d bytes", len(body))
	}
}

func TestReadBody_RespectsLimit(t *testing.T) {
	// Create reader with more data than limit
	data := strings.Repeat("x", 1000)
	reader := strings.NewReader(data)

	body, err := ReadBody(reader, 100)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(body) != 100 {
		t.Errorf("Expected 100 bytes (limit), got %d", len(body))
	}
}

func TestReadBody_ReadsAllWhenUnderLimit(t *testing.T) {
	data := "small data"
	reader := strings.NewReader(data)

	body, err := ReadBody(reader, 1024)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(body) != data {
		t.Errorf("Expected '%s', got '%s'", data, string(body))
	}
}

func TestReadBodyDefault(t *testing.T) {
	data := "test data"
	reader := strings.NewReader(data)

	body, err := ReadBodyDefault(reader)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(body) != data {
		t.Errorf("Expected '%s', got '%s'", data, string(body))
	}
}

func TestReadBodySmall(t *testing.T) {
	// Create data larger than SmallMaxBodySize
	data := strings.Repeat("x", int(SmallMaxBodySize)+1000)
	reader := strings.NewReader(data)

	body, err := ReadBodySmall(reader)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if int64(len(body)) != SmallMaxBodySize {
		t.Errorf("Expected %d bytes (small limit), got %d", SmallMaxBodySize, len(body))
	}
}

func TestDrainAndClose_NilReader(t *testing.T) {
	err := DrainAndClose(nil)
	if err != nil {
		t.Errorf("Expected nil error for nil reader, got %v", err)
	}
}

func TestDrainAndClose_Drains(t *testing.T) {
	data := "remaining data to drain"
	reader := strings.NewReader(data)

	err := DrainAndClose(reader)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

type mockReadCloser struct {
	*bytes.Reader
	closed bool
}

func (m *mockReadCloser) Close() error {
	m.closed = true
	return nil
}

func TestDrainAndClose_ClosesReadCloser(t *testing.T) {
	reader := &mockReadCloser{Reader: bytes.NewReader([]byte("data"))}

	err := DrainAndClose(reader)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !reader.closed {
		t.Error("Expected ReadCloser to be closed")
	}
}

func TestMaxBodySize_Constants(t *testing.T) {
	if DefaultMaxBodySize <= 0 {
		t.Error("DefaultMaxBodySize should be positive")
	}
	if SmallMaxBodySize <= 0 {
		t.Error("SmallMaxBodySize should be positive")
	}
	if SmallMaxBodySize >= DefaultMaxBodySize {
		t.Error("SmallMaxBodySize should be smaller than DefaultMaxBodySize")
	}
	if MediumMaxBodySize <= SmallMaxBodySize {
		t.Error("MediumMaxBodySize should be larger than SmallMaxBodySize")
	}
	if LargeMaxBodySize <= DefaultMaxBodySize {
		t.Error("LargeMaxBodySize should be larger than DefaultMaxBodySize")
	}
}
