package iohelper

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.dat")

	data := []byte("hello world")
	if err := WriteAtomic(path, data, 0644); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("expected 'hello world', got %q", got)
	}

	// Verify no temp file left behind
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file should not exist after successful write")
	}
}

func TestWriteAtomicJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	type payload struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	v := payload{Name: "test", Count: 42}

	if err := WriteAtomicJSON(path, v, 0644); err != nil {
		t.Fatalf("WriteAtomicJSON: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var loaded payload
	if err := json.Unmarshal(got, &loaded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if loaded.Name != "test" || loaded.Count != 42 {
		t.Errorf("expected {test 42}, got %+v", loaded)
	}
}

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

func TestCountWords(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"empty", []byte{}, 0},
		{"nil", nil, 0},
		{"single word", []byte("hello"), 1},
		{"two words", []byte("hello world"), 2},
		{"leading spaces", []byte("  hello"), 1},
		{"trailing spaces", []byte("hello  "), 1},
		{"multiple spaces", []byte("hello   world"), 2},
		{"tabs", []byte("hello\tworld"), 2},
		{"newlines", []byte("hello\nworld"), 2},
		{"mixed whitespace", []byte(" hello\t\n world "), 2},
		{"only spaces", []byte("   "), 0},
		{"carriage return", []byte("a\r\nb"), 2},
		{"many words", []byte("one two three four five"), 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CountWords(tt.data)
			if got != tt.want {
				t.Errorf("CountWords(%q) = %d, want %d", tt.data, got, tt.want)
			}
		})
	}
}

func TestCountLines(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"empty", []byte{}, 0},
		{"nil", nil, 0},
		{"single line no newline", []byte("hello"), 1},
		{"single line with newline", []byte("hello\n"), 2},
		{"two lines", []byte("hello\nworld"), 2},
		{"three lines", []byte("a\nb\nc"), 3},
		{"trailing newline", []byte("a\nb\n"), 3},
		{"only newlines", []byte("\n\n\n"), 4},
		{"blank lines between", []byte("a\n\nb"), 3},
		{"single newline", []byte("\n"), 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CountLines(tt.data)
			if got != tt.want {
				t.Errorf("CountLines(%q) = %d, want %d", tt.data, got, tt.want)
			}
		})
	}
}

func TestReadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	type payload struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	// Write a JSON file
	if err := WriteAtomicJSON(path, payload{Name: "read-test", Count: 99}, 0644); err != nil {
		t.Fatalf("WriteAtomicJSON: %v", err)
	}

	// Read it back
	var got payload
	if err := ReadJSON(path, &got); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if got.Name != "read-test" || got.Count != 99 {
		t.Errorf("expected {read-test 99}, got %+v", got)
	}
}

func TestReadJSON_FileNotFound(t *testing.T) {
	var v struct{}
	err := ReadJSON("/nonexistent/path.json", &v)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReadJSON_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatal(err)
	}

	var v struct{}
	err := ReadJSON(path, &v)
	if err == nil {
		t.Error("expected error for invalid JSON")
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
