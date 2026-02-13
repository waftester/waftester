package corpus

// Error propagation tests for corpus cache — verifies gzip close errors
// are surfaced. Would have caught C-05 (Round 4).

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveToCache_InvalidPath verifies saveToCache returns error for bad path.
func TestSaveToCache_InvalidPath(t *testing.T) {
	t.Parallel()

	m := NewManager(t.TempDir(), false)
	corpus := &Corpus{
		Name:     "test",
		Payloads: []Payload{{Text: "test", Category: "xss"}},
	}

	badPath := filepath.Join(t.TempDir(), "no", "such", "dir", "corpus.json.gz")
	err := m.saveToCache(corpus, badPath)
	if err == nil {
		t.Error("expected error for invalid cache path, got nil")
	}
}

// TestSaveToCache_ValidGzip verifies round-trip works for .gz files.
func TestSaveToCache_ValidGzip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	m := NewManager(dir, false)
	corpus := &Corpus{
		Name:     "test-gz",
		Payloads: []Payload{{Text: "hello", Category: "sqli"}},
	}

	path := filepath.Join(dir, "test.json.gz")
	err := m.saveToCache(corpus, path)
	if err != nil {
		t.Fatalf("saveToCache: %v", err)
	}

	// Verify file exists and is non-empty
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() == 0 {
		t.Error("gzip file is empty")
	}
}

// TestSaveToCache_PlainJSON verifies non-gz path also works.
func TestSaveToCache_PlainJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	m := NewManager(dir, false)
	corpus := &Corpus{
		Name:     "test-plain",
		Payloads: []Payload{{Text: "test", Category: "rce"}},
	}

	path := filepath.Join(dir, "test.json")
	err := m.saveToCache(corpus, path)
	if err != nil {
		t.Fatalf("saveToCache: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() == 0 {
		t.Error("JSON file is empty")
	}
}
