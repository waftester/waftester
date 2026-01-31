// pkg/input/targets_test.go
package input

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTargetSource_FromURLs(t *testing.T) {
	ts := &TargetSource{
		URLs: []string{"https://a.com", "https://b.com"},
	}

	targets, err := ts.GetTargets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(targets))
	}
}

func TestTargetSource_FromFile(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "targets.txt")
	content := "https://a.com\nhttps://b.com\n# comment\n\nhttps://c.com"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	ts := &TargetSource{
		ListFile: tmpFile,
	}

	targets, err := ts.GetTargets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 3 {
		t.Errorf("expected 3 targets (skipping comment/blank), got %d: %v", len(targets), targets)
	}
}

func TestTargetSource_Deduplication(t *testing.T) {
	ts := &TargetSource{
		URLs: []string{"https://a.com", "https://b.com", "https://a.com"},
	}

	targets, err := ts.GetTargets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 2 {
		t.Errorf("expected 2 targets after dedup, got %d: %v", len(targets), targets)
	}
}

func TestTargetSource_Combined(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "targets.txt")
	if err := os.WriteFile(tmpFile, []byte("https://file.com"), 0644); err != nil {
		t.Fatal(err)
	}

	ts := &TargetSource{
		URLs:     []string{"https://url.com"},
		ListFile: tmpFile,
	}

	targets, err := ts.GetTargets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 2 {
		t.Errorf("expected 2 targets combined, got %d: %v", len(targets), targets)
	}
}

func TestTargetSource_NormalizeURL(t *testing.T) {
	ts := &TargetSource{
		URLs: []string{"example.com", "https://secure.com"},
	}

	targets, err := ts.GetTargets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if targets[0] != "https://example.com" {
		t.Errorf("expected https:// prefix added, got %s", targets[0])
	}
}

func TestTargetSource_Empty(t *testing.T) {
	ts := &TargetSource{}

	targets, err := ts.GetTargets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(targets))
	}
}
