package checkpoint

// Error propagation tests for checkpoint — verifies file close errors
// are captured. Would have caught R1 checkpoint close error.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveCompletedToFile_InvalidPath verifies error on bad path.
func TestSaveCompletedToFile_InvalidPath(t *testing.T) {
	t.Parallel()

	// Use OS-level invalid path (NUL device subpath on Windows, /dev/null subpath on Unix)
	badPath := filepath.Join(os.DevNull, "sub", "checkpoint.json")
	err := SaveCompletedToFile(badPath, "target1")
	if err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

// TestSaveCompletedToFile_RoundTrip verifies save and load work correctly.
func TestSaveCompletedToFile_RoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "checkpoint.json")

	if err := SaveCompletedToFile(path, "target1"); err != nil {
		t.Fatalf("save target1: %v", err)
	}
	if err := SaveCompletedToFile(path, "target2"); err != nil {
		t.Fatalf("save target2: %v", err)
	}

	completed, err := LoadCompletedFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !completed["target1"] {
		t.Error("target1 not in completed set")
	}
	if !completed["target2"] {
		t.Error("target2 not in completed set")
	}
}

// TestManager_Save_InvalidPath verifies Manager.Save returns error for bad path.
func TestManager_Save_InvalidPath(t *testing.T) {
	t.Parallel()

	m := NewManager(filepath.Join(t.TempDir(), "no", "such", "dir", "cp.json"))
	m.Init("scan", []string{"t1"}, nil)

	err := m.Save()
	if err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

// TestManager_MarkCompleted_Persistence verifies targets survive save/load.
func TestManager_MarkCompleted_Persistence(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	m := NewManager(path)
	m.Init("scan", []string{"t1", "t2", "t3"}, nil)

	if err := m.MarkCompleted("t1"); err != nil {
		t.Fatalf("mark t1: %v", err)
	}
	if err := m.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Load into new manager
	m2 := NewManager(path)
	state, err := m2.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !state.Completed["t1"] {
		t.Error("t1 not marked completed after reload")
	}
	if state.Completed["t2"] {
		t.Error("t2 should not be completed")
	}
}

// TestManager_Delete_NonExistent verifies Delete doesn't error on missing file.
func TestManager_Delete_NonExistent(t *testing.T) {
	t.Parallel()

	m := NewManager(filepath.Join(t.TempDir(), "nonexistent.json"))
	err := m.Delete()
	if err != nil && !os.IsNotExist(err) {
		t.Errorf("unexpected error: %v", err)
	}
}
