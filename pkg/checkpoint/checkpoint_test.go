package checkpoint

import (
	"path/filepath"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager("")
	if m.FilePath != "resume.cfg" {
		t.Errorf("expected default file path 'resume.cfg', got %s", m.FilePath)
	}

	m = NewManager("custom.cfg")
	if m.FilePath != "custom.cfg" {
		t.Errorf("expected file path 'custom.cfg', got %s", m.FilePath)
	}
}

func TestInitAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test-resume.cfg")

	m := NewManager(filePath)
	targets := []string{"target1.com", "target2.com", "target3.com"}
	flags := map[string]interface{}{
		"timeout": 30,
		"workers": 10,
	}

	m.Init("probe", targets, flags)

	if err := m.Save(); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	// Verify file exists
	if !m.Exists() {
		t.Error("checkpoint file should exist after save")
	}

	// Load and verify
	m2 := NewManager(filePath)
	state, err := m2.Load()
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if state.Command != "probe" {
		t.Errorf("expected command 'probe', got %s", state.Command)
	}

	if state.TotalTargets != 3 {
		t.Errorf("expected 3 total targets, got %d", state.TotalTargets)
	}

	if state.Flags["timeout"] != float64(30) { // JSON unmarshals numbers as float64
		t.Errorf("expected timeout flag 30, got %v", state.Flags["timeout"])
	}
}

func TestMarkCompleted(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test-resume.cfg")

	m := NewManager(filePath)
	m.AutoSave = false // Disable auto-save for faster testing
	targets := []string{"target1.com", "target2.com", "target3.com"}

	m.Init("scan", targets, nil)

	// Mark targets as completed
	if err := m.MarkCompleted("target1.com"); err != nil {
		t.Fatalf("failed to mark completed: %v", err)
	}

	if err := m.MarkCompleted("target2.com"); err != nil {
		t.Fatalf("failed to mark completed: %v", err)
	}

	// Check completion status
	if !m.IsCompleted("target1.com") {
		t.Error("target1.com should be completed")
	}

	if !m.IsCompleted("target2.com") {
		t.Error("target2.com should be completed")
	}

	if m.IsCompleted("target3.com") {
		t.Error("target3.com should NOT be completed")
	}
}

func TestGetPendingTargets(t *testing.T) {
	m := NewManager("")
	targets := []string{"a.com", "b.com", "c.com", "d.com"}

	m.Init("fuzz", targets, nil)

	// Mark some as completed
	m.MarkCompleted("a.com")
	m.MarkCompleted("c.com")

	pending := m.GetPendingTargets(targets)

	if len(pending) != 2 {
		t.Errorf("expected 2 pending targets, got %d", len(pending))
	}

	// Check that correct targets are pending
	expected := map[string]bool{"b.com": true, "d.com": true}
	for _, p := range pending {
		if !expected[p] {
			t.Errorf("unexpected pending target: %s", p)
		}
	}
}

func TestGetProgress(t *testing.T) {
	m := NewManager("")
	targets := []string{"a.com", "b.com", "c.com", "d.com"}

	m.Init("probe", targets, nil)

	// 0% at start
	if m.GetProgress() != 0 {
		t.Errorf("expected 0%% progress, got %.2f%%", m.GetProgress())
	}

	// 25% after 1 target
	m.MarkCompleted("a.com")
	if m.GetProgress() != 25 {
		t.Errorf("expected 25%% progress, got %.2f%%", m.GetProgress())
	}

	// 50% after 2 targets
	m.MarkCompleted("b.com")
	if m.GetProgress() != 50 {
		t.Errorf("expected 50%% progress, got %.2f%%", m.GetProgress())
	}

	// 100% after all targets
	m.MarkCompleted("c.com")
	m.MarkCompleted("d.com")
	if m.GetProgress() != 100 {
		t.Errorf("expected 100%% progress, got %.2f%%", m.GetProgress())
	}
}

func TestDelete(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test-resume.cfg")

	m := NewManager(filePath)
	m.Init("scan", []string{"test.com"}, nil)

	if err := m.Save(); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	if !m.Exists() {
		t.Error("file should exist before delete")
	}

	if err := m.Delete(); err != nil {
		t.Fatalf("failed to delete: %v", err)
	}

	if m.Exists() {
		t.Error("file should not exist after delete")
	}
}

func TestSaveCompletedToFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "completed.txt")

	// Save multiple targets
	if err := SaveCompletedToFile(filePath, "target1.com"); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	if err := SaveCompletedToFile(filePath, "target2.com"); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	// Load and verify
	completed, err := LoadCompletedFromFile(filePath)
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if len(completed) != 2 {
		t.Errorf("expected 2 completed, got %d", len(completed))
	}

	if !completed["target1.com"] {
		t.Error("target1.com should be in completed")
	}

	if !completed["target2.com"] {
		t.Error("target2.com should be in completed")
	}
}

func TestLoadCompletedFromNonexistentFile(t *testing.T) {
	completed, err := LoadCompletedFromFile("nonexistent-file.txt")
	if err != nil {
		t.Fatalf("should not error on nonexistent file: %v", err)
	}

	if len(completed) != 0 {
		t.Errorf("expected empty map, got %d items", len(completed))
	}
}

func TestConcurrentMarkCompleted(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test-resume.cfg")

	m := NewManager(filePath)
	m.AutoSave = false // Disable to avoid file I/O race

	targets := make([]string, 100)
	for i := 0; i < 100; i++ {
		targets[i] = "target" + string(rune('0'+i%10)) + ".com"
	}

	m.Init("probe", targets, nil)

	// Mark all completed concurrently
	done := make(chan bool, 100)
	for _, target := range targets {
		go func(t string) {
			m.MarkCompleted(t)
			done <- true
		}(target)
	}

	// Wait for all to complete
	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify state
	state := m.GetState()
	if state.CompletedTargets != 100 {
		t.Errorf("expected 100 completed, got %d", state.CompletedTargets)
	}
}

func TestStateTimestamps(t *testing.T) {
	m := NewManager("")
	m.Init("probe", []string{"test.com"}, nil)

	state := m.GetState()
	if state.StartTime.IsZero() {
		t.Error("start time should be set")
	}

	// Last update should be around start time
	if time.Since(state.LastUpdate) > time.Second {
		t.Error("last update should be recent")
	}
}
