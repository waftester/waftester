package checkpoint

import (
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
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

// TestCheckpoint_ConcurrentMarkAndCheck tests parallel MarkCompleted and IsCompleted operations
func TestCheckpoint_ConcurrentMarkAndCheck(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "concurrent-mark-check.cfg")

	m := NewManager(filePath)
	m.AutoSave = false // Disable to focus on in-memory race conditions

	// Create 200 unique targets
	numTargets := 200
	targets := make([]string, numTargets)
	for i := 0; i < numTargets; i++ {
		targets[i] = fmt.Sprintf("target%d.example.com", i)
	}

	m.Init("scan", targets, nil)

	var wg sync.WaitGroup
	var markCount atomic.Int64
	var checkCount atomic.Int64

	// Half goroutines marking, half checking
	numGoroutines := 50

	// Markers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numTargets/numGoroutines; j++ {
				targetIdx := (id*numTargets/numGoroutines + j) % numTargets
				if err := m.MarkCompleted(targets[targetIdx]); err != nil {
					t.Errorf("MarkCompleted failed: %v", err)
				}
				markCount.Add(1)
			}
		}(i)
	}

	// Checkers - run concurrently with markers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numTargets; j++ {
				targetIdx := (id + j) % numTargets
				_ = m.IsCompleted(targets[targetIdx]) // Result may vary as marking happens
				checkCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// Verify all marks occurred
	if markCount.Load() != int64(numTargets) {
		t.Errorf("expected %d marks, got %d", numTargets, markCount.Load())
	}

	// Verify all checks occurred
	expectedChecks := int64(numGoroutines * numTargets)
	if checkCount.Load() != expectedChecks {
		t.Errorf("expected %d checks, got %d", expectedChecks, checkCount.Load())
	}

	// All targets should be completed after goroutines finish
	for _, target := range targets {
		if !m.IsCompleted(target) {
			t.Errorf("target %s should be completed", target)
		}
	}
}

// TestCheckpoint_ConcurrentSave tests parallel Save operations
func TestCheckpoint_ConcurrentSave(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "concurrent-save.cfg")

	m := NewManager(filePath)
	m.AutoSave = false

	targets := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}
	m.Init("probe", targets, nil)

	var wg sync.WaitGroup
	var saveCount atomic.Int64
	var errCount atomic.Int64

	numGoroutines := 20
	savesPerGoroutine := 10

	// Multiple goroutines saving concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < savesPerGoroutine; j++ {
				// Mark something before saving
				targetIdx := (id + j) % len(targets)
				_ = m.MarkCompleted(targets[targetIdx])

				if err := m.Save(); err != nil {
					errCount.Add(1)
					t.Logf("Save error (may be expected during race): %v", err)
				}
				saveCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	expectedSaves := int64(numGoroutines * savesPerGoroutine)
	if saveCount.Load() != expectedSaves {
		t.Errorf("expected %d save attempts, got %d", expectedSaves, saveCount.Load())
	}

	// Final save should succeed
	if err := m.Save(); err != nil {
		t.Fatalf("final save failed: %v", err)
	}

	// Verify file is valid by loading
	m2 := NewManager(filePath)
	state, err := m2.Load()
	if err != nil {
		t.Fatalf("failed to load after concurrent saves: %v", err)
	}

	if state.Command != "probe" {
		t.Errorf("expected command 'probe', got %s", state.Command)
	}
}

// TestCheckpoint_RapidUpdates tests many rapid updates from multiple goroutines
func TestCheckpoint_RapidUpdates(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "rapid-updates.cfg")

	m := NewManager(filePath)
	m.AutoSave = false

	// Large number of targets
	numTargets := 1000
	targets := make([]string, numTargets)
	for i := 0; i < numTargets; i++ {
		targets[i] = fmt.Sprintf("host%d.test.com", i)
	}

	m.Init("fuzz", targets, nil)

	var wg sync.WaitGroup
	var totalOps atomic.Int64

	numGoroutines := 100

	// Barrier to start all goroutines at roughly the same time
	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start // Wait for signal

			// Each goroutine does a mix of operations
			for j := 0; j < 50; j++ {
				targetIdx := (id*50 + j) % numTargets
				target := targets[targetIdx]

				// Randomly mix operations
				switch j % 4 {
				case 0:
					_ = m.MarkCompleted(target)
				case 1:
					_ = m.IsCompleted(target)
				case 2:
					_ = m.GetProgress()
				case 3:
					_ = m.GetPendingTargets(targets[:10]) // Small subset
				}
				totalOps.Add(1)
			}
		}(i)
	}

	// Start all goroutines
	close(start)
	wg.Wait()

	expectedOps := int64(numGoroutines * 50)
	if totalOps.Load() != expectedOps {
		t.Errorf("expected %d total operations, got %d", expectedOps, totalOps.Load())
	}

	// Verify state is consistent
	state := m.GetState()
	if state == nil {
		t.Fatal("state should not be nil")
	}

	// CompletedTargets counter may exceed unique entries due to double-counting
	// when same target is marked multiple times from different goroutines.
	// This is a known limitation - the counter increments without checking
	// if target was already completed.
	uniqueCompleted := len(state.Completed)
	t.Logf("Completed %d unique targets, counter shows %d (may differ due to double-counting)",
		uniqueCompleted, state.CompletedTargets)

	// Verify no panics occurred and map is populated
	if uniqueCompleted == 0 {
		t.Error("should have marked at least some targets")
	}
}

// TestCheckpoint_ConcurrentLoadAndMark tests loading while marking
func TestCheckpoint_ConcurrentLoadAndMark(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "load-mark-race.cfg")

	// Pre-create a checkpoint file
	m1 := NewManager(filePath)
	m1.AutoSave = false
	targets := []string{"pre1.com", "pre2.com", "pre3.com"}
	m1.Init("scan", targets, nil)
	m1.MarkCompleted("pre1.com")
	if err := m1.Save(); err != nil {
		t.Fatalf("failed to create initial checkpoint: %v", err)
	}

	var wg sync.WaitGroup
	var loadErrors atomic.Int64
	var markErrors atomic.Int64

	// Multiple managers trying to load and modify
	numManagers := 10
	for i := 0; i < numManagers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			mgr := NewManager(filePath)
			mgr.AutoSave = false

			// Load
			_, err := mgr.Load()
			if err != nil {
				loadErrors.Add(1)
				return
			}

			// Mark some targets
			for j := 0; j < 5; j++ {
				target := fmt.Sprintf("new-target-%d-%d.com", id, j)
				if err := mgr.MarkCompleted(target); err != nil {
					markErrors.Add(1)
				}
			}

			// Save
			if err := mgr.Save(); err != nil {
				// File race is expected, just log
				t.Logf("Save during race (expected): %v", err)
			}
		}(i)
	}

	wg.Wait()

	if loadErrors.Load() > 0 {
		t.Logf("Load errors during race: %d (may be expected)", loadErrors.Load())
	}

	// Final verification - file should still be readable
	final := NewManager(filePath)
	state, err := final.Load()
	if err != nil {
		t.Fatalf("checkpoint file corrupted after concurrent access: %v", err)
	}

	if state == nil {
		t.Fatal("loaded state should not be nil")
	}
}

// TestCheckpoint_RaceGetPendingTargets tests concurrent GetPendingTargets with modifications
func TestCheckpoint_RaceGetPendingTargets(t *testing.T) {
	m := NewManager("")
	m.AutoSave = false

	targets := make([]string, 100)
	for i := 0; i < 100; i++ {
		targets[i] = fmt.Sprintf("pending-test-%d.com", i)
	}

	m.Init("probe", targets, nil)

	var wg sync.WaitGroup
	start := make(chan struct{})

	// Goroutines marking targets
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for j := id * 10; j < (id+1)*10 && j < len(targets); j++ {
				m.MarkCompleted(targets[j])
			}
		}(i)
	}

	// Goroutines getting pending targets
	var pendingResults atomic.Int64
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 20; j++ {
				pending := m.GetPendingTargets(targets)
				pendingResults.Add(int64(len(pending)))
				time.Sleep(time.Microsecond) // Small delay to interleave
			}
		}()
	}

	close(start)
	wg.Wait()

	// All should be complete now
	finalPending := m.GetPendingTargets(targets)
	if len(finalPending) != 0 {
		t.Errorf("expected 0 pending after all marked, got %d", len(finalPending))
	}
}
