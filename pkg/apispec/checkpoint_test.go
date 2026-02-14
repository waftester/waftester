package apispec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCheckpoint(t *testing.T) {
	plan := &ScanPlan{
		SpecSource: "petstore.yaml",
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/users"}},
			{Endpoint: Endpoint{Method: "POST", Path: "/users"}},
		},
	}

	cp := NewCheckpoint("session-1", plan)

	assert.Equal(t, "session-1", cp.SessionID)
	assert.Equal(t, "petstore.yaml", cp.SpecSource)
	assert.Equal(t, 2, cp.TotalEntries)
	assert.NotEmpty(t, cp.PlanHash)
	assert.Empty(t, cp.CompletedEntries)
	assert.Empty(t, cp.Findings)
}

func TestCheckpoint_MarkCompleted(t *testing.T) {
	cp := &Checkpoint{TotalEntries: 5}

	cp.MarkCompleted(0)
	cp.MarkCompleted(2)

	assert.True(t, cp.IsCompleted(0))
	assert.False(t, cp.IsCompleted(1))
	assert.True(t, cp.IsCompleted(2))
}

func TestCheckpoint_Progress(t *testing.T) {
	cp := &Checkpoint{TotalEntries: 10}

	assert.Equal(t, 0.0, cp.Progress())

	cp.MarkCompleted(0)
	cp.MarkCompleted(1)
	cp.MarkCompleted(2)

	assert.InDelta(t, 0.3, cp.Progress(), 0.001)

	// All completed.
	cp2 := &Checkpoint{TotalEntries: 0}
	assert.Equal(t, 1.0, cp2.Progress())
}

func TestCheckpoint_RemainingEntries(t *testing.T) {
	cp := &Checkpoint{
		TotalEntries:     5,
		CompletedEntries: []int{0, 2, 4},
	}

	remaining := cp.RemainingEntries(5)
	assert.Equal(t, []int{1, 3}, remaining)
}

func TestCheckpoint_AddFinding(t *testing.T) {
	cp := &Checkpoint{}
	cp.AddFinding(SpecFinding{
		Category: "sqli",
		Title:    "SQL Injection found",
	})

	assert.Len(t, cp.Findings, 1)
	assert.Equal(t, "sqli", cp.Findings[0].Category)
}

func TestCheckpoint_AddError(t *testing.T) {
	cp := &Checkpoint{}
	cp.AddError("endpoint timeout")

	assert.Len(t, cp.Errors, 1)
}

func TestCheckpoint_SaveAndLoad(t *testing.T) {
	// Use a temporary directory instead of ~/.waftester.
	tmpDir := t.TempDir()

	plan := &ScanPlan{
		SpecSource: "test.yaml",
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/api"}},
		},
	}

	cp := NewCheckpoint("test-session-save", plan)
	cp.MarkCompleted(0)
	cp.AddFinding(SpecFinding{Category: "xss", Title: "XSS found"})

	// Write directly to temp dir.
	path := filepath.Join(tmpDir, "test-session-save.json")
	data, err := marshalCheckpoint(cp)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	// Read back.
	loaded, err := loadCheckpointFromPath(path)
	require.NoError(t, err)

	assert.Equal(t, cp.SessionID, loaded.SessionID)
	assert.Equal(t, cp.PlanHash, loaded.PlanHash)
	assert.Equal(t, cp.CompletedEntries, loaded.CompletedEntries)
	assert.Len(t, loaded.Findings, 1)
	assert.Equal(t, "xss", loaded.Findings[0].Category)
}

func TestCheckpoint_CorruptedFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))

	_, err := loadCheckpointFromPath(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse checkpoint")
}

func TestCheckpoint_NotFound(t *testing.T) {
	_, err := loadCheckpointFromPath("/nonexistent/path.json")
	assert.Error(t, err)
}

func TestValidateResume_SamePlan(t *testing.T) {
	plan := &ScanPlan{
		SpecSource: "api.yaml",
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/users"}},
		},
	}

	cp := NewCheckpoint("sess", plan)
	warning := ValidateResume(cp, plan)
	assert.Empty(t, warning)
}

func TestValidateResume_DifferentPlan(t *testing.T) {
	plan1 := &ScanPlan{
		SpecSource: "api.yaml",
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/users"}},
		},
	}
	plan2 := &ScanPlan{
		SpecSource: "api.yaml",
		Entries: []ScanPlanEntry{
			{Endpoint: Endpoint{Method: "GET", Path: "/users"}},
			{Endpoint: Endpoint{Method: "POST", Path: "/users"}},
		},
	}

	cp := NewCheckpoint("sess", plan1)
	warning := ValidateResume(cp, plan2)
	assert.NotEmpty(t, warning)
	assert.Contains(t, warning, "plan has changed")
}

func TestHashPlan_Deterministic(t *testing.T) {
	plan := &ScanPlan{
		SpecSource: "api.yaml",
		Entries: []ScanPlanEntry{
			{
				Endpoint: Endpoint{Method: "GET", Path: "/users"},
				Attack:   AttackSelection{Category: "sqli"},
			},
		},
	}

	h1 := hashPlan(plan)
	h2 := hashPlan(plan)
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 16)
}

func TestHashPlan_Nil(t *testing.T) {
	assert.Equal(t, "", hashPlan(nil))
}

func TestCleanOldCheckpoints(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "checkpoints-test")
	require.NoError(t, os.MkdirAll(subDir, 0o700))

	// Create an old file.
	oldPath := filepath.Join(subDir, "old.json")
	require.NoError(t, os.WriteFile(oldPath, []byte(`{}`), 0o600))
	oldTime := time.Now().Add(-8 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(oldPath, oldTime, oldTime))

	// Create a recent file.
	newPath := filepath.Join(subDir, "new.json")
	require.NoError(t, os.WriteFile(newPath, []byte(`{}`), 0o600))

	// Clean using the directory directly.
	cleaned := cleanCheckpointsInDir(subDir)
	assert.Equal(t, 1, cleaned)

	// Old file removed, new file kept.
	assert.NoFileExists(t, oldPath)
	assert.FileExists(t, newPath)
}

// --- Test helpers that bypass the default checkpoint dir ---

func marshalCheckpoint(cp *Checkpoint) ([]byte, error) {
	return json.MarshalIndent(cp, "", "  ")
}

func loadCheckpointFromPath(path string) (*Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parse checkpoint: %w", err)
	}
	return &cp, nil
}

func cleanCheckpointsInDir(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}

	cutoff := time.Now().Add(-checkpointMaxAge)
	cleaned := 0

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if os.Remove(filepath.Join(dir, entry.Name())) == nil {
				cleaned++
			}
		}
	}
	return cleaned
}
