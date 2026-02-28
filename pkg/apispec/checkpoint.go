package apispec

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Checkpoint stores the state of an in-progress scan so it can be resumed.
type Checkpoint struct {
	mu sync.Mutex `json:"-"`

	// SessionID uniquely identifies this scan session.
	SessionID string `json:"session_id"`

	// PlanHash is a hash of the scan plan for detecting plan changes on resume.
	PlanHash string `json:"plan_hash"`

	// SpecSource identifies the spec file.
	SpecSource string `json:"spec_source"`

	// CompletedEntries tracks which plan entry indices have been completed.
	CompletedEntries []int `json:"completed_entries"`

	// Findings accumulated so far.
	Findings []SpecFinding `json:"findings"`

	// Errors accumulated so far.
	Errors []string `json:"errors,omitempty"`

	// CreatedAt is when the checkpoint was first created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the checkpoint was last updated.
	UpdatedAt time.Time `json:"updated_at"`

	// TotalEntries is the total number of plan entries.
	TotalEntries int `json:"total_entries"`
}

const (
	checkpointDirName = "checkpoints"
	checkpointMaxAge  = 7 * 24 * time.Hour
)

// CheckpointDir returns the directory for storing checkpoints.
// Default: ~/.waftester/checkpoints/
func CheckpointDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("checkpoint dir: %w", err)
	}
	return filepath.Join(home, ".waftester", checkpointDirName), nil
}

// checkpointPath returns the file path for a checkpoint.
func checkpointPath(sessionID string) (string, error) {
	dir, err := CheckpointDir()
	if err != nil {
		return "", err
	}
	// Sanitize sessionID to prevent path traversal.
	clean := filepath.Base(sessionID)
	if clean == "." || clean == ".." || clean != sessionID {
		return "", fmt.Errorf("invalid session ID: %q", sessionID)
	}
	return filepath.Join(dir, clean+".json"), nil
}

// NewCheckpoint creates a new checkpoint for a scan session.
func NewCheckpoint(sessionID string, plan *ScanPlan) *Checkpoint {
	now := time.Now()
	return &Checkpoint{
		SessionID:    sessionID,
		PlanHash:     hashPlan(plan),
		SpecSource:   plan.SpecSource,
		TotalEntries: len(plan.Entries),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// MarkCompleted records a plan entry index as completed.
func (c *Checkpoint) MarkCompleted(entryIndex int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.CompletedEntries = append(c.CompletedEntries, entryIndex)
	c.UpdatedAt = time.Now()
}

// AddFinding appends a finding to the checkpoint.
func (c *Checkpoint) AddFinding(f SpecFinding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Findings = append(c.Findings, f)
	c.UpdatedAt = time.Now()
}

// AddError appends an error to the checkpoint.
func (c *Checkpoint) AddError(errMsg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Errors = append(c.Errors, errMsg)
	c.UpdatedAt = time.Now()
}

// IsCompleted checks if a plan entry index has already been completed.
func (c *Checkpoint) IsCompleted(entryIndex int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, idx := range c.CompletedEntries {
		if idx == entryIndex {
			return true
		}
	}
	return false
}

// Progress returns the completion fraction (0.0 to 1.0).
func (c *Checkpoint) Progress() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.TotalEntries == 0 {
		return 1.0
	}
	return float64(len(c.CompletedEntries)) / float64(c.TotalEntries)
}

// RemainingEntries returns the indices of entries that haven't been completed.
func (c *Checkpoint) RemainingEntries(totalEntries int) []int {
	c.mu.Lock()
	completed := make(map[int]bool, len(c.CompletedEntries))
	for _, idx := range c.CompletedEntries {
		completed[idx] = true
	}
	c.mu.Unlock()

	var remaining []int
	for i := 0; i < totalEntries; i++ {
		if !completed[i] {
			remaining = append(remaining, i)
		}
	}
	return remaining
}

// Save writes the checkpoint to disk.
func (c *Checkpoint) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}

	path, pathErr := checkpointPath(c.SessionID)
	if pathErr != nil {
		return pathErr
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create checkpoint dir: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename checkpoint: %w", err)
	}

	return nil
}

// LoadCheckpoint loads a checkpoint from disk by session ID.
func LoadCheckpoint(sessionID string) (*Checkpoint, error) {
	path, err := checkpointPath(sessionID)
	if err != nil {
		return nil, err
	}

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

// DeleteCheckpoint removes a checkpoint file.
func DeleteCheckpoint(sessionID string) error {
	path, err := checkpointPath(sessionID)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// CleanOldCheckpoints removes checkpoint files older than 7 days.
func CleanOldCheckpoints() (int, error) {
	dir, err := CheckpointDir()
	if err != nil {
		return 0, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read checkpoint dir: %w", err)
	}

	cutoff := time.Now().Add(-checkpointMaxAge)
	cleaned := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			path := filepath.Join(dir, entry.Name())
			if err := os.Remove(path); err == nil {
				cleaned++
			}
		}
	}

	return cleaned, nil
}

// ValidateResume checks if a checkpoint is compatible with the current plan.
// Returns a warning message if there's a mismatch, empty string if OK.
func ValidateResume(cp *Checkpoint, plan *ScanPlan) string {
	currentHash := hashPlan(plan)
	if cp.PlanHash != currentHash {
		return fmt.Sprintf("plan has changed since checkpoint (spec: %s). "+
			"Checkpoint: %d entries, current plan: %d entries. "+
			"Results may be inconsistent.",
			cp.SpecSource, cp.TotalEntries, len(plan.Entries))
	}
	return ""
}

// hashPlan produces a deterministic hash of a scan plan for change detection.
func hashPlan(plan *ScanPlan) string {
	if plan == nil {
		return ""
	}

	h := sha256.New()
	h.Write([]byte(plan.SpecSource))
	for _, entry := range plan.Entries {
		h.Write([]byte(entry.Endpoint.Method))
		h.Write([]byte{0})
		h.Write([]byte(entry.Endpoint.Path))
		h.Write([]byte{0})
		h.Write([]byte(entry.Attack.Category))
		h.Write([]byte{0})
		h.Write([]byte(entry.InjectionTarget.Parameter))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}
