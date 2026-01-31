// Package checkpoint provides scan resume/checkpoint functionality
package checkpoint

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State represents the checkpoint state for resumable scans
type State struct {
	// Version of the checkpoint format
	Version string `json:"version"`

	// Command being run (probe, scan, fuzz, etc.)
	Command string `json:"command"`

	// StartTime when the scan began
	StartTime time.Time `json:"start_time"`

	// LastUpdate when checkpoint was last saved
	LastUpdate time.Time `json:"last_update"`

	// TotalTargets is the total number of targets
	TotalTargets int `json:"total_targets"`

	// CompletedTargets is the number of completed targets
	CompletedTargets int `json:"completed_targets"`

	// Completed is a map of target -> completion status
	Completed map[string]bool `json:"completed"`

	// Flags stores the original command flags for resumption
	Flags map[string]interface{} `json:"flags,omitempty"`

	mu sync.Mutex `json:"-"`
}

// Manager handles checkpoint operations
type Manager struct {
	// FilePath is the path to the checkpoint file
	FilePath string

	// AutoSave enables automatic saving after each target
	AutoSave bool

	// SaveInterval is how often to save (if AutoSave is false)
	SaveInterval int

	state *State
	mu    sync.Mutex
}

// NewManager creates a new checkpoint manager
func NewManager(filePath string) *Manager {
	if filePath == "" {
		filePath = "resume.cfg"
	}
	return &Manager{
		FilePath:     filePath,
		AutoSave:     true,
		SaveInterval: 10, // Save every 10 targets by default
	}
}

// Init initializes a new checkpoint state
func (m *Manager) Init(command string, targets []string, flags map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.state = &State{
		Version:      "1.0",
		Command:      command,
		StartTime:    time.Now(),
		LastUpdate:   time.Now(),
		TotalTargets: len(targets),
		Completed:    make(map[string]bool),
		Flags:        flags,
	}
}

// Load loads checkpoint state from file
func (m *Manager) Load() (*State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.FilePath)
	if err != nil {
		return nil, err
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	m.state = &state
	return &state, nil
}

// Save saves the current checkpoint state to file
func (m *Manager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == nil {
		return nil
	}

	m.state.LastUpdate = time.Now()

	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}

	// Write to temp file first, then rename (atomic)
	tempFile := m.FilePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return err
	}

	return os.Rename(tempFile, m.FilePath)
}

// MarkCompleted marks a target as completed
func (m *Manager) MarkCompleted(target string) error {
	m.mu.Lock()
	if m.state == nil {
		m.mu.Unlock()
		return nil
	}
	m.state.mu.Lock()
	m.state.Completed[target] = true
	m.state.CompletedTargets++
	count := m.state.CompletedTargets
	m.state.mu.Unlock()
	m.mu.Unlock()

	// Auto-save if enabled
	if m.AutoSave {
		return m.Save()
	}

	// Periodic save
	if m.SaveInterval > 0 && count%m.SaveInterval == 0 {
		return m.Save()
	}

	return nil
}

// IsCompleted checks if a target has been completed
func (m *Manager) IsCompleted(target string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == nil {
		return false
	}

	m.state.mu.Lock()
	defer m.state.mu.Unlock()

	return m.state.Completed[target]
}

// GetPendingTargets returns targets that haven't been completed yet
func (m *Manager) GetPendingTargets(allTargets []string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == nil {
		return allTargets
	}

	m.state.mu.Lock()
	defer m.state.mu.Unlock()

	pending := make([]string, 0, len(allTargets))
	for _, t := range allTargets {
		if !m.state.Completed[t] {
			pending = append(pending, t)
		}
	}

	return pending
}

// GetState returns the current checkpoint state
func (m *Manager) GetState() *State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Delete removes the checkpoint file
func (m *Manager) Delete() error {
	return os.Remove(m.FilePath)
}

// Exists checks if a checkpoint file exists
func (m *Manager) Exists() bool {
	_, err := os.Stat(m.FilePath)
	return err == nil
}

// GetProgress returns progress as percentage
func (m *Manager) GetProgress() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state == nil || m.state.TotalTargets == 0 {
		return 0
	}

	return float64(m.state.CompletedTargets) / float64(m.state.TotalTargets) * 100
}

// SaveCompletedToFile appends completed targets to a simple text file (legacy format)
func SaveCompletedToFile(filePath, target string) error {
	dir := filepath.Dir(filePath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(target + "\n")
	return err
}

// LoadCompletedFromFile loads completed targets from a simple text file
func LoadCompletedFromFile(filePath string) (map[string]bool, error) {
	completed := make(map[string]bool)

	f, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return completed, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			completed[line] = true
		}
	}

	return completed, scanner.Err()
}
