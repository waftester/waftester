// Memory provides learning memory for the Intelligence Engine
package intelligence

import (
	"strings"
	"sync"
)

// Memory stores and retrieves findings efficiently
type Memory struct {
	mu sync.RWMutex

	// All findings
	findings []*Finding

	// Indexes for fast lookup
	byCategory map[string][]*Finding
	byPhase    map[string][]*Finding
	byPath     map[string][]*Finding
	bypasses   []*Finding

	// Priority overrides
	categoryPriority map[string]string
}

// NewMemory creates a new memory store
func NewMemory() *Memory {
	return &Memory{
		findings:         make([]*Finding, 0),
		byCategory:       make(map[string][]*Finding),
		byPhase:          make(map[string][]*Finding),
		byPath:           make(map[string][]*Finding),
		bypasses:         make([]*Finding, 0),
		categoryPriority: make(map[string]string),
	}
}

// Store adds a finding to memory
func (m *Memory) Store(f *Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.findings = append(m.findings, f)

	// Index by category
	m.byCategory[f.Category] = append(m.byCategory[f.Category], f)

	// Index by phase
	m.byPhase[f.Phase] = append(m.byPhase[f.Phase], f)

	// Index by path
	m.byPath[f.Path] = append(m.byPath[f.Path], f)

	// Track bypasses
	if !f.Blocked {
		m.bypasses = append(m.bypasses, f)
	}
}

// GetByCategory returns findings by category
func (m *Memory) GetByCategory(category string) []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if findings, ok := m.byCategory[category]; ok {
		result := make([]*Finding, len(findings))
		copy(result, findings)
		return result
	}
	return nil
}

// GetByPhase returns findings by phase
func (m *Memory) GetByPhase(phase string) []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if findings, ok := m.byPhase[phase]; ok {
		result := make([]*Finding, len(findings))
		copy(result, findings)
		return result
	}
	return nil
}

// GetByPath returns findings matching any of the path patterns
func (m *Memory) GetByPath(patterns ...string) []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Finding, 0)
	for _, f := range m.findings {
		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(f.Path), strings.ToLower(pattern)) {
				result = append(result, f)
				break
			}
		}
	}
	return result
}

// GetBypasses returns all non-blocked findings
func (m *Memory) GetBypasses() []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Finding, len(m.bypasses))
	copy(result, m.bypasses)
	return result
}

// GetSimilarBypasses returns bypasses similar to the given finding
func (m *Memory) GetSimilarBypasses(f *Finding, minCount int) []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	similar := make([]*Finding, 0)
	for _, b := range m.bypasses {
		if b == f {
			continue
		}
		// Same category counts as similar
		if b.Category == f.Category {
			similar = append(similar, b)
		}
	}
	return similar
}

// GetAll returns all findings
func (m *Memory) GetAll() []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Finding, len(m.findings))
	copy(result, m.findings)
	return result
}

// Count returns total finding count
func (m *Memory) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.findings)
}

// CountBlocked returns count of blocked findings
func (m *Memory) CountBlocked() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, f := range m.findings {
		if f.Blocked {
			count++
		}
	}
	return count
}

// SetPriority sets category priority
func (m *Memory) SetPriority(category, priority string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.categoryPriority[category] = priority
}

// GetPriority returns category priority
func (m *Memory) GetPriority(category string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if p, ok := m.categoryPriority[category]; ok {
		return p
	}
	return "normal"
}
