// Package intelligence provides adaptive learning capabilities for WAFtester.
// Memory provides finding storage with efficient indexing for the Intelligence Engine.
package intelligence

import (
	"strings"
	"sync"
)

// Memory capacity constants.
const (
	// DefaultMaxFindings is the default maximum number of findings to store.
	DefaultMaxFindings = 10000

	// DefaultEvictionPercent is the percentage of oldest findings to evict when at capacity.
	DefaultEvictionPercent = 0.10
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
	bySeverity map[string][]*Finding
	bypasses   []*Finding

	// Priority overrides
	categoryPriority map[string]string

	// Capacity limits
	maxFindings int
}

// NewMemory creates a new memory store
func NewMemory() *Memory {
	return &Memory{
		findings:         make([]*Finding, 0),
		byCategory:       make(map[string][]*Finding),
		byPhase:          make(map[string][]*Finding),
		byPath:           make(map[string][]*Finding),
		bySeverity:       make(map[string][]*Finding),
		bypasses:         make([]*Finding, 0),
		categoryPriority: make(map[string]string),
		maxFindings:      DefaultMaxFindings,
	}
}

// SetMaxFindings sets the maximum number of findings to store.
// Values <= 0 disable the limit.
func (m *Memory) SetMaxFindings(max int) {
	if max < 0 {
		max = 0 // Treat negative as "no limit"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxFindings = max
}

// Store adds a finding to memory
func (m *Memory) Store(f *Finding) {
	if f == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Evict oldest if at capacity
	if m.maxFindings > 0 && len(m.findings) >= m.maxFindings {
		m.evictOldest()
	}

	m.findings = append(m.findings, f)

	// Index by category
	m.byCategory[f.Category] = append(m.byCategory[f.Category], f)

	// Index by phase
	m.byPhase[f.Phase] = append(m.byPhase[f.Phase], f)

	// Index by path
	m.byPath[f.Path] = append(m.byPath[f.Path], f)

	// Index by severity
	m.bySeverity[f.Severity] = append(m.bySeverity[f.Severity], f)

	// Track bypasses
	if !f.Blocked {
		m.bypasses = append(m.bypasses, f)
	}
}

// evictOldest removes the oldest DefaultEvictionPercent of findings (must hold lock).
// This implements a simple LRU-style eviction to prevent unbounded memory growth.
func (m *Memory) evictOldest() {
	evictCount := int(float64(len(m.findings)) * DefaultEvictionPercent)
	if evictCount < 1 {
		evictCount = 1
	}

	// Remove oldest findings from the main slice
	m.findings = m.findings[evictCount:]

	// Rebuild all indexes from the remaining findings.
	// This is O(n) total vs the previous O(evictCount × indexSize × 5)
	// approach which did linear scans per evicted finding per index.
	m.rebuildIndexes()
}

// rebuildIndexes reconstructs all secondary indexes from the primary findings slice.
// Must hold m.mu write lock.
func (m *Memory) rebuildIndexes() {
	m.byCategory = make(map[string][]*Finding, len(m.byCategory))
	m.byPhase = make(map[string][]*Finding, len(m.byPhase))
	m.byPath = make(map[string][]*Finding, len(m.byPath))
	m.bySeverity = make(map[string][]*Finding, len(m.bySeverity))
	m.bypasses = m.bypasses[:0]

	for _, f := range m.findings {
		m.byCategory[f.Category] = append(m.byCategory[f.Category], f)
		m.byPhase[f.Phase] = append(m.byPhase[f.Phase], f)
		m.byPath[f.Path] = append(m.byPath[f.Path], f)
		m.bySeverity[f.Severity] = append(m.bySeverity[f.Severity], f)
		if !f.Blocked {
			m.bypasses = append(m.bypasses, f)
		}
	}
}

// GetByCategory returns findings by category (returns empty slice if none found)
func (m *Memory) GetByCategory(category string) []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if findings, ok := m.byCategory[category]; ok {
		result := make([]*Finding, len(findings))
		copy(result, findings)
		return result
	}
	return make([]*Finding, 0)
}

// GetByPhase returns findings by phase (returns empty slice if none found)
func (m *Memory) GetByPhase(phase string) []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if findings, ok := m.byPhase[phase]; ok {
		result := make([]*Finding, len(findings))
		copy(result, findings)
		return result
	}
	return make([]*Finding, 0)
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

// GetSimilarBypasses returns bypasses similar to the given finding.
// Returns nil if f is nil. Returns at most minCount results (0 = unlimited).
func (m *Memory) GetSimilarBypasses(f *Finding, minCount int) []*Finding {
	if f == nil {
		return nil
	}
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
			// Limit results if minCount specified
			if minCount > 0 && len(similar) >= minCount {
				break
			}
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
