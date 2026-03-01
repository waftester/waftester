// Package intelligence provides adaptive learning capabilities for WAFtester.
// Stats tracks engine statistics including phase timing, finding counts, and bypass rates.
package intelligence

import (
	"sort"
	"sync"
	"time"
)

// Stats tracks engine statistics
type Stats struct {
	mu sync.RWMutex

	// Phase timing
	phaseStart    map[string]time.Time
	phaseDuration map[string]time.Duration

	// Finding counts
	findingsByCategory map[string]int
	findingsByPhase    map[string]int
	findingsBySeverity map[string]int

	// Bypass tracking
	bypassesByCategory map[string]int
	blocksByCategory   map[string]int

	// Timing
	startTime  time.Time
	totalTime  time.Duration
	phaseOrder []string
}

// NewStats creates a new statistics tracker
func NewStats() *Stats {
	return &Stats{
		phaseStart:         make(map[string]time.Time),
		phaseDuration:      make(map[string]time.Duration),
		findingsByCategory: make(map[string]int),
		findingsByPhase:    make(map[string]int),
		findingsBySeverity: make(map[string]int),
		bypassesByCategory: make(map[string]int),
		blocksByCategory:   make(map[string]int),
		phaseOrder:         make([]string, 0),
		startTime:          time.Now(),
	}
}

// StartPhase records phase start time
func (s *Stats) StartPhase(phase string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if phase already exists to prevent duplicates in phaseOrder
	if _, exists := s.phaseStart[phase]; !exists {
		s.phaseOrder = append(s.phaseOrder, phase)
	}
	s.phaseStart[phase] = time.Now()
}

// EndPhase records phase end time
func (s *Stats) EndPhase(phase string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if start, ok := s.phaseStart[phase]; ok {
		s.phaseDuration[phase] = time.Since(start)
	}
}

// RecordFinding records a finding in statistics.
// Safe to call with nil finding (no-op).
// When isTesting is false (recon phase), the finding is counted by
// category/phase/severity but NOT in bypass/block counters, since
// recon findings have Blocked=false by default which would inflate bypass counts.
func (s *Stats) RecordFinding(f *Finding, isTesting bool) {
	if f == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.findingsByCategory[f.Category]++
	s.findingsByPhase[f.Phase]++
	s.findingsBySeverity[f.Severity]++

	if isTesting {
		if f.Blocked {
			s.blocksByCategory[f.Category]++
		} else if f.StatusCode > 0 {
			// Only count as bypass if StatusCode > 0. Skipped/dropped tests
			// have StatusCode=0 and Blocked=false, which would falsely
			// inflate per-category bypass rates.
			s.bypassesByCategory[f.Category]++
		}
	}
}

// TopCategories returns top N categories by finding count
func (s *Stats) TopCategories(n int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type catCount struct {
		cat   string
		count int
	}

	counts := make([]catCount, 0, len(s.findingsByCategory))
	for cat, count := range s.findingsByCategory {
		counts = append(counts, catCount{cat, count})
	}

	sort.Slice(counts, func(i, j int) bool {
		return counts[i].count > counts[j].count
	})

	result := make([]string, 0, n)
	for i, cc := range counts {
		if i >= n {
			break
		}
		result = append(result, cc.cat)
	}
	return result
}

// GetPhaseDuration returns duration for a phase
func (s *Stats) GetPhaseDuration(phase string) time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.phaseDuration[phase]
}

// GetTotalDuration returns total elapsed time
func (s *Stats) GetTotalDuration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.startTime)
}

// GetBypassRate returns bypass rate for a category
func (s *Stats) GetBypassRate(category string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bypasses := s.bypassesByCategory[category]
	blocks := s.blocksByCategory[category]
	total := bypasses + blocks
	if total == 0 {
		return 0
	}
	return float64(bypasses) / float64(total)
}

// GetSeverityDistribution returns finding distribution by severity
func (s *Stats) GetSeverityDistribution() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]int)
	for k, v := range s.findingsBySeverity {
		result[k] = v
	}
	return result
}

// GetPhaseOrder returns the order of executed phases
func (s *Stats) GetPhaseOrder() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]string, len(s.phaseOrder))
	copy(result, s.phaseOrder)
	return result
}
