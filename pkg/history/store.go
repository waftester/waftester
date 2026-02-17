// Package history provides file-based historical scan result storage.
// Historical data enables trend analysis, regression detection, and
// comparison across multiple WAF security assessments.
//
// Data is stored in JSON format for portability and simplicity.
// For high-volume production use, consider upgrading to a database backend.
package history

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Store manages historical scan data using JSON file storage.
type Store struct {
	mu       sync.RWMutex
	basePath string
	index    *storeIndex
}

// storeIndex tracks all stored scans for quick lookup.
type storeIndex struct {
	Scans map[string]*ScanRecord `json:"scans"`
}

// ScanRecord represents a stored scan result.
type ScanRecord struct {
	// ID is the unique scan identifier
	ID string `json:"id"`

	// Timestamp is when the scan was executed
	Timestamp time.Time `json:"timestamp"`

	// TargetURL is the scanned target
	TargetURL string `json:"target_url"`

	// WAFVendor is the detected WAF vendor
	WAFVendor string `json:"waf_vendor"`

	// Grade is the overall security grade (A+ to F)
	Grade string `json:"grade"`

	// DetectionRate is the percentage of attacks blocked
	DetectionRate float64 `json:"detection_rate"`

	// BypassCount is the number of bypasses found
	BypassCount int `json:"bypass_count"`

	// FalsePositiveCount is the number of false positives
	FalsePositiveCount int `json:"false_positive_count"`

	// TotalTests is the total number of tests executed
	TotalTests int `json:"total_tests"`

	// BlockedTests is the number of tests blocked
	BlockedTests int `json:"blocked_tests"`

	// PassedTests is the number of tests that passed
	PassedTests int `json:"passed_tests"`

	// Duration is the scan duration in milliseconds
	Duration int64 `json:"duration"`

	// AvgLatencyMs is the average response latency
	AvgLatencyMs int `json:"avg_latency_ms"`

	// P95LatencyMs is the 95th percentile latency
	P95LatencyMs int `json:"p95_latency_ms"`

	// CategoryScores maps category name to detection rate
	CategoryScores map[string]float64 `json:"category_scores"`

	// Version is the waftester version used
	Version string `json:"version"`

	// Tags are user-defined labels
	Tags []string `json:"tags"`

	// Notes are optional scan notes
	Notes string `json:"notes"`
}

// TrendPoint represents a single data point for trend visualization.
type TrendPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	Grade         string    `json:"grade"`
	DetectionRate float64   `json:"detection_rate"`
	BypassCount   int       `json:"bypass_count"`
}

// CategoryTrend represents category detection rate over time.
type CategoryTrend struct {
	Category string       `json:"category"`
	Points   []TrendPoint `json:"points"`
}

// ComparisonResult represents the difference between two scans.
type ComparisonResult struct {
	BaseID             string             `json:"base_id"`
	CompareID          string             `json:"compare_id"`
	BaseTimestamp      time.Time          `json:"base_timestamp"`
	CompareTimestamp   time.Time          `json:"compare_timestamp"`
	GradeChange        int                `json:"grade_change"`
	DetectionRateDelta float64            `json:"detection_rate_delta"`
	BypassCountDelta   int                `json:"bypass_count_delta"`
	FalsePositiveDelta int                `json:"false_positive_delta"`
	CategoryDeltas     map[string]float64 `json:"category_deltas"`
	Improved           bool               `json:"improved"`
}

// StoreStats contains storage statistics.
type StoreStats struct {
	TotalScans       int       `json:"total_scans"`
	UniqueTargets    int       `json:"unique_targets"`
	OldestScan       time.Time `json:"oldest_scan"`
	NewestScan       time.Time `json:"newest_scan"`
	StorageSizeBytes int64     `json:"storage_size_bytes"`
}

// NewStore creates a new history store at the specified directory.
func NewStore(basePath string) (*Store, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, err
	}

	store := &Store{
		basePath: basePath,
		index: &storeIndex{
			Scans: make(map[string]*ScanRecord),
		},
	}

	// Load existing index if present
	if err := store.loadIndex(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return store, nil
}

// indexPath returns the path to the store index file.
func (s *Store) indexPath() string {
	return filepath.Join(s.basePath, "index.json")
}

// loadIndex loads the store index from disk.
func (s *Store) loadIndex() error {
	data, err := os.ReadFile(s.indexPath())
	if err != nil {
		return err
	}
	return json.Unmarshal(data, s.index)
}

// saveIndex persists the store index to disk using atomic write.
// Writes to a temporary file first, then renames to prevent corruption.
func (s *Store) saveIndex() error {
	data, err := json.MarshalIndent(s.index, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := s.indexPath() + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.indexPath()); err != nil {
		os.Remove(tmpPath) // Clean up orphaned temp file
		return err
	}
	return nil
}

// Save stores a scan record.
func (s *Store) Save(record *ScanRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.index.Scans[record.ID] = record
	return s.saveIndex()
}

// copyScanRecord creates a deep copy of a ScanRecord.
func copyScanRecord(r *ScanRecord) *ScanRecord {
	c := *r
	if r.CategoryScores != nil {
		c.CategoryScores = make(map[string]float64, len(r.CategoryScores))
		for k, v := range r.CategoryScores {
			c.CategoryScores[k] = v
		}
	}
	if r.Tags != nil {
		c.Tags = make([]string, len(r.Tags))
		copy(c.Tags, r.Tags)
	}
	return &c
}

// Get retrieves a scan record by ID.
func (s *Store) Get(id string) (*ScanRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.index.Scans[id]
	if !ok {
		return nil, errors.New("scan not found")
	}
	return copyScanRecord(record), nil
}

// List retrieves scan records for a target within a time range.
func (s *Store) List(targetURL string, since, until time.Time, limit int) ([]*ScanRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var records []*ScanRecord
	for _, record := range s.index.Scans {
		if targetURL != "" && record.TargetURL != targetURL {
			continue
		}
		if record.Timestamp.Before(since) || record.Timestamp.After(until) {
			continue
		}
		records = append(records, copyScanRecord(record))
	}

	// Sort by timestamp descending
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.After(records[j].Timestamp)
	})

	// Apply limit
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}

	return records, nil
}

// GetTrend retrieves trend data for a target over time.
func (s *Store) GetTrend(targetURL string, since time.Time, maxPoints int) ([]TrendPoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var points []TrendPoint
	for _, record := range s.index.Scans {
		if targetURL != "" && record.TargetURL != targetURL {
			continue
		}
		if record.Timestamp.Before(since) {
			continue
		}
		points = append(points, TrendPoint{
			Timestamp:     record.Timestamp,
			Grade:         record.Grade,
			DetectionRate: record.DetectionRate,
			BypassCount:   record.BypassCount,
		})
	}

	// Sort by timestamp ascending
	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp.Before(points[j].Timestamp)
	})

	// Apply limit
	if maxPoints > 0 && len(points) > maxPoints {
		points = points[:maxPoints]
	}

	return points, nil
}

// GetCategoryTrends retrieves category-specific trends.
func (s *Store) GetCategoryTrends(targetURL string, since time.Time, categories []string) ([]CategoryTrend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	trends := make([]CategoryTrend, len(categories))
	for i, cat := range categories {
		trends[i] = CategoryTrend{
			Category: cat,
			Points:   []TrendPoint{},
		}
	}

	// Get matching scans
	for _, record := range s.index.Scans {
		if targetURL != "" && record.TargetURL != targetURL {
			continue
		}
		if record.Timestamp.Before(since) {
			continue
		}

		for i, cat := range categories {
			if rate, ok := record.CategoryScores[cat]; ok {
				trends[i].Points = append(trends[i].Points, TrendPoint{
					Timestamp:     record.Timestamp,
					DetectionRate: rate,
				})
			}
		}
	}

	// Sort each category's points
	for i := range trends {
		sort.Slice(trends[i].Points, func(a, b int) bool {
			return trends[i].Points[a].Timestamp.Before(trends[i].Points[b].Timestamp)
		})
	}

	return trends, nil
}

// Compare compares two scan records and returns the delta.
func (s *Store) Compare(baseID, compareID string) (*ComparisonResult, error) {
	base, err := s.Get(baseID)
	if err != nil {
		return nil, err
	}

	compare, err := s.Get(compareID)
	if err != nil {
		return nil, err
	}

	result := &ComparisonResult{
		BaseID:             baseID,
		CompareID:          compareID,
		BaseTimestamp:      base.Timestamp,
		CompareTimestamp:   compare.Timestamp,
		GradeChange:        gradeValue(compare.Grade) - gradeValue(base.Grade),
		DetectionRateDelta: compare.DetectionRate - base.DetectionRate,
		BypassCountDelta:   compare.BypassCount - base.BypassCount,
		FalsePositiveDelta: compare.FalsePositiveCount - base.FalsePositiveCount,
		CategoryDeltas:     make(map[string]float64),
	}

	// Calculate category deltas
	for cat, baseRate := range base.CategoryScores {
		if compareRate, ok := compare.CategoryScores[cat]; ok {
			result.CategoryDeltas[cat] = compareRate - baseRate
		}
	}

	// Determine if this is an improvement
	result.Improved = result.DetectionRateDelta > 0 && result.BypassCountDelta <= 0

	return result, nil
}

// gradeValue converts a grade to a numeric value for comparison.
func gradeValue(grade string) int {
	values := map[string]int{
		"A+": 12, "A": 11, "A-": 10,
		"B+": 9, "B": 8, "B-": 7,
		"C+": 6, "C": 5, "C-": 4,
		"D+": 3, "D": 2, "D-": 1,
		"F": 0,
	}
	if v, ok := values[grade]; ok {
		return v
	}
	return 0
}

// Delete removes a scan record.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.index.Scans[id]; !ok {
		return errors.New("scan not found")
	}

	delete(s.index.Scans, id)
	return s.saveIndex()
}

// Prune removes scan records older than the specified duration.
func (s *Store) Prune(olderThan time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	count := 0

	for id, record := range s.index.Scans {
		if record.Timestamp.Before(cutoff) {
			delete(s.index.Scans, id)
			count++
		}
	}

	if count > 0 {
		if err := s.saveIndex(); err != nil {
			return count, err
		}
	}

	return count, nil
}

// Stats returns storage statistics.
func (s *Store) Stats() (*StoreStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &StoreStats{
		TotalScans: len(s.index.Scans),
	}

	targets := make(map[string]bool)
	for _, record := range s.index.Scans {
		targets[record.TargetURL] = true
		if stats.OldestScan.IsZero() || record.Timestamp.Before(stats.OldestScan) {
			stats.OldestScan = record.Timestamp
		}
		if record.Timestamp.After(stats.NewestScan) {
			stats.NewestScan = record.Timestamp
		}
	}
	stats.UniqueTargets = len(targets)

	// Get storage size
	info, err := os.Stat(s.indexPath())
	if err == nil {
		stats.StorageSizeBytes = info.Size()
	}

	return stats, nil
}

// Close closes the store (no-op for file-based storage).
func (s *Store) Close() error {
	return nil
}

// ListAll returns all scan records, sorted by timestamp descending.
func (s *Store) ListAll(limit int) ([]*ScanRecord, error) {
	return s.List("", time.Time{}, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), limit)
}

// GetLatest returns the most recent scan for a target.
func (s *Store) GetLatest(targetURL string) (*ScanRecord, error) {
	records, err := s.List(targetURL, time.Time{}, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), 1)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no scans found for target")
	}
	return records[0], nil
}
