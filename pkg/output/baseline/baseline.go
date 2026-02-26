package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// Version is the current baseline file format version.
const Version = "1.0"

// ErrBaselineNotFound is returned when a baseline file does not exist.
var ErrBaselineNotFound = errors.New("baseline file not found")

// ErrInvalidBaseline is returned when a baseline file is malformed.
var ErrInvalidBaseline = errors.New("invalid baseline file")

// Baseline represents a baseline of known bypasses from a reference scan.
type Baseline struct {
	Version   string          `json:"version"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	ScanID    string          `json:"scan_id"`
	Target    string          `json:"target"`
	Bypasses  []BypassEntry   `json:"bypasses"`
	Summary   BaselineSummary `json:"summary"`

	mu sync.RWMutex
}

// BaselineSummary contains aggregate statistics from the baseline scan.
type BaselineSummary struct {
	TotalBypasses int     `json:"total_bypasses"`
	Effectiveness float64 `json:"effectiveness"`
}

// BypassEntry represents a single bypass record in the baseline.
type BypassEntry struct {
	ID          string    `json:"id"`
	Category    string    `json:"category"`
	Severity    string    `json:"severity"`
	PayloadHash string    `json:"payload_hash"`
	TargetPath  string    `json:"target_path"`
	FirstSeen   time.Time `json:"first_seen"`
}

// ComparisonResult contains the outcome of comparing current bypasses against a baseline.
type ComparisonResult struct {
	// NewBypasses contains bypasses in current scan but not in baseline.
	NewBypasses []BypassEntry

	// FixedBypasses contains bypasses in baseline but not in current scan.
	FixedBypasses []BypassEntry

	// UnchangedBypasses contains bypasses present in both baseline and current scan.
	UnchangedBypasses []BypassEntry

	// HasNewBypasses is true if there are any new bypasses.
	HasNewBypasses bool

	// Summary is a human-readable summary of the comparison.
	Summary string
}

// New creates a new empty baseline.
func New() *Baseline {
	now := time.Now().UTC()
	return &Baseline{
		Version:   Version,
		CreatedAt: now,
		UpdatedAt: now,
		Bypasses:  []BypassEntry{},
		Summary:   BaselineSummary{},
	}
}

// LoadBaseline loads and parses a baseline file from the given path.
// Returns ErrBaselineNotFound if the file doesn't exist.
// Returns ErrInvalidBaseline if the file is malformed.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrBaselineNotFound
		}
		return nil, fmt.Errorf("reading baseline file: %w", err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBaseline, err)
	}

	// Validate required fields
	if b.Version == "" {
		return nil, fmt.Errorf("%w: missing version field", ErrInvalidBaseline)
	}

	return &b, nil
}

// SaveBaseline saves the baseline to the given path.
func (b *Baseline) SaveBaseline(path string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Update timestamp on save
	b.UpdatedAt = time.Now().UTC()

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing baseline file: %w", err)
	}

	return nil
}

// Compare compares the given current bypasses against the baseline.
// It returns a ComparisonResult indicating new, fixed, and unchanged bypasses.
func (b *Baseline) Compare(current []BypassEntry) ComparisonResult {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Build lookup map by payload hash for baseline bypasses
	baselineMap := make(map[string]BypassEntry, len(b.Bypasses))
	for _, entry := range b.Bypasses {
		baselineMap[entry.PayloadHash] = entry
	}

	// Build lookup map for current bypasses
	currentMap := make(map[string]BypassEntry, len(current))
	for _, entry := range current {
		currentMap[entry.PayloadHash] = entry
	}

	result := ComparisonResult{
		NewBypasses:       []BypassEntry{},
		FixedBypasses:     []BypassEntry{},
		UnchangedBypasses: []BypassEntry{},
	}

	// Find new and unchanged bypasses
	for _, entry := range current {
		if _, exists := baselineMap[entry.PayloadHash]; exists {
			result.UnchangedBypasses = append(result.UnchangedBypasses, entry)
		} else {
			result.NewBypasses = append(result.NewBypasses, entry)
		}
	}

	// Find fixed bypasses (in baseline but not in current)
	for _, entry := range b.Bypasses {
		if _, exists := currentMap[entry.PayloadHash]; !exists {
			result.FixedBypasses = append(result.FixedBypasses, entry)
		}
	}

	result.HasNewBypasses = len(result.NewBypasses) > 0

	// Generate summary
	result.Summary = b.generateSummary(result)

	return result
}

// generateSummary creates a human-readable summary of the comparison result.
func (b *Baseline) generateSummary(result ComparisonResult) string {
	var summary string

	if result.HasNewBypasses {
		summary = fmt.Sprintf("REGRESSION: %d new bypass(es) detected", len(result.NewBypasses))
	} else {
		summary = "No new bypasses detected"
	}

	if len(result.FixedBypasses) > 0 {
		summary += fmt.Sprintf(", %d bypass(es) fixed", len(result.FixedBypasses))
	}

	if len(result.UnchangedBypasses) > 0 {
		summary += fmt.Sprintf(", %d unchanged", len(result.UnchangedBypasses))
	}

	return summary
}

// CreateFromResults creates a new baseline from scan results.
// Only results with OutcomeBypass are included in the baseline.
func CreateFromResults(results []*events.ResultEvent, scanID, target string) *Baseline {
	now := time.Now().UTC()

	b := &Baseline{
		Version:   Version,
		CreatedAt: now,
		UpdatedAt: now,
		ScanID:    scanID,
		Target:    target,
		Bypasses:  []BypassEntry{},
	}

	bypasses := ExtractBypasses(results)

	// Set FirstSeen for all new bypasses
	for i := range bypasses {
		bypasses[i].FirstSeen = now
	}

	b.Bypasses = bypasses
	b.Summary = BaselineSummary{
		TotalBypasses: len(bypasses),
		Effectiveness: calculateEffectiveness(results),
	}

	return b
}

// ExtractBypasses extracts bypass entries from scan results.
// Only results with OutcomeBypass are included.
func ExtractBypasses(results []*events.ResultEvent) []BypassEntry {
	bypasses := []BypassEntry{}
	seen := make(map[string]bool)

	for _, r := range results {
		if r == nil || r.Result.Outcome != events.OutcomeBypass {
			continue
		}

		payload := ""
		if r.Evidence != nil {
			payload = r.Evidence.Payload
		}

		hash := hashPayload(payload)

		// Deduplicate by hash
		if seen[hash] {
			continue
		}
		seen[hash] = true

		entry := BypassEntry{
			ID:          r.Test.ID,
			Category:    r.Test.Category,
			Severity:    string(r.Test.Severity),
			PayloadHash: hash,
			TargetPath:  r.Target.Endpoint,
		}

		bypasses = append(bypasses, entry)
	}

	// Sort for deterministic output
	sort.Slice(bypasses, func(i, j int) bool {
		if bypasses[i].Category != bypasses[j].Category {
			return bypasses[i].Category < bypasses[j].Category
		}
		return bypasses[i].ID < bypasses[j].ID
	})

	return bypasses
}

// hashPayload computes the SHA256 hash of a payload string.
func hashPayload(payload string) string {
	h := sha256.New()
	h.Write([]byte(payload))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// calculateEffectiveness calculates the WAF effectiveness percentage from results.
func calculateEffectiveness(results []*events.ResultEvent) float64 {
	if len(results) == 0 {
		return 0
	}

	blocked := 0
	total := 0

	for _, r := range results {
		if r == nil {
			continue
		}

		total++
		if r.Result.Outcome == events.OutcomeBlocked {
			blocked++
		}
	}

	if total == 0 {
		return 0
	}

	return float64(blocked) / float64(total) * 100
}

// AddBypass adds a bypass entry to the baseline.
// Thread-safe.
func (b *Baseline) AddBypass(entry BypassEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check for duplicate by hash
	for _, existing := range b.Bypasses {
		if existing.PayloadHash == entry.PayloadHash {
			return // Already exists
		}
	}

	if entry.FirstSeen.IsZero() {
		entry.FirstSeen = time.Now().UTC()
	}

	b.Bypasses = append(b.Bypasses, entry)
	b.Summary.TotalBypasses = len(b.Bypasses)
	b.UpdatedAt = time.Now().UTC()
}

// RemoveBypass removes a bypass entry by payload hash.
// Thread-safe.
func (b *Baseline) RemoveBypass(payloadHash string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, entry := range b.Bypasses {
		if entry.PayloadHash == payloadHash {
			b.Bypasses = append(b.Bypasses[:i], b.Bypasses[i+1:]...)
			b.Summary.TotalBypasses = len(b.Bypasses)
			b.UpdatedAt = time.Now().UTC()
			return true
		}
	}

	return false
}

// GetBypass returns a bypass entry by payload hash.
// Thread-safe.
func (b *Baseline) GetBypass(payloadHash string) (BypassEntry, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, entry := range b.Bypasses {
		if entry.PayloadHash == payloadHash {
			return entry, true
		}
	}

	return BypassEntry{}, false
}

// Len returns the number of bypasses in the baseline.
// Thread-safe.
func (b *Baseline) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.Bypasses)
}

// Merge merges another baseline into this one, preserving earliest FirstSeen times.
// Thread-safe.
func (b *Baseline) Merge(other *Baseline) {
	if other == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	other.mu.RLock()
	defer other.mu.RUnlock()

	// Build lookup map
	existingMap := make(map[string]*BypassEntry, len(b.Bypasses))
	for i := range b.Bypasses {
		existingMap[b.Bypasses[i].PayloadHash] = &b.Bypasses[i]
	}

	for _, entry := range other.Bypasses {
		if existing, ok := existingMap[entry.PayloadHash]; ok {
			// Preserve earliest FirstSeen
			if entry.FirstSeen.Before(existing.FirstSeen) {
				existing.FirstSeen = entry.FirstSeen
			}
		} else {
			b.Bypasses = append(b.Bypasses, entry)
		}
	}

	b.Summary.TotalBypasses = len(b.Bypasses)
	b.UpdatedAt = time.Now().UTC()
}
