package baseline

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

func TestNew(t *testing.T) {
	b := New()

	if b.Version != Version {
		t.Errorf("Version = %q, want %q", b.Version, Version)
	}

	if b.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}

	if b.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should not be zero")
	}

	if len(b.Bypasses) != 0 {
		t.Errorf("Bypasses length = %d, want 0", len(b.Bypasses))
	}
}

func TestLoadBaseline_FileNotFound(t *testing.T) {
	_, err := LoadBaseline("/nonexistent/path/baseline.json")

	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}

	if err != ErrBaselineNotFound {
		t.Errorf("err = %v, want ErrBaselineNotFound", err)
	}
}

func TestLoadBaseline_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "invalid.json")

	if err := os.WriteFile(path, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := LoadBaseline(path)

	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadBaseline_MissingVersion(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "noversion.json")

	data := `{"created_at": "2026-01-15T10:30:00Z", "bypasses": []}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := LoadBaseline(path)

	if err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestSaveAndLoadBaseline(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "baseline.json")

	original := New()
	original.ScanID = "test-scan-123"
	original.Target = "https://example.com"
	original.Bypasses = []BypassEntry{
		{
			ID:          "sqli-001",
			Category:    "sqli",
			Severity:    "critical",
			PayloadHash: "sha256:abc123",
			TargetPath:  "/api/users",
			FirstSeen:   time.Now().UTC(),
		},
	}
	original.Summary = BaselineSummary{
		TotalBypasses: 1,
		Effectiveness: 95.0,
	}

	if err := original.SaveBaseline(path); err != nil {
		t.Fatalf("SaveBaseline() error = %v", err)
	}

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline() error = %v", err)
	}

	if loaded.Version != original.Version {
		t.Errorf("Version = %q, want %q", loaded.Version, original.Version)
	}

	if loaded.ScanID != original.ScanID {
		t.Errorf("ScanID = %q, want %q", loaded.ScanID, original.ScanID)
	}

	if loaded.Target != original.Target {
		t.Errorf("Target = %q, want %q", loaded.Target, original.Target)
	}

	if len(loaded.Bypasses) != len(original.Bypasses) {
		t.Errorf("Bypasses length = %d, want %d", len(loaded.Bypasses), len(original.Bypasses))
	}

	if loaded.Summary.TotalBypasses != original.Summary.TotalBypasses {
		t.Errorf("TotalBypasses = %d, want %d", loaded.Summary.TotalBypasses, original.Summary.TotalBypasses)
	}
}

func TestCompare_NewBypasses(t *testing.T) {
	baseline := New()
	baseline.Bypasses = []BypassEntry{
		{ID: "existing", PayloadHash: "sha256:existing"},
	}

	current := []BypassEntry{
		{ID: "existing", PayloadHash: "sha256:existing"},
		{ID: "new-bypass", PayloadHash: "sha256:new"},
	}

	result := baseline.Compare(current)

	if !result.HasNewBypasses {
		t.Error("HasNewBypasses should be true")
	}

	if len(result.NewBypasses) != 1 {
		t.Errorf("NewBypasses length = %d, want 1", len(result.NewBypasses))
	}

	if result.NewBypasses[0].ID != "new-bypass" {
		t.Errorf("NewBypasses[0].ID = %q, want %q", result.NewBypasses[0].ID, "new-bypass")
	}

	if len(result.UnchangedBypasses) != 1 {
		t.Errorf("UnchangedBypasses length = %d, want 1", len(result.UnchangedBypasses))
	}
}

func TestCompare_FixedBypasses(t *testing.T) {
	baseline := New()
	baseline.Bypasses = []BypassEntry{
		{ID: "still-there", PayloadHash: "sha256:still"},
		{ID: "now-fixed", PayloadHash: "sha256:fixed"},
	}

	current := []BypassEntry{
		{ID: "still-there", PayloadHash: "sha256:still"},
	}

	result := baseline.Compare(current)

	if result.HasNewBypasses {
		t.Error("HasNewBypasses should be false")
	}

	if len(result.FixedBypasses) != 1 {
		t.Errorf("FixedBypasses length = %d, want 1", len(result.FixedBypasses))
	}

	if result.FixedBypasses[0].ID != "now-fixed" {
		t.Errorf("FixedBypasses[0].ID = %q, want %q", result.FixedBypasses[0].ID, "now-fixed")
	}
}

func TestCompare_NoChanges(t *testing.T) {
	baseline := New()
	baseline.Bypasses = []BypassEntry{
		{ID: "bypass-1", PayloadHash: "sha256:hash1"},
		{ID: "bypass-2", PayloadHash: "sha256:hash2"},
	}

	current := []BypassEntry{
		{ID: "bypass-1", PayloadHash: "sha256:hash1"},
		{ID: "bypass-2", PayloadHash: "sha256:hash2"},
	}

	result := baseline.Compare(current)

	if result.HasNewBypasses {
		t.Error("HasNewBypasses should be false")
	}

	if len(result.NewBypasses) != 0 {
		t.Errorf("NewBypasses length = %d, want 0", len(result.NewBypasses))
	}

	if len(result.FixedBypasses) != 0 {
		t.Errorf("FixedBypasses length = %d, want 0", len(result.FixedBypasses))
	}

	if len(result.UnchangedBypasses) != 2 {
		t.Errorf("UnchangedBypasses length = %d, want 2", len(result.UnchangedBypasses))
	}
}

func TestCompare_EmptyBaseline(t *testing.T) {
	baseline := New()

	current := []BypassEntry{
		{ID: "new-1", PayloadHash: "sha256:new1"},
		{ID: "new-2", PayloadHash: "sha256:new2"},
	}

	result := baseline.Compare(current)

	if !result.HasNewBypasses {
		t.Error("HasNewBypasses should be true")
	}

	if len(result.NewBypasses) != 2 {
		t.Errorf("NewBypasses length = %d, want 2", len(result.NewBypasses))
	}
}

func TestCompare_EmptyCurrent(t *testing.T) {
	baseline := New()
	baseline.Bypasses = []BypassEntry{
		{ID: "fixed-1", PayloadHash: "sha256:fixed1"},
	}

	result := baseline.Compare([]BypassEntry{})

	if result.HasNewBypasses {
		t.Error("HasNewBypasses should be false")
	}

	if len(result.FixedBypasses) != 1 {
		t.Errorf("FixedBypasses length = %d, want 1", len(result.FixedBypasses))
	}
}

func TestCompare_Summary(t *testing.T) {
	baseline := New()
	baseline.Bypasses = []BypassEntry{
		{ID: "unchanged", PayloadHash: "sha256:unchanged"},
		{ID: "fixed", PayloadHash: "sha256:fixed"},
	}

	current := []BypassEntry{
		{ID: "unchanged", PayloadHash: "sha256:unchanged"},
		{ID: "new", PayloadHash: "sha256:new"},
	}

	result := baseline.Compare(current)

	if result.Summary == "" {
		t.Error("Summary should not be empty")
	}

	// Summary should mention regression for new bypasses
	if !result.HasNewBypasses {
		t.Error("HasNewBypasses should be true")
	}
}

func TestCreateFromResults(t *testing.T) {
	results := []*events.ResultEvent{
		{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeResult,
				Time: time.Now(),
				Scan: "scan-123",
			},
			Test: events.TestInfo{
				ID:       "sqli-001",
				Category: "sqli",
				Severity: events.SeverityCritical,
			},
			Target: events.TargetInfo{
				URL:      "https://example.com/api/users",
				Endpoint: "/api/users",
			},
			Result: events.ResultInfo{
				Outcome: events.OutcomeBypass,
			},
			Evidence: &events.Evidence{
				Payload: "' OR 1=1 --",
			},
		},
		{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeResult,
				Time: time.Now(),
				Scan: "scan-123",
			},
			Test: events.TestInfo{
				ID:       "sqli-002",
				Category: "sqli",
				Severity: events.SeverityHigh,
			},
			Target: events.TargetInfo{
				URL:      "https://example.com/api/users",
				Endpoint: "/api/users",
			},
			Result: events.ResultInfo{
				Outcome: events.OutcomeBlocked,
			},
			Evidence: &events.Evidence{
				Payload: "SELECT * FROM users",
			},
		},
	}

	baseline := CreateFromResults(results, "scan-123", "https://example.com")

	if baseline.Version != Version {
		t.Errorf("Version = %q, want %q", baseline.Version, Version)
	}

	if baseline.ScanID != "scan-123" {
		t.Errorf("ScanID = %q, want %q", baseline.ScanID, "scan-123")
	}

	if baseline.Target != "https://example.com" {
		t.Errorf("Target = %q, want %q", baseline.Target, "https://example.com")
	}

	// Only bypasses should be included
	if len(baseline.Bypasses) != 1 {
		t.Errorf("Bypasses length = %d, want 1", len(baseline.Bypasses))
	}

	if baseline.Bypasses[0].ID != "sqli-001" {
		t.Errorf("Bypasses[0].ID = %q, want %q", baseline.Bypasses[0].ID, "sqli-001")
	}

	if baseline.Summary.TotalBypasses != 1 {
		t.Errorf("TotalBypasses = %d, want 1", baseline.Summary.TotalBypasses)
	}

	// 1 blocked out of 2 = 50%
	if baseline.Summary.Effectiveness != 50.0 {
		t.Errorf("Effectiveness = %f, want 50.0", baseline.Summary.Effectiveness)
	}
}

func TestCreateFromResults_EmptyResults(t *testing.T) {
	baseline := CreateFromResults([]*events.ResultEvent{}, "scan-123", "https://example.com")

	if len(baseline.Bypasses) != 0 {
		t.Errorf("Bypasses length = %d, want 0", len(baseline.Bypasses))
	}

	if baseline.Summary.Effectiveness != 0 {
		t.Errorf("Effectiveness = %f, want 0", baseline.Summary.Effectiveness)
	}
}

func TestCreateFromResults_NilResults(t *testing.T) {
	results := []*events.ResultEvent{nil, nil}
	baseline := CreateFromResults(results, "scan-123", "https://example.com")

	if len(baseline.Bypasses) != 0 {
		t.Errorf("Bypasses length = %d, want 0", len(baseline.Bypasses))
	}
}

func TestExtractBypasses_Deduplication(t *testing.T) {
	// Same payload should be deduplicated
	results := []*events.ResultEvent{
		{
			Test: events.TestInfo{
				ID:       "sqli-001",
				Category: "sqli",
				Severity: events.SeverityCritical,
			},
			Result: events.ResultInfo{
				Outcome: events.OutcomeBypass,
			},
			Evidence: &events.Evidence{
				Payload: "duplicate payload",
			},
		},
		{
			Test: events.TestInfo{
				ID:       "sqli-002",
				Category: "sqli",
				Severity: events.SeverityCritical,
			},
			Result: events.ResultInfo{
				Outcome: events.OutcomeBypass,
			},
			Evidence: &events.Evidence{
				Payload: "duplicate payload",
			},
		},
	}

	bypasses := ExtractBypasses(results)

	if len(bypasses) != 1 {
		t.Errorf("Bypasses length = %d, want 1 (should deduplicate)", len(bypasses))
	}
}

func TestHashPayload(t *testing.T) {
	hash1 := hashPayload("test payload")
	hash2 := hashPayload("test payload")
	hash3 := hashPayload("different payload")

	if hash1 != hash2 {
		t.Error("same payload should produce same hash")
	}

	if hash1 == hash3 {
		t.Error("different payloads should produce different hashes")
	}

	if len(hash1) < 64 {
		t.Errorf("hash length = %d, should be at least 64 chars (sha256)", len(hash1))
	}

	// Should have sha256: prefix
	if hash1[:7] != "sha256:" {
		t.Errorf("hash should start with 'sha256:', got %q", hash1[:7])
	}
}

func TestAddBypass(t *testing.T) {
	b := New()

	entry := BypassEntry{
		ID:          "test-001",
		Category:    "xss",
		Severity:    "high",
		PayloadHash: "sha256:abc123",
		TargetPath:  "/api/test",
	}

	b.AddBypass(entry)

	if b.Len() != 1 {
		t.Errorf("Len() = %d, want 1", b.Len())
	}

	// Adding duplicate should not increase count
	b.AddBypass(entry)

	if b.Len() != 1 {
		t.Errorf("Len() = %d after duplicate, want 1", b.Len())
	}
}

func TestAddBypass_SetsFirstSeen(t *testing.T) {
	b := New()

	entry := BypassEntry{
		ID:          "test-001",
		PayloadHash: "sha256:abc123",
		// FirstSeen not set
	}

	b.AddBypass(entry)

	stored, ok := b.GetBypass("sha256:abc123")
	if !ok {
		t.Fatal("GetBypass should find the entry")
	}

	if stored.FirstSeen.IsZero() {
		t.Error("FirstSeen should be set automatically")
	}
}

func TestRemoveBypass(t *testing.T) {
	b := New()
	b.Bypasses = []BypassEntry{
		{ID: "test-001", PayloadHash: "sha256:abc123"},
		{ID: "test-002", PayloadHash: "sha256:def456"},
	}
	b.Summary.TotalBypasses = 2

	removed := b.RemoveBypass("sha256:abc123")

	if !removed {
		t.Error("RemoveBypass should return true")
	}

	if b.Len() != 1 {
		t.Errorf("Len() = %d, want 1", b.Len())
	}

	// Removing non-existent should return false
	removed = b.RemoveBypass("sha256:nonexistent")
	if removed {
		t.Error("RemoveBypass should return false for non-existent")
	}
}

func TestGetBypass(t *testing.T) {
	b := New()
	b.Bypasses = []BypassEntry{
		{ID: "test-001", PayloadHash: "sha256:abc123"},
	}

	entry, ok := b.GetBypass("sha256:abc123")
	if !ok {
		t.Error("GetBypass should find existing entry")
	}
	if entry.ID != "test-001" {
		t.Errorf("entry.ID = %q, want %q", entry.ID, "test-001")
	}

	_, ok = b.GetBypass("sha256:nonexistent")
	if ok {
		t.Error("GetBypass should not find non-existent entry")
	}
}

func TestMerge(t *testing.T) {
	b1 := New()
	b1.Bypasses = []BypassEntry{
		{ID: "test-001", PayloadHash: "sha256:abc123", FirstSeen: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)},
	}

	b2 := New()
	b2.Bypasses = []BypassEntry{
		// Same hash but earlier FirstSeen
		{ID: "test-001", PayloadHash: "sha256:abc123", FirstSeen: time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)},
		// New bypass
		{ID: "test-002", PayloadHash: "sha256:def456", FirstSeen: time.Date(2026, 1, 20, 10, 0, 0, 0, time.UTC)},
	}

	b1.Merge(b2)

	if b1.Len() != 2 {
		t.Errorf("Len() = %d, want 2", b1.Len())
	}

	// FirstSeen should be preserved as earliest
	entry, ok := b1.GetBypass("sha256:abc123")
	if !ok {
		t.Fatal("should find merged entry")
	}

	expectedFirstSeen := time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)
	if !entry.FirstSeen.Equal(expectedFirstSeen) {
		t.Errorf("FirstSeen = %v, want %v", entry.FirstSeen, expectedFirstSeen)
	}
}

func TestMerge_NilOther(t *testing.T) {
	b := New()
	b.Bypasses = []BypassEntry{
		{ID: "test-001", PayloadHash: "sha256:abc123"},
	}

	b.Merge(nil) // Should not panic

	if b.Len() != 1 {
		t.Errorf("Len() = %d, want 1", b.Len())
	}
}

func TestThreadSafety(t *testing.T) {
	b := New()

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent adds
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			b.AddBypass(BypassEntry{
				ID:          "test",
				PayloadHash: hashPayload(string(rune(n))),
			})
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = b.Len()
		}()
	}

	wg.Wait()

	// Should not panic and all operations should complete
	if b.Len() == 0 {
		t.Error("Len() should be > 0 after concurrent adds")
	}
}

func TestCalculateEffectiveness(t *testing.T) {
	tests := []struct {
		name     string
		results  []*events.ResultEvent
		expected float64
	}{
		{
			name:     "empty results",
			results:  []*events.ResultEvent{},
			expected: 0,
		},
		{
			name: "all blocked",
			results: []*events.ResultEvent{
				{Result: events.ResultInfo{Outcome: events.OutcomeBlocked}},
				{Result: events.ResultInfo{Outcome: events.OutcomeBlocked}},
			},
			expected: 100,
		},
		{
			name: "all bypasses",
			results: []*events.ResultEvent{
				{Result: events.ResultInfo{Outcome: events.OutcomeBypass}},
				{Result: events.ResultInfo{Outcome: events.OutcomeBypass}},
			},
			expected: 0,
		},
		{
			name: "mixed results",
			results: []*events.ResultEvent{
				{Result: events.ResultInfo{Outcome: events.OutcomeBlocked}},
				{Result: events.ResultInfo{Outcome: events.OutcomeBypass}},
				{Result: events.ResultInfo{Outcome: events.OutcomeBlocked}},
				{Result: events.ResultInfo{Outcome: events.OutcomeBypass}},
			},
			expected: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateEffectiveness(tt.results)
			if result != tt.expected {
				t.Errorf("calculateEffectiveness() = %f, want %f", result, tt.expected)
			}
		})
	}
}

func TestExtractBypasses_NoEvidence(t *testing.T) {
	results := []*events.ResultEvent{
		{
			Test: events.TestInfo{
				ID:       "sqli-001",
				Category: "sqli",
				Severity: events.SeverityCritical,
			},
			Result: events.ResultInfo{
				Outcome: events.OutcomeBypass,
			},
			Evidence: nil, // No evidence
		},
	}

	bypasses := ExtractBypasses(results)

	if len(bypasses) != 1 {
		t.Errorf("Bypasses length = %d, want 1", len(bypasses))
	}

	// Should still have a hash (of empty string)
	if bypasses[0].PayloadHash == "" {
		t.Error("PayloadHash should not be empty")
	}
}

func TestExtractBypasses_Sorting(t *testing.T) {
	results := []*events.ResultEvent{
		{
			Test:     events.TestInfo{ID: "xss-002", Category: "xss"},
			Result:   events.ResultInfo{Outcome: events.OutcomeBypass},
			Evidence: &events.Evidence{Payload: "payload2"},
		},
		{
			Test:     events.TestInfo{ID: "sqli-001", Category: "sqli"},
			Result:   events.ResultInfo{Outcome: events.OutcomeBypass},
			Evidence: &events.Evidence{Payload: "payload1"},
		},
		{
			Test:     events.TestInfo{ID: "sqli-003", Category: "sqli"},
			Result:   events.ResultInfo{Outcome: events.OutcomeBypass},
			Evidence: &events.Evidence{Payload: "payload3"},
		},
	}

	bypasses := ExtractBypasses(results)

	// Should be sorted by category, then by ID
	if bypasses[0].Category != "sqli" || bypasses[0].ID != "sqli-001" {
		t.Errorf("First bypass should be sqli-001, got %s/%s", bypasses[0].Category, bypasses[0].ID)
	}
	if bypasses[1].Category != "sqli" || bypasses[1].ID != "sqli-003" {
		t.Errorf("Second bypass should be sqli-003, got %s/%s", bypasses[1].Category, bypasses[1].ID)
	}
	if bypasses[2].Category != "xss" {
		t.Errorf("Third bypass should be xss, got %s", bypasses[2].Category)
	}
}
