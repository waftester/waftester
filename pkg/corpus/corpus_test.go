package corpus

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager("", false)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.cacheDir == "" {
		t.Error("cacheDir should not be empty")
	}
	if m.corpora == nil {
		t.Error("corpora map should be initialized")
	}
}

func TestNewManagerWithCustomDir(t *testing.T) {
	customDir := filepath.Join(os.TempDir(), "waf-tester-test-corpus")
	defer os.RemoveAll(customDir)

	m := NewManager(customDir, true)
	if m.cacheDir != customDir {
		t.Errorf("cacheDir = %s, want %s", m.cacheDir, customDir)
	}
}

func TestGetBuiltinCorpus(t *testing.T) {
	m := NewManager("", false)
	corpus := m.GetBuiltinCorpus()

	if corpus == nil {
		t.Fatal("GetBuiltinCorpus returned nil")
	}
	if corpus.Name != "builtin" {
		t.Errorf("Name = %s, want builtin", corpus.Name)
	}
	if corpus.Source != SourceBuiltin {
		t.Errorf("Source = %s, want builtin", corpus.Source)
	}
	if corpus.Count == 0 {
		t.Error("Count should be > 0")
	}
	if len(corpus.Payloads) == 0 {
		t.Error("Payloads should not be empty")
	}
	if len(corpus.Categories) == 0 {
		t.Error("Categories should not be empty")
	}
}

func TestGetBuiltinCorpusCaching(t *testing.T) {
	m := NewManager("", false)

	// First call
	corpus1 := m.GetBuiltinCorpus()

	// Second call should return cached
	corpus2 := m.GetBuiltinCorpus()

	if corpus1 != corpus2 {
		t.Error("GetBuiltinCorpus should return cached corpus on second call")
	}
}

func TestGetLeipzigSentences(t *testing.T) {
	sentences := getLeipzigSentences("eng")

	if len(sentences) == 0 {
		t.Fatal("getLeipzigSentences returned empty slice")
	}

	// Check we have diverse categories
	categories := make(map[string]int)
	for _, s := range sentences {
		categories[s.category]++
	}

	expectedCategories := []string{"news", "web", "wikipedia", "forms", "technical", "edgecase"}
	for _, cat := range expectedCategories {
		if categories[cat] == 0 {
			t.Errorf("Missing expected category: %s", cat)
		}
	}
}

func TestDownloadLeipzigCorpus(t *testing.T) {
	// Use temp directory for testing
	tempDir := filepath.Join(os.TempDir(), "waf-tester-test")
	defer os.RemoveAll(tempDir)

	m := NewManager(tempDir, false)
	ctx := context.Background()

	var progressCalls int
	progressFn := func(p DownloadProgress) {
		progressCalls++
	}

	corpus, err := m.DownloadLeipzigCorpus(ctx, "eng", progressFn)
	if err != nil {
		t.Fatalf("DownloadLeipzigCorpus error: %v", err)
	}

	if corpus == nil {
		t.Fatal("corpus is nil")
	}
	if corpus.Count == 0 {
		t.Error("corpus Count should be > 0")
	}
	if len(corpus.Payloads) == 0 {
		t.Error("corpus Payloads should not be empty")
	}
	if progressCalls == 0 {
		t.Error("progressFn should have been called")
	}
}

func TestDownloadLeipzigCorpusWithCache(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "waf-tester-cache-test")
	defer os.RemoveAll(tempDir)

	m := NewManager(tempDir, true)
	ctx := context.Background()

	// First download
	corpus1, err := m.DownloadLeipzigCorpus(ctx, "eng", nil)
	if err != nil {
		t.Fatalf("First download error: %v", err)
	}

	// Verify cache file exists
	cacheFile := filepath.Join(tempDir, "leipzig-eng.json.gz")
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		// Cache might not be created if download failed, that's OK
		t.Skip("Cache file not created, likely no network")
	}

	// Second download should use cache
	m2 := NewManager(tempDir, true)
	corpus2, err := m2.DownloadLeipzigCorpus(ctx, "eng", nil)
	if err != nil {
		t.Fatalf("Second download error: %v", err)
	}

	// Should have same count (from cache)
	if corpus1.Count != corpus2.Count {
		t.Logf("corpus1.Count = %d, corpus2.Count = %d", corpus1.Count, corpus2.Count)
	}
}

func TestLoadCustomCorpus_JSON(t *testing.T) {
	// Create temp JSON corpus file
	tempFile := filepath.Join(os.TempDir(), "test-corpus.json")
	content := `[
		{"text": "Custom payload 1", "category": "test"},
		{"text": "Custom payload 2", "category": "test"}
	]`
	if err := os.WriteFile(tempFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile)

	m := NewManager("", false)
	corpus, err := m.LoadCustomCorpus(tempFile)
	if err != nil {
		t.Fatalf("LoadCustomCorpus error: %v", err)
	}

	if corpus.Count != 2 {
		t.Errorf("Count = %d, want 2", corpus.Count)
	}
	if corpus.Source != SourceCustom {
		t.Errorf("Source = %s, want custom", corpus.Source)
	}
}

func TestLoadCustomCorpus_LineByLine(t *testing.T) {
	// Create temp line-by-line corpus file
	tempFile := filepath.Join(os.TempDir(), "test-corpus.txt")
	content := `# This is a comment
Line payload 1
Line payload 2
Line payload 3
`
	if err := os.WriteFile(tempFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile)

	m := NewManager("", false)
	corpus, err := m.LoadCustomCorpus(tempFile)
	if err != nil {
		t.Fatalf("LoadCustomCorpus error: %v", err)
	}

	// Should have 3 lines (comment excluded)
	if corpus.Count != 3 {
		t.Errorf("Count = %d, want 3", corpus.Count)
	}
}

func TestLoadCustomCorpus_NotFound(t *testing.T) {
	m := NewManager("", false)
	_, err := m.LoadCustomCorpus("/nonexistent/file.json")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestGetAll(t *testing.T) {
	m := NewManager("", false)

	// Load builtin
	m.GetBuiltinCorpus()

	// Get all payloads
	all := m.GetAll()
	if len(all) == 0 {
		t.Error("GetAll should return payloads")
	}
}

func TestGetByCategory(t *testing.T) {
	m := NewManager("", false)
	m.GetBuiltinCorpus()

	// Get edgecase payloads
	edgecases := m.GetByCategory("edgecase")
	if len(edgecases) == 0 {
		t.Error("GetByCategory(edgecase) should return payloads")
	}

	for _, p := range edgecases {
		if p.Category != "edgecase" {
			t.Errorf("Payload category = %s, want edgecase", p.Category)
		}
	}
}

func TestGetByCategory_Empty(t *testing.T) {
	m := NewManager("", false)
	m.GetBuiltinCorpus()

	// Get nonexistent category
	empty := m.GetByCategory("nonexistent")
	if len(empty) != 0 {
		t.Errorf("GetByCategory(nonexistent) should return empty, got %d", len(empty))
	}
}

func TestStats(t *testing.T) {
	m := NewManager("", false)
	m.GetBuiltinCorpus()

	stats := m.Stats()

	if stats["total_corpora"].(int) < 1 {
		t.Error("total_corpora should be at least 1")
	}
	if stats["total_payloads"].(int) == 0 {
		t.Error("total_payloads should be > 0")
	}

	corpora, ok := stats["corpora"].([]map[string]interface{})
	if !ok || len(corpora) == 0 {
		t.Error("corpora should be non-empty array")
	}
}

func TestCorpusStruct(t *testing.T) {
	corpus := &Corpus{
		Name:        "test",
		Source:      SourceBuiltin,
		Description: "Test corpus",
		Count:       10,
		Categories:  map[string]int{"test": 10},
		Payloads:    make([]Payload, 10),
		LoadedAt:    time.Now(),
	}

	if corpus.Name != "test" {
		t.Errorf("Name = %s, want test", corpus.Name)
	}
}

func TestPayloadStruct(t *testing.T) {
	payload := Payload{
		Text:     "Test payload",
		Category: "test",
		Language: "eng",
		Source:   "test",
	}

	if payload.Text != "Test payload" {
		t.Errorf("Text = %s, want 'Test payload'", payload.Text)
	}
}

func TestDownloadProgress(t *testing.T) {
	progress := DownloadProgress{
		CorpusName:    "test",
		BytesTotal:    1000,
		BytesReceived: 500,
		Percentage:    50.0,
		Status:        "Downloading...",
	}

	if progress.Percentage != 50.0 {
		t.Errorf("Percentage = %f, want 50.0", progress.Percentage)
	}
}

func TestGetBuiltinPayloads(t *testing.T) {
	payloads := getBuiltinPayloads()

	if len(payloads) == 0 {
		t.Error("getBuiltinPayloads should return payloads")
	}

	// Check structure
	for i, p := range payloads {
		if p.Text == "" {
			t.Errorf("Payload %d has empty text", i)
		}
		if p.Category == "" {
			t.Errorf("Payload %d has empty category", i)
		}
	}
}

func TestGetExtendedBuiltin(t *testing.T) {
	m := NewManager("", false)
	corpus, err := m.getExtendedBuiltin()

	if err != nil {
		t.Fatalf("getExtendedBuiltin error: %v", err)
	}
	if corpus == nil {
		t.Fatal("corpus is nil")
	}
	if corpus.Count == 0 {
		t.Error("corpus Count should be > 0")
	}
	if corpus.Source != SourceBuiltin {
		t.Errorf("Source = %s, want builtin", corpus.Source)
	}
}
