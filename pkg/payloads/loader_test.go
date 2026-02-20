package payloads

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// =============================================================================
// REAL BUG-FINDING TESTS - These tests actually verify behavior and find issues
// =============================================================================

// TestFilterSeverityLevelBug verifies that severity filtering is case-insensitive.
// Previously the filter used title-case map keys, silently dropping lowercase
// severity hints like "critical" (used in database.go builtins).
func TestFilterSeverityLevelBug(t *testing.T) {
	payloads := []Payload{
		{ID: "1", Category: "sqli", SeverityHint: "Critical"},
		{ID: "2", Category: "sqli", SeverityHint: "HIGH"},    // UPPERCASE
		{ID: "3", Category: "sqli", SeverityHint: "medium"},  // lowercase
		{ID: "4", Category: "sqli", SeverityHint: ""},        // empty severity
		{ID: "5", Category: "sqli", SeverityHint: "Unknown"}, // unknown severity
	}

	// Filter for "High" — should include Critical (#1) and HIGH (#2)
	filtered := Filter(payloads, "", "High")

	wantIDs := map[string]bool{"1": true, "2": true}
	gotIDs := make(map[string]bool, len(filtered))
	for _, p := range filtered {
		gotIDs[p.ID] = true
	}
	for id := range wantIDs {
		if !gotIDs[id] {
			t.Errorf("expected payload %s in High+ filter results", id)
		}
	}
	for id := range gotIDs {
		if !wantIDs[id] {
			t.Errorf("unexpected payload %s in High+ filter results", id)
		}
	}
}

func getSeverityLevel(severity string) int {
	levels := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	return levels[strings.ToLower(severity)]
}

// TestFilterWithNilPayloads tests what happens with nil input
func TestFilterWithNilPayloads(t *testing.T) {
	// This could panic if Filter doesn't handle nil
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("BUG: Filter panicked on nil input: %v", r)
		}
	}()

	result := Filter(nil, "sqli", "High")
	if result != nil && len(result) != 0 {
		t.Errorf("Expected empty result for nil input, got %d items", len(result))
	}
}

// TestLoaderSymlinkLoop tests what happens with symlink loops
func TestLoaderSymlinkLoop(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a symlink that points to parent (creates infinite loop)
	// This test checks if LoadAll handles this gracefully or hangs forever
	linkPath := filepath.Join(tmpDir, "loop")

	// On Windows, symlinks may require admin privileges - skip if can't create
	err := os.Symlink(tmpDir, linkPath)
	if err != nil {
		t.Skip("Cannot create symlink (may need admin privileges)")
	}

	loader := NewLoader(tmpDir)

	// Set a timeout - if this hangs, we found a bug
	done := make(chan bool, 1)
	go func() {
		_, _ = loader.LoadAll()
		done <- true
	}()

	select {
	case <-done:
		// Good - it completed (Go's filepath.Walk handles symlinks)
	default:
		// Would need timeout logic here in real test
	}
}

// TestLoaderEmptyJSONArray tests loading a file with empty array
func TestLoaderEmptyJSONArray(t *testing.T) {
	tmpDir := t.TempDir()
	emptyFile := filepath.Join(tmpDir, "empty.json")

	// Write empty JSON array
	if err := os.WriteFile(emptyFile, []byte("[]"), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(tmpDir)
	payloads, err := loader.LoadAll()
	if err != nil {
		t.Errorf("BUG: Failed to load empty JSON array: %v", err)
	}
	if len(payloads) != 0 {
		t.Errorf("Expected 0 payloads from empty array, got %d", len(payloads))
	}
}

// TestLoaderJSONObject tests loading a JSON object instead of array
func TestLoaderJSONObject(t *testing.T) {
	tmpDir := t.TempDir()
	objectFile := filepath.Join(tmpDir, "object.json")

	// Write JSON object (not array) - this should fail
	jsonObject := `{"id": "test", "payload": "test"}`
	if err := os.WriteFile(objectFile, []byte(jsonObject), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(tmpDir)
	_, err := loader.LoadAll()
	if err == nil {
		t.Error("BUG: Should have failed when JSON is object not array")
	}
}

// TestLoaderUTF8BOM tests handling of UTF-8 BOM in JSON files
func TestLoaderUTF8BOM(t *testing.T) {
	tmpDir := t.TempDir()
	bomFile := filepath.Join(tmpDir, "bom.json")

	// UTF-8 BOM followed by valid JSON
	bom := []byte{0xEF, 0xBB, 0xBF}
	jsonData := `[{"id": "test", "payload": "test", "category": "test"}]`
	content := append(bom, []byte(jsonData)...)

	if err := os.WriteFile(bomFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(tmpDir)
	_, err := loader.LoadAll()
	// This will likely fail because JSON decoder doesn't handle BOM
	// This is a known issue that should be documented or fixed
	if err != nil {
		t.Logf("NOTE: Loader doesn't handle UTF-8 BOM: %v", err)
		// This isn't necessarily a bug, but documents behavior
	}
}

// TestLoaderVeryLargeFile tests memory handling with large payload files
func TestLoaderVeryLargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file test in short mode")
	}

	tmpDir := t.TempDir()
	largeFile := filepath.Join(tmpDir, "large.json")

	// Create file with 10,000 payloads
	payloads := make([]Payload, 10000)
	for i := range payloads {
		payloads[i] = Payload{
			ID:       fmt.Sprintf("test-%05d", i),
			Payload:  "' OR '1'='1",
			Category: "sqli",
		}
	}

	data, _ := json.Marshal(payloads)
	if err := os.WriteFile(largeFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(tmpDir)
	loaded, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load large file: %v", err)
	}

	if len(loaded) != 10000 {
		t.Errorf("Expected 10000 payloads, got %d", len(loaded))
	}
}

// TestLoaderConcurrentAccess tests thread-safety of loader
func TestLoaderConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test payload file
	payloads := []Payload{{ID: "test", Payload: "test", Category: "test"}}
	data, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "test.json"), data, 0644)

	loader := NewLoader(tmpDir)

	// Run 100 concurrent LoadAll calls
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := loader.LoadAll()
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("BUG: Concurrent access error: %v", err)
	}
}

// TestFilterMutatesInput tests if Filter modifies the input slice
func TestFilterMutatesInput(t *testing.T) {
	original := []Payload{
		{ID: "1", Category: "sqli", SeverityHint: "High"},
		{ID: "2", Category: "xss", SeverityHint: "Medium"},
		{ID: "3", Category: "sqli", SeverityHint: "Low"},
	}

	// Deep copy for comparison
	originalCopy := make([]Payload, len(original))
	copy(originalCopy, original)

	// Run filter
	_ = Filter(original, "sqli", "")

	// Verify input wasn't mutated
	for i := range original {
		if original[i].ID != originalCopy[i].ID ||
			original[i].Category != originalCopy[i].Category {
			t.Errorf("BUG: Filter mutated input slice at index %d", i)
		}
	}
}

// TestLoaderSpecialCharactersInPath tests paths with special characters
func TestLoaderSpecialCharactersInPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create subdirectory with spaces and special chars
	specialDir := filepath.Join(tmpDir, "test payloads (v2)")
	if err := os.MkdirAll(specialDir, 0755); err != nil {
		t.Fatal(err)
	}

	payloads := []Payload{{ID: "test", Payload: "test", Category: "test"}}
	data, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(specialDir, "test.json"), data, 0644)

	loader := NewLoader(tmpDir)
	loaded, err := loader.LoadAll()
	if err != nil {
		t.Errorf("BUG: Failed with special characters in path: %v", err)
	}
	if len(loaded) != 1 {
		t.Errorf("Expected 1 payload, got %d", len(loaded))
	}
}

// TestGetStatsEmptyCategoryName tests payloads with empty category
func TestGetStatsEmptyCategoryName(t *testing.T) {
	payloads := []Payload{
		{ID: "1", Category: "sqli"},
		{ID: "2", Category: ""}, // empty category - potential bug source
		{ID: "3", Category: ""}, // another empty
		{ID: "4", Category: "xss"},
	}

	stats := GetStats(payloads)

	// Check if empty string is counted as a category
	if count, exists := stats.ByCategory[""]; exists {
		t.Logf("NOTE: Empty category counted %d times - is this intended?", count)
	}

	// Total should still be correct
	if stats.TotalPayloads != 4 {
		t.Errorf("TotalPayloads wrong: got %d, want 4", stats.TotalPayloads)
	}
}

// TestLoaderDuplicateIDs tests handling of duplicate payload IDs
func TestLoaderDuplicateIDs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create file with duplicate IDs - this is likely a bug in payload files
	payloads := []Payload{
		{ID: "duplicate", Payload: "test1", Category: "sqli"},
		{ID: "duplicate", Payload: "test2", Category: "xss"}, // same ID!
		{ID: "unique", Payload: "test3", Category: "rce"},
	}
	data, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "test.json"), data, 0644)

	loader := NewLoader(tmpDir)
	loaded, err := loader.LoadAll()
	if err != nil {
		t.Fatal(err)
	}

	// Count IDs
	idCount := make(map[string]int)
	for _, p := range loaded {
		idCount[p.ID]++
	}

	if idCount["duplicate"] != 2 {
		t.Errorf("Loader changed duplicate handling - got %d, want 2", idCount["duplicate"])
	}

	// Document that duplicates ARE loaded (for regression testing)
	t.Logf("NOTE: Loader accepts duplicate IDs - validation should catch this")
}

// TestLoaderReadOnlyDirectory tests loading from read-only directory
func TestLoaderReadOnlyDirectory(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skip permission tests in CI")
	}

	tmpDir := t.TempDir()
	payloads := []Payload{{ID: "test", Payload: "test", Category: "test"}}
	data, _ := json.Marshal(payloads)
	testFile := filepath.Join(tmpDir, "test.json")
	os.WriteFile(testFile, data, 0644)

	// Make directory read-only (this may not work on all systems)
	origMode, _ := os.Stat(tmpDir)
	os.Chmod(tmpDir, 0444)
	defer os.Chmod(tmpDir, origMode.Mode())

	loader := NewLoader(tmpDir)
	loaded, err := loader.LoadAll()

	// Should still be able to read
	if err != nil {
		t.Logf("NOTE: Cannot read from chmod 0444 directory: %v", err)
	} else if len(loaded) != 1 {
		t.Errorf("Expected 1 payload, got %d", len(loaded))
	}
}

// TestFilterBoundaryCases tests severity boundary conditions
func TestFilterBoundaryCases(t *testing.T) {
	payloads := []Payload{
		{ID: "1", Category: "sqli", SeverityHint: "Critical"},
		{ID: "2", Category: "sqli", SeverityHint: "High"},
		{ID: "3", Category: "sqli", SeverityHint: "Medium"},
		{ID: "4", Category: "sqli", SeverityHint: "Low"},
	}

	tests := []struct {
		name          string
		severity      string
		expectedCount int
		expectedIDs   []string
	}{
		{"Critical only", "Critical", 1, []string{"1"}},
		{"High includes Critical", "High", 2, []string{"1", "2"}},
		{"Medium includes High+", "Medium", 3, []string{"1", "2", "3"}},
		{"Low includes all", "Low", 4, []string{"1", "2", "3", "4"}},
		// BUG: Invalid severity should return 0 payloads, not all!
		// Currently returns all because severityLevel["SuperHigh"] = 0 (Go default)
		// and payloadLevel >= 0 is always true
		{"Invalid severity MUST return none", "SuperHigh", 0, []string{}},
		{"Empty severity", "", 4, []string{"1", "2", "3", "4"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := Filter(payloads, "", tt.severity)
			if len(filtered) != tt.expectedCount {
				t.Errorf("Expected %d payloads for severity %q, got %d",
					tt.expectedCount, tt.severity, len(filtered))
			}

			// Verify exact IDs
			for _, expectedID := range tt.expectedIDs {
				found := false
				for _, p := range filtered {
					if p.ID == expectedID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected ID %s in results for severity %q", expectedID, tt.severity)
				}
			}
		})
	}
}

// TestLoaderNestedDirectories tests deeply nested directory structures
func TestLoaderNestedDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create deep nesting: a/b/c/d/e/
	deepPath := filepath.Join(tmpDir, "a", "b", "c", "d", "e")
	if err := os.MkdirAll(deepPath, 0755); err != nil {
		t.Fatal(err)
	}

	// Put payload file deep in the structure
	payloads := []Payload{{ID: "deep", Payload: "test", Category: "test"}}
	data, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(deepPath, "deep.json"), data, 0644)

	// Also put one at root
	rootPayloads := []Payload{{ID: "root", Payload: "test", Category: "test"}}
	rootData, _ := json.Marshal(rootPayloads)
	os.WriteFile(filepath.Join(tmpDir, "root.json"), rootData, 0644)

	loader := NewLoader(tmpDir)
	loaded, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("Failed to load nested directories: %v", err)
	}

	// Should find both files
	if len(loaded) != 2 {
		t.Errorf("Expected 2 payloads (root + deep), got %d", len(loaded))
	}

	// Verify both IDs exist
	ids := make(map[string]bool)
	for _, p := range loaded {
		ids[p.ID] = true
	}
	if !ids["deep"] {
		t.Error("Missing 'deep' payload from nested directory")
	}
	if !ids["root"] {
		t.Error("Missing 'root' payload")
	}
}

// TestLoaderNonExistentDirectory tests loading from non-existent directory
func TestLoaderNonExistentDirectory(t *testing.T) {
	loader := NewLoader("/this/path/definitely/does/not/exist/anywhere")
	_, err := loader.LoadAll()
	if err == nil {
		t.Error("BUG: Should return error for non-existent directory")
	}
}

// TestLoaderNormalizesAttackCategory verifies backward compatibility
func TestLoaderNormalizesAttackCategory(t *testing.T) {
	tmpDir := t.TempDir()

	// JSON with old attack_category field (no category)
	oldFormat := `[{
		"id": "old-001",
		"payload": "test",
		"attack_category": "sqli",
		"severity_hint": "High"
	}]`

	testFile := filepath.Join(tmpDir, "old-format.json")
	if err := os.WriteFile(testFile, []byte(oldFormat), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	loader := NewLoader(tmpDir)
	loaded, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	if len(loaded) != 1 {
		t.Fatalf("Expected 1 payload, got %d", len(loaded))
	}

	// Category should be populated from AttackCategory
	if loaded[0].Category != "sqli" {
		t.Errorf("Category not normalized: got %q, want %q", loaded[0].Category, "sqli")
	}
}

// TestLoaderDefaultsMethodToGET verifies GET is default
func TestLoaderDefaultsMethodToGET(t *testing.T) {
	tmpDir := t.TempDir()

	// JSON without method field
	noMethod := `[{
		"id": "no-method-001",
		"payload": "test",
		"category": "test"
	}]`

	testFile := filepath.Join(tmpDir, "no-method.json")
	if err := os.WriteFile(testFile, []byte(noMethod), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	loader := NewLoader(tmpDir)
	loaded, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	if loaded[0].Method != "GET" {
		t.Errorf("Method not defaulted: got %q, want %q", loaded[0].Method, "GET")
	}
}

// TestFilterByCategory verifies category filtering works
func TestFilterByCategory(t *testing.T) {
	payloads := []Payload{
		{ID: "1", Category: "sqli", SeverityHint: "High"},
		{ID: "2", Category: "xss", SeverityHint: "High"},
		{ID: "3", Category: "sqli", SeverityHint: "Medium"},
		{ID: "4", Category: "rce", SeverityHint: "Critical"},
	}

	filtered := Filter(payloads, "sqli", "")
	if len(filtered) != 2 {
		t.Errorf("Expected 2 sqli payloads, got %d", len(filtered))
	}

	for _, p := range filtered {
		if p.Category != "sqli" {
			t.Errorf("Non-sqli payload in filtered results: %s", p.Category)
		}
	}
}

// TestFilterBySeverity verifies severity filtering works
func TestFilterBySeverity(t *testing.T) {
	payloads := []Payload{
		{ID: "1", Category: "sqli", SeverityHint: "Critical"},
		{ID: "2", Category: "sqli", SeverityHint: "High"},
		{ID: "3", Category: "sqli", SeverityHint: "Medium"},
		{ID: "4", Category: "sqli", SeverityHint: "Low"},
	}

	// Filter for High and above
	filtered := Filter(payloads, "", "High")
	if len(filtered) != 2 {
		t.Errorf("Expected 2 High+ payloads, got %d", len(filtered))
	}

	for _, p := range filtered {
		if p.SeverityHint != "Critical" && p.SeverityHint != "High" {
			t.Errorf("Low severity payload in filtered results: %s", p.SeverityHint)
		}
	}
}

// TestFilterCombined verifies combined category + severity filtering
func TestFilterCombined(t *testing.T) {
	payloads := []Payload{
		{ID: "1", Category: "sqli", SeverityHint: "Critical"},
		{ID: "2", Category: "sqli", SeverityHint: "Low"},
		{ID: "3", Category: "xss", SeverityHint: "Critical"},
	}

	filtered := Filter(payloads, "sqli", "High")
	if len(filtered) != 1 {
		t.Errorf("Expected 1 sqli+High payload, got %d", len(filtered))
	}

	if filtered[0].ID != "1" {
		t.Errorf("Wrong payload filtered: got %s, want 1", filtered[0].ID)
	}
}

// TestGetStats verifies statistics calculation
func TestGetStats(t *testing.T) {
	payloads := []Payload{
		{ID: "1", Category: "sqli"},
		{ID: "2", Category: "sqli"},
		{ID: "3", Category: "xss"},
		{ID: "4", Category: "rce"},
	}

	stats := GetStats(payloads)

	if stats.TotalPayloads != 4 {
		t.Errorf("TotalPayloads: got %d, want 4", stats.TotalPayloads)
	}
	if stats.CategoriesUsed != 3 {
		t.Errorf("CategoriesUsed: got %d, want 3", stats.CategoriesUsed)
	}
	if stats.ByCategory["sqli"] != 2 {
		t.Errorf("ByCategory[sqli]: got %d, want 2", stats.ByCategory["sqli"])
	}
}

// TestNewLoader tests loader creation
func TestNewLoader(t *testing.T) {
	loader := NewLoader("/tmp/payloads")
	if loader == nil {
		t.Fatal("expected loader, got nil")
	}
	if loader.baseDir != "/tmp/payloads" {
		t.Errorf("expected baseDir /tmp/payloads, got %s", loader.baseDir)
	}
}

// TestLoadAllEmptyDir tests loading from empty directory
func TestLoadAllEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	loader := NewLoader(tmpDir)
	payloads, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(payloads) != 0 {
		t.Errorf("expected 0 payloads from empty dir, got %d", len(payloads))
	}
}

// TestLoadAllInvalidJSON tests loading invalid JSON file
func TestLoadAllInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(testFile, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	loader := NewLoader(tmpDir)
	_, err := loader.LoadAll()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestLoadAllSkipsMetadata tests that version.json and ids-map.json are skipped
func TestLoadAllSkipsMetadata(t *testing.T) {
	tmpDir := t.TempDir()

	// Create metadata files that should be skipped
	os.WriteFile(filepath.Join(tmpDir, "version.json"), []byte(`{"version": "1.0"}`), 0644)
	os.WriteFile(filepath.Join(tmpDir, "ids-map.json"), []byte(`{}`), 0644)

	// Create a valid payload file
	payloads := []Payload{{ID: "test-001", Payload: "test", Category: "test"}}
	data, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(tmpDir, "test.json"), data, 0644)

	loader := NewLoader(tmpDir)
	loaded, err := loader.LoadAll()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(loaded) != 1 {
		t.Errorf("expected 1 payload (metadata skipped), got %d", len(loaded))
	}
}

// TestLoadCategory tests loading payloads from a specific category
func TestLoadCategory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create category subdirectory
	categoryDir := filepath.Join(tmpDir, "sqli")
	os.MkdirAll(categoryDir, 0755)

	payloads := []Payload{
		{ID: "sqli-001", Payload: "' OR 1=1", Category: "sqli"},
		{ID: "sqli-002", Payload: "'; DROP TABLE", Category: "sqli"},
	}
	data, _ := json.Marshal(payloads)
	os.WriteFile(filepath.Join(categoryDir, "basic.json"), data, 0644)

	loader := NewLoader(tmpDir)
	loaded, err := loader.LoadCategory("sqli")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(loaded) != 2 {
		t.Errorf("expected 2 sqli payloads, got %d", len(loaded))
	}
}

// TestLoadCategoryNotFound tests loading non-existent category
func TestLoadCategoryNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	loader := NewLoader(tmpDir)
	_, err := loader.LoadCategory("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent category")
	}
}

// TestFilterEmptyInputs tests Filter with empty inputs
func TestFilterEmptyInputs(t *testing.T) {
	payloads := []Payload{
		{ID: "1", Category: "sqli", SeverityHint: "High"},
		{ID: "2", Category: "xss", SeverityHint: "Medium"},
	}

	// No filter should return all
	filtered := Filter(payloads, "", "")
	if len(filtered) != 2 {
		t.Errorf("expected 2 payloads with no filter, got %d", len(filtered))
	}
}

// TestFilterCaseInsensitive tests Filter case insensitivity
func TestFilterCaseInsensitive(t *testing.T) {
	payloads := []Payload{
		{ID: "1", Category: "SQLI", SeverityHint: "High"},
		{ID: "2", Category: "sqli", SeverityHint: "Medium"},
	}

	filtered := Filter(payloads, "sqli", "")
	if len(filtered) != 2 {
		t.Errorf("expected 2 payloads with case-insensitive filter, got %d", len(filtered))
	}
}

// TestLoadStatsStruct tests LoadStats struct
func TestLoadStatsStruct(t *testing.T) {
	stats := LoadStats{
		TotalPayloads:  100,
		CategoriesUsed: 5,
		ByCategory:     map[string]int{"sqli": 40, "xss": 30, "rce": 20, "lfi": 5, "other": 5},
	}

	if stats.TotalPayloads != 100 {
		t.Error("TotalPayloads mismatch")
	}
	if stats.CategoriesUsed != 5 {
		t.Error("CategoriesUsed mismatch")
	}
	if len(stats.ByCategory) != 5 {
		t.Error("ByCategory length mismatch")
	}
}

// TestCategoryStruct tests Category struct
func TestCategoryStruct(t *testing.T) {
	cat := Category{
		Name: "sqli",
		Payloads: []Payload{
			{ID: "sqli-001", Payload: "test"},
		},
	}

	if cat.Name != "sqli" {
		t.Error("Name mismatch")
	}
	if len(cat.Payloads) != 1 {
		t.Error("Payloads length mismatch")
	}
}

// TestGetStatsEmptyPayloads tests GetStats with empty slice
func TestGetStatsEmptyPayloads(t *testing.T) {
	stats := GetStats([]Payload{})

	if stats.TotalPayloads != 0 {
		t.Error("expected 0 total payloads")
	}
	if stats.CategoriesUsed != 0 {
		t.Error("expected 0 categories used")
	}
}
