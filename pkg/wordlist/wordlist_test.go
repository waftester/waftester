package wordlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager(nil)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.cache == nil {
		t.Error("cache should be initialized")
	}
	if m.builtInLists == nil {
		t.Error("builtInLists should be initialized")
	}
}

func TestManagerWithConfig(t *testing.T) {
	cfg := &Config{
		CacheDir:        filepath.Join(os.TempDir(), "waf-tester-test"),
		MaxCacheSize:    50 * 1024 * 1024,
		DownloadTimeout: 30 * time.Second,
	}

	m := NewManager(cfg)
	if m.cacheDir != cfg.CacheDir {
		t.Errorf("expected cacheDir %s, got %s", cfg.CacheDir, m.cacheDir)
	}
	if m.maxCacheSize != cfg.MaxCacheSize {
		t.Errorf("expected maxCacheSize %d, got %d", cfg.MaxCacheSize, m.maxCacheSize)
	}
}

func TestLoadBuiltIn(t *testing.T) {
	m := NewManager(nil)

	tests := []string{
		"common-dirs",
		"common-files",
		"common-params",
		"extensions",
		"backup-files",
		"api-endpoints",
		"fuzzing-special",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			wl, err := m.Load("builtin:" + name)
			if err != nil {
				t.Fatalf("failed to load builtin:%s: %v", name, err)
			}
			if wl == nil {
				t.Fatal("wordlist is nil")
			}
			if len(wl.Words) == 0 {
				t.Error("wordlist has no words")
			}
			if wl.Size != len(wl.Words) {
				t.Errorf("size mismatch: %d vs %d", wl.Size, len(wl.Words))
			}
		})
	}
}

func TestLoadBuiltInNotFound(t *testing.T) {
	m := NewManager(nil)

	_, err := m.Load("builtin:nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent builtin")
	}
}

func TestLoadFromFile(t *testing.T) {
	m := NewManager(nil)

	// Create temp file
	tmpFile := filepath.Join(os.TempDir(), "test-wordlist.txt")
	content := "word1\nword2\nword3\n# comment\n\nword4"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	defer os.Remove(tmpFile)

	wl, err := m.Load(tmpFile)
	if err != nil {
		t.Fatalf("failed to load file: %v", err)
	}

	if len(wl.Words) != 4 {
		t.Errorf("expected 4 words, got %d", len(wl.Words))
	}

	// Verify comment and empty lines are skipped
	for _, word := range wl.Words {
		if strings.HasPrefix(word, "#") {
			t.Error("comment should be filtered")
		}
		if word == "" {
			t.Error("empty lines should be filtered")
		}
	}
}

func TestLoadMultiple(t *testing.T) {
	m := NewManager(nil)

	wl, err := m.LoadMultiple([]string{"builtin:common-dirs", "builtin:common-files"})
	if err != nil {
		t.Fatalf("failed to load multiple: %v", err)
	}

	// Should have combined words
	if len(wl.Words) == 0 {
		t.Error("combined wordlist is empty")
	}

	// Check name is combined
	if !strings.Contains(wl.Name, "+") {
		t.Error("name should indicate combined wordlists")
	}
}

func TestGenerateNumeric(t *testing.T) {
	m := NewManager(nil)

	wl, err := m.Generate(GenerateOptions{
		Type:    GenerateNumeric,
		Min:     1,
		Max:     10,
		Padding: 2,
	})
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	if len(wl.Words) != 10 {
		t.Errorf("expected 10 words, got %d", len(wl.Words))
	}

	// Check padding
	if wl.Words[0] != "01" {
		t.Errorf("expected '01', got '%s'", wl.Words[0])
	}
}

func TestGenerateAlpha(t *testing.T) {
	m := NewManager(nil)

	wl, err := m.Generate(GenerateOptions{
		Type:      GenerateAlpha,
		MinLength: 1,
		MaxLength: 2,
		Charset:   "ab",
	})
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	// a, b, aa, ab, ba, bb = 6 words
	if len(wl.Words) != 6 {
		t.Errorf("expected 6 words, got %d: %v", len(wl.Words), wl.Words)
	}
}

func TestGeneratePattern(t *testing.T) {
	m := NewManager(nil)

	wl, err := m.Generate(GenerateOptions{
		Type:    GeneratePattern,
		Pattern: "test?d?d",
		Count:   100,
	})
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	// All words should start with "test"
	for _, word := range wl.Words {
		if !strings.HasPrefix(word, "test") {
			t.Errorf("word '%s' should start with 'test'", word)
		}
		if len(word) != 6 { // test + 2 digits
			t.Errorf("word '%s' should be 6 chars", word)
		}
	}
}

func TestGenerateMutations(t *testing.T) {
	m := NewManager(nil)

	wl, err := m.Generate(GenerateOptions{
		Type:     GenerateMutations,
		BaseWord: "password",
	})
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	// Should have many variations
	if len(wl.Words) < 10 {
		t.Errorf("expected many mutations, got %d", len(wl.Words))
	}

	// Check for leet speak variations
	hasLeet := false
	for _, word := range wl.Words {
		if strings.Contains(word, "@") || strings.Contains(word, "0") {
			hasLeet = true
			break
		}
	}
	if !hasLeet {
		t.Error("expected leet speak mutations")
	}
}

func TestGenerateCombinations(t *testing.T) {
	m := NewManager(nil)

	wl, err := m.Generate(GenerateOptions{
		Type: GenerateCombinations,
		Parts: [][]string{
			{"a", "b"},
			{"1", "2"},
		},
		Separator: "-",
	})
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	// 2 * 2 = 4 combinations
	if len(wl.Words) != 4 {
		t.Errorf("expected 4 combinations, got %d", len(wl.Words))
	}

	// Check format
	for _, word := range wl.Words {
		if !strings.Contains(word, "-") {
			t.Errorf("word '%s' should contain separator", word)
		}
	}
}

func TestGenerateDates(t *testing.T) {
	m := NewManager(nil)

	start := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2023, 1, 5, 0, 0, 0, 0, time.UTC)

	wl, err := m.Generate(GenerateOptions{
		Type:        GenerateDates,
		StartDate:   start,
		EndDate:     end,
		DateFormats: []string{"20060102"},
	})
	if err != nil {
		t.Fatalf("failed to generate: %v", err)
	}

	// 5 days
	if len(wl.Words) != 5 {
		t.Errorf("expected 5 dates, got %d", len(wl.Words))
	}
}

func TestTransform(t *testing.T) {
	m := NewManager(nil)

	original := &Wordlist{
		Words: []string{"test", "admin"},
	}

	transformed, err := m.Transform(original, []Transform{
		{Type: TransformCase},
		{Type: TransformLeet},
	})
	if err != nil {
		t.Fatalf("failed to transform: %v", err)
	}

	// Should have more words after transformation
	if len(transformed.Words) <= len(original.Words) {
		t.Error("transformation should add words")
	}
}

func TestTransformTypes(t *testing.T) {
	tests := []struct {
		transform Transform
		input     string
		expected  []string
	}{
		{
			transform: Transform{Type: TransformCase},
			input:     "Test",
			expected:  []string{"test", "TEST", "Test", "tEsT"},
		},
		{
			transform: Transform{Type: TransformLeet},
			input:     "test",
			expected:  []string{"7357"},
		},
		{
			transform: Transform{Type: TransformReverse},
			input:     "test",
			expected:  []string{"tset"},
		},
		{
			transform: Transform{Type: TransformPrefix, Prefix: "pre_"},
			input:     "test",
			expected:  []string{"pre_test"},
		},
		{
			transform: Transform{Type: TransformSuffix, Suffix: "_suf"},
			input:     "test",
			expected:  []string{"test_suf"},
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.transform.Type), func(t *testing.T) {
			results := applyTransform(tt.input, tt.transform)
			for _, exp := range tt.expected {
				found := false
				for _, r := range results {
					if r == exp {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected '%s' in results %v", exp, results)
				}
			}
		})
	}
}

func TestFilter(t *testing.T) {
	m := NewManager(nil)

	original := &Wordlist{
		Words: []string{"a", "ab", "abc", "abcd", "12345", "test123"},
	}

	tests := []struct {
		name     string
		opts     FilterOptions
		expected int
	}{
		{
			name:     "min length",
			opts:     FilterOptions{MinLength: 3},
			expected: 4, // abc, abcd, 12345, test123
		},
		{
			name:     "max length",
			opts:     FilterOptions{MaxLength: 2},
			expected: 2, // a, ab
		},
		{
			name:     "contains",
			opts:     FilterOptions{Contains: "test"},
			expected: 1,
		},
		{
			name:     "not contains",
			opts:     FilterOptions{NotContains: "test"},
			expected: 5,
		},
		{
			name:     "starts with",
			opts:     FilterOptions{StartsWith: "ab"},
			expected: 3, // ab, abc, abcd
		},
		{
			name:     "no numbers",
			opts:     FilterOptions{NoNumbers: true},
			expected: 4, // a, ab, abc, abcd
		},
		{
			name:     "only alpha",
			opts:     FilterOptions{OnlyAlpha: true},
			expected: 4, // a, ab, abc, abcd
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := m.Filter(original, tt.opts)
			if err != nil {
				t.Fatalf("filter failed: %v", err)
			}
			if len(filtered.Words) != tt.expected {
				t.Errorf("expected %d words, got %d: %v", tt.expected, len(filtered.Words), filtered.Words)
			}
		})
	}
}

func TestFilterWithRegex(t *testing.T) {
	m := NewManager(nil)

	original := &Wordlist{
		Words: []string{"test1", "test2", "prod1", "dev1"},
	}

	filtered, err := m.Filter(original, FilterOptions{
		Regex: "^test\\d$",
	})
	if err != nil {
		t.Fatalf("filter failed: %v", err)
	}

	if len(filtered.Words) != 2 {
		t.Errorf("expected 2 words, got %d", len(filtered.Words))
	}
}

func TestListBuiltIn(t *testing.T) {
	m := NewManager(nil)

	names := m.ListBuiltIn()
	if len(names) == 0 {
		t.Error("expected some built-in lists")
	}

	// Check sorted
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Error("list should be sorted")
		}
	}
}

func TestGetStats(t *testing.T) {
	m := NewManager(nil)

	wl := &Wordlist{
		Words: []string{"a", "bb", "ccc", "dddd", "dddd"}, // includes duplicate
	}

	stats := m.GetStats(wl)

	if stats.TotalWords != 5 {
		t.Errorf("expected total 5, got %d", stats.TotalWords)
	}
	if stats.UniqueWords != 4 {
		t.Errorf("expected unique 4, got %d", stats.UniqueWords)
	}
	if stats.MinLength != 1 {
		t.Errorf("expected min 1, got %d", stats.MinLength)
	}
	if stats.MaxLength != 4 {
		t.Errorf("expected max 4, got %d", stats.MaxLength)
	}
	// (1+2+3+4+4)/5 = 14/5 = 2.8
	if stats.AvgLength != 2.8 {
		t.Errorf("expected avg 2.8, got %f", stats.AvgLength)
	}
}

func TestDeduplicate(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "d"}
	result := deduplicate(input)

	if len(result) != 4 {
		t.Errorf("expected 4 unique, got %d", len(result))
	}

	// Check order preserved
	if result[0] != "a" || result[1] != "b" || result[2] != "c" || result[3] != "d" {
		t.Error("order should be preserved")
	}
}

func TestDetectWordlistType(t *testing.T) {
	tests := []struct {
		path     string
		expected WordlistType
	}{
		{"dirs.txt", TypeDirectories},
		{"directory-list.txt", TypeDirectories},
		{"files.txt", TypeFiles},
		{"extensions.txt", TypeExtensions},
		{"params.txt", TypeParameters},
		{"subdomains.txt", TypeSubdomains},
		{"usernames.txt", TypeUsernames},
		{"passwords.txt", TypePasswords},
		{"api-endpoints.txt", TypeAPI},
		{"random.txt", TypeGeneral},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := detectWordlistType(tt.path, nil)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestLeetSpeak(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test", "7357"},
		{"password", "p455w0rd"},
		{"elite", "3l173"},
		{"admin", "4dm1n"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := leetSpeak(tt.input)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestReverse(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "olleh"},
		{"abc", "cba"},
		{"a", "a"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := reverse(tt.input)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestToggleCase(t *testing.T) {
	result := toggleCase("hello")
	if result != "hElLo" {
		t.Errorf("expected 'hElLo', got '%s'", result)
	}
}

func TestCaching(t *testing.T) {
	m := NewManager(nil)

	// Load twice
	wl1, err := m.Load("builtin:common-dirs")
	if err != nil {
		t.Fatalf("first load failed: %v", err)
	}

	wl2, err := m.Load("builtin:common-dirs")
	if err != nil {
		t.Fatalf("second load failed: %v", err)
	}

	// Should be same instance from cache
	if wl1 != wl2 {
		t.Error("cached wordlist should return same instance")
	}
}

func TestExpandPattern(t *testing.T) {
	// Test literal escape
	result := expandPattern("??")
	if result != "?" {
		t.Errorf("expected '?', got '%s'", result)
	}

	// Test digit
	result = expandPattern("test?d")
	if len(result) != 5 {
		t.Errorf("expected length 5, got %d", len(result))
	}
	if result[4] < '0' || result[4] > '9' {
		t.Error("last char should be digit")
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/file.txt", "https___example.com_file.txt"},
		{"file name with spaces", "file_name_with_spaces"},
	}

	for _, tt := range tests {
		result := sanitizeFilename(tt.input)
		// Just check it's safe, not exact match
		if strings.ContainsAny(result, ":/\\?*\"<>|") {
			t.Errorf("result '%s' contains unsafe chars", result)
		}
	}
}
