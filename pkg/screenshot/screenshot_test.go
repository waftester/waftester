package screenshot

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Width != 1920 {
		t.Errorf("expected Width 1920, got %d", config.Width)
	}
	if config.Height != 1080 {
		t.Errorf("expected Height 1080, got %d", config.Height)
	}
	if config.Quality != 80 {
		t.Errorf("expected Quality 80, got %d", config.Quality)
	}
	if config.Format != FormatPNG {
		t.Errorf("expected Format PNG, got %s", config.Format)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("expected Timeout 30s, got %v", config.Timeout)
	}
	if config.Concurrency != 5 {
		t.Errorf("expected Concurrency 5, got %d", config.Concurrency)
	}
}

func TestNewCapturer(t *testing.T) {
	config := DefaultConfig()
	capturer := NewCapturer(config)

	if capturer == nil {
		t.Fatal("NewCapturer returned nil")
	}
	if capturer.config.Width != 1920 {
		t.Error("config not set correctly")
	}
}

func TestNewCapturer_Defaults(t *testing.T) {
	// Test with zero values
	config := Config{}
	capturer := NewCapturer(config)

	if capturer.config.Width != 1920 {
		t.Errorf("expected default Width 1920, got %d", capturer.config.Width)
	}
	if capturer.config.Height != 1080 {
		t.Errorf("expected default Height 1080, got %d", capturer.config.Height)
	}
	if capturer.config.Quality != 80 {
		t.Errorf("expected default Quality 80, got %d", capturer.config.Quality)
	}
}

func TestNewCapturer_CustomValues(t *testing.T) {
	config := Config{
		Width:       1280,
		Height:      720,
		Quality:     50,
		Format:      FormatJPEG,
		Concurrency: 10,
	}
	capturer := NewCapturer(config)

	if capturer.config.Width != 1280 {
		t.Error("custom Width not preserved")
	}
	if capturer.config.Format != FormatJPEG {
		t.Error("custom Format not preserved")
	}
}

func TestCapturer_CaptureURL(t *testing.T) {
	tmpDir := t.TempDir()
	config := DefaultConfig()
	config.OutputDir = tmpDir

	capturer := NewCapturer(config)

	result, err := capturer.CaptureURL(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.URL != "https://example.com" {
		t.Errorf("wrong URL: %s", result.URL)
	}
	if result.Width != config.Width {
		t.Errorf("wrong Width: %d", result.Width)
	}
	if len(result.Data) == 0 {
		t.Error("expected image data")
	}
	if result.Base64 == "" {
		t.Error("expected base64 data")
	}
	// Duration might be 0 in fast mock mode, that's OK
}

func TestCapturer_CaptureURLs(t *testing.T) {
	config := DefaultConfig()
	config.OutputDir = t.TempDir()

	capturer := NewCapturer(config)

	urls := []string{
		"https://example.com",
		"https://example.org",
		"https://example.net",
	}

	results, err := capturer.CaptureURLs(context.Background(), urls)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

func TestCapturer_GetResults(t *testing.T) {
	capturer := NewCapturer(DefaultConfig())

	results := capturer.GetResults()
	if results == nil {
		t.Error("expected non-nil results")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestCapturer_SaveToFile(t *testing.T) {
	tmpDir := t.TempDir()
	config := DefaultConfig()
	config.OutputDir = tmpDir

	capturer := NewCapturer(config)

	result := Result{
		FilePath: filepath.Join(tmpDir, "test.png"),
		Data:     []byte{1, 2, 3, 4},
	}

	err := capturer.saveToFile(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(result.FilePath); os.IsNotExist(err) {
		t.Error("file not created")
	}
}

func TestNewBatchCapturer(t *testing.T) {
	config := DefaultConfig()
	batch := NewBatchCapturer(config)

	if batch == nil {
		t.Fatal("NewBatchCapturer returned nil")
	}
	if batch.capturer == nil {
		t.Error("capturer not initialized")
	}
}

func TestBatchCapturer_Stop(t *testing.T) {
	batch := NewBatchCapturer(DefaultConfig())

	// Should not panic
	batch.Stop()
}

func TestBatchCapturer_Add(t *testing.T) {
	batch := NewBatchCapturer(DefaultConfig())

	// Should not block
	go batch.Add("https://example.com")

	select {
	case url := <-batch.queue:
		if url != "https://example.com" {
			t.Errorf("wrong URL in queue: %s", url)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for URL in queue")
	}
}

func TestCompare(t *testing.T) {
	img1 := []byte{1, 2, 3}
	img2 := []byte{1, 2, 3}

	result, err := Compare(img1, img2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Similarity != 1.0 {
		t.Errorf("expected similarity 1.0, got %f", result.Similarity)
	}
}

func TestGenerateThumbnail(t *testing.T) {
	result := Result{
		Data: []byte{1, 2, 3, 4},
	}
	config := ThumbnailConfig{
		Width:   100,
		Height:  100,
		Quality: 80,
	}

	thumbnail, err := GenerateThumbnail(result, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(thumbnail) == 0 {
		t.Error("expected thumbnail data")
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com/path", "example.com_path"},
		{"https://example.com?query=1", "example.com_query_1"},
		{"https://example.com:8080/path", "example.com_8080_path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeFilename(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeFilename_LongURL(t *testing.T) {
	longURL := "https://example.com/" + string(make([]byte, 200))
	result := sanitizeFilename(longURL)

	if len(result) > 100 {
		t.Errorf("expected max 100 chars, got %d", len(result))
	}
}

func TestGenerateMockImage_PNG(t *testing.T) {
	data, err := generateMockImage(100, 100, FormatPNG)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected image data")
	}
	// Check PNG signature
	if data[0] != 0x89 || data[1] != 0x50 {
		t.Error("invalid PNG signature")
	}
}

func TestGenerateMockImage_JPEG(t *testing.T) {
	data, err := generateMockImage(100, 100, FormatJPEG)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected image data")
	}
	// Check JPEG signature
	if data[0] != 0xFF || data[1] != 0xD8 {
		t.Error("invalid JPEG signature")
	}
}

func TestGetExtension(t *testing.T) {
	tests := []struct {
		format   Format
		expected string
	}{
		{FormatPNG, ".png"},
		{FormatJPEG, ".jpg"},
		{FormatWebP, ".webp"},
		{Format("unknown"), ".png"},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			result := GetExtension(tt.format)
			if result != tt.expected {
				t.Errorf("GetExtension(%s) = %s, want %s", tt.format, result, tt.expected)
			}
		})
	}
}

func TestValidURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com", true},
		{"http://example.com", true},
		{"ftp://example.com", false},
		{"example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := ValidURL(tt.url)
			if result != tt.expected {
				t.Errorf("ValidURL(%s) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
}

func TestFormat_Constants(t *testing.T) {
	formats := []Format{FormatPNG, FormatJPEG, FormatWebP}

	seen := make(map[Format]bool)
	for _, f := range formats {
		if seen[f] {
			t.Errorf("duplicate format: %s", f)
		}
		seen[f] = true
	}
}

func TestResult_Fields(t *testing.T) {
	result := Result{
		URL:       "https://example.com",
		FilePath:  "/path/to/file.png",
		Data:      []byte{1, 2, 3},
		Base64:    "AQID",
		Width:     1920,
		Height:    1080,
		Size:      3,
		Duration:  5 * time.Second,
		Timestamp: time.Now(),
		Error:     "",
	}

	if result.URL != "https://example.com" {
		t.Error("URL field incorrect")
	}
	if result.Size != 3 {
		t.Error("Size field incorrect")
	}
}

func TestComparisonResult_Fields(t *testing.T) {
	result := ComparisonResult{
		URL1:       "https://example.com",
		URL2:       "https://example.org",
		Similarity: 0.95,
		DiffPixels: 100,
		DiffImage:  []byte{1, 2, 3},
	}

	if result.Similarity != 0.95 {
		t.Error("Similarity field incorrect")
	}
}

func TestThumbnailConfig_Fields(t *testing.T) {
	config := ThumbnailConfig{
		Width:   100,
		Height:  100,
		Quality: 80,
	}

	if config.Width != 100 {
		t.Error("Width field incorrect")
	}
}

func TestBatchCapturer_Results(t *testing.T) {
	batch := NewBatchCapturer(DefaultConfig())

	results := batch.Results()
	if results == nil {
		t.Error("expected non-nil results channel")
	}
}
