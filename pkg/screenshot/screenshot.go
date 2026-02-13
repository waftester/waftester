// Package screenshot provides screenshot capture capabilities for web pages
package screenshot

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
)

// Timeout constants for screenshot operations
var (
	// TimeoutFuzzing is the default timeout for screenshot capture (30s)
	// Uses duration.BrowserPage for consistency across codebase
	TimeoutFuzzing = duration.BrowserPage
)

// Config configures screenshot capture
type Config struct {
	attackconfig.Base
	Width     int           // Viewport width
	Height    int           // Viewport height
	FullPage  bool          // Capture full page
	Quality   int           // JPEG quality (1-100)
	Format    Format        // Output format
	WaitFor   time.Duration // Wait after page load
	OutputDir string        // Output directory
}

// Format represents output format
type Format string

const (
	FormatPNG  Format = "png"
	FormatJPEG Format = "jpeg"
	FormatWebP Format = "webp"
)

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Base: attackconfig.Base{
			Concurrency: defaults.ConcurrencyLow,
			Timeout:     TimeoutFuzzing,
		},
		Width:     1920,
		Height:    1080,
		FullPage:  false,
		Quality:   80,
		Format:    FormatPNG,
		WaitFor:   duration.BrowserIdle,
		OutputDir: "screenshots",
	}
}

// Result represents a screenshot result
type Result struct {
	URL       string        `json:"url"`
	FilePath  string        `json:"file_path"`
	Data      []byte        `json:"-"` // Raw image data
	Base64    string        `json:"base64,omitempty"`
	Width     int           `json:"width"`
	Height    int           `json:"height"`
	Size      int64         `json:"size_bytes"`
	Duration  time.Duration `json:"capture_duration"`
	Timestamp time.Time     `json:"timestamp"`
	Error     string        `json:"error,omitempty"`
}

// Capturer captures screenshots
type Capturer struct {
	config    Config
	results   []Result
	mu        sync.RWMutex
	semaphore chan struct{}
}

// NewCapturer creates a screenshot capturer
func NewCapturer(config Config) *Capturer {
	if config.Width <= 0 {
		config.Width = 1920
	}
	if config.Height <= 0 {
		config.Height = 1080
	}
	if config.Quality <= 0 || config.Quality > 100 {
		config.Quality = 80
	}
	if config.Timeout <= 0 {
		config.Timeout = TimeoutFuzzing
	}
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyLow
	}
	if config.Format == "" {
		config.Format = FormatPNG
	}

	return &Capturer{
		config:    config,
		results:   make([]Result, 0),
		semaphore: make(chan struct{}, config.Concurrency),
	}
}

// CaptureURL captures a screenshot of a URL
func (c *Capturer) CaptureURL(ctx context.Context, url string) (Result, error) {
	c.semaphore <- struct{}{}        // Acquire
	defer func() { <-c.semaphore }() // Release

	start := time.Now()
	result := Result{
		URL:       url,
		Width:     c.config.Width,
		Height:    c.config.Height,
		Timestamp: time.Now(),
	}

	// Generate filename
	filename := sanitizeFilename(url) + "." + string(c.config.Format)
	result.FilePath = filepath.Join(c.config.OutputDir, filename)

	// Simulate screenshot capture (actual chromedp integration would go here)
	// In production, this would use chromedp.CaptureScreenshot
	data, err := c.captureWithChrome(ctx, url)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Data = data
	result.Size = int64(len(data))
	result.Duration = time.Since(start)

	// Save to file if output dir specified
	if c.config.OutputDir != "" {
		if err := c.saveToFile(result); err != nil {
			result.Error = err.Error()
		}
	}

	// Optionally encode to base64
	result.Base64 = base64.StdEncoding.EncodeToString(data)

	c.mu.Lock()
	c.results = append(c.results, result)
	c.mu.Unlock()

	return result, nil
}

// CaptureURLs captures screenshots of multiple URLs
// Returns partial results even if some captures fail, with aggregated errors
func (c *Capturer) CaptureURLs(ctx context.Context, urls []string) ([]Result, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	results := make([]Result, len(urls))

	for i, url := range urls {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()
			result, err := c.CaptureURL(ctx, u)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			results[idx] = result
		}(i, url)
	}

	wg.Wait()

	// Return combined error if any captures failed
	if len(errs) > 0 {
		return results, fmt.Errorf("%d/%d captures failed", len(errs), len(urls))
	}
	return results, nil
}

// GetResults returns all captured results
func (c *Capturer) GetResults() []Result {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.results
}

// captureWithChrome performs actual screenshot capture
// This is a placeholder - in production would use chromedp
func (c *Capturer) captureWithChrome(ctx context.Context, url string) ([]byte, error) {
	// Placeholder implementation
	// Actual implementation would use:
	//
	// var buf []byte
	// tasks := chromedp.Tasks{
	//     chromedp.EmulateViewport(int64(c.config.Width), int64(c.config.Height)),
	//     chromedp.Navigate(url),
	//     chromedp.Sleep(c.config.WaitFor),
	//     chromedp.CaptureScreenshot(&buf),
	// }
	// ctx, cancel := chromedp.NewContext(ctx)
	// defer cancel()
	// if err := chromedp.Run(ctx, tasks); err != nil {
	//     return nil, err
	// }
	// return buf, nil

	// For now, return mock data
	return generateMockImage(c.config.Width, c.config.Height, c.config.Format)
}

// saveToFile saves screenshot to file
func (c *Capturer) saveToFile(result Result) error {
	if err := os.MkdirAll(c.config.OutputDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(result.FilePath, result.Data, 0644)
}

// ThumbnailConfig configures thumbnail generation
type ThumbnailConfig struct {
	Width   int
	Height  int
	Quality int
}

// GenerateThumbnail creates a thumbnail from a result
func GenerateThumbnail(result Result, config ThumbnailConfig) ([]byte, error) {
	// Placeholder - would use image resizing library
	return result.Data, nil
}

// BatchCapturer handles batch screenshot operations
type BatchCapturer struct {
	capturer  *Capturer
	queue     chan string
	results   chan Result
	done      chan struct{}
	stopOnce  sync.Once
	drainDone chan struct{}
	wg        sync.WaitGroup
}

// NewBatchCapturer creates a batch capturer
func NewBatchCapturer(config Config) *BatchCapturer {
	return &BatchCapturer{
		capturer:  NewCapturer(config),
		queue:     make(chan string, 1000),
		results:   make(chan Result, 1000),
		done:      make(chan struct{}),
		drainDone: make(chan struct{}),
	}
}

// Start begins processing the queue
func (b *BatchCapturer) Start(ctx context.Context, workers int) {
	for i := 0; i < workers; i++ {
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-b.done:
					return
				case url := <-b.queue:
					result, _ := b.capturer.CaptureURL(ctx, url)
					b.results <- result
				}
			}
		}()
	}
}

// Add adds a URL to the queue
func (b *BatchCapturer) Add(url string) {
	b.queue <- url
}

// Results returns the results channel
func (b *BatchCapturer) Results() <-chan Result {
	return b.results
}

// Stop stops the batch capturer and drains channels to prevent goroutine leaks
func (b *BatchCapturer) Stop() {
	b.stopOnce.Do(func() {
		close(b.done)
		// Wait for workers to exit, then close channels so drain goroutines terminate
		b.wg.Wait()
		close(b.queue)
		close(b.results)
		// Drain remaining items
		go func() {
			for range b.queue {
			}
		}()
		go func() {
			for range b.results {
			}
			close(b.drainDone)
		}()
	})
}

// ComparisonResult represents a visual comparison result
type ComparisonResult struct {
	URL1       string  `json:"url1"`
	URL2       string  `json:"url2"`
	Similarity float64 `json:"similarity"` // 0.0 to 1.0
	DiffPixels int     `json:"diff_pixels"`
	DiffImage  []byte  `json:"-"`
}

// Compare compares two screenshots
func Compare(img1, img2 []byte) (ComparisonResult, error) {
	// Placeholder - would use image comparison library
	return ComparisonResult{
		Similarity: 1.0,
		DiffPixels: 0,
	}, nil
}

// Helper functions

func sanitizeFilename(url string) string {
	// Remove protocol
	s := strings.TrimPrefix(url, "https://")
	s = strings.TrimPrefix(s, "http://")

	// Replace invalid characters
	replacer := strings.NewReplacer(
		"/", "_",
		":", "_",
		"?", "_",
		"&", "_",
		"=", "_",
		"#", "_",
		" ", "_",
	)
	s = replacer.Replace(s)

	// Limit length
	if len(s) > 100 {
		s = s[:100]
	}

	return s
}

func generateMockImage(width, height int, format Format) ([]byte, error) {
	// Generate minimal valid image data based on format
	switch format {
	case FormatPNG:
		// Minimal 1x1 PNG
		return []byte{
			0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
			0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
			0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
			0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
			0x54, 0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0x3F,
			0x00, 0x05, 0xFE, 0x02, 0xFE, 0xDC, 0xCC, 0x59,
			0xE7, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
			0x44, 0xAE, 0x42, 0x60, 0x82,
		}, nil
	case FormatJPEG:
		// Minimal JPEG
		return []byte{
			0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
			0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
			0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9,
		}, nil
	default:
		return []byte{}, nil
	}
}

// GetExtension returns the file extension for a format
func GetExtension(format Format) string {
	switch format {
	case FormatPNG:
		return ".png"
	case FormatJPEG:
		return ".jpg"
	case FormatWebP:
		return ".webp"
	default:
		return ".png"
	}
}

// ValidURL checks if a URL is valid for screenshotting
func ValidURL(url string) bool {
	if url == "" {
		return false
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return false
	}
	return true
}
