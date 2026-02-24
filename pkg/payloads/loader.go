package payloads

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/jsonutil"
)

// cacheEntry holds cached payload data for a single file.
type cacheEntry struct {
	payloads []Payload
	modTime  time.Time
	size     int64
}

// fileCache caches parsed payload files, keyed by absolute path.
// Re-parses only when the file's modTime or size has changed.
type fileCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

var defaultCache = &fileCache{entries: make(map[string]*cacheEntry)}

// get returns cached payloads if the file hasn't changed, or nil if stale/missing.
func (fc *fileCache) get(absPath string, info os.FileInfo) ([]Payload, bool) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	e, ok := fc.entries[absPath]
	if !ok {
		return nil, false
	}
	if e.modTime.Equal(info.ModTime()) && e.size == info.Size() {
		return e.payloads, true
	}
	return nil, false
}

// put stores parsed payloads in the cache.
func (fc *fileCache) put(absPath string, info os.FileInfo, payloads []Payload) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.entries[absPath] = &cacheEntry{
		payloads: payloads,
		modTime:  info.ModTime(),
		size:     info.Size(),
	}
}

// Loader handles loading payloads from JSON files
type Loader struct {
	baseDir string
}

// NewLoader creates a new payload loader
func NewLoader(baseDir string) *Loader {
	return &Loader{baseDir: baseDir}
}

// LoadAll loads all payloads from the directory structure.
// Symlinks are resolved via filepath.EvalSymlinks and verified to stay
// within the base directory, preventing traversal attacks.
func (l *Loader) LoadAll() ([]Payload, error) {
	absBase, err := filepath.Abs(l.baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolving base path: %w", err)
	}

	// Resolve symlinks in the base path to establish the real root.
	resolvedBase, err := filepath.EvalSymlinks(absBase)
	if err != nil {
		return nil, fmt.Errorf("resolving base symlinks: %w", err)
	}

	allPayloads := make([]Payload, 0, 3072)

	err = filepath.WalkDir(l.baseDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-JSON files
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}

		// Resolve the real path (follows symlinks) and verify it
		// stays within the resolved base directory.
		absPath, absErr := filepath.Abs(path)
		if absErr != nil {
			return nil
		}
		resolvedPath, evalErr := filepath.EvalSymlinks(absPath)
		if evalErr != nil {
			return nil // skip files whose symlinks can't be resolved
		}
		if !strings.HasPrefix(resolvedPath, resolvedBase+string(filepath.Separator)) && resolvedPath != resolvedBase {
			return nil // symlink escapes base directory
		}

		// Skip metadata files
		if d.Name() == "version.json" || d.Name() == "ids-map.json" {
			return nil
		}

		// Load payloads from file
		payloads, loadErr := l.loadFile(path)
		if loadErr != nil {
			return fmt.Errorf("loading %s: %w", path, loadErr)
		}

		allPayloads = append(allPayloads, payloads...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return allPayloads, nil
}

// LoadCategory loads payloads from a specific category directory
func (l *Loader) LoadCategory(category string) ([]Payload, error) {
	categoryDir := filepath.Join(l.baseDir, category)

	// Prevent path traversal via crafted category names
	absCategory, err := filepath.Abs(categoryDir)
	if err != nil {
		return nil, fmt.Errorf("resolving category path: %w", err)
	}
	absBase, err := filepath.Abs(l.baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolving base path: %w", err)
	}
	if !strings.HasPrefix(absCategory, absBase+string(filepath.Separator)) && absCategory != absBase {
		return nil, fmt.Errorf("category %q escapes payload directory", category)
	}
	var payloads []Payload

	entries, err := os.ReadDir(categoryDir)
	if err != nil {
		return nil, fmt.Errorf("reading category %s: %w", category, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(categoryDir, entry.Name())
		loaded, err := l.loadFile(filePath)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, loaded...)
	}

	return payloads, nil
}

// loadFile loads payloads from a single JSON file, using the file cache
// to avoid re-parsing unchanged files.
func (l *Loader) loadFile(path string) ([]Payload, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, err
	}

	// Return cached result if the file hasn't changed.
	if cached, ok := defaultCache.get(absPath, info); ok {
		return cached, nil
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}

	var payloads []Payload
	if err := jsonutil.Unmarshal(data, &payloads); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	// Normalize and validate each payload, keeping only valid ones.
	valid := make([]Payload, 0, len(payloads))
	for i := range payloads {
		payloads[i].Normalize()
		if err := payloads[i].Validate(); err != nil {
			log.Printf("payloads: skipping invalid payload in %s (index %d): %v", path, i, err)
			continue
		}
		valid = append(valid, payloads[i])
	}

	defaultCache.put(absPath, info, valid)
	return valid, nil
}

// GetStats returns statistics about loaded payloads
func GetStats(payloads []Payload) LoadStats {
	stats := LoadStats{
		TotalPayloads: len(payloads),
		ByCategory:    make(map[string]int),
	}

	for _, p := range payloads {
		stats.ByCategory[p.Category]++
	}

	stats.CategoriesUsed = len(stats.ByCategory)
	return stats
}

// Filter filters payloads by category and severity
func Filter(payloads []Payload, category, severity string) []Payload {
	if category == "" && severity == "" {
		return payloads
	}

	// Severity priority map for filtering (Critical > High > Medium > Low).
	// Keys are lowercase so lookups are case-insensitive.
	severityLevel := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	minLevel := 0
	if severity != "" {
		var ok bool
		minLevel, ok = severityLevel[strings.ToLower(severity)]
		if !ok {
			// Invalid severity - return empty slice instead of all payloads
			return []Payload{}
		}
	}

	// Build category set from comma-separated list for multi-category support.
	// e.g., "sqli,xss" matches payloads with category "sqli" OR "xss".
	var categorySet map[string]bool
	if category != "" {
		parts := strings.Split(category, ",")
		categorySet = make(map[string]bool, len(parts))
		for _, c := range parts {
			c = strings.TrimSpace(c)
			if c != "" {
				categorySet[strings.ToLower(c)] = true
			}
		}
	}

	var filtered []Payload
	for _, p := range payloads {
		// Category filter (case-insensitive, supports comma-separated list)
		if len(categorySet) > 0 {
			if !categorySet[strings.ToLower(p.Category)] {
				continue
			}
		}

		// Severity filter (case-insensitive)
		if severity != "" {
			payloadLevel := severityLevel[strings.ToLower(p.SeverityHint)]
			if payloadLevel < minLevel {
				continue
			}
		}

		filtered = append(filtered, p)
	}

	return filtered
}
