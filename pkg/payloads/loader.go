package payloads

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/waftester/waftester/pkg/jsonutil"
)

// Loader handles loading payloads from JSON files
type Loader struct {
	baseDir string
}

// NewLoader creates a new payload loader
func NewLoader(baseDir string) *Loader {
	return &Loader{baseDir: baseDir}
}

// LoadAll loads all payloads from the directory structure.
// Only regular files under baseDir are loaded; symlinks are skipped
// to prevent directory escapes and infinite loops.
func (l *Loader) LoadAll() ([]Payload, error) {
	absBase, err := filepath.Abs(l.baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolving base path: %w", err)
	}

	allPayloads := make([]Payload, 0, 3072)

	err = filepath.WalkDir(l.baseDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip symlinks to prevent directory escapes and loops
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		// Skip directories and non-JSON files
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}

		// Verify path stays under base directory
		absPath, absErr := filepath.Abs(path)
		if absErr != nil {
			return nil
		}
		if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) && absPath != absBase {
			return nil
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

// loadFile loads payloads from a single JSON file
func (l *Loader) loadFile(path string) ([]Payload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var payloads []Payload
	if err := jsonutil.Unmarshal(data, &payloads); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	// Normalize payloads: if AttackCategory is set but Category is not, copy it
	for i := range payloads {
		if payloads[i].Category == "" && payloads[i].AttackCategory != "" {
			payloads[i].Category = payloads[i].AttackCategory
		}
		// Default method to GET if not specified
		if payloads[i].Method == "" {
			payloads[i].Method = "GET"
		}
	}

	return payloads, nil
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

	var filtered []Payload
	for _, p := range payloads {
		// Category filter (case-insensitive)
		if category != "" {
			if !strings.EqualFold(p.Category, category) {
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
