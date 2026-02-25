// Package presets loads service preset definitions for endpoint discovery.
//
// Resolution order:
//  1. On-disk directory (defaults.PresetDir or WAF_TESTER_PRESET_DIR)
//  2. Embedded fallback (presets.FS compiled into the binary)
//
// Add new services by dropping a JSON file in the presets/ directory.
// The JSON schema is:
//
//	{
//	  "name": "myservice",
//	  "description": "My service description",
//	  "endpoints": ["/api/v1/", "/health"],
//	  "attack_surface": { "has_api_endpoints": true }
//	}
package presets

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	embedded "github.com/waftester/waftester/presets"
)

// Preset defines a service endpoint preset loaded from JSON.
type Preset struct {
	Name          string      `json:"name"`
	Description   string      `json:"description"`
	Endpoints     []string    `json:"endpoints"`
	AttackSurface AttackHints `json:"attack_surface"`
}

// AttackHints declares which attack surface characteristics a service has.
// Fields match discovery.AttackSurface so the caller can apply them directly.
type AttackHints struct {
	HasAuthEndpoints bool `json:"has_auth_endpoints"`
	HasAPIEndpoints  bool `json:"has_api_endpoints"`
	HasFileUpload    bool `json:"has_file_upload"`
	HasOAuth         bool `json:"has_oauth"`
	HasSAML          bool `json:"has_saml"`
	HasGraphQL       bool `json:"has_graphql"`
	HasWebSockets    bool `json:"has_websockets"`
}

var (
	registry     map[string]*Preset
	registryOnce sync.Once
	presetDir    string // set via SetDir before first access
	dirMu        sync.Mutex
)

// SetDir configures the on-disk directory to load presets from.
// Must be called before the first Get/Names/All call.
// If never called or dir is empty, falls back to embedded presets.
func SetDir(dir string) {
	dirMu.Lock()
	defer dirMu.Unlock()
	presetDir = dir
}

func getDir() string {
	dirMu.Lock()
	defer dirMu.Unlock()
	return presetDir
}

func loadRegistry() map[string]*Preset {
	registryOnce.Do(func() {
		registry = make(map[string]*Preset)

		// Try on-disk directory first
		dir := getDir()
		if dir != "" {
			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				loadFromDisk(dir, registry)
				return
			}
		}

		// Fall back to embedded presets
		loadFromFS(embedded.FS, registry)
	})
	return registry
}

// loadFromDisk reads all JSON files from an on-disk directory.
func loadFromDisk(dir string, reg map[string]*Preset) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(absDir, entry.Name())

		// Resolve symlinks and verify we stay within the preset directory.
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(resolved, absDir) {
			continue
		}

		data, err := os.ReadFile(resolved)
		if err != nil {
			continue
		}
		parseAndRegister(data, entry.Name(), reg)
	}
}

// loadFromFS reads all JSON files from an embed.FS.
func loadFromFS(fsys fs.FS, reg map[string]*Preset) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := fs.ReadFile(fsys, entry.Name())
		if err != nil {
			continue
		}
		parseAndRegister(data, entry.Name(), reg)
	}
}

func parseAndRegister(data []byte, filename string, reg map[string]*Preset) {
	var p Preset
	if err := json.Unmarshal(data, &p); err != nil {
		return
	}
	if p.Name == "" {
		p.Name = strings.TrimSuffix(filename, ".json")
	}
	reg[strings.ToLower(p.Name)] = &p
}

// Get returns a preset by name (case-insensitive). Returns nil if not found.
func Get(name string) *Preset {
	return loadRegistry()[strings.ToLower(name)]
}

// Names returns all registered preset names in sorted order.
func Names() []string {
	reg := loadRegistry()
	names := make([]string, 0, len(reg))
	for name := range reg {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All returns all registered presets.
func All() map[string]*Preset {
	return loadRegistry()
}

// Validate returns an error if the named preset does not exist.
func Validate(name string) error {
	if Get(name) == nil {
		return fmt.Errorf("unknown service preset %q (available: %s)", name, strings.Join(Names(), ", "))
	}
	return nil
}

// Reset clears the registry so the next call reloads from disk/embedded.
// Intended for testing only.
func Reset() {
	dirMu.Lock()
	defer dirMu.Unlock()
	registry = nil
	registryOnce = sync.Once{}
}
