// Package presets provides embedded service preset definitions for endpoint
// discovery. Presets are JSON files that define service-specific endpoints
// and attack surface characteristics. Add new services by dropping a JSON
// file into this directory — no Go code changes required.
package presets

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed *.json
var embedded embed.FS

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
)

func loadRegistry() map[string]*Preset {
	registryOnce.Do(func() {
		registry = make(map[string]*Preset)
		entries, err := embedded.ReadDir(".")
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, err := embedded.ReadFile(entry.Name())
			if err != nil {
				continue
			}
			var p Preset
			if err := json.Unmarshal(data, &p); err != nil {
				continue
			}
			if p.Name == "" {
				p.Name = strings.TrimSuffix(entry.Name(), ".json")
			}
			registry[strings.ToLower(p.Name)] = &p
		}
	})
	return registry
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
