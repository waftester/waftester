// Package presets embeds all bundled service preset files for distribution.
//
// This ensures presets are available regardless of installation method
// (Homebrew, Scoop, npm, Docker, or manual download). The discovery engine
// falls back to these embedded presets when no on-disk presets directory exists.
//
// Usage:
//
//	fs := presets.FS
//	data, _ := fs.ReadFile("authentik.json")
package presets

import "embed"

// FS contains all bundled service preset JSON files. Each file defines
// service-specific endpoints and attack surface characteristics.
//
//go:embed *.json
var FS embed.FS
