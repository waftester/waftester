// Package templates embeds all bundled template files for distribution.
//
// This ensures templates are available regardless of installation method
// (Homebrew, Scoop, npm, Docker, or manual download). The CLI falls back
// to these embedded templates when no on-disk templates directory exists.
//
// Usage:
//
//	fs := templates.FS
//	data, _ := fs.ReadFile("policies/strict.yaml")
package templates

import "embed"

// FS contains all bundled template files (nuclei, workflows, policies,
// overrides, output formats, and report configs). Subdirectory structure
// matches the on-disk templates/ layout minus this Go file and README.md.
//
//go:embed nuclei/**/* workflows/*.yaml policies/*.yaml overrides/*.yaml output/*.tmpl report-configs/*.yaml
var FS embed.FS
