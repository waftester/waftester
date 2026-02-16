// Package templateresolver resolves template references to file paths or embedded content.
//
// It implements a resolution chain: explicit path → on-disk defaults directory →
// WAF_TESTER_TEMPLATE_DIR env var → embedded FS fallback.
// This ensures templates are always available regardless of installation method.
//
// Usage:
//
//	// Resolve a policy by short name
//	result, err := templateresolver.Resolve("strict", templateresolver.KindPolicy)
//	if err != nil { ... }
//	defer result.Content.Close()
//	data, _ := io.ReadAll(result.Content)
//
//	// Resolve a nuclei template directory
//	dir, err := templateresolver.ResolveNucleiDir("/custom/templates")
package templateresolver

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/templates"
)

// containsTraversal reports whether a template reference attempts directory traversal.
func containsTraversal(value string) bool {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}

// Kind identifies the template category for resolution.
type Kind string

const (
	// KindPolicy resolves policy YAML files from policies/.
	KindPolicy Kind = "policies"

	// KindOverride resolves override YAML files from overrides/.
	KindOverride Kind = "overrides"

	// KindReportConfig resolves report config YAML files from report-configs/.
	KindReportConfig Kind = "report-configs"

	// KindOutputFormat resolves Go text/template files from output/.
	KindOutputFormat Kind = "output"

	// KindWorkflow resolves workflow YAML files from workflows/.
	KindWorkflow Kind = "workflows"

	// KindNuclei resolves nuclei template YAML files from nuclei/.
	KindNuclei Kind = "nuclei"
)

// extensions maps each Kind to its expected file extension.
var extensions = map[Kind]string{
	KindPolicy:       ".yaml",
	KindOverride:     ".yaml",
	KindReportConfig: ".yaml",
	KindOutputFormat: ".tmpl",
	KindWorkflow:     ".yaml",
	KindNuclei:       ".yaml",
}

// envKey is the environment variable for overriding the template root directory.
const envKey = "WAF_TESTER_TEMPLATE_DIR"

// diskDirs maps each Kind to its on-disk directory from defaults.
var diskDirs = map[Kind]string{
	KindPolicy:       defaults.PolicyDir,
	KindOverride:     defaults.OverrideDir,
	KindReportConfig: defaults.ReportConfigDir,
	KindOutputFormat: defaults.OutputTemplateDir,
	KindWorkflow:     defaults.WorkflowDir,
	KindNuclei:       defaults.TemplateDir,
}

// Result holds a resolved template's content and metadata.
type Result struct {
	// Source describes where the template was found (e.g. "embedded:policies/strict.yaml", "disk:/path").
	Source string

	// Content is a ReadCloser for the template data. Caller must close it.
	Content io.ReadCloser
}

// validKind reports whether kind is a recognized template category.
func validKind(kind Kind) bool {
	_, ok := extensions[kind]
	return ok
}

// locateResult describes where a template was found during resolution.
type locateResult struct {
	source   string // e.g. "disk:/path", "env:/path", "embedded:rel"
	diskPath string // non-empty for disk/env sources
	rel      string // relative path in embedded FS; non-empty for short-name resolution
}

// locate implements the shared resolution chain for both Resolve and ResolveToPath.
// For embedded templates, it briefly opens the file to verify existence, then closes it.
func locate(value string, kind Kind) (*locateResult, error) {
	if value == "" {
		return nil, fmt.Errorf("templateresolver: empty template reference")
	}
	if containsTraversal(value) {
		return nil, fmt.Errorf("templateresolver: path traversal not allowed: %q", value)
	}
	if !validKind(kind) {
		return nil, fmt.Errorf("templateresolver: unknown kind %q", kind)
	}

	// If it looks like a file path (contains directory separators), use disk directly.
	if strings.ContainsAny(value, "/\\") {
		return &locateResult{source: "disk:" + value, diskPath: value}, nil
	}

	// Short name resolution: add extension if missing.
	name := value
	ext := extensions[kind]
	if ext != "" && !strings.HasSuffix(name, ext) {
		name += ext
	}
	rel := string(kind) + "/" + name

	// 1. Check on-disk directory from defaults
	diskPath := filepath.Join(diskDirs[kind], name)
	if _, err := os.Stat(diskPath); err == nil {
		return &locateResult{source: "disk:" + diskPath, diskPath: diskPath, rel: rel}, nil
	}

	// 2. Check WAF_TESTER_TEMPLATE_DIR env var
	if envDir := os.Getenv(envKey); envDir != "" {
		envPath := filepath.Join(envDir, string(kind), name)
		if _, err := os.Stat(envPath); err == nil {
			return &locateResult{source: "env:" + envPath, diskPath: envPath, rel: rel}, nil
		}
	}

	// 3. Check embedded FS
	if f, err := templates.FS.Open(rel); err == nil {
		f.Close()
		return &locateResult{source: "embedded:" + rel, rel: rel}, nil
	}

	return nil, fmt.Errorf("templateresolver: %q not found (kind=%s): tried disk, env, embedded", value, kind)
}

// Resolve resolves a template reference to its content.
//
// The value parameter can be:
//   - A filesystem path (contains / or \) → read from disk
//   - A short name (e.g. "strict") → look up via resolution chain
//   - A filename with extension (e.g. "strict.yaml") → same resolution chain
//
// Resolution order for short names:
//  1. On-disk ./templates/<kind>/<name><ext> (backward compat)
//  2. WAF_TESTER_TEMPLATE_DIR env var: <dir>/<kind>/<name><ext>
//  3. Embedded FS fallback (always available)
func Resolve(value string, kind Kind) (*Result, error) {
	loc, err := locate(value, kind)
	if err != nil {
		return nil, err
	}

	// Disk or env source: open the file.
	if loc.diskPath != "" {
		f, openErr := os.Open(loc.diskPath)
		if openErr != nil {
			return nil, fmt.Errorf("templateresolver: opening %q: %w", loc.diskPath, openErr)
		}
		return &Result{Source: loc.source, Content: f}, nil
	}

	// Embedded source.
	data, openErr := templates.FS.Open(loc.rel)
	if openErr != nil {
		return nil, fmt.Errorf("templateresolver: opening embedded %q: %w", loc.rel, openErr)
	}
	return &Result{Source: loc.source, Content: data}, nil
}

// nucleiCache holds the result of the one-time embedded nuclei extraction.
var (
	nucleiOnce      sync.Once
	nucleiCachedDir string
	nucleiCachedErr error
)

// ResolveNucleiDir returns a directory path for nuclei templates.
// If the provided dir exists on disk, it is returned as-is.
// Otherwise, it extracts embedded nuclei templates to a temp directory.
// The extraction runs at most once; subsequent calls return the cached path.
func ResolveNucleiDir(dir string) (string, error) {
	// Reject empty or traversal attempts.
	if dir == "" {
		return "", fmt.Errorf("templateresolver: empty nuclei directory")
	}
	if containsTraversal(dir) {
		return "", fmt.Errorf("templateresolver: path traversal not allowed: %q", dir)
	}

	// If dir exists on disk, use it directly.
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return dir, nil
	}

	// Extract embedded templates exactly once.
	nucleiOnce.Do(func() {
		nucleiCachedDir, nucleiCachedErr = extractNucleiTemplates()
	})
	return nucleiCachedDir, nucleiCachedErr
}

// extractNucleiTemplates writes embedded nuclei templates to a temporary directory.
func extractNucleiTemplates() (string, error) {
	tmpDir, err := os.MkdirTemp("", "waftester-nuclei-*")
	if err != nil {
		return "", fmt.Errorf("templateresolver: creating temp dir: %w", err)
	}

	err = fs.WalkDir(templates.FS, "nuclei", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		dest := filepath.Join(tmpDir, path)
		if d.IsDir() {
			return os.MkdirAll(dest, 0o755)
		}
		data, readErr := templates.FS.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		return os.WriteFile(dest, data, 0o600)
	})
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("templateresolver: extracting nuclei templates: %w", err)
	}

	return filepath.Join(tmpDir, "nuclei"), nil
}

// ResetNucleiCache cleans up any cached temp directory and resets the
// sync.Once so the next ResolveNucleiDir call re-extracts.
// Not safe to call while ResolveNucleiDir is running concurrently.
func ResetNucleiCache() {
	if nucleiCachedDir != "" {
		// nucleiCachedDir is <tmpDir>/nuclei; remove the parent temp directory.
		os.RemoveAll(filepath.Dir(nucleiCachedDir))
	}
	nucleiOnce = sync.Once{}
	nucleiCachedDir = ""
	nucleiCachedErr = nil
}

// ListCategory returns metadata for all templates in a category from the embedded FS.
func ListCategory(kind Kind) ([]TemplateInfo, error) {
	if !validKind(kind) {
		return nil, fmt.Errorf("templateresolver: unknown kind %q", kind)
	}

	dir := string(kind)

	infos := make([]TemplateInfo, 0)
	err := fs.WalkDir(templates.FS, dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		infos = append(infos, parseTemplateInfo(path, kind))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("templateresolver: listing %s: %w", kind, err)
	}
	return infos, nil
}

// ListAllCategories returns a summary of all template categories.
// Categories that fail to list are logged and skipped.
func ListAllCategories() []CategoryInfo {
	kinds := []Kind{KindNuclei, KindWorkflow, KindPolicy, KindOverride, KindOutputFormat, KindReportConfig}
	categories := make([]CategoryInfo, 0, len(kinds))
	for _, k := range kinds {
		infos, err := ListCategory(k)
		if err != nil {
			log.Printf("templateresolver: listing %s: %v", k, err)
			continue
		}
		categories = append(categories, CategoryInfo{
			Kind:  k,
			Count: len(infos),
		})
	}
	return categories
}

// TemplateInfo holds metadata about a single template.
type TemplateInfo struct {
	// Name is the short name (e.g. "strict", "sqli-basic").
	Name string `json:"name"`

	// Path is the relative path within the embedded FS (e.g. "policies/strict.yaml").
	// For non-nuclei templates, use Name with Resolve() to access content.
	// For nuclei templates in subdirectories, use ResolveEmbeddedPath(Path) instead.
	Path string `json:"path"`

	// Kind is the template category.
	Kind Kind `json:"kind"`
}

// CategoryInfo holds summary information about a template category.
type CategoryInfo struct {
	Kind  Kind `json:"kind"`
	Count int  `json:"count"`
}

// ResolveToPath resolves a template reference to a filesystem path.
// If the template is embedded, it materializes it to a temp file.
// The caller should call the returned cleanup function when done.
// If no cleanup is needed (disk file), cleanup is a no-op.
func ResolveToPath(value string, kind Kind) (path string, cleanup func(), err error) {
	noop := func() {}

	loc, locErr := locate(value, kind)
	if locErr != nil {
		return "", noop, locErr
	}

	// Disk or env source: verify it exists and return the path.
	if loc.diskPath != "" {
		if _, statErr := os.Stat(loc.diskPath); statErr != nil {
			return "", noop, fmt.Errorf("templateresolver: file not found: %w", statErr)
		}
		return loc.diskPath, noop, nil
	}

	// Embedded source: materialize to temp file.
	ext := extensions[kind]
	data, readErr := templates.FS.ReadFile(loc.rel)
	if readErr != nil {
		return "", noop, fmt.Errorf("templateresolver: reading embedded %q: %w", loc.rel, readErr)
	}

	tmpFile, tmpErr := os.CreateTemp("", "waftester-template-*"+ext)
	if tmpErr != nil {
		return "", noop, fmt.Errorf("templateresolver: creating temp file: %w", tmpErr)
	}

	if _, writeErr := tmpFile.Write(data); writeErr != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", noop, fmt.Errorf("templateresolver: writing temp file: %w", writeErr)
	}
	if closeErr := tmpFile.Close(); closeErr != nil {
		os.Remove(tmpFile.Name())
		return "", noop, fmt.Errorf("templateresolver: closing temp file: %w", closeErr)
	}

	return tmpFile.Name(), func() { os.Remove(tmpFile.Name()) }, nil
}

// ResolveEmbeddedPath resolves a template by its full embedded-FS relative path.
// Use this for templates in subdirectories (e.g. "nuclei/http/waf-bypass/sqli-basic")
// where the name itself contains directory separators that locate() would
// misinterpret as a filesystem path.
func ResolveEmbeddedPath(rel string) (*Result, error) {
	if rel == "" {
		return nil, fmt.Errorf("templateresolver: empty embedded path")
	}

	// Normalize backslashes so Windows callers don't get silent embed.FS failures.
	rel = strings.ReplaceAll(rel, "\\", "/")

	if containsTraversal(rel) {
		return nil, fmt.Errorf("templateresolver: path traversal not allowed: %q", rel)
	}

	// Try with and without common extensions.
	candidates := []string{rel}
	if !strings.HasSuffix(rel, ".yaml") && !strings.HasSuffix(rel, ".tmpl") {
		candidates = append(candidates, rel+".yaml", rel+".tmpl")
	}

	for _, c := range candidates {
		f, err := templates.FS.Open(c)
		if err != nil {
			continue
		}
		info, statErr := f.Stat()
		if statErr != nil || info.IsDir() {
			f.Close()
			continue
		}
		return &Result{Source: "embedded:" + c, Content: f}, nil
	}

	return nil, fmt.Errorf("templateresolver: embedded path %q not found", rel)
}

// parseTemplateInfo extracts info from an embedded FS path.
func parseTemplateInfo(path string, kind Kind) TemplateInfo {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	return TemplateInfo{
		Name: name,
		Path: path,
		Kind: kind,
	}
}
