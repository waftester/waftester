// Package contracts enforces codebase-wide patterns via source scanning.
// These tests grep production source files for forbidden inline patterns
// that should use shared utilities instead. They prevent pattern drift
// after unification work — any new violation fails CI.
//
// To add an allowlist entry: add the file path to the allowlist map
// with a comment explaining why the exception is needed.
package contracts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// repoRoot returns the repository root (two levels up from pkg/contracts).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// pkg/contracts -> repo root
	return filepath.Join(wd, "..", "..")
}

// violation records a pattern violation found in source code.
type violation struct {
	File string
	Line int
	Text string
}

// cachedSourceLine holds pre-read source file data for contracts scanning.
type cachedSourceLine struct {
	relPath string // forward-slash relative path
	lines   []string
}

var (
	_sourceCache     []*cachedSourceLine
	_sourceCacheOnce sync.Once
	_sourceCacheRoot string
)

// loadSourceCache walks pkg/ and cmd/ once, reading all non-test Go files.
// Results are cached via sync.Once for reuse across contract tests.
func loadSourceCache(t *testing.T) (string, []*cachedSourceLine) {
	t.Helper()
	_sourceCacheOnce.Do(func() {
		_sourceCacheRoot = repoRoot(t)
		for _, dir := range []string{"pkg", "cmd"} {
			base := filepath.Join(_sourceCacheRoot, dir)
			_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}
				content, err := os.ReadFile(path)
				if err != nil {
					return nil
				}
				rel, _ := filepath.Rel(_sourceCacheRoot, path)
				rel = filepath.ToSlash(rel)
				_sourceCache = append(_sourceCache, &cachedSourceLine{
					relPath: rel,
					lines:   strings.Split(string(content), "\n"),
				})
				return nil
			})
		}
	})
	return _sourceCacheRoot, _sourceCache
}

// scanFiles iterates cached source files, skipping allowlisted paths,
// and returns violations for lines matching pattern.
func scanFiles(t *testing.T, root string, dirs []string, pattern *regexp.Regexp, allowlist map[string]string) []violation {
	t.Helper()
	_, files := loadSourceCache(t)
	var violations []violation

	// Build directory prefix set
	dirPrefixes := make([]string, len(dirs))
	for i, dir := range dirs {
		dirPrefixes[i] = filepath.ToSlash(dir) + "/"
	}

	for _, f := range files {
		// Check if file is in one of the requested directories
		inDir := false
		for _, prefix := range dirPrefixes {
			if strings.HasPrefix(f.relPath, prefix) {
				inDir = true
				break
			}
		}
		if !inDir {
			continue
		}

		if _, ok := allowlist[f.relPath]; ok {
			continue
		}

		for lineNum, line := range f.lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if pattern.MatchString(line) {
				violations = append(violations, violation{
					File: f.relPath,
					Line: lineNum + 1,
					Text: strings.TrimSpace(line),
				})
			}
		}
	}
	return violations
}

// --- Contract: No inline json.MarshalIndent + os.WriteFile ---
// All JSON file saves must use iohelper.WriteAtomicJSON for crash safety.

func TestNoInlineJSONWrite(t *testing.T) {
	root := repoRoot(t)
	// We scan for os.WriteFile in files that also import encoding/json.
	// Direct pattern: os.WriteFile(...) in a file that has json.MarshalIndent.
	// Since single-line regex can't span functions, we check for os.WriteFile
	// and then verify the file doesn't also have json.MarshalIndent.
	pattern := regexp.MustCompile(`os\.WriteFile\(`)

	allowlist := map[string]string{
		"pkg/iohelper/iohelper.go": "WriteAtomic definition uses os.WriteFile internally",
	}

	dirs := []string{"pkg", "cmd"}
	allWriteFiles := scanFiles(t, root, dirs, pattern, allowlist)

	// Filter: only flag files that ALSO have json.MarshalIndent (= JSON write pattern)
	marshalPattern := regexp.MustCompile(`json\.MarshalIndent\(`)
	for _, v := range allWriteFiles {
		absPath := filepath.Join(root, filepath.FromSlash(v.File))
		content, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}
		if marshalPattern.Match(content) {
			t.Errorf("VIOLATION: %s:%d uses json.MarshalIndent + os.WriteFile — use iohelper.WriteAtomicJSON instead\n  %s", v.File, v.Line, v.Text)
		}
	}
}

// --- Contract: No inline os.ReadFile + json.Unmarshal ---
// All JSON file loads must use iohelper.ReadJSON.

func TestNoInlineJSONRead(t *testing.T) {
	root := repoRoot(t)
	// Scan for json.Unmarshal in files that also use os.ReadFile
	pattern := regexp.MustCompile(`json\.Unmarshal\(`)

	allowlist := map[string]string{
		"pkg/iohelper/iohelper.go":        "ReadJSON definition uses json.Unmarshal internally",
		"pkg/jsonutil/jsonutil.go":        "JSON utility package — wraps encoding/json by design",
		"pkg/report/html_builder.go":      "Loads multiple JSON files with intermediate processing",
		"pkg/validate/validate.go":        "Validation logic processes data between read and unmarshal",
		"pkg/cli/cli.go":                  "RunReport loads JSON with intermediate fmt.Println",
		"pkg/intelligence/persistence.go": "Complex load with gzip decompression between read and unmarshal",
		"pkg/compare/compare.go":          "Loads JSON with custom error wrapping",
		"pkg/output/policy/policy.go":     "Loads YAML or JSON based on extension",
		"pkg/history/store.go":            "Uses iohelper.ReadJSON already, json.Unmarshal for inline bytes",
		"pkg/output/testutil/helpers.go":  "Test utility — unmarshals inline bytes, not file reads",
		"pkg/ftw/ftw.go":                  "Loads YAML-or-JSON with extension detection between read and unmarshal",
		"pkg/openapi/parser.go":           "Tries JSON then YAML unmarshal on same data",
		"pkg/api/openapi.go":              "Unmarshals to raw map for schema inspection before typed parse",
		"pkg/update/update.go":            "Reads+merges JSON payloads with intermediate byte processing",
		"cmd/mcp-smoke/main.go":           "Unmarshals MCP response strings, not file reads",
		"cmd/cli/cmd_probe.go":            "Loads metrics/fingerprints with intermediate processing",
		"pkg/params/params.go":            "DiscoverFromJSON unmarshals caller-provided bytes, not file reads",
	}

	dirs := []string{"pkg", "cmd"}
	unmarshalFiles := scanFiles(t, root, dirs, pattern, allowlist)

	readFilePattern := regexp.MustCompile(`os\.ReadFile\(`)
	for _, v := range unmarshalFiles {
		absPath := filepath.Join(root, filepath.FromSlash(v.File))
		content, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}
		if readFilePattern.Match(content) {
			t.Errorf("VIOLATION: %s:%d uses os.ReadFile + json.Unmarshal — use iohelper.ReadJSON instead\n  %s", v.File, v.Line, v.Text)
		}
	}
}

// --- Contract: No inline sorted-map-keys boilerplate ---
// Use strutil.SortedMapKeys instead of for-range + append + sort.Strings.

func TestNoInlineSortedMapKeys(t *testing.T) {
	root := repoRoot(t)
	// The telltale: `for k := range` followed by `sort.Strings(` in same file,
	// with `append(keys` or `append(paramKeys` between them.
	// We detect the pattern: `for <var> := range <map> {` + `<var> = append(<var>, <key>)`
	// Simplified: look for `sort.Strings(` on a variable that was built with for-range.
	//
	// Pragmatic approach: flag any `sort.Strings(xxxKeys)` where xxxKeys was built inline.
	// Since this is hard with single-line regex, we use a two-pass approach:
	// 1. Find files with `sort.Strings(` on a variable
	// 2. Check if same file has `for ... := range ... {` + `append(` on same variable
	//
	// Simpler proxy: flag the append-in-range pattern directly.
	pattern := regexp.MustCompile(`for\s+\w+\s*:=\s*range\s+\w+\s*\{`)

	allowlist := map[string]string{
		"pkg/strutil/strutil.go": "SortedMapKeys definition",
	}

	dirs := []string{"pkg", "cmd"}
	rangeFiles := scanFiles(t, root, dirs, pattern, allowlist)

	// For each file with for-range, check if it also has sort.Strings on a keys variable
	sortKeysPattern := regexp.MustCompile(`sort\.Strings\(\w*[Kk]eys\)`)
	for _, v := range rangeFiles {
		absPath := filepath.Join(root, filepath.FromSlash(v.File))
		content, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}
		if sortKeysPattern.Match(content) {
			// Double check: is there an append(xxxKeys, k) pattern?
			appendKeysPattern := regexp.MustCompile(`append\(\w*[Kk]eys,\s*\w+\)`)
			if appendKeysPattern.Match(content) {
				t.Errorf("VIOLATION: %s has inline sorted-map-keys pattern — use strutil.SortedMapKeys instead", v.File)
			}
		}
	}
}

// --- Contract: No inline HTTP URL prefix check ---
// Use urlutil.IsHTTPURL instead of strings.HasPrefix pairs.

func TestNoInlineIsHTTPURL(t *testing.T) {
	root := repoRoot(t)
	// Match: strings.HasPrefix(x, "http://") ... strings.HasPrefix(x, "https://")
	// on the SAME line (the common inline pattern)
	pattern := regexp.MustCompile(`strings\.HasPrefix\(\w+,\s*"https?://".*strings\.HasPrefix\(\w+,\s*"https?://"`)

	allowlist := map[string]string{
		"pkg/urlutil/urlutil.go": "IsHTTPURL definition",
		// These check "//" (protocol-relative) in addition to http/https — different semantics
		"pkg/crawler/extractors.go":             "looksLikeURL also checks // protocol-relative",
		"pkg/discovery/discovery_javascript.go": "normalizeJSPath also checks // protocol-relative",
	}

	dirs := []string{"pkg", "cmd"}
	violations := scanFiles(t, root, dirs, pattern, allowlist)
	for _, v := range violations {
		t.Errorf("VIOLATION: %s:%d uses inline HasPrefix http/https — use urlutil.IsHTTPURL instead\n  %s", v.File, v.Line, v.Text)
	}
}

// --- Contract: No inline scheme stripping ---
// Use urlutil.StripScheme instead of double TrimPrefix.

func TestNoInlineStripScheme(t *testing.T) {
	root := repoRoot(t)
	// Match: TrimPrefix(..., "https://") and TrimPrefix(..., "http://") in same file
	// We look for lines with double TrimPrefix for both schemes
	pattern := regexp.MustCompile(`TrimPrefix\(.*"https?://".*TrimPrefix\(.*"https?://"`)

	allowlist := map[string]string{
		"pkg/urlutil/urlutil.go": "StripScheme definition",
	}

	dirs := []string{"pkg", "cmd"}
	violations := scanFiles(t, root, dirs, pattern, allowlist)
	for _, v := range violations {
		t.Errorf("VIOLATION: %s:%d uses inline double TrimPrefix for scheme — use urlutil.StripScheme instead\n  %s", v.File, v.Line, v.Text)
	}
}

// --- Contract: No inline URL path joining ---
// Use urlutil.JoinPath instead of TrimSuffix(base, "/") + path.

func TestNoInlineJoinPath(t *testing.T) {
	root := repoRoot(t)
	// Match: strings.TrimSuffix(xxx, "/") + "/ or + path  (URL join pattern)
	// This catches: strings.TrimSuffix(x, "/") + "/something"
	pattern := regexp.MustCompile(`strings\.TrimSuffix\(\w+[\.\w]*,\s*"/"\)\s*\+\s*"/`)

	allowlist := map[string]string{
		"pkg/urlutil/urlutil.go": "JoinPath definition",
		// These do TrimSuffix + "/" + TrimPrefix (bidirectional trim, not simple join)
		"pkg/browser/client.go":              "bidirectional trim: TrimSuffix + / + TrimPrefix",
		"pkg/discovery/active_extraction.go": "directory listing entry: TrimSuffix + / + entry",
		"pkg/enterprise/protocols.go":        "multi-segment Sprintf, not simple two-part join",
	}

	dirs := []string{"pkg", "cmd"}
	violations := scanFiles(t, root, dirs, pattern, allowlist)
	for _, v := range violations {
		t.Errorf("VIOLATION: %s:%d uses inline TrimSuffix+path concat — use urlutil.JoinPath instead\n  %s", v.File, v.Line, v.Text)
	}
}
