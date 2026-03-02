// Package contracts enforces codebase-wide patterns via source scanning.
// These tests grep production source files for forbidden inline patterns
// that should use shared utilities instead. They prevent pattern drift
// after unification work — any new violation fails CI.
//
// To add an allowlist entry: add the file path to the allowlist map
// with a comment explaining why the exception is needed.
package contracts

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// scanFiles walks all .go files under dirs, skipping test files and
// allowlisted paths, and returns violations for lines matching pattern.
func scanFiles(t *testing.T, root string, dirs []string, pattern *regexp.Regexp, allowlist map[string]string) []violation {
	t.Helper()
	var violations []violation

	for _, dir := range dirs {
		base := filepath.Join(root, filepath.FromSlash(dir))
		_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			// Skip test files — contracts only govern production code
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}

			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)

			// Check allowlist
			if _, ok := allowlist[rel]; ok {
				return nil
			}

			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()

			scanner := bufio.NewScanner(f)
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				// Skip comments
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") {
					continue
				}
				if pattern.MatchString(line) {
					violations = append(violations, violation{
						File: rel,
						Line: lineNum,
						Text: strings.TrimSpace(line),
					})
				}
			}
			return nil
		})
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
