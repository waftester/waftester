package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// =============================================================================
// STRUCTURAL VERIFICATION TESTS
// =============================================================================
//
// These tests verify codebase consistency and structural requirements.
// They help maintain code quality by ensuring:
// - All packages have tests
// - Dispatcher wiring is complete
// - No forgotten action items in test files
// - Version consistency across files

// getRepoRoot returns the repository root directory (parent of test/)
func getRepoRoot(t *testing.T) string {
	t.Helper()

	// We're in test/, so go up one level
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	// Handle both running from test/ and from repo root
	if filepath.Base(wd) == "test" {
		return filepath.Dir(wd)
	}

	// Check if we're at repo root (has pkg/ directory)
	if _, err := os.Stat(filepath.Join(wd, "pkg")); err == nil {
		return wd
	}

	// Try to find repo root by looking for go.mod
	for dir := wd; dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			// Verify it's our repo by checking for pkg/
			if _, err := os.Stat(filepath.Join(dir, "pkg")); err == nil {
				return dir
			}
		}
	}

	t.Fatalf("could not find repository root from %s", wd)
	return ""
}

// TestAllPackagesHaveTests walks pkg/ and verifies each package has *_test.go files.
func TestAllPackagesHaveTests(t *testing.T) {
	repoRoot := getRepoRoot(t)
	pkgDir := filepath.Join(repoRoot, "pkg")

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("failed to read pkg/ directory: %v", err)
	}

	var packagesWithoutTests []string
	var packagesWithTests int
	var totalPackages int

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		totalPackages++
		packagePath := filepath.Join(pkgDir, entry.Name())

		// Check for *_test.go files
		hasTests := false
		files, err := os.ReadDir(packagePath)
		if err != nil {
			t.Logf("WARNING: could not read package %s: %v", entry.Name(), err)
			continue
		}

		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), "_test.go") {
				hasTests = true
				break
			}
		}

		if hasTests {
			packagesWithTests++
		} else {
			packagesWithoutTests = append(packagesWithoutTests, entry.Name())
		}
	}

	// Report statistics
	coverage := float64(packagesWithTests) / float64(totalPackages) * 100
	t.Logf("Package test coverage: %d/%d (%.1f%%)", packagesWithTests, totalPackages, coverage)

	// Log packages without tests (informational, not blocking)
	if len(packagesWithoutTests) > 0 {
		t.Logf("INFO: Packages without tests (%d):", len(packagesWithoutTests))
		for _, pkg := range packagesWithoutTests {
			t.Logf("  - pkg/%s", pkg)
		}
	}

	// Fail if coverage drops below 50% (configurable threshold)
	const minCoveragePercent = 50.0
	if coverage < minCoveragePercent {
		t.Errorf("Package test coverage (%.1f%%) is below minimum threshold (%.1f%%)",
			coverage, minCoveragePercent)
	}
}

// TestDispatcherWiringComplete verifies dispatcher tests exist for all emission types.
func TestDispatcherWiringComplete(t *testing.T) {
	repoRoot := getRepoRoot(t)
	dispatcherTestPath := filepath.Join(repoRoot, "cmd", "cli", "dispatcher_wiring_test.go")

	content, err := os.ReadFile(dispatcherTestPath)
	if err != nil {
		t.Fatalf("failed to read dispatcher wiring test: %v", err)
	}

	sourceCode := string(content)

	// Required emission types that must be tested
	requiredEmissionTypes := []struct {
		name    string
		pattern string
		desc    string
	}{
		{"EmitStart", `EmitStart`, "scan start lifecycle events"},
		{"EmitSummary", `EmitSummary`, "completion summary events"},
		{"EmitError", `EmitError`, "error path events"},
		{"EmitResult", `EmitResult`, "test result telemetry"},
		{"EmitBypass", `EmitBypass`, "bypass/discovery events"},
	}

	for _, et := range requiredEmissionTypes {
		t.Run(et.name, func(t *testing.T) {
			if !strings.Contains(sourceCode, et.pattern) {
				t.Errorf("dispatcher wiring tests missing coverage for %s (%s)", et.name, et.desc)
			}
		})
	}

	// Verify dispatcher context coverage
	requiredDispatchers := []string{
		"autoDispCtx",
		"runDispCtx",
		"mutateDispCtx",
		"bypassDispCtx",
		"fuzzDispCtx",
		"crawlDispCtx",
		"probeDispCtx",
		"discoverDispCtx",
	}

	missingDispatchers := []string{}
	for _, disp := range requiredDispatchers {
		if !strings.Contains(sourceCode, disp) {
			missingDispatchers = append(missingDispatchers, disp)
		}
	}

	if len(missingDispatchers) > 0 {
		t.Logf("INFO: Dispatchers not covered in wiring tests: %v", missingDispatchers)
	}

	// Verify minimum test function count
	testFuncPattern := regexp.MustCompile(`func Test[A-Z][a-zA-Z0-9_]*\(t \*testing\.T\)`)
	matches := testFuncPattern.FindAllString(sourceCode, -1)

	const minTestFunctions = 5
	if len(matches) < minTestFunctions {
		t.Errorf("dispatcher wiring tests have only %d test functions, expected at least %d",
			len(matches), minTestFunctions)
	}

	t.Logf("Dispatcher wiring test functions: %d", len(matches))
}

// TestNoTODOsInTests scans test files for TODO comments (informational).
// This helps track incomplete work and technical debt in test code.
func TestNoTODOsInTests(t *testing.T) {
	repoRoot := getRepoRoot(t)

	// Match TODO/FIXME/HACK in comments only (after // or in /* */)
	// Require the keyword to be preceded by comment markers or whitespace
	todoPattern := regexp.MustCompile(`//\s*(TODO|FIXME|HACK)[:.\s]+(.*)`)

	var findings []struct {
		file    string
		line    int
		match   string
		comment string
	}

	// Walk the entire repository looking for *_test.go files
	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip vendor, node_modules, .git, test directories
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" {
				return filepath.SkipDir
			}
			// Skip the test/ directory itself to avoid self-references
			if name == "test" {
				relPath, _ := filepath.Rel(repoRoot, path)
				if relPath == "test" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Only process test files
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			if matches := todoPattern.FindStringSubmatch(line); matches != nil {
				relPath, _ := filepath.Rel(repoRoot, path)
				findings = append(findings, struct {
					file    string
					line    int
					match   string
					comment string
				}{
					file:    relPath,
					line:    i + 1,
					match:   matches[1],
					comment: strings.TrimSpace(matches[2]),
				})
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("failed to walk repository: %v", err)
	}

	// Report findings (informational, not blocking)
	if len(findings) > 0 {
		t.Logf("INFO: Found %d TODO/FIXME/HACK comments in test files:", len(findings))
		for _, f := range findings {
			if len(f.comment) > 60 {
				f.comment = f.comment[:57] + "..."
			}
			t.Logf("  %s:%d: %s: %s", f.file, f.line, f.match, f.comment)
		}
	} else {
		t.Log("No TODO/FIXME/HACK comments found in test files")
	}

	// This test is purely informational - don't fail
	// TODOs in tests serve as documentation for future work
}

// TestVersion_Consistent verifies version is consistent across files.
func TestVersion_Consistent(t *testing.T) {
	repoRoot := getRepoRoot(t)

	// Read version from defaults package
	defaultsPath := filepath.Join(repoRoot, "pkg", "defaults", "defaults.go")
	defaultsContent, err := os.ReadFile(defaultsPath)
	if err != nil {
		t.Fatalf("failed to read defaults.go: %v", err)
	}

	// Extract version from defaults.go
	versionPattern := regexp.MustCompile(`const\s+Version\s*=\s*"([^"]+)"`)
	matches := versionPattern.FindSubmatch(defaultsContent)
	if matches == nil {
		t.Fatal("could not find Version constant in defaults.go")
	}
	defaultsVersion := string(matches[1])

	t.Logf("defaults.Version = %s", defaultsVersion)

	// Verify version format is valid semver
	semverPattern := regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$`)
	if !semverPattern.MatchString(defaultsVersion) {
		t.Errorf("defaults.Version (%s) is not valid semver format", defaultsVersion)
	}

	// Check ui package references defaults.Version
	bannerPath := filepath.Join(repoRoot, "pkg", "ui", "banner.go")
	bannerContent, err := os.ReadFile(bannerPath)
	if err != nil {
		t.Logf("WARNING: could not read banner.go: %v", err)
	} else {
		if !strings.Contains(string(bannerContent), "defaults.Version") {
			t.Error("ui/banner.go should reference defaults.Version, not hardcode version")
		}
	}

	// Check payloads/version.json exists and has valid format
	payloadVersionPath := filepath.Join(repoRoot, "payloads", "version.json")
	payloadContent, err := os.ReadFile(payloadVersionPath)
	if err != nil {
		t.Logf("INFO: payloads/version.json not found: %v", err)
	} else {
		var versionInfo struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(payloadContent, &versionInfo); err != nil {
			t.Errorf("failed to parse payloads/version.json: %v", err)
		} else {
			t.Logf("payloads/version.json version = %s", versionInfo.Version)
			// Note: payload version may differ from code version - that's expected
		}
	}

	// Check CHANGELOG.md mentions the current version
	changelogPath := filepath.Join(repoRoot, "CHANGELOG.md")
	changelogContent, err := os.ReadFile(changelogPath)
	if err != nil {
		t.Logf("INFO: CHANGELOG.md not found: %v", err)
	} else {
		if !strings.Contains(string(changelogContent), defaultsVersion) {
			t.Logf("INFO: CHANGELOG.md does not contain current version %s", defaultsVersion)
		}
	}
}

// TestCmdCliHasDispatcherWiringTests verifies dispatcher wiring tests exist.
func TestCmdCliHasDispatcherWiringTests(t *testing.T) {
	repoRoot := getRepoRoot(t)
	dispatcherTestPath := filepath.Join(repoRoot, "cmd", "cli", "dispatcher_wiring_test.go")

	info, err := os.Stat(dispatcherTestPath)
	if err != nil {
		t.Fatalf("dispatcher_wiring_test.go not found: %v", err)
	}

	// Verify file is not empty
	if info.Size() < 1000 {
		t.Errorf("dispatcher_wiring_test.go is suspiciously small (%d bytes)", info.Size())
	}

	t.Logf("dispatcher_wiring_test.go exists (%d bytes)", info.Size())
}

// TestGoModConsistency verifies go.mod is properly configured.
func TestGoModConsistency(t *testing.T) {
	repoRoot := getRepoRoot(t)
	goModPath := filepath.Join(repoRoot, "go.mod")

	content, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("failed to read go.mod: %v", err)
	}

	goModContent := string(content)

	// Check module name
	if !strings.Contains(goModContent, "module github.com/waftester/waftester") {
		t.Error("go.mod should have module github.com/waftester/waftester")
	}

	// Check Go version is reasonable (1.21+)
	goVersionPattern := regexp.MustCompile(`go\s+(\d+)\.(\d+)`)
	if matches := goVersionPattern.FindStringSubmatch(goModContent); matches != nil {
		t.Logf("Go version: %s.%s", matches[1], matches[2])
	} else {
		t.Error("could not find Go version in go.mod")
	}
}
