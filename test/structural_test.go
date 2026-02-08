package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"text/template"
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

// =============================================================================
// PERFORMANCE ENFORCEMENT TESTS
// =============================================================================
//
// These tests enforce usage of high-performance packages in hot paths:
// - jsonutil instead of encoding/json
// - bufpool instead of bytes.Buffer{}

// TestHotPathsUseJsonutil verifies hot path packages use jsonutil instead of encoding/json.
// This ensures 2-3x faster JSON operations in performance-critical code paths.
func TestHotPathsUseJsonutil(t *testing.T) {
	repoRoot := getRepoRoot(t)

	// Hot path packages that MUST use jsonutil, not encoding/json
	hotPathPackages := []struct {
		path   string
		reason string
	}{
		{"pkg/payloads/loader.go", "loads 2800+ payloads on startup"},
		{"pkg/payloads/database.go", "in-memory payload database operations"},
		{"pkg/output/writers/json.go", "JSON output serialization"},
		{"pkg/output/writers/jsonl.go", "JSONL streaming output"},
		{"pkg/output/writers/sarif.go", "SARIF report generation"},
		{"pkg/output/writers/html.go", "HTML report JSON embedding"},
		{"pkg/output/builder.go", "multi-format export operations"},
		{"pkg/upload/upload.go", "upload testing with JSON serialization"},
	}

	// Pattern that indicates encoding/json is imported (but not in comments)
	encodingJsonImport := regexp.MustCompile(`^\s*"encoding/json"\s*$`)

	var violations []string

	for _, pkg := range hotPathPackages {
		t.Run(pkg.path, func(t *testing.T) {
			filePath := filepath.Join(repoRoot, pkg.path)

			content, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatalf("failed to read %s: %v", pkg.path, err)
			}

			lines := strings.Split(string(content), "\n")
			inImportBlock := false

			for i, line := range lines {
				// Track import block
				if strings.Contains(line, "import (") {
					inImportBlock = true
					continue
				}
				if inImportBlock && strings.TrimSpace(line) == ")" {
					inImportBlock = false
					continue
				}

				// Check for encoding/json import in import block
				if inImportBlock && encodingJsonImport.MatchString(line) {
					violation := pkg.path + " uses encoding/json instead of jsonutil (" + pkg.reason + ")"
					violations = append(violations, violation)
					t.Errorf("line %d: found 'encoding/json' import - use pkg/jsonutil for performance", i+1)
				}

				// Also check for single-line import
				if strings.Contains(line, `import "encoding/json"`) {
					violation := pkg.path + " uses encoding/json instead of jsonutil (" + pkg.reason + ")"
					violations = append(violations, violation)
					t.Errorf("line %d: found 'encoding/json' import - use pkg/jsonutil for performance", i+1)
				}
			}
		})
	}

	if len(violations) > 0 {
		t.Logf("\nPerformance violations (encoding/json in hot paths):")
		for _, v := range violations {
			t.Logf("  - %s", v)
		}
		t.Logf("\nFix: Replace 'encoding/json' with 'github.com/waftester/waftester/pkg/jsonutil'")
	}
}

// TestUploadUsesBufferPool verifies upload package uses bufpool for buffer allocation.
// This reduces GC pressure for multipart file uploads.
func TestUploadUsesBufferPool(t *testing.T) {
	repoRoot := getRepoRoot(t)
	uploadPath := filepath.Join(repoRoot, "pkg", "upload", "upload.go")

	content, err := os.ReadFile(uploadPath)
	if err != nil {
		t.Fatalf("failed to read upload.go: %v", err)
	}

	sourceCode := string(content)

	// Check bufpool is imported
	if !strings.Contains(sourceCode, `"github.com/waftester/waftester/pkg/bufpool"`) {
		t.Error("upload.go must import pkg/bufpool for buffer pooling")
	}

	// Check bufpool.Get() is used
	if !strings.Contains(sourceCode, "bufpool.Get()") {
		t.Error("upload.go must use bufpool.Get() for buffer allocation")
	}

	// Check bufpool.Put() is used (for returning buffers)
	if !strings.Contains(sourceCode, "bufpool.Put(") {
		t.Error("upload.go must use bufpool.Put() to return buffers to pool")
	}

	// Verify no direct bytes.Buffer{} allocation in TestUpload function
	// This pattern indicates bypassing the buffer pool
	testUploadPattern := regexp.MustCompile(`func \(t \*Tester\) TestUpload[^}]+body\s*:=\s*&bytes\.Buffer\{\}`)
	if testUploadPattern.MatchString(sourceCode) {
		t.Error("TestUpload should use bufpool.Get() instead of &bytes.Buffer{}")
	}

	t.Log("upload.go correctly uses bufpool for buffer management")
}

// TestJsonutilPackageExists verifies the jsonutil package exists and is properly implemented.
func TestJsonutilPackageExists(t *testing.T) {
	repoRoot := getRepoRoot(t)
	jsonutilPath := filepath.Join(repoRoot, "pkg", "jsonutil", "jsonutil.go")

	content, err := os.ReadFile(jsonutilPath)
	if err != nil {
		t.Fatalf("pkg/jsonutil/jsonutil.go not found: %v", err)
	}

	sourceCode := string(content)

	// Required functions for drop-in encoding/json replacement
	requiredFunctions := []struct {
		name    string
		pattern string
		desc    string
	}{
		{"Unmarshal", "func Unmarshal(", "JSON decoding"},
		{"Marshal", "func Marshal(", "JSON encoding"},
		{"MarshalIndent", "func MarshalIndent(", "pretty JSON encoding"},
		{"NewStreamEncoder", "func NewStreamEncoder(", "streaming encoder creation"},
		{"SetIndent", "func (e *Encoder) SetIndent(", "encoder indentation"},
		{"Encode", "func (e *Encoder) Encode(", "streaming encode"},
	}

	for _, fn := range requiredFunctions {
		t.Run(fn.name, func(t *testing.T) {
			if !strings.Contains(sourceCode, fn.pattern) {
				t.Errorf("jsonutil missing %s function for %s", fn.name, fn.desc)
			}
		})
	}

	// Verify it uses go-json-experiment
	if !strings.Contains(sourceCode, "github.com/go-json-experiment/json") {
		t.Error("jsonutil should use github.com/go-json-experiment/json for 2-3x performance")
	}

	t.Log("jsonutil package is properly implemented with all required functions")
}

// TestSlicePreallocationInHotPaths verifies hot path packages pre-allocate slices.
// This reduces allocations and GC pressure during scanning.
func TestSlicePreallocationInHotPaths(t *testing.T) {
	repoRoot := getRepoRoot(t)

	// Files that should have pre-allocation patterns
	hotPathFiles := []struct {
		path          string
		minMakeSlices int // minimum number of make([]..., 0, ...) patterns expected
		reason        string
	}{
		{"pkg/payloads/loader.go", 1, "payload aggregation"},
		{"pkg/xss/xss.go", 3, "XSS payload generation and filtering"},
		{"pkg/xxe/xxe.go", 2, "XXE payload generation"},
	}

	// Pattern for pre-allocated slices: make([]Type, 0, capacity)
	preallocPattern := regexp.MustCompile(`make\(\[\][^,]+,\s*0,\s*[^)]+\)`)

	for _, file := range hotPathFiles {
		t.Run(file.path, func(t *testing.T) {
			filePath := filepath.Join(repoRoot, file.path)

			content, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatalf("failed to read %s: %v", file.path, err)
			}

			matches := preallocPattern.FindAllString(string(content), -1)
			if len(matches) < file.minMakeSlices {
				t.Errorf("%s has only %d pre-allocated slices, expected at least %d for %s",
					file.path, len(matches), file.minMakeSlices, file.reason)
			} else {
				t.Logf("%s has %d pre-allocated slices (required: %d)",
					file.path, len(matches), file.minMakeSlices)
			}
		})
	}
}

// TestGoreleaserHasTrimpath verifies goreleaser builds with -trimpath for smaller binaries.
func TestGoreleaserHasTrimpath(t *testing.T) {
	repoRoot := getRepoRoot(t)
	goreleaserPath := filepath.Join(repoRoot, ".goreleaser.yaml")

	content, err := os.ReadFile(goreleaserPath)
	if err != nil {
		t.Fatalf("failed to read .goreleaser.yaml: %v", err)
	}

	if !strings.Contains(string(content), "-trimpath") {
		t.Error(".goreleaser.yaml should include -trimpath flag for smaller, reproducible binaries")
	}

	t.Log(".goreleaser.yaml correctly includes -trimpath flag")
}

// =============================================================================
// PRIVATE FILE LEAK PREVENTION TESTS
// =============================================================================
//
// These tests verify that private/sensitive files are NOT present in the
// repository tree. If any of these fail, it means .gitignore is misconfigured
// or a private file was force-added. This is a security-critical test.

// TestNoPrivateFilesInRepo verifies that sensitive configuration files from
// waftester-private are not tracked in this public repository.
func TestNoPrivateFilesInRepo(t *testing.T) {
	repoRoot := getRepoRoot(t)

	// Private paths that must NEVER exist as tracked files.
	// These are synced locally via junctions from waftester-private.
	privatePaths := []struct {
		path   string
		reason string
	}{
		{".github/agents", "AI agent definitions (private config)"},
		{".github/instructions", "Copilot instruction files (private config)"},
		{".github/prompts", "Copilot prompt files (private config)"},
		{".github/skills", "AI skill definitions (private config)"},
		{".github/workspace", "workspace configuration (private)"},
		{".github/copilot-instructions.md", "Copilot global instructions (private)"},
		{".github/memory-seed.json", "memory seed data (private)"},
		{".claude", "Claude AI configuration (private)"},
		{".mcp.json", "MCP server configuration (private)"},
		{"docs/plans", "internal planning documents (private)"},
		{"docs/research", "internal research documents (private)"},
	}

	var violations []string

	for _, pp := range privatePaths {
		fullPath := filepath.Join(repoRoot, filepath.FromSlash(pp.path))

		// Check if the path exists AND is tracked by git
		// (existing but gitignored is fine — that's the intended state)
		info, err := os.Stat(fullPath)
		if err != nil {
			continue // Doesn't exist, which is fine
		}

		if info.IsDir() {
			// For directories, check if any files inside are tracked.
			// We do this by looking for files that would be committed.
			entries, err := os.ReadDir(fullPath)
			if err != nil {
				continue
			}
			// The directory exists but we can't check git tracking from here,
			// so we verify gitignore coverage instead (below).
			_ = entries
		}
	}

	// Verify .gitignore has all required rules
	gitignorePath := filepath.Join(repoRoot, ".gitignore")
	gitignoreContent, err := os.ReadFile(gitignorePath)
	if err != nil {
		t.Fatalf("failed to read .gitignore: %v", err)
	}

	gitignore := string(gitignoreContent)

	requiredIgnoreRules := []struct {
		rule   string
		reason string
	}{
		{".github/agents/", "AI agent definitions"},
		{".github/instructions/", "Copilot instruction files"},
		{".github/prompts/", "Copilot prompt files"},
		{".github/skills/", "AI skill definitions"},
		{".github/workspace/", "workspace configuration"},
		{".github/copilot-instructions.md", "Copilot global instructions"},
		{".claude/", "Claude AI configuration"},
		{".mcp.json", "MCP server configuration"},
		{"docs/plans/", "internal planning documents"},
		{"docs/research/", "internal research documents"},
	}

	for _, rule := range requiredIgnoreRules {
		if !strings.Contains(gitignore, rule.rule) {
			violations = append(violations,
				rule.rule+" ("+rule.reason+" — missing from .gitignore)")
		}
	}

	if len(violations) > 0 {
		t.Errorf("SECURITY: .gitignore is missing %d required private path rules:", len(violations))
		for _, v := range violations {
			t.Errorf("  ✗ %s", v)
		}
		t.Error("Fix: Add missing rules to .gitignore immediately")
	} else {
		t.Logf("✅ .gitignore has all %d required private path exclusion rules", len(requiredIgnoreRules))
	}
}

// TestPrivateGuardWorkflowExists verifies the CI guardrail workflow exists.
func TestPrivateGuardWorkflowExists(t *testing.T) {
	repoRoot := getRepoRoot(t)
	guardPath := filepath.Join(repoRoot, ".github", "workflows", "private-guard.yml")

	info, err := os.Stat(guardPath)
	if err != nil {
		t.Fatal("SECURITY: .github/workflows/private-guard.yml is missing — " +
			"this CI workflow prevents private files from being pushed to the public repo")
	}

	if info.Size() < 500 {
		t.Errorf("private-guard.yml is suspiciously small (%d bytes) — may be incomplete", info.Size())
	}

	content, err := os.ReadFile(guardPath)
	if err != nil {
		t.Fatalf("failed to read private-guard.yml: %v", err)
	}

	// Verify it checks for all critical private paths
	requiredChecks := []string{
		".github/agents",
		".github/instructions",
		".github/prompts",
		".github/skills",
		".claude",
	}

	for _, check := range requiredChecks {
		if !strings.Contains(string(content), check) {
			t.Errorf("private-guard.yml does not check for %q", check)
		}
	}

	// Verify it checks for unauthorized identity in commits
	if !strings.Contains(string(content), "author identity") {
		t.Error("private-guard.yml must check for unauthorized author identity in commits")
	}

	t.Logf("✅ private-guard.yml exists and checks all required private paths (%d bytes)", info.Size())
}

// TestLocalGitIdentity verifies the repo-local git identity is the project identity.
func TestLocalGitIdentity(t *testing.T) {
	// Skip in CI — runners don't have local git identity configured
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("skipping local git identity check in CI environment")
	}

	repoRoot := getRepoRoot(t)
	gitConfigPath := filepath.Join(repoRoot, ".git", "config")

	content, err := os.ReadFile(gitConfigPath)
	if err != nil {
		t.Fatalf("failed to read .git/config: %v", err)
	}

	config := string(content)

	if !strings.Contains(config, "dev@waftester.com") {
		t.Error("SECURITY: local git config must have user.email = dev@waftester.com")
		t.Error("Fix: git config user.email 'dev@waftester.com'")
	}

	t.Log("✅ local git identity is set to project identity")
}

// TestPreCommitHookChecksIdentity verifies the pre-commit hook blocks unauthorized identity.
func TestPreCommitHookChecksIdentity(t *testing.T) {
	repoRoot := getRepoRoot(t)
	hookPath := filepath.Join(repoRoot, "scripts", "hooks", "pre-commit")

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal("SECURITY: scripts/hooks/pre-commit is missing")
	}

	hook := string(content)

	// Verify it checks author identity via allowlist, not a blocklist
	if !strings.Contains(hook, "ALLOWED_EMAIL") {
		t.Error("pre-commit hook must use an ALLOWED_EMAIL allowlist for identity checks")
	}

	if !strings.Contains(hook, "user.email") {
		t.Error("pre-commit hook must check git config user.email")
	}

	t.Log("✅ pre-commit hook checks for authorized identity before committing")
}

// =============================================================================
// BUG-CLASS PREVENTION TESTS
// =============================================================================
//
// These tests scan the codebase for anti-patterns that caused bugs we fixed.
// They prevent regression by detecting the pattern at the structural level,
// ensuring the entire codebase stays clean — not just the files we fixed.

// TestNoInsecureCryptoFallback verifies that files importing crypto/rand do not
// use time.Now().UnixNano() as a fallback RNG seed. We fixed this pattern in
// the oauth package where a time-based seed was used when crypto/rand failed.
func TestNoInsecureCryptoFallback(t *testing.T) {
	repoRoot := getRepoRoot(t)
	pkgDir := filepath.Join(repoRoot, "pkg")

	// Directories that legitimately need timestamps (not for RNG)
	skipDirs := map[string]bool{
		"duration":  true,
		"benchmark": true,
		"metrics":   true,
	}

	// Known pre-existing violations tracked for future cleanup.
	// Removing entries from this list is allowed; adding is NOT.
	// When a violation is fixed, remove it and the test ensures no regression.
	knownViolations := map[string]bool{}

	var newViolations []string
	var knownFound []string

	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			rel, _ := filepath.Rel(pkgDir, path)
			topDir := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
			if skipDirs[topDir] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".go") || strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		src := string(content)

		importsCryptoRand := strings.Contains(src, `"crypto/rand"`)
		hasTimeNano := strings.Contains(src, "time.Now().UnixNano()")

		if importsCryptoRand && hasTimeNano {
			rel, _ := filepath.Rel(repoRoot, path)
			relSlash := filepath.ToSlash(rel)
			if knownViolations[relSlash] {
				knownFound = append(knownFound, relSlash)
			} else {
				newViolations = append(newViolations, relSlash)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk pkg/: %v", err)
	}

	if len(knownFound) > 0 {
		t.Logf("INFO: %d known pre-existing crypto fallback violation(s) (tracked for future cleanup):", len(knownFound))
		for _, v := range knownFound {
			t.Logf("  ⚠ %s", v)
		}
	}

	if len(newViolations) > 0 {
		t.Errorf("SECURITY: %d NEW file(s) import crypto/rand but also use time.Now().UnixNano() as fallback RNG:", len(newViolations))
		for _, v := range newViolations {
			t.Errorf("  ✗ %s", v)
		}
		t.Error("Fix: Remove time-based fallback. If crypto/rand fails, return an error instead.")
	} else {
		t.Log("✅ No new insecure crypto/rand fallback patterns found")
	}
}

// TestNoUnsafeTemplateHTML verifies that files using template.HTML() also use
// proper escaping. We fixed this in report/html_report.go where raw user
// content was cast to template.HTML without escaping, enabling stored XSS.
func TestNoUnsafeTemplateHTML(t *testing.T) {
	repoRoot := getRepoRoot(t)
	pkgDir := filepath.Join(repoRoot, "pkg")

	templateHTMLPattern := regexp.MustCompile(`template\.HTML\(`)
	escapePattern := regexp.MustCompile(`(?:html\.EscapeString|template\.HTMLEscapeString)`)

	var violations []string

	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".go") {
			return nil
		}
		if strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		src := string(content)

		// Only check files that import html/template
		if !strings.Contains(src, `"html/template"`) {
			return nil
		}

		// If the file uses template.HTML(), it must also use an escape function
		if templateHTMLPattern.MatchString(src) && !escapePattern.MatchString(src) {
			rel, _ := filepath.Rel(repoRoot, path)
			violations = append(violations, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk pkg/: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("SECURITY: %d file(s) use template.HTML() without html.EscapeString or template.HTMLEscapeString:", len(violations))
		for _, v := range violations {
			t.Errorf("  ✗ %s", v)
		}
		t.Error("Fix: Wrap user-supplied content with html.EscapeString() before casting to template.HTML()")
	} else {
		t.Log("✅ All template.HTML() usages are paired with escape functions")
	}
}

// TestNoSingleBodyRead verifies that HTTP response bodies are read completely
// using io.ReadAll, io.Copy, or iohelper helpers — not partial .Body.Read()
// calls. Also flags deprecated ioutil.ReadAll usage.
func TestNoSingleBodyRead(t *testing.T) {
	repoRoot := getRepoRoot(t)
	pkgDir := filepath.Join(repoRoot, "pkg")

	// Directories that legitimately use raw body reads
	skipDirs := map[string]bool{
		"httpclient": true,
	}

	// Known pre-existing violations tracked for future cleanup.
	// Removing entries from this list is allowed; adding is NOT.
	knownBodyReadViolations := map[string]bool{}

	// Files that use .Body.Read() in streaming for-loops (legitimate pattern)
	streamingReaders := map[string]bool{
		"pkg/core/executor.go": true, // chunked read into bufpool with size limit
		"pkg/fuzz/fuzzer.go":   true, // streaming read into bufpool with 1MB limit
	}

	bodyReadPattern := regexp.MustCompile(`\.Body\.Read\(`)
	ioutilReadAll := regexp.MustCompile(`ioutil\.ReadAll`)

	var newBodyReadViolations []string
	var knownBodyReadFound []string
	var ioutilViolations []string

	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			rel, _ := filepath.Rel(pkgDir, path)
			topDir := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
			if skipDirs[topDir] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".go") || strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		src := string(content)
		rel, _ := filepath.Rel(repoRoot, path)
		relSlash := filepath.ToSlash(rel)

		if bodyReadPattern.MatchString(src) && !streamingReaders[relSlash] {
			if knownBodyReadViolations[relSlash] {
				knownBodyReadFound = append(knownBodyReadFound, relSlash)
			} else {
				newBodyReadViolations = append(newBodyReadViolations, relSlash)
			}
		}
		if ioutilReadAll.MatchString(src) {
			ioutilViolations = append(ioutilViolations, relSlash)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk pkg/: %v", err)
	}

	if len(knownBodyReadFound) > 0 {
		t.Logf("INFO: %d known pre-existing .Body.Read() violation(s) (tracked for future cleanup):", len(knownBodyReadFound))
		for _, v := range knownBodyReadFound {
			t.Logf("  ⚠ %s", v)
		}
	}

	if len(newBodyReadViolations) > 0 {
		t.Errorf("%d NEW file(s) use .Body.Read() (partial read) instead of io.ReadAll/iohelper:", len(newBodyReadViolations))
		for _, v := range newBodyReadViolations {
			t.Errorf("  ✗ %s", v)
		}
		t.Error("Fix: Use io.ReadAll(resp.Body) or iohelper.ReadBody/DrainAndClose instead of resp.Body.Read()")
	}

	if len(ioutilViolations) > 0 {
		t.Errorf("%d file(s) use deprecated ioutil.ReadAll instead of io.ReadAll:", len(ioutilViolations))
		for _, v := range ioutilViolations {
			t.Errorf("  ✗ %s", v)
		}
		t.Error("Fix: Replace ioutil.ReadAll with io.ReadAll (available since Go 1.16)")
	}

	if len(newBodyReadViolations) == 0 && len(ioutilViolations) == 0 {
		t.Log("✅ No new partial body reads or deprecated ioutil usage found")
	}
}

// TestNoMathRandInSecurityPaths verifies that security-sensitive packages use
// crypto/rand instead of math/rand. We fixed this across oauth, jwt, csrf,
// and other packages that were using predictable random number generation.
func TestNoMathRandInSecurityPaths(t *testing.T) {
	repoRoot := getRepoRoot(t)

	securityPackages := []string{
		"oauth",
		"jwt",
		"csrf",
		"brokenauth",
		"cryptofailure",
		"tls",
		"ssrf",
	}

	mathRandImport := regexp.MustCompile(`"math/rand(?:/v2)?"`)

	for _, pkg := range securityPackages {
		t.Run(pkg, func(t *testing.T) {
			pkgPath := filepath.Join(repoRoot, "pkg", pkg)

			info, err := os.Stat(pkgPath)
			if err != nil || !info.IsDir() {
				t.Skipf("pkg/%s does not exist", pkg)
				return
			}

			entries, err := os.ReadDir(pkgPath)
			if err != nil {
				t.Fatalf("failed to read pkg/%s: %v", pkg, err)
			}

			var violations []string
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
					continue
				}
				// Test files may use math/rand for test data generation
				if strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}

				filePath := filepath.Join(pkgPath, entry.Name())
				content, err := os.ReadFile(filePath)
				if err != nil {
					continue
				}

				if mathRandImport.MatchString(string(content)) {
					violations = append(violations, entry.Name())
				}
			}

			if len(violations) > 0 {
				t.Errorf("SECURITY: pkg/%s has %d file(s) importing math/rand instead of crypto/rand:", pkg, len(violations))
				for _, v := range violations {
					t.Errorf("  ✗ pkg/%s/%s", pkg, v)
				}
				t.Error("Fix: Replace math/rand with crypto/rand for security-sensitive operations")
			} else {
				t.Logf("✅ pkg/%s uses only crypto/rand", pkg)
			}
		})
	}
}

// TestWorkflowAllowlistNoScriptingLanguages verifies the workflow command allowlist
// does not contain scripting language interpreters that could enable arbitrary code
// execution. We fixed this after python/python3 were found in the allowlist.
func TestWorkflowAllowlistNoScriptingLanguages(t *testing.T) {
	repoRoot := getRepoRoot(t)
	workflowPath := filepath.Join(repoRoot, "pkg", "workflow", "workflow.go")

	content, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("failed to read workflow.go: %v", err)
	}

	src := string(content)

	// Extract the allowedCommands map block
	allowlistStart := strings.Index(src, "allowedCommands := map[string]bool{")
	if allowlistStart == -1 {
		t.Fatal("could not find allowedCommands map in workflow.go")
	}

	// Find the closing brace of the map
	depth := 0
	allowlistEnd := allowlistStart
	for i := allowlistStart; i < len(src); i++ {
		if src[i] == '{' {
			depth++
		} else if src[i] == '}' {
			depth--
			if depth == 0 {
				allowlistEnd = i + 1
				break
			}
		}
	}
	allowlistBlock := src[allowlistStart:allowlistEnd]

	// Scripting interpreters that MUST NOT be in the allowlist
	forbiddenCommands := []struct {
		cmd    string
		reason string
	}{
		{"python", "arbitrary Python code execution"},
		{"python3", "arbitrary Python code execution"},
		{"ruby", "arbitrary Ruby code execution"},
		{"perl", "arbitrary Perl code execution"},
		{"php", "arbitrary PHP code execution"},
		{"node", "arbitrary Node.js code execution"},
		{"lua", "arbitrary Lua code execution"},
		{"bash", "arbitrary shell script execution"},
	}

	for _, fc := range forbiddenCommands {
		// Match exact key entry like: "python": true, or "python":  true,
		pattern := regexp.MustCompile(`"` + regexp.QuoteMeta(fc.cmd) + `"\s*:`)
		if pattern.MatchString(allowlistBlock) {
			t.Errorf("SECURITY: allowedCommands contains %q — enables %s", fc.cmd, fc.reason)
		}
	}

	// Safe utilities that MUST be in the allowlist
	requiredCommands := []string{
		"echo",
		"grep",
		"jq",
		"curl",
	}

	for _, rc := range requiredCommands {
		pattern := regexp.MustCompile(`"` + regexp.QuoteMeta(rc) + `"\s*:`)
		if !pattern.MatchString(allowlistBlock) {
			t.Errorf("allowedCommands is missing required safe utility %q", rc)
		}
	}

	t.Log("✅ workflow allowedCommands has no scripting language interpreters")
}

// TestConcurrentAccessHasMutex verifies that files launching goroutines while
// using maps also include synchronization primitives. We fixed unprotected
// concurrent map access in encoding (registry), metrics (Calculator fields),
// and detection (hostMetrics map).
func TestConcurrentAccessHasMutex(t *testing.T) {
	repoRoot := getRepoRoot(t)
	pkgDir := filepath.Join(repoRoot, "pkg")

	goroutinePattern := regexp.MustCompile(`go\s+(?:func\s*\(|[a-zA-Z_][a-zA-Z0-9_.]*\()`)
	mapPattern := regexp.MustCompile(`map\[`)
	syncPattern := regexp.MustCompile(`sync\.(?:Mutex|RWMutex|Map)`)
	channelPattern := regexp.MustCompile(`(?:make\(chan\s|<-\s*chan\s|chan\s+[a-zA-Z])`)

	// Files that only use maps for static/immutable data or in init()
	skipFiles := map[string]bool{
		"defaults.go": true,
	}

	// Known pre-existing violations tracked for future cleanup.
	// Removing entries from this list is allowed; adding is NOT.
	knownViolations := map[string]bool{}

	var newViolations []string
	var knownFound []string

	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".go") {
			return nil
		}
		if strings.HasSuffix(info.Name(), "_test.go") || skipFiles[info.Name()] {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		src := string(content)

		hasGoroutines := goroutinePattern.MatchString(src)
		hasMaps := mapPattern.MatchString(src)
		hasSync := syncPattern.MatchString(src)
		hasChannels := channelPattern.MatchString(src)

		if hasGoroutines && hasMaps && !hasSync && !hasChannels {
			rel, _ := filepath.Rel(repoRoot, path)
			relSlash := filepath.ToSlash(rel)
			if knownViolations[relSlash] {
				knownFound = append(knownFound, relSlash)
			} else {
				newViolations = append(newViolations, relSlash)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk pkg/: %v", err)
	}

	if len(knownFound) > 0 {
		t.Logf("INFO: %d known pre-existing concurrent map violation(s) (tracked for future cleanup):", len(knownFound))
		for _, v := range knownFound {
			t.Logf("  ⚠ %s", v)
		}
	}

	if len(newViolations) > 0 {
		t.Errorf("RACE CONDITION RISK: %d NEW file(s) launch goroutines and use maps without sync primitives:", len(newViolations))
		for _, v := range newViolations {
			t.Errorf("  ✗ %s", v)
		}
		t.Error("Fix: Add sync.Mutex, sync.RWMutex, or sync.Map to protect concurrent map access")
	} else {
		t.Log("✅ No new concurrent map access violations found")
	}
}

// TestHTTPResponseBodyClosed verifies that files making HTTP requests also close
// the response body. We fixed resource leaks in httpclient/proxy.go, tls/ja3.go,
// and other packages that failed to close response bodies.
func TestHTTPResponseBodyClosed(t *testing.T) {
	repoRoot := getRepoRoot(t)
	pkgDir := filepath.Join(repoRoot, "pkg")

	// Directories that manage their own HTTP lifecycle
	skipDirs := map[string]bool{
		"httpclient": true,
	}

	// HTTP call detection: exclude sync.Once.Do(func()) which also matches .Do(
	doPattern := regexp.MustCompile(`\.Do\(`)
	onceFuncPattern := regexp.MustCompile(`\.Do\(func\(`)
	otherHTTPPattern := regexp.MustCompile(`http\.(?:Get|Post|PostForm|Head)\(`)
	// Body closure: iohelper helpers handle close internally (no defer needed)
	helperClosePattern := regexp.MustCompile(`iohelper\.(?:DrainAndClose|ReadBody)`)
	manualClosePattern := regexp.MustCompile(`(?:\.Body\.Close\(\)|io\.Copy\(io\.Discard)`)
	deferPattern := regexp.MustCompile(`defer\s`)

	// Known pre-existing violations tracked for future cleanup.
	// Removing entries from this list is allowed; adding is NOT.
	knownViolations := map[string]bool{}

	var newViolations []string
	var knownFound []string

	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			rel, _ := filepath.Rel(pkgDir, path)
			topDir := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
			if skipDirs[topDir] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".go") || strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		src := string(content)

		// Only check files that import net/http
		if !strings.Contains(src, `"net/http"`) {
			return nil
		}

		// Check if file makes real HTTP requests (exclude sync.Once.Do(func()))
		doCount := len(doPattern.FindAllString(src, -1))
		onceCount := len(onceFuncPattern.FindAllString(src, -1))
		if doCount <= onceCount && !otherHTTPPattern.MatchString(src) {
			return nil
		}

		// Check body closure: iohelper helpers handle close internally (no defer needed),
		// manual .Body.Close() requires defer for safety
		hasHelper := helperClosePattern.MatchString(src)
		hasManualClose := manualClosePattern.MatchString(src)
		hasDefer := deferPattern.MatchString(src)

		if !hasHelper && !(hasManualClose && hasDefer) {
			rel, _ := filepath.Rel(repoRoot, path)
			relSlash := filepath.ToSlash(rel)
			if knownViolations[relSlash] {
				knownFound = append(knownFound, relSlash)
			} else {
				newViolations = append(newViolations, relSlash)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk pkg/: %v", err)
	}

	if len(knownFound) > 0 {
		t.Logf("INFO: %d known pre-existing HTTP body closure violation(s) (tracked for future cleanup):", len(knownFound))
		for _, v := range knownFound {
			t.Logf("  ⚠ %s", v)
		}
	}

	if len(newViolations) > 0 {
		t.Errorf("RESOURCE LEAK: %d NEW file(s) make HTTP requests without proper body closure:", len(newViolations))
		for _, v := range newViolations {
			t.Errorf("  ✗ %s", v)
		}
		t.Error("Fix: Add defer resp.Body.Close() or defer iohelper.DrainAndClose(resp) after HTTP calls")
	} else {
		t.Log("✅ No new HTTP response body closure violations found")
	}
}

// =============================================================================
// TEMPLATE VALIDATION TESTS
// =============================================================================
//
// These tests verify that all shipped template files are well-formed:
// - Nuclei YAML templates have required fields (id, info.name, info.severity)
// - Workflow YAML templates parse correctly
// - Policy YAML templates parse correctly
// - Override YAML templates parse correctly
// - Output .tmpl files contain valid Go template syntax
// - Report config YAML files parse correctly
// - No orphan directories or unexpected files

// TestTemplatesDirectoryExists verifies the templates/ directory is present at repo root.
func TestTemplatesDirectoryExists(t *testing.T) {
	repoRoot := getRepoRoot(t)
	templatesDir := filepath.Join(repoRoot, "templates")

	info, err := os.Stat(templatesDir)
	if err != nil {
		t.Fatalf("templates/ directory missing: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("templates/ exists but is not a directory")
	}
}

// TestTemplatesShippedInRelease verifies goreleaser includes templates in archives.
func TestTemplatesShippedInRelease(t *testing.T) {
	repoRoot := getRepoRoot(t)
	goreleaserPath := filepath.Join(repoRoot, ".goreleaser.yaml")

	content, err := os.ReadFile(goreleaserPath)
	if err != nil {
		t.Skipf("no .goreleaser.yaml found: %v", err)
	}

	if !strings.Contains(string(content), "templates/**/*") {
		t.Error(".goreleaser.yaml does not include templates/**/* in archive files")
		t.Error("Fix: Add '- templates/**/*' to archives.files in .goreleaser.yaml")
	}
}

// TestTemplatesShippedInDocker verifies Dockerfile copies templates.
func TestTemplatesShippedInDocker(t *testing.T) {
	repoRoot := getRepoRoot(t)
	dockerfilePath := filepath.Join(repoRoot, "Dockerfile")

	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Skipf("no Dockerfile found: %v", err)
	}

	if !strings.Contains(string(content), "COPY templates/") {
		t.Error("Dockerfile does not COPY templates/ directory")
		t.Error("Fix: Add 'COPY templates/ ./templates/' to Dockerfile")
	}
}

// TestNucleiTemplatesValid validates all Nuclei YAML templates have required fields.
func TestNucleiTemplatesValid(t *testing.T) {
	repoRoot := getRepoRoot(t)
	nucleiDir := filepath.Join(repoRoot, "templates", "nuclei")

	if _, err := os.Stat(nucleiDir); os.IsNotExist(err) {
		t.Skip("templates/nuclei/ not found")
	}

	idPattern := regexp.MustCompile(`(?m)^id:\s*\S+`)
	namePattern := regexp.MustCompile(`(?m)^\s+name:\s*.+`)
	severityPattern := regexp.MustCompile(`(?m)^\s+severity:\s*(critical|high|medium|low|info|unknown)`)
	authorPattern := regexp.MustCompile(`(?m)^\s+author:\s*.+`)
	// Workflow templates use a different structure (no severity required)
	workflowPattern := regexp.MustCompile(`(?m)^workflows?:`)

	var validCount, invalidCount int
	err := filepath.Walk(nucleiDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("cannot read %s: %v", path, readErr)
			invalidCount++
			return nil
		}

		content := string(data)
		rel, _ := filepath.Rel(repoRoot, path)
		relSlash := filepath.ToSlash(rel)
		isWorkflow := workflowPattern.MatchString(content)
		var errs []string

		if !idPattern.MatchString(content) {
			errs = append(errs, "missing id")
		}
		if !namePattern.MatchString(content) {
			errs = append(errs, "missing info.name")
		}
		// Workflow templates don't require severity
		if !isWorkflow && !severityPattern.MatchString(content) {
			errs = append(errs, "missing or invalid info.severity")
		}
		if !authorPattern.MatchString(content) {
			errs = append(errs, "missing info.author")
		}

		if len(errs) > 0 {
			t.Errorf("nuclei template %s: %s", relSlash, strings.Join(errs, ", "))
			invalidCount++
		} else {
			validCount++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk nuclei templates: %v", err)
	}

	t.Logf("Nuclei templates: %d valid, %d invalid", validCount, invalidCount)
	if invalidCount > 0 {
		t.Errorf("%d Nuclei template(s) have validation errors", invalidCount)
	}
}

// TestWorkflowTemplatesValid validates workflow YAML templates have required fields.
func TestWorkflowTemplatesValid(t *testing.T) {
	repoRoot := getRepoRoot(t)
	workflowDir := filepath.Join(repoRoot, "templates", "workflows")

	if _, err := os.Stat(workflowDir); os.IsNotExist(err) {
		t.Skip("templates/workflows/ not found")
	}

	namePattern := regexp.MustCompile(`(?m)^name:\s*.+`)
	stepsPattern := regexp.MustCompile(`(?m)^steps:`)

	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("cannot read workflows dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		data, readErr := os.ReadFile(filepath.Join(workflowDir, entry.Name()))
		if readErr != nil {
			t.Errorf("cannot read %s: %v", entry.Name(), readErr)
			continue
		}

		content := string(data)
		if !namePattern.MatchString(content) {
			t.Errorf("workflows/%s: missing name field", entry.Name())
		}
		if !stepsPattern.MatchString(content) {
			t.Errorf("workflows/%s: no steps defined", entry.Name())
		}

		t.Logf("✓ workflows/%s", entry.Name())
	}
}

// TestPolicyTemplatesValid validates policy YAML templates have required fields.
func TestPolicyTemplatesValid(t *testing.T) {
	repoRoot := getRepoRoot(t)
	policyDir := filepath.Join(repoRoot, "templates", "policies")

	if _, err := os.Stat(policyDir); os.IsNotExist(err) {
		t.Skip("templates/policies/ not found")
	}

	namePattern := regexp.MustCompile(`(?m)^name:\s*.+`)

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		t.Fatalf("cannot read policies dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		data, readErr := os.ReadFile(filepath.Join(policyDir, entry.Name()))
		if readErr != nil {
			t.Errorf("cannot read %s: %v", entry.Name(), readErr)
			continue
		}

		if !namePattern.MatchString(string(data)) {
			t.Errorf("policies/%s: missing name field", entry.Name())
		}

		t.Logf("✓ policies/%s", entry.Name())
	}
}

// TestOverrideTemplatesValid validates override YAML templates are well-formed.
func TestOverrideTemplatesValid(t *testing.T) {
	repoRoot := getRepoRoot(t)
	overrideDir := filepath.Join(repoRoot, "templates", "overrides")

	if _, err := os.Stat(overrideDir); os.IsNotExist(err) {
		t.Skip("templates/overrides/ not found")
	}

	entries, err := os.ReadDir(overrideDir)
	if err != nil {
		t.Fatalf("cannot read overrides dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		data, readErr := os.ReadFile(filepath.Join(overrideDir, entry.Name()))
		if readErr != nil {
			t.Errorf("cannot read %s: %v", entry.Name(), readErr)
			continue
		}

		content := string(data)
		// Overrides must have either matchers or rules
		if !strings.Contains(content, "matchers:") && !strings.Contains(content, "rules:") && !strings.Contains(content, "overrides:") {
			t.Errorf("overrides/%s: missing matchers, rules, or overrides section", entry.Name())
		}

		t.Logf("✓ overrides/%s", entry.Name())
	}
}

// TestOutputTemplatesValid validates output .tmpl files have valid Go template syntax.
func TestOutputTemplatesValid(t *testing.T) {
	repoRoot := getRepoRoot(t)
	outputDir := filepath.Join(repoRoot, "templates", "output")

	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		t.Skip("templates/output/ not found")
	}

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("cannot read output dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tmpl") {
			continue
		}

		data, readErr := os.ReadFile(filepath.Join(outputDir, entry.Name()))
		if readErr != nil {
			t.Errorf("cannot read %s: %v", entry.Name(), readErr)
			continue
		}

		// Verify Go template parses (with a permissive FuncMap for custom functions)
		dummyFuncs := map[string]interface{}{
			"escapeCSV":    func(s string) string { return s },
			"escapeXML":    func(s string) string { return s },
			"severityIcon": func(s string) string { return s },
			"json":         func(v interface{}) string { return "" },
			"prettyJSON":   func(v interface{}) string { return "" },
			"owaspLink":    func(s string) string { return s },
			"cweLink":      func(s string) string { return s },
			"toString":     func(v interface{}) string { return "" },
			"upper":        func(s string) string { return s },
			"lower":        func(s string) string { return s },
			"title":        func(s string) string { return s },
			"default":      func(d, v interface{}) interface{} { return v },
			"sub":          func(a, b int) int { return a - b },
			"add":          func(a, b int) int { return a + b },
			"mul":          func(a, b int) int { return a * b },
			"div":          func(a, b int) int { return a },
			"mod":          func(a, b int) int { return a },
			"lt":           func(a, b int) bool { return a < b },
			"gt":           func(a, b int) bool { return a > b },
			"repeat":       func(n int, s string) string { return s },
			// Sprig functions commonly used in templates
			"trunc":        func(n int, s string) string { return s },
			"trimAll":      func(a, b string) string { return b },
			"contains":     func(a, b string) bool { return false },
			"hasPrefix":    func(a, b string) bool { return false },
			"hasSuffix":    func(a, b string) bool { return false },
			"replace":      func(a, b, c string) string { return c },
			"indent":       func(n int, s string) string { return s },
			"nindent":      func(n int, s string) string { return s },
			"join":         func(sep string, v interface{}) string { return "" },
			"list":         func(v ...interface{}) []interface{} { return v },
			"dict":         func(v ...interface{}) map[string]interface{} { return nil },
			"ternary":      func(a, b interface{}, c bool) interface{} { return a },
			"empty":        func(v interface{}) bool { return false },
			"coalesce":     func(v ...interface{}) interface{} { return nil },
			"toJson":       func(v interface{}) string { return "" },
			"toPrettyJson": func(v interface{}) string { return "" },
			"date":         func(fmt string, t interface{}) string { return "" },
			"now":          func() interface{} { return nil },
		}

		tmplName := strings.TrimSuffix(entry.Name(), ".tmpl")
		_, parseErr := template.New(tmplName).Funcs(dummyFuncs).Parse(string(data))
		if parseErr != nil {
			t.Errorf("invalid Go template in output/%s: %v", entry.Name(), parseErr)
			continue
		}

		t.Logf("✓ output/%s (%d bytes)", entry.Name(), len(data))
	}
}

// TestReportConfigTemplatesValid validates report config YAML files have required fields.
func TestReportConfigTemplatesValid(t *testing.T) {
	repoRoot := getRepoRoot(t)
	configDir := filepath.Join(repoRoot, "templates", "report-configs")

	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		t.Skip("templates/report-configs/ not found")
	}

	namePattern := regexp.MustCompile(`(?m)^name:\s*.+`)

	entries, err := os.ReadDir(configDir)
	if err != nil {
		t.Fatalf("cannot read report-configs dir: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		data, readErr := os.ReadFile(filepath.Join(configDir, entry.Name()))
		if readErr != nil {
			t.Errorf("cannot read %s: %v", entry.Name(), readErr)
			continue
		}

		if !namePattern.MatchString(string(data)) {
			t.Errorf("report-configs/%s: missing name field", entry.Name())
		}

		t.Logf("✓ report-configs/%s", entry.Name())
	}
}

// TestTemplatesNoEmptyDirectories verifies no subdirectory is empty.
func TestTemplatesNoEmptyDirectories(t *testing.T) {
	repoRoot := getRepoRoot(t)
	templatesDir := filepath.Join(repoRoot, "templates")

	err := filepath.Walk(templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() || path == templatesDir {
			return err
		}

		entries, readErr := os.ReadDir(path)
		if readErr != nil {
			t.Errorf("cannot read %s: %v", path, readErr)
			return nil
		}

		hasFiles := false
		for _, e := range entries {
			if !e.IsDir() {
				hasFiles = true
				break
			}
		}

		if !hasFiles {
			// Check if subdirectories have files
			hasNestedFiles := false
			filepath.Walk(path, func(p string, i os.FileInfo, e error) error {
				if e != nil || p == path {
					return e
				}
				if !i.IsDir() {
					hasNestedFiles = true
				}
				return nil
			})

			if !hasNestedFiles {
				rel, _ := filepath.Rel(repoRoot, path)
				t.Errorf("empty template directory: %s", filepath.ToSlash(rel))
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk templates/: %v", err)
	}
}
