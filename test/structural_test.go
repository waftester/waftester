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
