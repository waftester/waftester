package defaults_test

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/ui"
)

// TestVersionConsistency ensures all version references match defaults.Version
func TestVersionConsistency(t *testing.T) {
	// Verify ui.Version matches defaults.Version
	if ui.Version != defaults.Version {
		t.Errorf("ui.Version (%s) != defaults.Version (%s)", ui.Version, defaults.Version)
	}

	// Verify version format is valid semver
	semverPattern := regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$`)
	if !semverPattern.MatchString(defaults.Version) {
		t.Errorf("defaults.Version (%s) is not valid semver", defaults.Version)
	}

	// Scan for hardcoded version strings that should use defaults.Version
	root := findProjectRoot(t)
	var violations []string

	for _, dir := range []string{"pkg", "cmd"} {
		dirPath := filepath.Join(root, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}

			// Skip test files and the definition files
			if strings.HasSuffix(path, "_test.go") ||
				strings.HasSuffix(path, "defaults.go") ||
				strings.Contains(path, "banner.go") { // banner.go uses defaults.Version
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			contentStr := string(content)

			// Skip files with legitimate non-waftester version references
			// - update/ package: deals with payload versions
			// - workflow/ package: workflow definition versions
			// - SARIF spec version: always "2.1.0" per SARIF standard
			if strings.Contains(path, "update") ||
				strings.Contains(path, "workflow") {
				return nil
			}

			// Look for hardcoded version strings like Version = "X.Y.Z" or Version: "X.Y.Z"
			// Exclude SARIF spec version (schema line contains "sarif")
			versionPattern := regexp.MustCompile(`(?m)Version\s*[:=]\s*"(\d+\.\d+\.\d+)"`)
			lines := strings.Split(contentStr, "\n")
			for i, line := range lines {
				if matches := versionPattern.FindStringSubmatch(line); len(matches) > 1 {
					// Skip if this is SARIF spec version (check surrounding context)
					contextStart := max(0, i-3)
					contextEnd := min(len(lines), i+3)
					context := strings.Join(lines[contextStart:contextEnd], "\n")
					if strings.Contains(strings.ToLower(context), "sarif") &&
						strings.Contains(strings.ToLower(context), "schema") {
						continue
					}
					// Skip if this is GitLab SAST format version (spec version, not waftester version)
					if strings.Contains(strings.ToLower(context), "gitlab") &&
						strings.Contains(strings.ToLower(context), "sast") {
						continue
					}
					relPath, _ := filepath.Rel(root, path)
					violations = append(violations, relPath+":"+strconv.Itoa(i+1)+": hardcoded Version = \""+matches[1]+"\"")
				}
			}

			return nil
		})
	}

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded version strings. Use defaults.Version instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}

	// Also check markdown files for "Current stable release: X.Y.Z" pattern
	mdViolations := checkMarkdownVersions(t, root)
	if len(mdViolations) > 0 {
		t.Errorf("Found %d outdated version references in markdown files:", len(mdViolations))
		for _, v := range mdViolations {
			t.Errorf("  %s", v)
		}
	}
}

// checkMarkdownVersions checks markdown files for version references that should match defaults.Version
func checkMarkdownVersions(t *testing.T, root string) []string {
	t.Helper()
	var violations []string

	// Files and patterns to check for exact version match
	checks := []struct {
		file    string
		pattern *regexp.Regexp
	}{
		{"SECURITY.md", regexp.MustCompile(`Current stable release:\s*(\d+\.\d+\.\d+)`)},
	}

	for _, check := range checks {
		path := filepath.Join(root, check.file)
		content, err := os.ReadFile(path)
		if err != nil {
			continue // File might not exist
		}

		matches := check.pattern.FindStringSubmatch(string(content))
		if len(matches) > 1 && matches[1] != defaults.Version {
			violations = append(violations,
				check.file+": found \""+matches[1]+"\" but expected \""+defaults.Version+"\"")
		}
	}

	// Check CHANGELOG.md has an entry for current version
	changelogPath := filepath.Join(root, "CHANGELOG.md")
	if content, err := os.ReadFile(changelogPath); err == nil {
		versionHeader := regexp.MustCompile(`## \[` + regexp.QuoteMeta(defaults.Version) + `\]`)
		if !versionHeader.Match(content) {
			violations = append(violations,
				"CHANGELOG.md: missing entry for version "+defaults.Version)
		}

		// Check CHANGELOG.md has a footer comparison link for the current version
		// Keep a Changelog format: [X.Y.Z]: https://github.com/.../compare/vPREV...vX.Y.Z
		footerLink := regexp.MustCompile(`\[` + regexp.QuoteMeta(defaults.Version) + `\]: https://`)
		if !footerLink.Match(content) {
			violations = append(violations,
				"CHANGELOG.md: missing footer comparison link for version "+defaults.Version+
					" (add ["+defaults.Version+"]: https://github.com/waftester/waftester/compare/vPREV...v"+defaults.Version+")")
		}
	}

	return violations
}

// TestDocVersionConsistency ensures documentation files reference the current version.
// This catches stale version examples in docs that no other test validates.
func TestDocVersionConsistency(t *testing.T) {
	root := findProjectRoot(t)

	tests := []struct {
		name    string
		file    string
		pattern *regexp.Regexp
		desc    string
	}{
		{
			name:    "EXAMPLES.md document version",
			file:    "docs/EXAMPLES.md",
			pattern: regexp.MustCompile(`\*\*Document Version:\*\*\s*(\d+\.\d+\.\d+)`),
			desc:    "Document Version header",
		},
		{
			name:    "INSTALLATION.md docker tag example",
			file:    "docs/INSTALLATION.md",
			pattern: regexp.MustCompile("`(\\d+\\.\\d+\\.\\d+)` \\| Exact version"),
			desc:    "Docker exact version tag example",
		},
		{
			name:    "INSTALLATION.md docker compose VERSION",
			file:    "docs/INSTALLATION.md",
			pattern: regexp.MustCompile(`VERSION=(\d+\.\d+\.\d+)`),
			desc:    "Docker compose VERSION example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(root, tt.file)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("File not found: %s", tt.file)
				return
			}

			matches := tt.pattern.FindSubmatch(content)
			if len(matches) < 2 {
				t.Errorf("%s: pattern not found in %s", tt.desc, tt.file)
				return
			}

			found := string(matches[1])
			if found != defaults.Version {
				t.Errorf("%s: %s has %q, want %q", tt.file, tt.desc, found, defaults.Version)
			}
		})
	}
}

// TestWebsiteChangelogSync ensures the website changelog is in sync with the main repo.
// This catches forgotten syncs that leave waftester.com/changelog stale after a version bump.
func TestWebsiteChangelogSync(t *testing.T) {
	root := findProjectRoot(t)

	mainPath := filepath.Join(root, "CHANGELOG.md")
	websitePath := filepath.Join(root, "..", "waftester.com", "src", "content", "changelog.md")

	mainContent, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("Failed to read CHANGELOG.md: %v", err)
	}

	websiteContent, err := os.ReadFile(websitePath)
	if err != nil {
		t.Skipf("Website repo not found at %s (only available locally)", websitePath)
		return
	}

	// Files must be identical — the website changelog is a direct copy
	if !bytes.Equal(mainContent, websiteContent) {
		// Check if just the current version is missing vs total drift
		versionHeader := "## [" + defaults.Version + "]"
		if !strings.Contains(string(websiteContent), versionHeader) {
			t.Errorf("website changelog missing version %s — run: copy CHANGELOG.md ..\\waftester.com\\src\\content\\changelog.md", defaults.Version)
		} else {
			t.Errorf("website changelog differs from CHANGELOG.md — run: copy CHANGELOG.md ..\\waftester.com\\src\\content\\changelog.md")
		}
	}
}

// TestExamplesVersionConsistency validates ALL version-stamped content in docs/EXAMPLES.md.
// This catches stale output banners, Docker tag examples, and output format
// version references that went stale across v2.6.5 → v2.7.0 → v2.9.3.
func TestExamplesVersionConsistency(t *testing.T) {
	root := findProjectRoot(t)
	path := filepath.Join(root, "docs", "EXAMPLES.md")

	content, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("docs/EXAMPLES.md not found: %v", err)
		return
	}

	text := string(content)

	// --- Version strings that must match defaults.Version ---

	// Sample output banners: "WAFtester vX.Y.Z — ..."
	bannerRe := regexp.MustCompile(`WAFtester v(\d+\.\d+\.\d+)`)
	bannerMatches := bannerRe.FindAllStringSubmatchIndex(text, -1)

	// "What's New in vX.Y.Z" headers are historical — skip them
	whatsNewRe := regexp.MustCompile(`What's New in v(\d+\.\d+\.\d+)`)
	whatsNewPositions := make(map[int]bool)
	for _, m := range whatsNewRe.FindAllStringSubmatchIndex(text, -1) {
		whatsNewPositions[m[0]] = true
	}

	// Feature introduction headers like "Intelligence Engine (v2.6.5)" are historical — skip
	featureHeaderRe := regexp.MustCompile(`##[^(]*\(v(\d+\.\d+\.\d+)\)`)
	for _, m := range featureHeaderRe.FindAllStringSubmatchIndex(text, -1) {
		whatsNewPositions[m[0]] = true
	}

	// TOC links referencing feature headers like "- [Intelligence Engine (v2.6.5)]" — skip
	tocFeatureRe := regexp.MustCompile(`- \[[^\]]*\(v\d+\.\d+\.\d+\)\]`)
	for _, m := range tocFeatureRe.FindAllStringSubmatchIndex(text, -1) {
		whatsNewPositions[m[0]] = true
	}

	// MCP intro line "WAFtester includes" should NOT have a version pin.
	// If it says "WAFtester vX.Y.Z includes", that's a stale pin.
	// Already checked by banner regex — the pin will be caught if present.

	for _, m := range bannerMatches {
		// m[0] is the full match start position
		if whatsNewPositions[m[0]] {
			continue
		}
		// Check if this is inside a TOC or feature header we should skip
		skip := false
		for pos := range whatsNewPositions {
			if m[0] >= pos && m[0] <= pos+100 {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		found := text[m[2]:m[3]]
		if found != defaults.Version {
			line := 1 + strings.Count(text[:m[0]], "\n")
			t.Errorf("docs/EXAMPLES.md:%d: stale banner %q, want %q", line, "WAFtester v"+found, "WAFtester v"+defaults.Version)
		}
	}

	// Docker tag examples: "ghcr.io/waftester/waftester:X.Y.Z"
	dockerTagRe := regexp.MustCompile(`ghcr\.io/waftester/waftester:(\d+\.\d+\.\d+)`)
	for _, m := range dockerTagRe.FindAllStringSubmatchIndex(text, -1) {
		found := text[m[2]:m[3]]
		if found != defaults.Version {
			line := 1 + strings.Count(text[:m[0]], "\n")
			t.Errorf("docs/EXAMPLES.md:%d: stale Docker tag %q, want %q", line, found, defaults.Version)
		}
	}

	// Docker tag table: "`X.Y.Z` | Exact version"
	tagTableRe := regexp.MustCompile("`(\\d+\\.\\d+\\.\\d+)` \\| Exact version")
	for _, m := range tagTableRe.FindAllStringSubmatchIndex(text, -1) {
		found := text[m[2]:m[3]]
		if found != defaults.Version {
			line := 1 + strings.Count(text[:m[0]], "\n")
			t.Errorf("docs/EXAMPLES.md:%d: stale Docker tag table %q, want %q", line, found, defaults.Version)
		}
	}

	// Minor alias: "`X.Y`, `X`" should match current major.minor
	parts := strings.SplitN(defaults.Version, ".", 3)
	if len(parts) >= 2 {
		expectedMinor := parts[0] + "." + parts[1]
		minorAliasRe := regexp.MustCompile("`(\\d+\\.\\d+)`, `\\d+` \\| Minor/major")
		for _, m := range minorAliasRe.FindAllStringSubmatchIndex(text, -1) {
			found := text[m[2]:m[3]]
			if found != expectedMinor {
				line := 1 + strings.Count(text[:m[0]], "\n")
				t.Errorf("docs/EXAMPLES.md:%d: stale minor alias %q, want %q", line, found, expectedMinor)
			}
		}
	}

	// Docker compose VERSION=X.Y.Z
	composeVersionRe := regexp.MustCompile(`VERSION=(\d+\.\d+\.\d+)`)
	for _, m := range composeVersionRe.FindAllStringSubmatchIndex(text, -1) {
		found := text[m[2]:m[3]]
		if found != defaults.Version {
			line := 1 + strings.Count(text[:m[0]], "\n")
			t.Errorf("docs/EXAMPLES.md:%d: stale compose VERSION=%q, want %q", line, found, defaults.Version)
		}
	}

	// Output format versions — match specific WAFtester version patterns, not generic "version" fields.
	// These patterns target the tool/generator version, not component/app/spec versions.
	outputVersionPatterns := []struct {
		re   *regexp.Regexp
		desc string
	}{
		// CycloneDX/JSON tool version: "name": "waf-tester",\n        "version": "X.Y.Z"
		{regexp.MustCompile(`"name":\s*"waf-tester",\s*"version":\s*"(\d+\.\d+\.\d+)"`), "CycloneDX tool version"},
		// Elasticsearch: "tool": "waftester",\n    "version": "X.Y.Z"
		{regexp.MustCompile(`"tool":\s*"waftester",\s*"version":\s*"(\d+\.\d+\.\d+)"`), "Elasticsearch version"},
		// XML generator: <name>WAFtester</name>\n    <version>X.Y.Z</version>
		{regexp.MustCompile(`<name>WAFtester</name>\s*<version>(\d+\.\d+\.\d+)</version>`), "XML generator version"},
		// XML root attr: <waftester-report version="X.Y.Z"
		{regexp.MustCompile(`<waftester-report\s+version="(\d+\.\d+\.\d+)"`), "XML report version attr"},
		// OpenTelemetry: "service.version".*"stringValue": "X.Y.Z"
		{regexp.MustCompile(`"service\.version".*?"stringValue":\s*"(\d+\.\d+\.\d+)"`), "OpenTelemetry version"},
		// Slack message: WAFtester vX.Y.Z |
		{regexp.MustCompile(`WAFtester v(\d+\.\d+\.\d+) \|`), "Slack message version"},
		// GitHub issue: WAFtester vX.Y.Z*
		{regexp.MustCompile(`Created by WAFtester v(\d+\.\d+\.\d+)`), "GitHub issue version"},
	}
	for _, p := range outputVersionPatterns {
		for _, m := range p.re.FindAllStringSubmatchIndex(text, -1) {
			found := text[m[2]:m[3]]
			if found != defaults.Version {
				line := 1 + strings.Count(text[:m[0]], "\n")
				t.Errorf("docs/EXAMPLES.md:%d: stale %s %q, want %q", line, p.desc, found, defaults.Version)
			}
		}
	}

	// service.version in OpenTelemetry: "stringValue": "X.Y.Z"
	otelVersionRe := regexp.MustCompile(`"stringValue":\s*"(\d+\.\d+\.\d+)"`)
	for _, m := range otelVersionRe.FindAllStringSubmatchIndex(text, -1) {
		found := text[m[2]:m[3]]
		if found != defaults.Version {
			line := 1 + strings.Count(text[:m[0]], "\n")
			t.Errorf("docs/EXAMPLES.md:%d: stale OpenTelemetry version %q, want %q", line, found, defaults.Version)
		}
	}
}

// TestNpmVersionConsistency ensures npm package.json versions match defaults.Version.
// This catches version drift between Go and npm distributions.
func TestNpmVersionConsistency(t *testing.T) {
	root := findProjectRoot(t)

	// npmPackageJSON represents the fields we care about
	type npmPackageJSON struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}

	// --- Main package: npm/cli/package.json ---
	mainPkgPath := filepath.Join(root, "npm", "cli", "package.json")
	mainData, err := os.ReadFile(mainPkgPath)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", mainPkgPath, err)
	}

	var mainPkg npmPackageJSON
	if err := json.Unmarshal(mainData, &mainPkg); err != nil {
		t.Fatalf("Failed to parse %s: %v", mainPkgPath, err)
	}

	if mainPkg.Version != defaults.Version {
		t.Errorf("npm/cli/package.json version (%s) != defaults.Version (%s)",
			mainPkg.Version, defaults.Version)
	}

	// --- optionalDependencies must all match ---
	expectedPlatforms := []string{
		"@waftester/darwin-x64",
		"@waftester/darwin-arm64",
		"@waftester/linux-x64",
		"@waftester/linux-arm64",
		"@waftester/win32-x64",
		"@waftester/win32-arm64",
	}

	if len(mainPkg.OptionalDependencies) != len(expectedPlatforms) {
		t.Errorf("npm/cli/package.json has %d optionalDependencies, expected %d",
			len(mainPkg.OptionalDependencies), len(expectedPlatforms))
	}

	for _, pkg := range expectedPlatforms {
		ver, ok := mainPkg.OptionalDependencies[pkg]
		if !ok {
			t.Errorf("npm/cli/package.json missing optionalDependency %s", pkg)
			continue
		}
		if ver != defaults.Version {
			t.Errorf("npm/cli/package.json optionalDependencies[%s] = %s, want %s",
				pkg, ver, defaults.Version)
		}
	}

	// --- Platform template: npm/platform-template/package.json.tmpl ---
	// Template uses {{VERSION}} placeholder that build script replaces.
	// Verify the placeholder exists (not a hardcoded version).
	templatePath := filepath.Join(root, "npm", "platform-template", "package.json.tmpl")
	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		t.Logf("Skipping platform template check: %v", err)
	} else {
		tmplContent := string(templateData)
		if !strings.Contains(tmplContent, `"version": "{{VERSION}}"`) {
			t.Error("npm/platform-template/package.json.tmpl missing {{VERSION}} placeholder in version field")
		}
		// Ensure no hardcoded version leaked into the template
		hardcodedVersion := regexp.MustCompile(`"version":\s*"\d+\.\d+\.\d+"`)
		if hardcodedVersion.MatchString(tmplContent) {
			t.Error("npm/platform-template/package.json.tmpl has hardcoded version — must use {{VERSION}} placeholder")
		}
	}

	// --- Verify cli.js has no console.log (stdout purity for MCP) ---
	cliJSPath := filepath.Join(root, "npm", "cli", "bin", "cli.js")
	cliJS, err := os.ReadFile(cliJSPath)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", cliJSPath, err)
	}

	cliJSContent := string(cliJS)
	consoleLogPattern := regexp.MustCompile(`\bconsole\.log\b`)
	if matches := consoleLogPattern.FindAllString(cliJSContent, -1); len(matches) > 0 {
		t.Errorf("npm/cli/bin/cli.js contains %d console.log calls — must use console.error for MCP stdout purity",
			len(matches))
	}

	// --- Verify cli.js shebang ---
	if !strings.HasPrefix(cliJSContent, "#!/usr/bin/env node") {
		t.Error("npm/cli/bin/cli.js missing shebang: #!/usr/bin/env node")
	}

	// --- Verify no CRLF line endings in cli.js ---
	if strings.Contains(cliJSContent, "\r\n") {
		t.Error("npm/cli/bin/cli.js contains CRLF line endings — must use LF for cross-platform #!/usr/bin/env node")
	}
}

// TestNoHardcodedConcurrency ensures all concurrency values use defaults.Concurrency* constants
func TestNoHardcodedConcurrency(t *testing.T) {
	violations := findHardcodedValues(t, "Concurrency", 3, 200, []string{
		"defaults.go",
		"_test.go",
	})

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded Concurrency values. Use defaults.Concurrency* instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

// TestNoHardcodedRetries ensures all retry values use defaults.Retry* constants
func TestNoHardcodedRetries(t *testing.T) {
	violations := findHardcodedValues(t, "Retries", 2, 20, []string{
		"defaults.go",
		"_test.go",
	})
	violations = append(violations, findHardcodedValues(t, "MaxRetries", 2, 20, []string{
		"defaults.go",
		"_test.go",
	})...)
	violations = append(violations, findHardcodedValues(t, "RetryCount", 2, 20, []string{
		"defaults.go",
		"_test.go",
	})...)

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded retry values. Use defaults.Retry* instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

// TestNoHardcodedMaxDepth ensures all depth values use defaults.Depth* constants
func TestNoHardcodedMaxDepth(t *testing.T) {
	violations := findHardcodedValues(t, "MaxDepth", 2, 50, []string{
		"defaults.go",
		"_test.go",
	})

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded MaxDepth values. Use defaults.Depth* instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

// TestNoHardcodedMaxRedirects ensures redirect limits use defaults.MaxRedirects
func TestNoHardcodedMaxRedirects(t *testing.T) {
	violations := findHardcodedValues(t, "MaxRedirects", 2, 50, []string{
		"defaults.go",
		"_test.go",
	})

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded MaxRedirects values. Use defaults.MaxRedirects instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

// TestNoHardcodedContentType ensures Content-Type headers use defaults.ContentType* constants
func TestNoHardcodedContentType(t *testing.T) {
	violations := findHardcodedStrings(t, "ContentType", []string{
		"application/json",
		"application/x-www-form-urlencoded",
		"text/xml",
		"application/xml",
	}, []string{
		"defaults.go",
		"_test.go",
		"payloads", // payload definitions are test data
	})

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded ContentType values. Use defaults.ContentType* instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

// TestNoHardcodedUserAgent ensures User-Agent values use defaults.UA* or ui.UserAgentWithContext()
func TestNoHardcodedUserAgent(t *testing.T) {
	violations := findHardcodedStrings(t, "UserAgent", []string{
		"Mozilla/5.0",    // Browser UA patterns
		"API-Fuzzer/1.0", // Old component-specific UAs
		"BizLogic-Tester/1.0",
		"Deserialize-Tester/1.0",
		"OAuth-Tester/1.0",
		"WAF-Tester-Discovery/1.0",
		"FuzzBot/1.0",
		"GraphQLTester/1.0",
	}, []string{
		"defaults.go",
		"_test.go",
		"browser/client.go", // Browser profiles legitimately define UA strings
		"realistic",         // Realistic testing needs various UAs
	})

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded UserAgent values. Use defaults.UA* or ui.UserAgentWithContext() instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

// findHardcodedStrings walks the codebase and finds struct field assignments with hardcoded string literals
func findHardcodedStrings(t *testing.T, fieldName string, forbiddenValues []string, excludePatterns []string) []string {
	t.Helper()

	var violations []string
	root := findProjectRoot(t)

	for _, dir := range []string{"pkg", "cmd"} {
		dirPath := filepath.Join(root, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}

			for _, pattern := range excludePatterns {
				if strings.Contains(path, pattern) {
					return nil
				}
			}

			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil
			}

			ast.Inspect(node, func(n ast.Node) bool {
				if kv, ok := n.(*ast.KeyValueExpr); ok {
					if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == fieldName {
						if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							val := strings.Trim(lit.Value, `"`)
							for _, forbidden := range forbiddenValues {
								if val == forbidden {
									pos := fset.Position(lit.Pos())
									relPath, _ := filepath.Rel(root, pos.Filename)
									violations = append(violations,
										relPath+":"+strconv.Itoa(pos.Line)+": "+fieldName+" = "+lit.Value)
								}
							}
						}
					}
				}
				return true
			})

			return nil
		})
	}

	return violations
}

// findHardcodedValues walks the codebase and finds struct field assignments with hardcoded numeric values
func findHardcodedValues(t *testing.T, fieldName string, minVal, maxVal int, excludePatterns []string) []string {
	t.Helper()

	var violations []string
	root := findProjectRoot(t)

	// Walk pkg/ and cmd/ directories
	for _, dir := range []string{"pkg", "cmd"} {
		dirPath := filepath.Join(root, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip errors
			}

			// Skip non-Go files
			if info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}

			// Skip excluded patterns
			for _, pattern := range excludePatterns {
				if strings.Contains(path, pattern) {
					return nil
				}
			}

			// Parse the file
			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil // Skip parse errors
			}

			// Find hardcoded values
			ast.Inspect(node, func(n ast.Node) bool {
				// Look for key-value expressions in composite literals (struct initialization)
				if kv, ok := n.(*ast.KeyValueExpr); ok {
					if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == fieldName {
						// Check if value is a basic literal (hardcoded number)
						if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.INT {
							val, _ := strconv.Atoi(lit.Value)
							if val >= minVal && val <= maxVal {
								pos := fset.Position(lit.Pos())
								relPath, _ := filepath.Rel(root, pos.Filename)
								violations = append(violations,
									relPath+":"+strconv.Itoa(pos.Line)+": "+fieldName+" = "+lit.Value)
							}
						}
					}
				}

				// Look for assignment statements: config.Concurrency = 10
				if assign, ok := n.(*ast.AssignStmt); ok {
					for i, lhs := range assign.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok {
							if sel.Sel.Name == fieldName && i < len(assign.Rhs) {
								if lit, ok := assign.Rhs[i].(*ast.BasicLit); ok && lit.Kind == token.INT {
									val, _ := strconv.Atoi(lit.Value)
									if val >= minVal && val <= maxVal {
										pos := fset.Position(lit.Pos())
										relPath, _ := filepath.Rel(root, pos.Filename)
										violations = append(violations,
											relPath+":"+strconv.Itoa(pos.Line)+": "+fieldName+" = "+lit.Value)
									}
								}
							}
						}
					}
				}

				return true
			})

			return nil
		})

		if err != nil {
			t.Logf("Warning: error walking %s: %v", dir, err)
		}
	}

	return violations
}

// findProjectRoot finds the project root by looking for go.mod
func findProjectRoot(t *testing.T) string {
	t.Helper()

	// Start from the current working directory
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	// Walk up to find go.mod
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("Could not find project root (go.mod)")
		}
		dir = parent
	}
}

// TestNoHardcodedOWASPData ensures OWASP Top 10 data is only defined in defaults/owasp.go
func TestNoHardcodedOWASPData(t *testing.T) {
	root := findProjectRoot(t)
	var violations []string

	// Patterns that indicate OWASP Top 10 data duplication
	// This catches struct/slice literals that define OWASP codes with descriptions
	// e.g., {"A01:2021", "Broken Access Control"} or Code: "A01:2021", Name: "..."
	owaspCodePattern := regexp.MustCompile(`"A(0[1-9]|10):2021`)

	// Variable definitions that likely contain duplicated OWASP Top 10 data
	// Match: var owaspTop10Mapping = []struct or var pdfOWASPTop10 = ...
	// Must include "Top10" or "top10" to avoid false positives like "owaspSources"
	owaspVarDefPattern := regexp.MustCompile(`^var\s+(owasp[Tt]op10|pdfOWASP[Tt]op10|owaspURLMap)\w*\s*=\s*(\[\]struct|\[\]string|map\[)`)

	// Files that are allowed to have OWASP data
	allowedFiles := []string{
		"owasp.go",       // The centralized source
		"_test.go",       // Test files (test data is OK)
		"html_report.go", // Template data (uses OWASP strings in test fixtures)
	}

	for _, dir := range []string{"pkg", "cmd"} {
		dirPath := filepath.Join(root, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}

			// Skip allowed files
			for _, allowed := range allowedFiles {
				if strings.HasSuffix(path, allowed) {
					return nil
				}
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			contentStr := string(content)
			lines := strings.Split(contentStr, "\n")

			relPath, _ := filepath.Rel(root, path)

			// Check for OWASP variable definitions (not just usage)
			for i, line := range lines {
				// Skip comments
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
					continue
				}

				// Check for OWASP Top 10 mapping variable definitions with struct/slice/map literals
				if owaspVarDefPattern.MatchString(trimmed) {
					violations = append(violations,
						relPath+":"+strconv.Itoa(i+1)+": OWASP Top 10 variable definition - use defaults.OWASPTop10 instead")
				}

				// Check for struct/map definitions with OWASP codes AND their full descriptions
				// This catches things like:
				//   {"A01:2021", "Broken Access Control"},
				//   {"A02:2021", "Cryptographic Failures"},
				// We look for lines that define OWASP codes with their full descriptions
				if owaspCodePattern.MatchString(line) {
					// Check if this is a struct/map definition (has both code and description)
					// Avoid flagging simple string comparisons or single references
					if strings.Contains(line, "Broken Access Control") ||
						strings.Contains(line, "Cryptographic Failures") ||
						strings.Contains(line, "Insecure Design") ||
						strings.Contains(line, "Security Misconfiguration") ||
						strings.Contains(line, "Vulnerable and Outdated") ||
						strings.Contains(line, "Authentication Failures") ||
						strings.Contains(line, "Integrity Failures") ||
						strings.Contains(line, "Monitoring Failures") ||
						strings.Contains(line, "Request Forgery") {
						violations = append(violations,
							relPath+":"+strconv.Itoa(i+1)+": hardcoded OWASP mapping - use defaults.OWASPTop10 instead")
					}
				}
			}

			return nil
		})
	}

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded OWASP data definitions. Use pkg/defaults/owasp.go as the single source of truth:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

// TestNoHardcodedToolName ensures all tool name references use defaults.ToolName
// in the pkg/output package (v2.5.0+ code)
func TestNoHardcodedToolName(t *testing.T) {
	root := findProjectRoot(t)
	var violations []string

	// Patterns that indicate hardcoded tool names in defaults (not string comparisons)
	// Look for assignments like: = "waftester" or : "waftester" or ("waftester")
	assignmentPatterns := []*regexp.Regexp{
		regexp.MustCompile(`=\s*"waftester"`),
		regexp.MustCompile(`:\s*"waftester"`),
		regexp.MustCompile(`\(\s*"waftester"\s*\)`),
		regexp.MustCompile(`=\s*"WAFtester"`),
		regexp.MustCompile(`:\s*"WAFtester"`),
	}

	// Only check pkg/output for now (v2.5.0 code)
	// Other packages will be migrated separately
	dirPath := filepath.Join(root, "pkg", "output")
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		t.Skip("pkg/output directory not found")
	}

	_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Skip test files
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		// Skip template.go - contains embedded template literals with AWS ASFF product identifiers
		// and template.New() internal names that are not user-facing tool identifiers
		if strings.HasSuffix(path, "template.go") {
			return nil
		}

		relPath, _ := filepath.Rel(root, path)
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			// Skip comments
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			for _, pattern := range assignmentPatterns {
				if pattern.MatchString(line) {
					violations = append(violations,
						relPath+":"+strconv.Itoa(i+1)+": hardcoded tool name - use defaults.ToolName or defaults.ToolNameDisplay")
					break
				}
			}
		}

		return nil
	})

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded tool name strings. Use defaults.ToolName or defaults.ToolNameDisplay:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}
