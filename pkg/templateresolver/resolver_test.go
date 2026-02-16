package templateresolver

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/waftester/waftester/templates"
)

// =============================================================================
// Resolve — short name → embedded FS
// =============================================================================

func TestResolve_ShortName_Embedded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		kind  Kind
	}{
		{"policy strict", "strict", KindPolicy},
		{"policy permissive", "permissive", KindPolicy},
		{"policy standard", "standard", KindPolicy},
		{"policy owasp-top10", "owasp-top10", KindPolicy},
		{"policy pci-dss", "pci-dss", KindPolicy},
		{"override api-only", "api-only", KindOverride},
		{"override crs-tuning", "crs-tuning", KindOverride},
		{"override false-positive-suppression", "false-positive-suppression", KindOverride},
		{"report-config dark", "dark", KindReportConfig},
		{"report-config enterprise", "enterprise", KindReportConfig},
		{"report-config minimal", "minimal", KindReportConfig},
		{"report-config compliance", "compliance", KindReportConfig},
		{"report-config print", "print", KindReportConfig},
		{"output csv", "csv", KindOutputFormat},
		{"output junit", "junit", KindOutputFormat},
		{"output slack-notification", "slack-notification", KindOutputFormat},
		{"output asff", "asff", KindOutputFormat},
		{"output text-summary", "text-summary", KindOutputFormat},
		{"output markdown-report", "markdown-report", KindOutputFormat},
		{"workflow full-scan", "full-scan", KindWorkflow},
		{"workflow ci-gate", "ci-gate", KindWorkflow},
		{"workflow api-scan", "api-scan", KindWorkflow},
		{"workflow quick-probe", "quick-probe", KindWorkflow},
		{"workflow waf-detection", "waf-detection", KindWorkflow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := Resolve(tt.value, tt.kind)
			if err != nil {
				t.Fatalf("Resolve(%q, %s): %v", tt.value, tt.kind, err)
			}
			defer result.Content.Close()

			if result.Source == "" {
				t.Error("expected non-empty source")
			}
			if !strings.HasPrefix(result.Source, "embedded:") && !strings.HasPrefix(result.Source, "disk:") {
				t.Errorf("unexpected source prefix: %q", result.Source)
			}

			data, err := io.ReadAll(result.Content)
			if err != nil {
				t.Fatalf("reading content: %v", err)
			}
			if len(data) == 0 {
				t.Error("expected non-empty content")
			}
		})
	}
}

// TestResolve_ContentValidation verifies embedded templates contain expected content markers.
func TestResolve_ContentValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    string
		kind     Kind
		contains string // substring that must appear in content
	}{
		{"strict policy has name field", "strict", KindPolicy, "name: strict"},
		{"strict policy has fail_on", "strict", KindPolicy, "fail_on:"},
		{"permissive policy has name field", "permissive", KindPolicy, "name: permissive"},
		{"csv output has header", "csv", KindOutputFormat, "Test ID"},
		{"junit output has testsuites", "junit", KindOutputFormat, "testsuites"},
		{"dark report-config has name", "dark", KindReportConfig, "name:"},
		{"api-only override has overrides key", "api-only", KindOverride, "overrides:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := Resolve(tt.value, tt.kind)
			if err != nil {
				t.Fatalf("Resolve(%q, %s): %v", tt.value, tt.kind, err)
			}
			defer result.Content.Close()

			data, err := io.ReadAll(result.Content)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), tt.contains) {
				t.Errorf("content of %q missing expected substring %q\ngot: %s",
					tt.value, tt.contains, string(data)[:min(200, len(data))])
			}
		})
	}
}

// =============================================================================
// Resolve — file path inputs
// =============================================================================

func TestResolve_FilePath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	testFile := filepath.Join(tmp, "test-policy.yaml")
	if err := os.WriteFile(testFile, []byte("name: test"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Resolve(testFile, KindPolicy)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", testFile, err)
	}
	defer result.Content.Close()

	if result.Source != "disk:"+testFile {
		t.Errorf("source = %q, want %q", result.Source, "disk:"+testFile)
	}

	data, err := io.ReadAll(result.Content)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "name: test" {
		t.Errorf("content = %q, want %q", string(data), "name: test")
	}
}

// TestResolve_FilePathNotFound verifies error when explicit path doesn't exist.
func TestResolve_FilePathNotFound(t *testing.T) {
	t.Parallel()

	_, err := Resolve("/nonexistent/path/to/template.yaml", KindPolicy)
	if err == nil {
		t.Error("expected error for nonexistent file path")
	}
	if !strings.Contains(err.Error(), "opening") {
		t.Errorf("error should mention opening, got: %v", err)
	}
}

// TestResolve_FilePathDiskPriority verifies that an explicit on-disk file
// is preferred over embedded templates.
func TestResolve_FilePathDiskPriority(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	customFile := filepath.Join(tmp, "custom.yaml")
	content := "name: disk-override-content"
	if err := os.WriteFile(customFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Resolve(customFile, KindPolicy)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", customFile, err)
	}
	defer result.Content.Close()

	if !strings.HasPrefix(result.Source, "disk:") {
		t.Errorf("expected disk source, got %q", result.Source)
	}

	data, _ := io.ReadAll(result.Content)
	if string(data) != content {
		t.Errorf("got %q, want %q", string(data), content)
	}
}

// =============================================================================
// Resolve — error cases
// =============================================================================

func TestResolve_Empty(t *testing.T) {
	t.Parallel()

	_, err := Resolve("", KindPolicy)
	if err == nil {
		t.Error("expected error for empty value")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty, got: %v", err)
	}
}

func TestResolve_NotFound(t *testing.T) {
	t.Parallel()

	_, err := Resolve("nonexistent-template", KindPolicy)
	if err == nil {
		t.Error("expected error for nonexistent template")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

// TestResolve_NotFoundPerKind verifies each kind returns errors for missing templates.
func TestResolve_NotFoundPerKind(t *testing.T) {
	t.Parallel()

	kinds := []Kind{KindPolicy, KindOverride, KindReportConfig, KindOutputFormat, KindWorkflow, KindNuclei}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			_, err := Resolve("this-does-not-exist-xyz", kind)
			if err == nil {
				t.Errorf("expected error for nonexistent %s template", kind)
			}
		})
	}
}

// TestResolve_WithExtension verifies that passing a short name with explicit extension works.
func TestResolve_WithExtension(t *testing.T) {
	t.Parallel()

	// "strict.yaml" has no directory separator, so it goes through short name resolution.
	// The name already has the .yaml extension so it shouldn't be doubled.
	result, err := Resolve("strict.yaml", KindPolicy)
	if err != nil {
		// If CWD doesn't have on-disk templates, embedded FS is used.
		// Either way, it should NOT fail with ".yaml.yaml" double-extension.
		t.Fatalf("Resolve(\"strict.yaml\", KindPolicy) failed: %v", err)
	}
	defer result.Content.Close()

	data, _ := io.ReadAll(result.Content)
	if !strings.Contains(string(data), "name:") {
		t.Error("resolved content missing expected 'name:' field")
	}
}

// =============================================================================
// Resolve — env var override
// =============================================================================

// TestResolve_EnvVarOverride verifies WAF_TESTER_TEMPLATE_DIR is checked
// as part of the resolution chain.
func TestResolve_EnvVarOverride(t *testing.T) {
	// No t.Parallel — modifies env.
	tmp := t.TempDir()

	// Create a custom template in the env dir structure.
	policyDir := filepath.Join(tmp, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "name: env-custom-policy\ndescription: from env var"
	if err := os.WriteFile(filepath.Join(policyDir, "env-custom.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv(envKey, tmp)

	result, err := Resolve("env-custom", KindPolicy)
	if err != nil {
		t.Fatalf("Resolve with env var: %v", err)
	}
	defer result.Content.Close()

	if !strings.HasPrefix(result.Source, "env:") {
		t.Errorf("expected env: source, got %q", result.Source)
	}

	data, _ := io.ReadAll(result.Content)
	if !strings.Contains(string(data), "env-custom-policy") {
		t.Error("content should come from env var template dir")
	}
}

// TestResolve_EnvVarFallsThrough verifies embedded FS is used when env var
// dir doesn't contain the template.
func TestResolve_EnvVarFallsThrough(t *testing.T) {
	// No t.Parallel — modifies env.
	tmp := t.TempDir() // Empty dir, no templates
	t.Setenv(envKey, tmp)

	result, err := Resolve("strict", KindPolicy)
	if err != nil {
		t.Fatalf("expected embedded fallback, got error: %v", err)
	}
	defer result.Content.Close()

	if !strings.HasPrefix(result.Source, "embedded:") {
		t.Errorf("expected embedded source, got %q", result.Source)
	}
}

// TestResolve_DiskDefaultsPriority verifies that on-disk defaults directory
// templates take priority over embedded templates (step 1 of resolution chain).
func TestResolve_DiskDefaultsPriority(t *testing.T) {
	// No t.Parallel — modifies package-level diskDirs.
	tmp := t.TempDir()
	content := "name: disk-default-override"
	if err := os.WriteFile(filepath.Join(tmp, "strict.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	origDir := diskDirs[KindPolicy]
	diskDirs[KindPolicy] = tmp
	t.Cleanup(func() { diskDirs[KindPolicy] = origDir })

	result, err := Resolve("strict", KindPolicy)
	if err != nil {
		t.Fatalf("Resolve with disk default: %v", err)
	}
	defer result.Content.Close()

	if !strings.HasPrefix(result.Source, "disk:") {
		t.Errorf("expected disk: source, got %q", result.Source)
	}

	data, _ := io.ReadAll(result.Content)
	if !strings.Contains(string(data), "disk-default-override") {
		t.Error("content should come from disk defaults directory")
	}
}

// =============================================================================
// ResolveToPath
// =============================================================================

// TestResolveToPath_ShortName verifies short names are materialized to temp files.
func TestResolveToPath_ShortName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		kind  Kind
	}{
		{"policy", "strict", KindPolicy},
		{"override", "api-only", KindOverride},
		{"report-config", "dark", KindReportConfig},
		{"output", "csv", KindOutputFormat},
		{"workflow", "ci-gate", KindWorkflow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path, cleanup, err := ResolveToPath(tt.value, tt.kind)
			if err != nil {
				t.Fatalf("ResolveToPath(%q, %s): %v", tt.value, tt.kind, err)
			}
			defer cleanup()

			// Path must exist on disk.
			info, statErr := os.Stat(path)
			if statErr != nil {
				t.Fatalf("resolved path %q does not exist: %v", path, statErr)
			}
			if info.Size() == 0 {
				t.Error("resolved file is empty")
			}

			// Content must be readable and non-empty.
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("reading resolved file: %v", readErr)
			}
			if len(data) == 0 {
				t.Error("resolved file content is empty")
			}
		})
	}
}

// TestResolveToPath_CleanupRemovesFile verifies cleanup deletes temp file.
func TestResolveToPath_CleanupRemovesFile(t *testing.T) {
	t.Parallel()

	path, cleanup, err := ResolveToPath("strict", KindPolicy)
	if err != nil {
		t.Fatal(err)
	}

	// File must exist before cleanup.
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("file should exist before cleanup: %v", statErr)
	}

	cleanup()

	// If path is inside CWD templates/ (disk resolution), cleanup is a no-op
	// and file still exists. Only check removal for temp files.
	if strings.Contains(path, os.TempDir()) || strings.Contains(path, "waftester-template-") {
		if _, statErr := os.Stat(path); statErr == nil {
			t.Error("temp file should be removed after cleanup")
		}
	}
}

// TestResolveToPath_DiskFile verifies existing files pass through without temp copy.
func TestResolveToPath_DiskFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	diskFile := filepath.Join(tmp, "my-policy.yaml")
	if err := os.WriteFile(diskFile, []byte("name: disk"), 0o644); err != nil {
		t.Fatal(err)
	}

	path, cleanup, err := ResolveToPath(diskFile, KindPolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if path != diskFile {
		t.Errorf("expected original path %q, got %q", diskFile, path)
	}
}

// TestResolveToPath_Empty verifies empty input returns error.
func TestResolveToPath_Empty(t *testing.T) {
	t.Parallel()

	_, _, err := ResolveToPath("", KindPolicy)
	if err == nil {
		t.Error("expected error for empty value")
	}
}

// TestResolveToPath_FilePathNotFound verifies explicit nonexistent path gives error.
func TestResolveToPath_FilePathNotFound(t *testing.T) {
	t.Parallel()

	_, _, err := ResolveToPath("/no/such/file.yaml", KindPolicy)
	if err == nil {
		t.Error("expected error for nonexistent file path")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found, got: %v", err)
	}
}

// TestResolveToPath_ShortNameNotFound verifies unknown short name gives error.
func TestResolveToPath_ShortNameNotFound(t *testing.T) {
	t.Parallel()

	_, _, err := ResolveToPath("imaginary-template-xyz", KindPolicy)
	if err == nil {
		t.Error("expected error for nonexistent short name")
	}
}

// TestResolveToPath_EnvVarOverride verifies env var dir is used.
func TestResolveToPath_EnvVarOverride(t *testing.T) {
	tmp := t.TempDir()
	overrideDir := filepath.Join(tmp, "overrides")
	if err := os.MkdirAll(overrideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(overrideDir, "env-test.yaml"), []byte("name: env"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envKey, tmp)

	path, cleanup, err := ResolveToPath("env-test", KindOverride)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if !strings.Contains(path, "env-test.yaml") {
		t.Errorf("expected env file path, got %q", path)
	}
}

// =============================================================================
// ResolveNucleiDir
// =============================================================================

func TestResolveNucleiDir_Embedded(t *testing.T) {
	ResetNucleiCache()
	t.Cleanup(func() { ResetNucleiCache() })

	dir, err := ResolveNucleiDir("nonexistent-dir-that-wont-exist-12345")
	if err != nil {
		t.Fatalf("ResolveNucleiDir: %v", err)
	}

	// Verify extracted files exist.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading extracted dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected extracted nuclei templates, got empty directory")
	}

	// Verify at least the http directory exists.
	httpDir := filepath.Join(dir, "http")
	if _, statErr := os.Stat(httpDir); statErr != nil {
		t.Errorf("expected http subdirectory in extracted templates: %v", statErr)
	}
}

// TestResolveNucleiDir_ExtractedContentReadable verifies extracted YAML files are valid.
func TestResolveNucleiDir_ExtractedContentReadable(t *testing.T) {
	ResetNucleiCache()
	t.Cleanup(func() { ResetNucleiCache() })

	dir, err := ResolveNucleiDir("nonexistent-abc123")
	if err != nil {
		t.Fatal(err)
	}

	// Walk extracted templates and verify at least some are non-empty YAML.
	found := 0
	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("failed to read extracted file %s: %v", path, readErr)
			return nil
		}
		if len(data) == 0 {
			t.Errorf("extracted file %s is empty", path)
		}
		// Basic YAML sanity: must contain "id:" (nuclei template mandatory field).
		if !strings.Contains(string(data), "id:") {
			t.Errorf("extracted file %s missing 'id:' field", path)
		}
		found++
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if found == 0 {
		t.Error("no YAML files found in extracted nuclei templates")
	}
}

// TestResolveNucleiDir_EmptyString rejects empty input.
func TestResolveNucleiDir_EmptyString(t *testing.T) {
	t.Parallel()

	_, err := ResolveNucleiDir("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty, got: %v", err)
	}
}

func TestResolveNucleiDir_ExistingDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	result, err := ResolveNucleiDir(tmp)
	if err != nil {
		t.Fatalf("ResolveNucleiDir: %v", err)
	}
	if result != tmp {
		t.Errorf("got %q, want %q", result, tmp)
	}
}

// TestResolveNucleiDir_ExistingDirWithFiles verifies existing dir is returned untouched.
func TestResolveNucleiDir_ExistingDirWithFiles(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	// Put a custom file in the dir.
	custom := filepath.Join(tmp, "custom.yaml")
	if err := os.WriteFile(custom, []byte("id: custom"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ResolveNucleiDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if result != tmp {
		t.Errorf("expected original dir, got %q", result)
	}

	// Verify custom file still there (not overwritten).
	data, _ := os.ReadFile(custom)
	if string(data) != "id: custom" {
		t.Error("existing dir content was modified")
	}
}

// =============================================================================
// ListCategory
// =============================================================================

func TestListCategory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind     Kind
		minCount int
	}{
		{KindPolicy, 5},
		{KindOverride, 3},
		{KindReportConfig, 5},
		{KindOutputFormat, 6},
		{KindWorkflow, 5},
		{KindNuclei, 11},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			t.Parallel()

			infos, err := ListCategory(tt.kind)
			if err != nil {
				t.Fatalf("ListCategory(%s): %v", tt.kind, err)
			}
			if len(infos) < tt.minCount {
				t.Errorf("got %d templates, want at least %d", len(infos), tt.minCount)
			}

			for _, info := range infos {
				if info.Name == "" {
					t.Error("template info has empty name")
				}
				if info.Path == "" {
					t.Error("template info has empty path")
				}
				if info.Kind != tt.kind {
					t.Errorf("template kind = %s, want %s", info.Kind, tt.kind)
				}
			}
		})
	}
}

// TestListCategory_NamesMatchResolve verifies every listed template can be resolved.
func TestListCategory_NamesMatchResolve(t *testing.T) {
	t.Parallel()

	// Test non-nuclei categories (nuclei has nested dirs with different naming).
	kinds := []Kind{KindPolicy, KindOverride, KindReportConfig, KindOutputFormat, KindWorkflow}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			infos, err := ListCategory(kind)
			if err != nil {
				t.Fatal(err)
			}

			for _, info := range infos {
				result, resolveErr := Resolve(info.Name, kind)
				if resolveErr != nil {
					t.Errorf("listed template %q (kind=%s) cannot be resolved: %v",
						info.Name, kind, resolveErr)
					continue
				}
				result.Content.Close()
			}
		})
	}
}

// TestListCategory_NucleiMatchResolveEmbeddedPath verifies every listed nuclei
// template can be resolved via ResolveEmbeddedPath using its Path field.
func TestListCategory_NucleiMatchResolveEmbeddedPath(t *testing.T) {
	t.Parallel()

	infos, err := ListCategory(KindNuclei)
	if err != nil {
		t.Fatal(err)
	}

	for _, info := range infos {
		t.Run(info.Path, func(t *testing.T) {
			t.Parallel()

			result, resolveErr := ResolveEmbeddedPath(info.Path)
			if resolveErr != nil {
				t.Fatalf("listed nuclei template %q cannot be resolved: %v", info.Path, resolveErr)
			}
			defer result.Content.Close()

			data, readErr := io.ReadAll(result.Content)
			if readErr != nil {
				t.Fatalf("reading nuclei template %q: %v", info.Path, readErr)
			}
			if len(data) == 0 {
				t.Errorf("nuclei template %q has empty content", info.Path)
			}
		})
	}
}

// TestListCategory_InvalidKind verifies error for unknown kind.
func TestListCategory_InvalidKind(t *testing.T) {
	t.Parallel()

	_, err := ListCategory(Kind("nonexistent-category"))
	if err == nil {
		t.Error("expected error for invalid kind")
	}
	if !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("error should mention unknown kind, got: %v", err)
	}
}

// TestListCategory_NoDuplicateNames verifies no duplicate template names per category.
func TestListCategory_NoDuplicateNames(t *testing.T) {
	t.Parallel()

	kinds := []Kind{KindPolicy, KindOverride, KindReportConfig, KindOutputFormat, KindWorkflow}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			infos, err := ListCategory(kind)
			if err != nil {
				t.Fatal(err)
			}

			seen := make(map[string]bool)
			for _, info := range infos {
				if seen[info.Name] {
					t.Errorf("duplicate template name %q in %s", info.Name, kind)
				}
				seen[info.Name] = true
			}
		})
	}
}

// TestListCategory_NoDuplicatePaths_Nuclei verifies no duplicate Paths in nuclei templates.
// Name collisions are allowed (different subdirectories, same base name) but Path must be unique.
func TestListCategory_NoDuplicatePaths_Nuclei(t *testing.T) {
	t.Parallel()

	infos, err := ListCategory(KindNuclei)
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]bool)
	for _, info := range infos {
		if seen[info.Path] {
			t.Errorf("duplicate template path %q in nuclei", info.Path)
		}
		seen[info.Path] = true
	}
}

// =============================================================================
// ListAllCategories
// =============================================================================

func TestListAllCategories(t *testing.T) {
	t.Parallel()

	categories := ListAllCategories()
	// Derive expected count from extensions map — the single source of truth
	// for valid Kinds. Catches a new Kind added to extensions but missing from
	// the hardcoded slice inside ListAllCategories.
	if len(categories) != len(extensions) {
		t.Errorf("got %d categories, want %d (one per Kind in extensions map)", len(categories), len(extensions))
	}

	for _, cat := range categories {
		if cat.Count == 0 {
			t.Errorf("category %s has 0 templates", cat.Kind)
		}
	}
}

// TestListAllCategories_TotalCount verifies the aggregate template count is reasonable.
func TestListAllCategories_TotalCount(t *testing.T) {
	t.Parallel()

	categories := ListAllCategories()
	total := 0
	for _, cat := range categories {
		total += cat.Count
	}
	// We ship 41+ templates. Allow growth but catch catastrophic drops.
	if total < 35 {
		t.Errorf("total template count %d is suspiciously low (expected 35+)", total)
	}
}

// TestListAllCategories_KindCoverage verifies all expected kinds are present.
func TestListAllCategories_KindCoverage(t *testing.T) {
	t.Parallel()

	categories := ListAllCategories()

	// Build expected set from the extensions map — the single source of truth.
	// If a new Kind is added to extensions, this test automatically requires
	// ListAllCategories to include it.
	expected := make(map[Kind]bool, len(extensions))
	for kind := range extensions {
		expected[kind] = false
	}

	for _, cat := range categories {
		expected[cat.Kind] = true
	}

	for kind, found := range expected {
		if !found {
			t.Errorf("missing expected category: %s", kind)
		}
	}
}

// =============================================================================
// ResolveEmbeddedPath
// =============================================================================

func TestResolveEmbeddedPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
	}{
		{"policy by path", "policies/strict.yaml"},
		{"nuclei subdirectory", "nuclei/http/waf-bypass/sqli-basic.yaml"},
		{"without yaml extension", "policies/strict"},
		{"without tmpl extension", "output/csv"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := ResolveEmbeddedPath(tt.path)
			if err != nil {
				t.Fatalf("ResolveEmbeddedPath(%q): %v", tt.path, err)
			}
			defer result.Content.Close()

			if !strings.HasPrefix(result.Source, "embedded:") {
				t.Errorf("source = %q, want embedded: prefix", result.Source)
			}

			data, _ := io.ReadAll(result.Content)
			if len(data) == 0 {
				t.Error("expected non-empty content")
			}
		})
	}
}

func TestResolveEmbeddedPath_NotFound(t *testing.T) {
	t.Parallel()

	_, err := ResolveEmbeddedPath("nuclei/nonexistent/template")
	if err == nil {
		t.Fatal("expected error for nonexistent embedded path")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found, got: %v", err)
	}
}

func TestResolveEmbeddedPath_Empty(t *testing.T) {
	t.Parallel()

	_, err := ResolveEmbeddedPath("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestResolveEmbeddedPath_Traversal(t *testing.T) {
	t.Parallel()

	tests := []string{
		"../etc/passwd",
		"..\\etc\\passwd",
	}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			_, err := ResolveEmbeddedPath(path)
			if err == nil {
				t.Fatal("expected error for path traversal")
			}
			if !strings.Contains(err.Error(), "traversal") {
				t.Errorf("error should mention traversal, got: %v", err)
			}
		})
	}
}

// TestResolveEmbeddedPath_BackslashNormalization verifies Windows-style paths are normalized.
func TestResolveEmbeddedPath_BackslashNormalization(t *testing.T) {
	t.Parallel()

	result, err := ResolveEmbeddedPath("policies\\strict.yaml")
	if err != nil {
		t.Fatalf("ResolveEmbeddedPath with backslashes failed: %v", err)
	}
	defer result.Content.Close()

	if !strings.HasPrefix(result.Source, "embedded:") {
		t.Errorf("source = %q, want embedded: prefix", result.Source)
	}

	data, _ := io.ReadAll(result.Content)
	if len(data) == 0 {
		t.Error("expected non-empty content")
	}
}

// TestResolveEmbeddedPath_DirectoryRejected verifies that directory paths are
// not returned as resolved templates.
func TestResolveEmbeddedPath_DirectoryRejected(t *testing.T) {
	t.Parallel()

	dirs := []string{"nuclei", "nuclei/http", "policies", "output"}
	for _, dir := range dirs {
		t.Run(dir, func(t *testing.T) {
			t.Parallel()
			_, err := ResolveEmbeddedPath(dir)
			if err == nil {
				t.Errorf("ResolveEmbeddedPath(%q) should reject directory path", dir)
			}
			if !strings.Contains(err.Error(), "not found") {
				t.Errorf("error should mention not found, got: %v", err)
			}
		})
	}
}

// =============================================================================
// Kind validation
// =============================================================================

func TestResolve_InvalidKind(t *testing.T) {
	t.Parallel()

	_, err := Resolve("strict", Kind("bogus"))
	if err == nil {
		t.Fatal("expected error for invalid kind")
	}
	if !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("error should mention unknown kind, got: %v", err)
	}
}

func TestResolveToPath_InvalidKind(t *testing.T) {
	t.Parallel()

	_, _, err := ResolveToPath("strict", Kind("bogus"))
	if err == nil {
		t.Fatal("expected error for invalid kind")
	}
	if !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("error should mention unknown kind, got: %v", err)
	}
}

// =============================================================================
// parseTemplateInfo
// =============================================================================

func TestParseTemplateInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		kind     Kind
		wantName string
	}{
		{"policies/strict.yaml", KindPolicy, "strict"},
		{"overrides/api-only.yaml", KindOverride, "api-only"},
		{"output/csv.tmpl", KindOutputFormat, "csv"},
		{"nuclei/http/waf-bypass/sqli-basic.yaml", KindNuclei, "sqli-basic"},
		{"report-configs/enterprise.yaml", KindReportConfig, "enterprise"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()

			info := parseTemplateInfo(tt.path, tt.kind)
			if info.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", info.Name, tt.wantName)
			}
			if info.Path != tt.path {
				t.Errorf("Path = %q, want %q", info.Path, tt.path)
			}
			if info.Kind != tt.kind {
				t.Errorf("Kind = %s, want %s", info.Kind, tt.kind)
			}
		})
	}
}

// =============================================================================
// Cross-cutting: resolution chain consistency
// =============================================================================

// TestResolutionChain_EmbeddedMatchesList verifies that every non-nuclei
// template returned by ListCategory can be resolved by Resolve and ResolveToPath.
func TestResolutionChain_EmbeddedMatchesList(t *testing.T) {
	t.Parallel()

	kinds := []Kind{KindPolicy, KindOverride, KindReportConfig, KindOutputFormat, KindWorkflow}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			infos, err := ListCategory(kind)
			if err != nil {
				t.Fatal(err)
			}

			for _, info := range infos {
				// Resolve: should return content.
				result, resolveErr := Resolve(info.Name, kind)
				if resolveErr != nil {
					t.Errorf("Resolve(%q, %s) failed: %v", info.Name, kind, resolveErr)
					continue
				}
				data, _ := io.ReadAll(result.Content)
				result.Content.Close()
				if len(data) == 0 {
					t.Errorf("Resolve(%q, %s) returned empty content", info.Name, kind)
				}

				// ResolveToPath: should return a readable file path.
				path, cleanup, pathErr := ResolveToPath(info.Name, kind)
				if pathErr != nil {
					t.Errorf("ResolveToPath(%q, %s) failed: %v", info.Name, kind, pathErr)
					continue
				}
				fileData, readErr := os.ReadFile(path)
				cleanup()
				if readErr != nil {
					t.Errorf("cannot read resolved path for %q: %v", info.Name, readErr)
				}
				if len(fileData) == 0 {
					t.Errorf("ResolveToPath(%q, %s) produced empty file", info.Name, kind)
				}
			}
		})
	}
}

// =============================================================================
// Path traversal rejection
// =============================================================================

func TestResolve_PathTraversal(t *testing.T) {
	t.Parallel()

	traversals := []string{
		"../../etc/passwd",
		"../../../etc/shadow",
		"..\\..\\windows\\system32\\config\\sam",
		"../policies/strict",
		"..\\policies\\strict",
		"valid/../../../etc/passwd",
	}
	for _, val := range traversals {
		t.Run(val, func(t *testing.T) {
			t.Parallel()
			_, err := Resolve(val, KindPolicy)
			if err == nil {
				t.Errorf("Resolve(%q) should reject path traversal", val)
			}
			if !strings.Contains(err.Error(), "traversal") {
				t.Errorf("error should mention traversal, got: %v", err)
			}
		})
	}
}

func TestResolveToPath_PathTraversal(t *testing.T) {
	t.Parallel()

	traversals := []string{
		"../../etc/passwd",
		"..\\..\\windows\\system32",
		"../secrets",
	}
	for _, val := range traversals {
		t.Run(val, func(t *testing.T) {
			t.Parallel()
			_, _, err := ResolveToPath(val, KindPolicy)
			if err == nil {
				t.Errorf("ResolveToPath(%q) should reject path traversal", val)
			}
			if !strings.Contains(err.Error(), "traversal") {
				t.Errorf("error should mention traversal, got: %v", err)
			}
		})
	}
}

func TestResolveNucleiDir_PathTraversal(t *testing.T) {
	t.Parallel()

	_, err := ResolveNucleiDir("../../etc")
	if err == nil {
		t.Fatal("expected path traversal rejection")
	}
	if !strings.Contains(err.Error(), "traversal") {
		t.Errorf("error should mention traversal, got: %v", err)
	}
}

func TestContainsTraversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  bool
	}{
		{"strict", false},
		{"strict.yaml", false},
		{"policies/strict.yaml", false},
		{"./templates/nuclei", false},
		{".hidden", false},
		{"..", true},
		{"../etc/passwd", true},
		{"foo/../bar", true},
		{"foo\\..\\bar", true},
		{"../../etc/shadow", true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Parallel()
			if got := containsTraversal(tt.value); got != tt.want {
				t.Errorf("containsTraversal(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// =============================================================================
// ResolveNucleiDir — concurrency
// =============================================================================

func TestResolveNucleiDir_Concurrent(t *testing.T) {
	ResetNucleiCache()
	t.Cleanup(func() { ResetNucleiCache() })

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	dirs := make([]string, goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			dirs[idx], errs[idx] = ResolveNucleiDir("nonexistent-concurrent-test")
		}(i)
	}
	wg.Wait()

	// All goroutines must succeed.
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d failed: %v", i, err)
		}
	}

	// All goroutines must return the exact same path (sync.Once guarantee).
	for i := 1; i < goroutines; i++ {
		if dirs[i] != dirs[0] {
			t.Errorf("goroutine %d returned %q, want %q", i, dirs[i], dirs[0])
		}
	}

	// Verify the single extracted dir exists and has content.
	entries, err := os.ReadDir(dirs[0])
	if err != nil {
		t.Fatalf("reading extracted dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected extracted nuclei templates, got empty directory")
	}
}

// =============================================================================
// Invariant tests — proactive regression guards
// =============================================================================
//
// These tests encode structural invariants discovered during adversarial audits
// (Rounds 9-23). Each test targets a specific class of bug and will break
// immediately if that class is reintroduced.

// TestTemplateCount_MatchesShortNameTestTable verifies the exact embedded
// template count per non-nuclei Kind. When templates are added or removed,
// this test fails — signaling that TestResolve_ShortName_Embedded must also
// be updated. Catches registry drift (Round 9 class).
func TestTemplateCount_MatchesShortNameTestTable(t *testing.T) {
	t.Parallel()

	expectedPerKind := map[Kind]int{
		KindPolicy:       5,
		KindOverride:     3,
		KindReportConfig: 5,
		KindOutputFormat: 6,
		KindWorkflow:     5,
	}

	for kind, expected := range expectedPerKind {
		infos, err := ListCategory(kind)
		if err != nil {
			t.Fatalf("ListCategory(%s): %v", kind, err)
		}
		if len(infos) != expected {
			t.Errorf("ListCategory(%s) = %d templates, want %d; update TestResolve_ShortName_Embedded too",
				kind, len(infos), expected)
		}
	}
}

// TestInternalMaps_CoverAllKinds verifies extensions and diskDirs maps contain
// entries for every Kind constant, and that no stale entries exist.
// Catches "new Kind added but internal map not updated" (Round 9 class).
func TestInternalMaps_CoverAllKinds(t *testing.T) {
	t.Parallel()

	allKinds := []Kind{KindPolicy, KindOverride, KindReportConfig, KindOutputFormat, KindWorkflow, KindNuclei}

	for _, kind := range allKinds {
		if _, ok := extensions[kind]; !ok {
			t.Errorf("extensions map missing entry for %s", kind)
		}
		if _, ok := diskDirs[kind]; !ok {
			t.Errorf("diskDirs map missing entry for %s", kind)
		}
	}

	// Verify no stale entries exist in either map.
	kindSet := make(map[Kind]bool, len(allKinds))
	for _, k := range allKinds {
		kindSet[k] = true
	}
	for kind := range extensions {
		if !kindSet[kind] {
			t.Errorf("stale entry in extensions for %q", kind)
		}
	}
	for kind := range diskDirs {
		if !kindSet[kind] {
			t.Errorf("stale entry in diskDirs for %q", kind)
		}
	}
}

// TestResolveEmbeddedPath_AllEmbeddedDirectoriesRejected walks the entire
// embedded FS and verifies every directory path is rejected by ResolveEmbeddedPath.
// Catches the embed.FS.Open directory bug (Round 19 class).
func TestResolveEmbeddedPath_AllEmbeddedDirectoriesRejected(t *testing.T) {
	t.Parallel()

	var dirs []string
	err := fs.WalkDir(templates.FS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() && path != "." {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) == 0 {
		t.Fatal("expected directories in embedded FS")
	}

	for _, dir := range dirs {
		t.Run(dir, func(t *testing.T) {
			t.Parallel()
			_, resolveErr := ResolveEmbeddedPath(dir)
			if resolveErr == nil {
				t.Errorf("ResolveEmbeddedPath(%q) should reject directory path", dir)
			}
		})
	}
}

// TestResolveEmbeddedPath_BackslashNormalization_AllTemplates verifies that
// backslash-separated paths resolve correctly for EVERY embedded template.
// Catches cross-platform normalization gaps (Rounds 9/10/11 class).
func TestResolveEmbeddedPath_BackslashNormalization_AllTemplates(t *testing.T) {
	t.Parallel()

	allKinds := []Kind{KindPolicy, KindOverride, KindReportConfig, KindOutputFormat, KindWorkflow, KindNuclei}

	for _, kind := range allKinds {
		infos, err := ListCategory(kind)
		if err != nil {
			t.Fatalf("ListCategory(%s): %v", kind, err)
		}
		for _, info := range infos {
			backslashPath := strings.ReplaceAll(info.Path, "/", "\\")
			if backslashPath == info.Path {
				continue // No forward slashes to convert.
			}

			t.Run(backslashPath, func(t *testing.T) {
				t.Parallel()

				result, resolveErr := ResolveEmbeddedPath(backslashPath)
				if resolveErr != nil {
					t.Fatalf("backslash path %q failed: %v", backslashPath, resolveErr)
				}
				defer result.Content.Close()

				data, _ := io.ReadAll(result.Content)
				if len(data) == 0 {
					t.Errorf("backslash path %q returned empty content", backslashPath)
				}
			})
		}
	}
}

// TestAllErrors_PackagePrefix verifies every error from public API functions
// starts with "templateresolver:". Catches error message inconsistency and
// ensures user-facing errors are always identifiable (Round 22 class).
func TestAllErrors_PackagePrefix(t *testing.T) {
	t.Parallel()

	const prefix = "templateresolver:"

	errCases := []struct {
		name string
		fn   func() error
	}{
		{"Resolve_empty", func() error { _, err := Resolve("", KindPolicy); return err }},
		{"Resolve_unknown_kind", func() error { _, err := Resolve("x", Kind("bogus")); return err }},
		{"Resolve_not_found", func() error { _, err := Resolve("nonexistent-xyz", KindPolicy); return err }},
		{"Resolve_traversal", func() error { _, err := Resolve("../etc/passwd", KindPolicy); return err }},
		{"ResolveToPath_empty", func() error { _, _, err := ResolveToPath("", KindPolicy); return err }},
		{"ResolveToPath_unknown_kind", func() error { _, _, err := ResolveToPath("x", Kind("bogus")); return err }},
		{"ResolveToPath_traversal", func() error { _, _, err := ResolveToPath("../x", KindPolicy); return err }},
		{"ResolveNucleiDir_empty", func() error { _, err := ResolveNucleiDir(""); return err }},
		{"ResolveNucleiDir_traversal", func() error { _, err := ResolveNucleiDir("../../x"); return err }},
		{"ResolveEmbeddedPath_empty", func() error { _, err := ResolveEmbeddedPath(""); return err }},
		{"ResolveEmbeddedPath_traversal", func() error { _, err := ResolveEmbeddedPath("../x"); return err }},
		{"Resolve_disk_not_found", func() error {
			_, err := Resolve("/nonexistent/path/to/file.yaml", KindPolicy)
			return err
		}},
		{"ResolveToPath_disk_not_found", func() error {
			_, _, err := ResolveToPath("/nonexistent/path/to/file.yaml", KindPolicy)
			return err
		}},
		{"ResolveEmbeddedPath_not_found", func() error {
			_, err := ResolveEmbeddedPath("nuclei/nonexistent-xyz")
			return err
		}},
		{"ListCategory_unknown_kind", func() error { _, err := ListCategory(Kind("bogus")); return err }},
	}

	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.fn()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.HasPrefix(err.Error(), prefix) {
				t.Errorf("error %q does not start with %q", err.Error(), prefix)
			}
		})
	}
}

// TestResolutionChain_FullPriority verifies the complete three-step resolution
// priority in a single test: disk defaults > env var > embedded. Tests all
// three sources simultaneously to verify correct shadowing (Round 14 class).
func TestResolutionChain_FullPriority(t *testing.T) {
	// No t.Parallel — modifies package-level state and env.

	// Step 1: Baseline — embedded works.
	result, err := Resolve("strict", KindPolicy)
	if err != nil {
		t.Fatal(err)
	}
	baseData, _ := io.ReadAll(result.Content)
	result.Content.Close()
	if len(baseData) == 0 {
		t.Fatal("embedded baseline is empty")
	}

	// Step 2: Set env var — should shadow embedded.
	envDir := t.TempDir()
	if mkErr := os.MkdirAll(filepath.Join(envDir, "policies"), 0o755); mkErr != nil {
		t.Fatal(mkErr)
	}
	envContent := "name: from-env-var-priority-test"
	if wErr := os.WriteFile(filepath.Join(envDir, "policies", "strict.yaml"), []byte(envContent), 0o644); wErr != nil {
		t.Fatal(wErr)
	}
	t.Setenv(envKey, envDir)

	result, err = Resolve("strict", KindPolicy)
	if err != nil {
		t.Fatal(err)
	}
	envData, _ := io.ReadAll(result.Content)
	result.Content.Close()
	if !strings.Contains(string(envData), "from-env-var-priority-test") {
		t.Errorf("env var should shadow embedded; got %q", string(envData))
	}

	// Step 3: Set disk defaults — should shadow both env and embedded.
	diskDir := t.TempDir()
	diskContent := "name: from-disk-defaults-priority-test"
	if wErr := os.WriteFile(filepath.Join(diskDir, "strict.yaml"), []byte(diskContent), 0o644); wErr != nil {
		t.Fatal(wErr)
	}
	origDir := diskDirs[KindPolicy]
	diskDirs[KindPolicy] = diskDir
	t.Cleanup(func() { diskDirs[KindPolicy] = origDir })

	result, err = Resolve("strict", KindPolicy)
	if err != nil {
		t.Fatal(err)
	}
	diskData, _ := io.ReadAll(result.Content)
	result.Content.Close()
	if !strings.Contains(string(diskData), "from-disk-defaults-priority-test") {
		t.Errorf("disk defaults should shadow env var; got %q", string(diskData))
	}
}
