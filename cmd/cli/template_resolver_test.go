package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// ResolveTemplatePaths — short name resolution for output flags
// =============================================================================

// TestResolveTemplatePaths_PolicyShortName verifies --policy "strict" resolves
// to a readable file path.
func TestResolveTemplatePaths_PolicyShortName(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{PolicyFile: "strict"}
	cleanup := o.ResolveTemplatePaths()
	defer cleanup()

	if o.PolicyFile == "strict" {
		t.Error("PolicyFile was not resolved — still the short name")
	}
	if _, err := os.Stat(o.PolicyFile); err != nil {
		t.Errorf("resolved PolicyFile path does not exist: %v", err)
	}
}

// TestResolveTemplatePaths_OverridesShortName verifies --overrides "api-only"
// resolves to a readable file.
func TestResolveTemplatePaths_OverridesShortName(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{OverridesFile: "api-only"}
	cleanup := o.ResolveTemplatePaths()
	defer cleanup()

	if o.OverridesFile == "api-only" {
		t.Error("OverridesFile was not resolved — still the short name")
	}
	if _, err := os.Stat(o.OverridesFile); err != nil {
		t.Errorf("resolved OverridesFile path does not exist: %v", err)
	}
}

// TestResolveTemplatePaths_TemplateConfigShortName verifies --template-config "dark"
// resolves to a readable file.
func TestResolveTemplatePaths_TemplateConfigShortName(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{TemplateConfigPath: "dark"}
	cleanup := o.ResolveTemplatePaths()
	defer cleanup()

	if o.TemplateConfigPath == "dark" {
		t.Error("TemplateConfigPath was not resolved — still the short name")
	}
	if _, err := os.Stat(o.TemplateConfigPath); err != nil {
		t.Errorf("resolved TemplateConfigPath path does not exist: %v", err)
	}
}

// TestResolveTemplatePaths_AllThreeAtOnce verifies all three flags resolve simultaneously.
func TestResolveTemplatePaths_AllThreeAtOnce(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{
		PolicyFile:         "strict",
		OverridesFile:      "api-only",
		TemplateConfigPath: "enterprise",
	}
	cleanup := o.ResolveTemplatePaths()
	defer cleanup()

	if o.PolicyFile == "strict" {
		t.Error("PolicyFile not resolved")
	}
	if o.OverridesFile == "api-only" {
		t.Error("OverridesFile not resolved")
	}
	if o.TemplateConfigPath == "enterprise" {
		t.Error("TemplateConfigPath not resolved")
	}

	// All resolved paths should actually exist.
	for _, path := range []string{o.PolicyFile, o.OverridesFile, o.TemplateConfigPath} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("resolved path %q does not exist: %v", path, err)
		}
	}
}

// TestResolveTemplatePaths_EmptyFieldsNoOp verifies empty fields are left alone.
func TestResolveTemplatePaths_EmptyFieldsNoOp(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{}
	cleanup := o.ResolveTemplatePaths()
	defer cleanup()

	if o.PolicyFile != "" {
		t.Error("empty PolicyFile should stay empty")
	}
	if o.OverridesFile != "" {
		t.Error("empty OverridesFile should stay empty")
	}
	if o.TemplateConfigPath != "" {
		t.Error("empty TemplateConfigPath should stay empty")
	}
}

// TestResolveTemplatePaths_ExplicitPath verifies explicit file paths pass through.
func TestResolveTemplatePaths_ExplicitPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	policyFile := filepath.Join(tmp, "custom-policy.yaml")
	if err := os.WriteFile(policyFile, []byte("name: custom"), 0o644); err != nil {
		t.Fatal(err)
	}

	o := &OutputFlags{PolicyFile: policyFile}
	cleanup := o.ResolveTemplatePaths()
	defer cleanup()

	if o.PolicyFile != policyFile {
		t.Errorf("expected original path %q, got %q", policyFile, o.PolicyFile)
	}
}

// TestResolveTemplatePaths_InvalidShortNameKeepsOriginal verifies that
// an unresolvable short name is preserved for downstream error handling.
func TestResolveTemplatePaths_InvalidShortNameKeepsOriginal(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{PolicyFile: "nonexistent-policy-xyz"}
	cleanup := o.ResolveTemplatePaths()
	defer cleanup()

	if o.PolicyFile != "nonexistent-policy-xyz" {
		t.Errorf("unresolvable short name should be preserved, got %q", o.PolicyFile)
	}
}

// TestResolveTemplatePaths_CleanupFunction verifies the cleanup function is safe
// to call multiple times and on empty flags.
func TestResolveTemplatePaths_CleanupFunction(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{PolicyFile: "strict"}
	cleanup := o.ResolveTemplatePaths()

	// Calling cleanup multiple times should not panic.
	cleanup()
	cleanup()
}

// =============================================================================
// Template path flag registration
// =============================================================================

// TestOutputFlags_TemplateFlagsRegistered verifies --policy, --overrides, and
// --template-config are registered via RegisterFlags.
func TestOutputFlags_TemplateFlagsRegistered(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o.RegisterFlags(fs)

	want := []string{"policy", "overrides", "template-config"}
	for _, name := range want {
		f := fs.Lookup(name)
		if f == nil {
			t.Errorf("missing flag: --%s", name)
		}
	}
}

// TestOutputFlags_PolicyFlagHelpText verifies the --policy flag has useful help text.
func TestOutputFlags_PolicyFlagHelpText(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o.RegisterFlags(fs)

	f := fs.Lookup("policy")
	if f == nil {
		t.Fatal("missing --policy flag")
	}
	if f.Usage == "" {
		t.Error("--policy flag has no usage text")
	}
}

// =============================================================================
// LoadPolicy — with resolver integration
// =============================================================================

// TestLoadPolicy_EmptyReturnsNil verifies no-op when PolicyFile is empty.
func TestLoadPolicy_EmptyReturnsNil(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{}
	p, err := o.LoadPolicy()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Error("expected nil policy for empty PolicyFile")
	}
}

// TestLoadPolicy_ExplicitPath verifies loading a policy from a real file path
// with the schema that the policy loader actually expects.
func TestLoadPolicy_ExplicitPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	policyFile := filepath.Join(tmp, "test-policy.yaml")
	// Use the actual policy schema (numeric thresholds, not category lists).
	content := `name: test-policy
severity_threshold: high
fail_on:
  bypasses:
    total: 5
    critical: 1
`
	if err := os.WriteFile(policyFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	o := &OutputFlags{PolicyFile: policyFile}
	p, err := o.LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy with explicit path: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil policy")
	}
}

// TestLoadPolicy_InvalidPath verifies error for nonexistent file.
func TestLoadPolicy_InvalidPath(t *testing.T) {
	t.Parallel()

	o := &OutputFlags{PolicyFile: "/nonexistent/path/policy.yaml"}
	_, err := o.LoadPolicy()
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

// =============================================================================
// Cross-cutting: short names in all bundled template types
// =============================================================================

// TestAllBundledOverrides_Resolvable verifies all shipped overrides are usable.
func TestAllBundledOverrides_Resolvable(t *testing.T) {
	t.Parallel()

	names := []string{"api-only", "crs-tuning", "false-positive-suppression"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			o := &OutputFlags{OverridesFile: name}
			cleanup := o.ResolveTemplatePaths()
			defer cleanup()

			if o.OverridesFile == name {
				t.Errorf("override %q was not resolved", name)
			}
			if _, err := os.Stat(o.OverridesFile); err != nil {
				t.Errorf("resolved override %q path doesn't exist: %v", name, err)
			}
		})
	}
}

// TestAllBundledReportConfigs_Resolvable verifies all shipped report configs are usable.
func TestAllBundledReportConfigs_Resolvable(t *testing.T) {
	t.Parallel()

	names := []string{"dark", "enterprise", "minimal", "compliance", "print"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			o := &OutputFlags{TemplateConfigPath: name}
			cleanup := o.ResolveTemplatePaths()
			defer cleanup()

			if o.TemplateConfigPath == name {
				t.Errorf("report-config %q was not resolved", name)
			}
			if _, err := os.Stat(o.TemplateConfigPath); err != nil {
				t.Errorf("resolved report-config %q path doesn't exist: %v", name, err)
			}
		})
	}
}

// TestResolvedContent_PolicyHasRequiredFields verifies resolved policy content
// has the fields the policy loader expects.
func TestResolvedContent_PolicyHasRequiredFields(t *testing.T) {
	t.Parallel()

	policies := []string{"strict", "permissive", "standard", "owasp-top10", "pci-dss"}
	requiredFields := []string{"name:", "fail_on:"}

	for _, name := range policies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			o := &OutputFlags{PolicyFile: name}
			cleanup := o.ResolveTemplatePaths()
			defer cleanup()

			data, err := os.ReadFile(o.PolicyFile)
			if err != nil {
				t.Fatal(err)
			}

			for _, field := range requiredFields {
				if !strings.Contains(string(data), field) {
					t.Errorf("policy %q missing required field %q", name, field)
				}
			}
		})
	}
}
