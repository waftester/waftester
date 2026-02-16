package main

import (
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/templateresolver"
)

// =============================================================================
// parseKind — singular/plural/alias resolution
// =============================================================================

func TestParseKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		want    templateresolver.Kind
		wantErr bool
	}{
		// Exact matches
		{"nuclei", templateresolver.KindNuclei, false},
		{"policies", templateresolver.KindPolicy, false},
		{"overrides", templateresolver.KindOverride, false},
		{"workflows", templateresolver.KindWorkflow, false},
		{"output", templateresolver.KindOutputFormat, false},
		{"report-configs", templateresolver.KindReportConfig, false},

		// Singular forms
		{"policy", templateresolver.KindPolicy, false},
		{"override", templateresolver.KindOverride, false},
		{"workflow", templateresolver.KindWorkflow, false},
		{"report-config", templateresolver.KindReportConfig, false},

		// Aliases
		{"output-format", templateresolver.KindOutputFormat, false},
		{"output-formats", templateresolver.KindOutputFormat, false},
		{"report", templateresolver.KindReportConfig, false},
		{"template", templateresolver.KindNuclei, false},
		{"templates", templateresolver.KindNuclei, false},

		// Case insensitivity
		{"NUCLEI", templateresolver.KindNuclei, false},
		{"Policy", templateresolver.KindPolicy, false},
		{"Override", templateresolver.KindOverride, false},
		{"WORKFLOWS", templateresolver.KindWorkflow, false},
		{"Report-Configs", templateresolver.KindReportConfig, false},

		// Invalid
		{"invalid", templateresolver.Kind(""), true},
		{"", templateresolver.Kind(""), true},
		{"scan", templateresolver.Kind(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			got, err := parseKind(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseKind(%q): expected error, got %s", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseKind(%q): unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parseKind(%q) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

// =============================================================================
// categoryDescriptions — coverage check
// =============================================================================

// TestCategoryDescriptions_AllKindsCovered verifies every Kind constant has a description
// and that the map contains no stale entries for non-existent Kinds.
func TestCategoryDescriptions_AllKindsCovered(t *testing.T) {
	t.Parallel()

	expected := []templateresolver.Kind{
		templateresolver.KindNuclei,
		templateresolver.KindWorkflow,
		templateresolver.KindPolicy,
		templateresolver.KindOverride,
		templateresolver.KindOutputFormat,
		templateresolver.KindReportConfig,
	}

	expectedSet := make(map[templateresolver.Kind]bool, len(expected))
	for _, kind := range expected {
		expectedSet[kind] = true

		desc, ok := categoryDescriptions[kind]
		if !ok {
			t.Errorf("missing description for category %s", kind)
			continue
		}
		if desc == "" {
			t.Errorf("empty description for category %s", kind)
		}
	}

	// Verify no stale entries exist in the map.
	for kind := range categoryDescriptions {
		if !expectedSet[kind] {
			t.Errorf("stale entry in categoryDescriptions for unknown kind %q", kind)
		}
	}
}

// =============================================================================
// parseKind — invariant tests (Round 9 regression guards)
// =============================================================================

// TestParseKind_CanonicalFormsAccepted verifies that parseKind accepts
// the canonical string form of every Kind constant (e.g. "policies" for KindPolicy).
// This is the most fundamental contract — a Kind's own string must be accepted.
func TestParseKind_CanonicalFormsAccepted(t *testing.T) {
	t.Parallel()

	canonicalKinds := []templateresolver.Kind{
		templateresolver.KindPolicy,       // "policies"
		templateresolver.KindOverride,     // "overrides"
		templateresolver.KindReportConfig, // "report-configs"
		templateresolver.KindOutputFormat, // "output"
		templateresolver.KindWorkflow,     // "workflows"
		templateresolver.KindNuclei,       // "nuclei"
	}

	for _, kind := range canonicalKinds {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			got, err := parseKind(string(kind))
			if err != nil {
				t.Fatalf("parseKind(%q) should accept canonical Kind form: %v", string(kind), err)
			}
			if got != kind {
				t.Errorf("parseKind(%q) = %s, want %s", string(kind), got, kind)
			}
		})
	}
}

// TestParseKind_AllKindsHaveMultipleAliases verifies every Kind constant has
// at least 2 accepted inputs (singular + plural/canonical). Catches the
// Round 9 bug where a Kind only had one recognized alias.
func TestParseKind_AllKindsHaveMultipleAliases(t *testing.T) {
	t.Parallel()

	allKinds := []templateresolver.Kind{
		templateresolver.KindPolicy,
		templateresolver.KindOverride,
		templateresolver.KindReportConfig,
		templateresolver.KindOutputFormat,
		templateresolver.KindWorkflow,
		templateresolver.KindNuclei,
	}

	// Probe all known aliases to build a map of kind → accepted aliases.
	candidates := []string{
		"nuclei", "template", "templates",
		"workflow", "workflows",
		"policy", "policies",
		"override", "overrides",
		"output", "output-format", "output-formats",
		"report-config", "report-configs", "report",
	}

	kindAliases := make(map[templateresolver.Kind][]string)
	for _, c := range candidates {
		kind, err := parseKind(c)
		if err != nil {
			continue
		}
		kindAliases[kind] = append(kindAliases[kind], c)
	}

	for _, kind := range allKinds {
		aliases := kindAliases[kind]
		if len(aliases) < 2 {
			t.Errorf("Kind %s has only %d alias(es) %v, want at least 2", kind, len(aliases), aliases)
		}
	}
}

// TestParseKind_ErrorMessageListsAllAcceptedInputs verifies the error message
// from parseKind includes every valid alias string. Catches the original
// Round 9 bug where valid aliases were accepted but not listed in the error hint.
func TestParseKind_ErrorMessageListsAllAcceptedInputs(t *testing.T) {
	t.Parallel()

	_, err := parseKind("invalid-category-xyz")
	if err == nil {
		t.Fatal("expected error for invalid category")
	}

	// All aliases that parseKind accepts must appear in the error message.
	acceptedAliases := []string{
		"nuclei", "template", "templates",
		"workflow", "workflows",
		"policy", "policies",
		"override", "overrides",
		"output", "output-format", "output-formats",
		"report-config", "report-configs", "report",
	}

	// Parse the comma-separated list from the error message for exact matching.
	errMsg := err.Error()
	const marker = "Valid categories: "
	idx := strings.Index(errMsg, marker)
	if idx < 0 {
		t.Fatalf("error message missing %q marker: %s", marker, errMsg)
	}

	listedPart := errMsg[idx+len(marker):]
	listedAliases := strings.Split(listedPart, ", ")
	listedSet := make(map[string]bool, len(listedAliases))
	for _, a := range listedAliases {
		listedSet[strings.TrimSpace(a)] = true
	}

	for _, alias := range acceptedAliases {
		if !listedSet[alias] {
			t.Errorf("error message missing accepted alias %q; listed: %v", alias, listedAliases)
		}
	}
}
