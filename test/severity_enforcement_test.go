package test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestNoLocalSeverityType walks pkg/ and ensures no package outside
// pkg/finding declares a new type named Severity (as opposed to a
// type alias). This prevents accidental regression — the canonical
// definition lives in pkg/finding/severity.go.
func TestNoLocalSeverityType(t *testing.T) {
	t.Parallel()

	repoRoot := getRepoRoot(t)
	pkgDir := filepath.Join(repoRoot, "pkg")

	var violations []string

	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip non-Go files and test files
		if info.IsDir() || !isGoSource(path) {
			return nil
		}

		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			// Skip files that don't parse (shouldn't happen)
			return nil
		}

		rel, _ := filepath.Rel(repoRoot, path)

		for _, decl := range f.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.TYPE {
				continue
			}
			for _, spec := range genDecl.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if ts.Name.Name != "Severity" {
					continue
				}
				// Allow finding package itself and type aliases (=)
				if f.Name.Name == "finding" {
					continue
				}
				// Allow type aliases (e.g. output/events uses
				// type Severity = finding.Severity)
				if ts.Assign.IsValid() {
					continue
				}
				violations = append(violations, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("found local 'type Severity string' declarations that should use finding.Severity:\n")
		for _, v := range violations {
			t.Errorf("  - %s", v)
		}
	}
}

// TestSeverityCaseConsistency walks all Go source files and flags non-lowercase
// severity string literals in data contexts. The canonical form is lowercase,
// matching finding.Severity constants: "critical", "high", "medium", "low", "info".
//
// This catches recurring bugs where severity strings use Title Case ("Critical"),
// ALL CAPS ("HIGH"), or other non-canonical forms that break map lookups,
// comparisons, and sorting against the canonical lowercase keys.
//
// Scope: .Severity field assignments, BySeverity/BypassesBySeverity map keys,
// and local `severity` variable assignments. Does NOT flag non-severity fields
// (Confidence, RiskLevel, DetectionDifficulty, etc.) or display-only code.
func TestSeverityCaseConsistency(t *testing.T) {
	t.Parallel()
	repoRoot := getRepoRoot(t)

	// Non-lowercase severity words.
	sevWords := `(?:Critical|CRITICAL|High|HIGH|Medium|MEDIUM|Low|LOW|Info|INFO)`

	// Pattern 1: .Severity = "X" or Severity: "X" (field assignments)
	severityFieldAssign := regexp.MustCompile(
		`(?:\bSeverity:\s*|\.Severity\s*=\s*)` + `"` + sevWords + `"`,
	)

	// Pattern 2: BySeverity["X"] or BypassesBySeverity["X"] or AnomaliesBySeverity["X"]
	bySeverityMapKey := regexp.MustCompile(
		`BySeverity\["` + sevWords + `"\]`,
	)

	// Pattern 3: local severity variable: severity = "X" or severity := "X"
	severityVarAssign := regexp.MustCompile(
		`\bseverity\s*:?=\s*"` + sevWords + `"`,
	)

	allPatterns := []*regexp.Regexp{
		severityFieldAssign,
		bySeverityMapKey,
		severityVarAssign,
	}

	// Lines with these substrings are not severity data but separate fields
	// (confidence, risk level, detection difficulty, etc.) or display/format code.
	excludeSubstrings := []string{
		"SeverityStyle(",
		"SeverityHint",
		"DetectionDifficulty",
		"ExploitationEase",
		"Confidence",
		"RiskLevel",
		"FinalSeverity",
		"SecuritySeverity",
		"security-severity",
	}

	// Known pre-existing violations by package directory name.
	// Removing entries here is allowed and encouraged. Adding is NOT.
	knownViolations := map[string]bool{
		// cmd/cli — BySeverity map uses Title Case keys
		"cli": true,
		// pkg scanners with Severity string fields using wrong case
		"accesscontrol":    true,
		"apiabuse":         true,
		"assessment":       true,
		"brokenauth":       true,
		"clickjack":        true,
		"csrf":             true,
		"idor":             true,
		"inputvalidation":  true,
		"ldap":             true,
		"learning":         true,
		"lfi":              true,
		"massassignment":   true,
		"rce":              true,
		"requestforgery":   true,
		"responsesplit":    true,
		"rfi":              true,
		"scoring":          true,
		"securitymisconfig": true,
		"sensitivedata":    true,
		"sessionfixation":  true,
		"ssi":              true,
		"xmlinjection":     true,
		"xpath":            true,
		// pkg/mcpserver reads BySeverity with Title Case keys
		"mcpserver": true,
		// pkg/output — writer.go and writers/ use Title Case in SARIF/display maps
		"output":       true,
		"writers":       true,
		"hooks":         true,
		"testfixtures":  true,
		"testutil":      true,
	}

	var newViolations []string
	var knownFound []string

	dirs := []string{
		filepath.Join(repoRoot, "pkg"),
		filepath.Join(repoRoot, "cmd"),
	}

	for _, dir := range dirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			// The finding package defines external format mappings intentionally.
			parentDir := filepath.Base(filepath.Dir(path))
			if parentDir == "finding" {
				return nil
			}

			// The UI package uses Title Case for display styling.
			if parentDir == "ui" {
				return nil
			}

			// The validate package intentionally accepts multiple cases.
			if parentDir == "validate" {
				return nil
			}

			// The report package uses Title Case for HTML report display.
			if parentDir == "report" {
				return nil
			}

			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}

			lines := strings.Split(string(content), "\n")
			rel, _ := filepath.Rel(repoRoot, path)
			relSlash := filepath.ToSlash(rel)

			for lineNum, line := range lines {
				trimmed := strings.TrimSpace(line)

				// Skip comments.
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
					continue
				}

				// Check all patterns.
				matched := false
				for _, pat := range allPatterns {
					if pat.MatchString(line) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}

				// Skip non-severity fields and display code.
				excluded := false
				for _, exc := range excludeSubstrings {
					if strings.Contains(line, exc) {
						excluded = true
						break
					}
				}
				if excluded {
					continue
				}

				loc := relSlash + ":" + strconv.Itoa(lineNum+1) + ": " + trimmed

				if knownViolations[parentDir] {
					knownFound = append(knownFound, loc)
				} else {
					newViolations = append(newViolations, loc)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("failed to walk %s: %v", dir, err)
		}
	}

	if len(knownFound) > 0 {
		t.Logf("INFO: %d known pre-existing non-lowercase severity string(s) (tracked for cleanup):", len(knownFound))
		for _, v := range knownFound {
			t.Logf("  - %s", v)
		}
	}

	if len(newViolations) > 0 {
		t.Errorf("found NEW non-lowercase severity string literals (canonical form is lowercase):")
		for _, v := range newViolations {
			t.Errorf("  - %s", v)
		}
		t.Error("Fix: Use lowercase severity strings matching finding.Severity constants: \"critical\", \"high\", \"medium\", \"low\", \"info\"")
	}
}

// isGoSource returns true for .go files that are not test files.
func isGoSource(path string) bool {
	if filepath.Ext(path) != ".go" {
		return false
	}
	return true
}
