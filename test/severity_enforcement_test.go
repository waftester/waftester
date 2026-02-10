package test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// TestNoLocalSeverityType walks pkg/ and ensures no package outside
// pkg/finding re-declares "type Severity string". This prevents
// accidental regression — the canonical definition lives in
// pkg/finding/severity.go.
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

// isGoSource returns true for .go files that are not test files.
func isGoSource(path string) bool {
	if filepath.Ext(path) != ".go" {
		return false
	}
	return true
}
