package duration_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoHardcodedTimeouts ensures Timeout fields use duration.* or httpclient.Timeout* constants
func TestNoHardcodedTimeouts(t *testing.T) {
	violations := findHardcodedDurations(t, "Timeout", []string{
		"duration.go",
		"httpclient.go",
		"_test.go",
	})

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded Timeout values. Use duration.* or httpclient.Timeout* instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

// TestNoHardcodedIntervals ensures Interval/Delay fields use duration.* constants
func TestNoHardcodedIntervals(t *testing.T) {
	violations := findHardcodedDurations(t, "Interval", []string{
		"duration.go",
		"_test.go",
		"spinners.go", // UI animation timing is intentionally specific
	})
	violations = append(violations, findHardcodedDurations(t, "Delay", []string{
		"duration.go",
		"_test.go",
	})...)

	if len(violations) > 0 {
		t.Errorf("Found %d hardcoded Interval/Delay values. Use duration.* instead:", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

// findHardcodedDurations walks the codebase and finds struct field assignments with time.Duration expressions
func findHardcodedDurations(t *testing.T, fieldName string, excludePatterns []string) []string {
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
				return nil
			}

			if info.IsDir() || !strings.HasSuffix(path, ".go") {
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
				// Look for key-value expressions: Timeout: 30 * time.Second
				if kv, ok := n.(*ast.KeyValueExpr); ok {
					if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == fieldName {
						if isHardcodedDuration(kv.Value) {
							pos := fset.Position(kv.Value.Pos())
							relPath, _ := filepath.Rel(root, pos.Filename)
							violations = append(violations,
								relPath+":"+strconv.Itoa(pos.Line)+": "+fieldName+" = <hardcoded duration>")
						}
					}
				}

				// Look for assignment statements: config.Timeout = 30 * time.Second
				if assign, ok := n.(*ast.AssignStmt); ok {
					for i, lhs := range assign.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok {
							if sel.Sel.Name == fieldName && i < len(assign.Rhs) {
								if isHardcodedDuration(assign.Rhs[i]) {
									pos := fset.Position(assign.Rhs[i].Pos())
									relPath, _ := filepath.Rel(root, pos.Filename)
									violations = append(violations,
										relPath+":"+strconv.Itoa(pos.Line)+": "+fieldName+" = <hardcoded duration>")
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

// isHardcodedDuration checks if an expression is a hardcoded duration like "30 * time.Second"
func isHardcodedDuration(expr ast.Expr) bool {
	// Pattern: N * time.Second/Minute/Hour/Millisecond
	if binExpr, ok := expr.(*ast.BinaryExpr); ok {
		// Left side should be a number
		if _, ok := binExpr.X.(*ast.BasicLit); ok {
			// Right side should be time.Second/Minute/etc
			if sel, ok := binExpr.Y.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "time" {
					switch sel.Sel.Name {
					case "Second", "Minute", "Hour", "Millisecond", "Microsecond", "Nanosecond":
						return true
					}
				}
			}
		}
	}
	return false
}

// findProjectRoot finds the project root by looking for go.mod
func findProjectRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

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
