package defaults_test

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
