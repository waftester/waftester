package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// TestOutputHygieneContracts enforces CLI output contracts via AST analysis:
//
//   - Errors must go through ui.PrintError, not fmt.Println(ui.ErrorStyle.Render(...))
//   - Warnings/errors to stderr must use ui.PrintWarning/PrintError, not raw fmt.Fprintf(os.Stderr, "[!]...")
//   - Emoji in terminal output must be wrapped in ui.SanitizeString (or use ui.Printf/Icon)
//
// These rules prevent:
//   - stderr/stdout interleaving (errors on stdout mix with banner on stderr)
//   - Inconsistent error formatting (raw prefixes vs styled ui output)
//   - Garbled emoji on Windows terminals without Unicode support
func TestOutputHygieneContracts(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(findRepoRoot(t), "cmd", "cli")

	fset := token.NewFileSet()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		// cmd_mcp.go intentionally uses raw stderr (machine protocol, no UI chrome)
		if name == "cmd_mcp.go" {
			continue
		}

		path := filepath.Join(dir, name)
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checkNoErrorStyleRender(t, fset, f, name)
			checkNoRawStderrPrefixes(t, fset, f, name)
			checkNoRawEmoji(t, fset, f, name)
		})
	}
}

// checkNoErrorStyleRender detects fmt.Println(ui.ErrorStyle.Render(...)) calls.
// These send styled error messages to stdout instead of stderr.
// Fix: use ui.PrintError("message") which writes to stderr with consistent formatting.
func checkNoErrorStyleRender(t *testing.T, fset *token.FileSet, f *ast.File, fileName string) {
	t.Helper()

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Match fmt.Println or fmt.Printf
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "fmt" {
			return true
		}
		if sel.Sel.Name != "Println" && sel.Sel.Name != "Printf" {
			return true
		}

		// Check if any argument is ui.ErrorStyle.Render(...)
		for _, arg := range call.Args {
			if containsErrorStyleRender(arg) {
				pos := fset.Position(call.Pos())
				t.Errorf(
					"OUTPUT HYGIENE: %s:%d — fmt.%s(ui.ErrorStyle.Render(...)) sends error to stdout\n"+
						"  Fix: use ui.PrintError(message) which writes to stderr with consistent formatting",
					fileName, pos.Line, sel.Sel.Name,
				)
			}
		}

		return true
	})
}

// containsErrorStyleRender checks if an expression is ui.ErrorStyle.Render(...)
// or ui.FailStyle.Render(...).
func containsErrorStyleRender(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}

	// Match X.Render where X is ui.ErrorStyle or ui.FailStyle
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Render" {
		return false
	}

	// Check for ui.ErrorStyle or ui.FailStyle
	innerSel, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	innerIdent, ok := innerSel.X.(*ast.Ident)
	if !ok || innerIdent.Name != "ui" {
		return false
	}

	return innerSel.Sel.Name == "ErrorStyle" || innerSel.Sel.Name == "FailStyle"
}

// checkNoRawStderrPrefixes detects fmt.Fprintf(os.Stderr, "[!]...")
// and fmt.Fprintf(os.Stderr, "[ERR]...") and fmt.Fprintf(os.Stderr, "[ERROR]...").
// These bypass ui.PrintWarning/PrintError which provide consistent styling.
func checkNoRawStderrPrefixes(t *testing.T, fset *token.FileSet, f *ast.File, fileName string) {
	t.Helper()

	// Prefixes that indicate a warning or error being written raw to stderr.
	// Normal informational output (e.g. "[*] Starting...") is acceptable.
	badPrefixes := []string{"[!]", "[ERR]", "[ERROR]", "[err]", "[error]"}

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Match fmt.Fprintf
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "fmt" || sel.Sel.Name != "Fprintf" {
			return true
		}

		// First arg must be os.Stderr
		if len(call.Args) < 2 {
			return true
		}
		if !isOsStderr(call.Args[0]) {
			return true
		}

		// Second arg (format string) must be a string literal containing a bad prefix
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}

		for _, prefix := range badPrefixes {
			if strings.Contains(lit.Value, prefix) {
				pos := fset.Position(call.Pos())
				t.Errorf(
					"OUTPUT HYGIENE: %s:%d — fmt.Fprintf(os.Stderr, %q...) uses raw error prefix\n"+
						"  Fix: use ui.PrintWarning() or ui.PrintError() for consistent styling",
					fileName, pos.Line, prefix,
				)
				break
			}
		}

		return true
	})
}

// isOsStderr returns true if expr is os.Stderr.
func isOsStderr(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "os" && sel.Sel.Name == "Stderr"
}

// checkNoRawEmoji detects fmt.Println("...emoji...") and fmt.Printf("...emoji...")
// where the string literal contains emoji characters not wrapped in ui.SanitizeString().
// These render as garbled text on Windows terminals without Unicode support.
//
// Allowlist: string literals inside file-writing contexts (os.WriteFile, io.WriteString)
// don't need sanitization because they target files, not terminals.
func checkNoRawEmoji(t *testing.T, fset *token.FileSet, f *ast.File, fileName string) {
	t.Helper()

	// Report files skip emoji checks — they write markdown to files, not terminals
	if strings.Contains(fileName, "_reports") || strings.Contains(fileName, "_report") {
		return
	}

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Match fmt.Println, fmt.Printf, fmt.Sprintf used as direct terminal output
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		// Only check fmt.Println, fmt.Printf, fmt.Fprint, fmt.Fprintln — these go to terminal.
		// fmt.Fprintf is checked separately; fmt.Sprintf is intermediate.
		if ident.Name != "fmt" || (sel.Sel.Name != "Println" && sel.Sel.Name != "Printf" &&
			sel.Sel.Name != "Fprint" && sel.Sel.Name != "Fprintln") {
			return true
		}

		// Check each argument for string literals with emoji
		for _, arg := range call.Args {
			checkExprForRawEmoji(t, fset, arg, fileName, sel.Sel.Name)
		}

		return true
	})
}

// checkExprForRawEmoji checks if an expression is a string literal containing emoji.
// It skips expressions wrapped in ui.SanitizeString() or ui.Icon().
func checkExprForRawEmoji(t *testing.T, fset *token.FileSet, expr ast.Expr, fileName, funcName string) {
	t.Helper()

	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return
		}
		if containsEmoji(e.Value) {
			pos := fset.Position(e.Pos())
			t.Errorf(
				"OUTPUT HYGIENE: %s:%d — fmt.%s() contains raw emoji in string literal\n"+
					"  Fix: wrap in ui.SanitizeString() or use ui.Icon(emoji, fallback)",
				fileName, pos.Line, funcName,
			)
		}

	case *ast.CallExpr:
		// If the argument is ui.SanitizeString(...) or ui.Icon(...), it's safe
		if isSafeUICall(e) {
			return
		}
		// Check nested string literals (e.g. fmt.Sprintf("emoji %s", ...))
		for _, arg := range e.Args {
			checkExprForRawEmoji(t, fset, arg, fileName, funcName)
		}
	}
}

// isSafeUICall returns true if the call is to a ui function that sanitizes emoji:
// ui.SanitizeString, ui.Sanitizef, ui.Icon, ui.Printf, ui.Fprintf,
// or any ui.Print*/Render function that sanitizes internally.
func isSafeUICall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}

	if ident.Name == "ui" {
		// All ui.Print*, ui.Sanitize*, ui.Icon, and Render calls are safe
		name := sel.Sel.Name
		return strings.HasPrefix(name, "Print") ||
			strings.HasPrefix(name, "Sanitize") ||
			name == "Icon" ||
			name == "Render"
	}

	return false
}

// containsEmoji returns true if a Go string literal contains emoji characters.
// Checks for characters in the Supplementary Multilingual Plane (U+1F000+)
// and common symbol blocks used as emoji (U+2600-U+27FF, U+2B50, etc.).
func containsEmoji(s string) bool {
	// Unquote the string literal — remove surrounding quotes
	// For raw strings `...` and regular strings "..."
	inner := s
	if len(inner) >= 2 {
		if inner[0] == '"' || inner[0] == '`' {
			inner = inner[1 : len(inner)-1]
		}
	}

	for i := 0; i < len(inner); {
		r, size := utf8.DecodeRuneInString(inner[i:])
		if isEmoji(r) {
			return true
		}
		i += size
	}
	return false
}

// isEmoji returns true for Unicode code points commonly rendered as emoji.
// Covers the main emoji blocks without flagging safe characters like arrows or math symbols.
func isEmoji(r rune) bool {
	// Miscellaneous Symbols (subset: commonly emoji)
	if r >= 0x2600 && r <= 0x26FF {
		return true
	}
	// Dingbats (subset: commonly emoji)
	if r >= 0x2700 && r <= 0x27BF {
		return true
	}
	// Supplemental Symbols and Pictographs, Emoticons, etc.
	if r >= 0x1F000 && r <= 0x1FFFF {
		return true
	}
	// Transport and map symbols, enclosed characters
	if r >= 0x1F680 && r <= 0x1F6FF {
		return true
	}
	// Regional indicator symbols (flags)
	if r >= 0x1F1E0 && r <= 0x1F1FF {
		return true
	}
	// Variation selectors (emoji style) — these accompany emoji
	if r >= 0xFE00 && r <= 0xFE0F {
		return true
	}
	// Zero-width joiner (used in compound emoji)
	if r == 0x200D {
		return true
	}
	// Common standalone emoji symbols
	if r == 0x2B50 || r == 0x2B55 || r == 0x2934 || r == 0x2935 {
		return true
	}
	// Check if it's in a supplementary plane (non-BMP) and not a letter/number
	// This catches emoji that sneak through the above ranges
	if r > 0xFFFF && !unicode.IsLetter(r) && !unicode.IsNumber(r) {
		return true
	}
	return false
}
