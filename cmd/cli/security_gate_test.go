package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Contract types
// ---------------------------------------------------------------------------

// presenceContract: any function calling Trigger MUST also call Gate
// (directly or via a local helper).
type presenceContract struct {
	Trigger     string // e.g. "apispec.ParseContext"
	Gate        string // e.g. "apispec.CheckServerURLs"
	Description string
}

// orderingContract: when both Before and After appear in the same function,
// After MUST appear at a higher source offset than Before.
// This catches "check then mutate" bugs where validation runs before the
// data it validates is fully resolved.
type orderingContract struct {
	Before      string // must come first (e.g. "apispec.ResolveVariables")
	After       string // must come second (e.g. "apispec.CheckServerURLs")
	Description string
}

// contextContract: functions that have a context.Context parameter must use
// the Context variant of a call, not the non-Context variant.
type contextContract struct {
	Forbidden   string // e.g. "apispec.Parse"
	Preferred   string // e.g. "apispec.ParseContext"
	Description string
}

// forbiddenCallContract: a call that must never appear in non-test files
// under a given path. Used for library hygiene (no os.Exit in pkg/).
type forbiddenCallContract struct {
	Call        string // e.g. "os.Exit"
	Description string
	// AllowFuncs lists function names where the call is acceptable
	// (e.g. signal handlers, TestMain).
	AllowFuncs []string
}

// forbiddenRefContract: an identifier reference (not a call) that must never
// appear in non-test files. Used for things like os.Stderr which is passed
// as an argument, not called directly.
type forbiddenRefContract struct {
	Ref         string // e.g. "os.Stderr"
	Description string
	AllowFuncs  []string
}

// ---------------------------------------------------------------------------
// Contract definitions
// ---------------------------------------------------------------------------

// scanScope groups all contracts to enforce in a directory.
type scanScope struct {
	RelPath      string
	Presence     []presenceContract
	Ordering     []orderingContract
	Context      []contextContract
	Forbidden    []forbiddenCallContract
	ForbiddenRef []forbiddenRefContract
}

// allScopes is the single source of truth for every security contract.
// To add a contract: add an entry to the appropriate slice.
var allScopes = []scanScope{
	{
		RelPath: filepath.Join("cmd", "cli"),
		Presence: []presenceContract{
			{
				Trigger:     "apispec.Parse",
				Gate:        "apispec.CheckServerURLs",
				Description: "spec server URLs must be validated against SSRF blocklist after parsing",
			},
			{
				Trigger:     "apispec.ParseContext",
				Gate:        "apispec.CheckServerURLs",
				Description: "spec server URLs must be validated against SSRF blocklist after parsing",
			},
			{
				Trigger:     "apispec.ParseContent",
				Gate:        "apispec.CheckServerURLs",
				Description: "inline spec server URLs must be validated against SSRF blocklist",
			},
			{
				Trigger:     "apispec.ParseContentContext",
				Gate:        "apispec.CheckServerURLs",
				Description: "inline spec server URLs must be validated against SSRF blocklist",
			},
			{
				Trigger:     "apispec.CheckServerURLs",
				Gate:        "apispec.ResolveVariables",
				Description: "variable defaults must be resolved before SSRF check — unresolved {{var}} patterns bypass blocklist",
			},
		},
		Ordering: []orderingContract{
			{
				Before:      "apispec.ResolveVariables",
				After:       "apispec.CheckServerURLs",
				Description: "SSRF check must run AFTER variable resolution — variables can inject internal URLs",
			},
		},
		Context: []contextContract{
			{
				Forbidden:   "apispec.Parse",
				Preferred:   "apispec.ParseContext",
				Description: "use ParseContext to propagate cancellation and timeouts from the caller's context",
			},
			{
				Forbidden:   "apispec.ParseContent",
				Preferred:   "apispec.ParseContentContext",
				Description: "use ParseContentContext to propagate cancellation and timeouts",
			},
		},
	},
	{
		RelPath: filepath.Join("pkg", "mcpserver"),
		Presence: []presenceContract{
			{
				Trigger:     "apispec.Parse",
				Gate:        "apispec.CheckServerURLs",
				Description: "MCP tool must validate spec server URLs against SSRF blocklist",
			},
			{
				Trigger:     "apispec.ParseContext",
				Gate:        "apispec.CheckServerURLs",
				Description: "MCP tool must validate spec server URLs against SSRF blocklist",
			},
			{
				Trigger:     "apispec.ParseContent",
				Gate:        "apispec.CheckServerURLs",
				Description: "MCP tool must validate spec server URLs against SSRF blocklist",
			},
			{
				Trigger:     "apispec.ParseContentContext",
				Gate:        "apispec.CheckServerURLs",
				Description: "MCP tool must validate spec server URLs against SSRF blocklist",
			},
			{
				Trigger:     "apispec.CheckServerURLs",
				Gate:        "apispec.ResolveVariables",
				Description: "variable defaults must be resolved before SSRF check — unresolved {{var}} patterns bypass blocklist",
			},
		},
		Ordering: []orderingContract{
			{
				Before:      "apispec.ResolveVariables",
				After:       "apispec.CheckServerURLs",
				Description: "SSRF check must run AFTER variable resolution — spec defaults can inject internal URLs",
			},
		},
		Context: []contextContract{
			{
				Forbidden:   "apispec.Parse",
				Preferred:   "apispec.ParseContext",
				Description: "use ParseContext to propagate cancellation from MCP request context",
			},
			{
				Forbidden:   "apispec.ParseContent",
				Preferred:   "apispec.ParseContentContext",
				Description: "use ParseContentContext to propagate cancellation from MCP request context",
			},
		},
		Forbidden: []forbiddenCallContract{
			{Call: "os.Exit", Description: "MCP server must not call os.Exit — return an error"},
			{Call: "log.Fatal", Description: "log.Fatal calls os.Exit(1) — return an error instead"},
			{Call: "log.Fatalf", Description: "log.Fatalf calls os.Exit(1) — return an error instead"},
			{Call: "fmt.Print", Description: "stdout is the MCP JSON-RPC transport in stdio mode — use structured responses"},
			{Call: "fmt.Printf", Description: "stdout is the MCP JSON-RPC transport in stdio mode — use structured responses"},
			{Call: "fmt.Println", Description: "stdout is the MCP JSON-RPC transport in stdio mode — use structured responses"},
		},
		ForbiddenRef: []forbiddenRefContract{
			{Ref: "os.Stderr", Description: "library code must not write to stderr — return errors via MCP protocol"},
			{Ref: "os.Stdout", Description: "stdout is the MCP JSON-RPC transport in stdio mode — writing corrupts the protocol"},
		},
	},
	{
		RelPath: filepath.Join("pkg", "apispec"),
		Forbidden: []forbiddenCallContract{
			{Call: "os.Exit", Description: "library code must not call os.Exit — return an error to the caller"},
			{Call: "log.Fatal", Description: "log.Fatal calls os.Exit(1) — return an error instead"},
			{Call: "log.Fatalf", Description: "log.Fatalf calls os.Exit(1) — return an error instead"},
		},
		ForbiddenRef: []forbiddenRefContract{
			{Ref: "os.Stderr", Description: "library code must not write to stderr — return errors to caller (breaks MCP transport)"},
		},
	},
	{
		RelPath: filepath.Join("pkg", "input"),
		Forbidden: []forbiddenCallContract{
			{Call: "os.Exit", Description: "library code must not call os.Exit — return an error"},
			{Call: "log.Fatal", Description: "log.Fatal calls os.Exit(1) — return an error instead"},
			{Call: "log.Fatalf", Description: "log.Fatalf calls os.Exit(1) — return an error instead"},
		},
		ForbiddenRef: []forbiddenRefContract{
			{Ref: "os.Stderr", Description: "library code must not write to stderr — return warnings to caller"},
		},
	},
	{
		RelPath: filepath.Join("pkg", "config"),
		Forbidden: []forbiddenCallContract{
			{Call: "os.Exit", Description: "library code must not call os.Exit — return an error"},
			{Call: "log.Fatal", Description: "log.Fatal calls os.Exit(1) — return an error instead"},
			{Call: "log.Fatalf", Description: "log.Fatalf calls os.Exit(1) — return an error instead"},
		},
	},
	{
		RelPath: filepath.Join("pkg", "core"),
		Forbidden: []forbiddenCallContract{
			{Call: "os.Exit", Description: "library code must not call os.Exit — return an error"},
			{Call: "log.Fatal", Description: "log.Fatal calls os.Exit(1) — return an error instead"},
			{Call: "log.Fatalf", Description: "log.Fatalf calls os.Exit(1) — return an error instead"},
		},
	},
	{
		RelPath: filepath.Join("pkg", "runner"),
		Forbidden: []forbiddenCallContract{
			{Call: "os.Exit", Description: "library code must not call os.Exit — return an error"},
			{Call: "log.Fatal", Description: "log.Fatal calls os.Exit(1) — return an error instead"},
			{Call: "log.Fatalf", Description: "log.Fatalf calls os.Exit(1) — return an error instead"},
		},
	},
	{
		RelPath: filepath.Join("pkg", "regexcache"),
		Forbidden: []forbiddenCallContract{
			{Call: "os.Exit", Description: "library code must not call os.Exit — return an error"},
			{Call: "log.Fatal", Description: "log.Fatal calls os.Exit(1) — return an error instead"},
			{Call: "log.Fatalf", Description: "log.Fatalf calls os.Exit(1) — return an error instead"},
			{Call: "panic", Description: "library code must not panic — return an error", AllowFuncs: []string{"MustGet"}},
		},
	},
}

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

// TestSecurityGateContract enforces security contracts via AST analysis:
//
//   - Presence:  "if you call A, you must also call B"
//   - Ordering:  "B must appear after A in source order"
//   - Context:   "use the Context variant when context.Context is in scope"
//   - Forbidden: "never call X in this package"
//
// Transitive gate propagation: if function F calls helper H, and H contains
// the gate, F satisfies the contract. This avoids false positives when
// security checks live in shared helpers (e.g. resolveSpecInput).
func TestSecurityGateContract(t *testing.T) {
	t.Parallel()

	repoRoot := findRepoRoot(t)

	for _, scope := range allScopes {
		dir := filepath.Join(repoRoot, scope.RelPath)

		// Capture for parallel closure.
		scope := scope

		t.Run(scope.RelPath, func(t *testing.T) {
			t.Parallel()

			fset, files := parseGoFiles(t, dir)

			if len(scope.Presence) > 0 {
				checkPresenceContracts(t, fset, files, scope.Presence, scope.RelPath)
			}
			if len(scope.Ordering) > 0 {
				checkOrderingContracts(t, fset, files, scope.Ordering, scope.RelPath)
			}
			if len(scope.Context) > 0 {
				checkContextContracts(t, fset, files, scope.Context, scope.RelPath)
			}
			if len(scope.Forbidden) > 0 {
				checkForbiddenContracts(t, fset, files, scope.Forbidden, scope.RelPath)
			}
			if len(scope.ForbiddenRef) > 0 {
				checkForbiddenRefContracts(t, fset, files, scope.ForbiddenRef, scope.RelPath)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Presence contracts: trigger → gate
// ---------------------------------------------------------------------------

func checkPresenceContracts(
	t *testing.T,
	fset *token.FileSet,
	files map[string]*ast.File,
	contracts []presenceContract,
	label string,
) {
	t.Helper()

	funcs, localCalls := buildFuncIndex(fset, files)

	for _, c := range contracts {
		for _, fi := range funcs {
			if !fi.calls[c.Trigger] {
				continue
			}
			if hasGateTransitive(fi.name, c.Gate, localCalls, make(map[string]bool)) {
				continue
			}
			t.Errorf(
				"PRESENCE CONTRACT VIOLATION in %s:\n"+
					"  Function:  %s (at %s:%d)\n"+
					"  Calls:     %s\n"+
					"  Missing:   %s\n"+
					"  Reason:    %s",
				label, fi.name, fi.fileName, fi.line,
				c.Trigger, c.Gate, c.Description,
			)
		}
	}
}

// ---------------------------------------------------------------------------
// Ordering contracts: Before must precede After
// ---------------------------------------------------------------------------

func checkOrderingContracts(
	t *testing.T,
	fset *token.FileSet,
	files map[string]*ast.File,
	contracts []orderingContract,
	label string,
) {
	t.Helper()

	for fileName, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			positions := collectCallPositions(fn.Body, fset)

			for _, c := range contracts {
				beforePos, hasBefore := positions[c.Before]
				afterPos, hasAfter := positions[c.After]

				// Only enforce ordering when BOTH calls exist in the same function.
				if !hasBefore || !hasAfter {
					continue
				}

				if afterPos < beforePos {
					pos := fset.Position(fn.Pos())
					t.Errorf(
						"ORDERING CONTRACT VIOLATION in %s:\n"+
							"  Function:  %s (at %s:%d)\n"+
							"  %s appears at line %d\n"+
							"  %s appears at line %d\n"+
							"  Required:  %s must come AFTER %s\n"+
							"  Reason:    %s",
						label, fn.Name.Name, fileName, pos.Line,
						c.After, afterPos,
						c.Before, beforePos,
						c.After, c.Before,
						c.Description,
					)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Context contracts: forbid non-Context variant when ctx is available
// ---------------------------------------------------------------------------

func checkContextContracts(
	t *testing.T,
	fset *token.FileSet,
	files map[string]*ast.File,
	contracts []contextContract,
	label string,
) {
	t.Helper()

	for fileName, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			if !hasContextAvailable(fn) {
				continue
			}

			calls := collectSelectorCalls(fn.Body)

			for _, c := range contracts {
				if calls[c.Forbidden] {
					pos := fset.Position(fn.Pos())
					t.Errorf(
						"CONTEXT CONTRACT VIOLATION in %s:\n"+
							"  Function:  %s (at %s:%d)\n"+
							"  Calls:     %s (non-Context variant)\n"+
							"  Should be: %s\n"+
							"  Reason:    %s",
						label, fn.Name.Name, fileName, pos.Line,
						c.Forbidden, c.Preferred, c.Description,
					)
				}
			}
		}
	}
}

// hasContextAvailable returns true if the function either:
//   - has a context.Context parameter, OR
//   - creates a context locally (ctx, cancel := ... pattern)
//
// The local detection looks for short variable declarations where one of the
// LHS names is "ctx" — the universal Go convention.
func hasContextAvailable(fn *ast.FuncDecl) bool {
	// Check parameters.
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			if sel, ok := field.Type.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Context" {
					if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "context" {
						return true
					}
				}
			}
		}
	}

	// Check for local context creation: `ctx, cancel := ...` or `ctx := ...`.
	if fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name == "ctx" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// ---------------------------------------------------------------------------
// Forbidden call contracts: calls banned in a directory
// ---------------------------------------------------------------------------

func checkForbiddenContracts(
	t *testing.T,
	fset *token.FileSet,
	files map[string]*ast.File,
	contracts []forbiddenCallContract,
	label string,
) {
	t.Helper()

	for fileName, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			calls := collectSelectorCalls(fn.Body)

			for _, c := range contracts {
				if !calls[c.Call] {
					continue
				}

				// Check allowlist.
				allowed := false
				for _, af := range c.AllowFuncs {
					if fn.Name.Name == af {
						allowed = true
						break
					}
				}
				if allowed {
					continue
				}

				pos := fset.Position(fn.Pos())
				t.Errorf(
					"FORBIDDEN CALL in %s:\n"+
						"  Function:  %s (at %s:%d)\n"+
						"  Calls:     %s\n"+
						"  Reason:    %s",
					label, fn.Name.Name, fileName, pos.Line,
					c.Call, c.Description,
				)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Forbidden ref contracts: identifier references banned in a directory
// ---------------------------------------------------------------------------

func checkForbiddenRefContracts(
	t *testing.T,
	fset *token.FileSet,
	files map[string]*ast.File,
	contracts []forbiddenRefContract,
	label string,
) {
	t.Helper()

	for fileName, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			refs := collectSelectorRefs(fn.Body)

			for _, c := range contracts {
				if !refs[c.Ref] {
					continue
				}

				allowed := false
				for _, af := range c.AllowFuncs {
					if fn.Name.Name == af {
						allowed = true
						break
					}
				}
				if allowed {
					continue
				}

				pos := fset.Position(fn.Pos())
				t.Errorf(
					"FORBIDDEN REFERENCE in %s:\n"+
						"  Function:  %s (at %s:%d)\n"+
						"  Uses:      %s\n"+
						"  Reason:    %s",
					label, fn.Name.Name, fileName, pos.Line,
					c.Ref, c.Description,
				)
			}
		}
	}
}

// collectSelectorRefs walks an AST block and returns all selector expression
// references ("pkg.Name"), whether they appear as call targets, arguments,
// assignments, or anywhere else. Unlike collectSelectorCalls which only
// captures function calls, this captures identifiers like os.Stderr.
func collectSelectorRefs(block *ast.BlockStmt) map[string]bool {
	refs := make(map[string]bool)

	ast.Inspect(block, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		if ident, ok := sel.X.(*ast.Ident); ok {
			refs[ident.Name+"."+sel.Sel.Name] = true
		}

		return true
	})

	return refs
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

type funcInfo struct {
	name     string
	fileName string
	line     int
	calls    map[string]bool
}

// buildFuncIndex builds a list of all functions and a local call graph.
func buildFuncIndex(fset *token.FileSet, files map[string]*ast.File) ([]funcInfo, map[string]map[string]bool) {
	var funcs []funcInfo
	localCalls := make(map[string]map[string]bool)

	for fileName, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			calls := collectSelectorCalls(fn.Body)
			pos := fset.Position(fn.Pos())
			fi := funcInfo{
				name:     fn.Name.Name,
				fileName: fileName,
				line:     pos.Line,
				calls:    calls,
			}
			funcs = append(funcs, fi)
			localCalls[fn.Name.Name] = calls
		}
	}

	return funcs, localCalls
}

// hasGateTransitive checks whether funcName (or any local function it calls,
// transitively) contains a call to gate.
func hasGateTransitive(funcName, gate string, localCalls map[string]map[string]bool, visited map[string]bool) bool {
	if visited[funcName] {
		return false
	}
	visited[funcName] = true

	calls, ok := localCalls[funcName]
	if !ok {
		return false
	}

	if calls[gate] {
		return true
	}

	for call := range calls {
		if !strings.Contains(call, ".") {
			if hasGateTransitive(call, gate, localCalls, visited) {
				return true
			}
		}
	}

	return false
}

// collectSelectorCalls walks an AST block and returns all calls.
// Selector calls: "pkg.Func". Local calls: "funcName".
func collectSelectorCalls(block *ast.BlockStmt) map[string]bool {
	calls := make(map[string]bool)

	ast.Inspect(block, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if ident, ok := fun.X.(*ast.Ident); ok {
				calls[ident.Name+"."+fun.Sel.Name] = true
			}
		case *ast.Ident:
			calls[fun.Name] = true
		}

		return true
	})

	return calls
}

// collectCallPositions returns the first source line of each selector call
// in a function body. Used by ordering contracts.
func collectCallPositions(block *ast.BlockStmt, fset *token.FileSet) map[string]int {
	positions := make(map[string]int)

	ast.Inspect(block, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		key := ident.Name + "." + sel.Sel.Name
		line := fset.Position(call.Pos()).Line

		// Store the FIRST occurrence (lowest line number).
		if existing, found := positions[key]; !found || line < existing {
			positions[key] = line
		}
		return true
	})

	return positions
}

// parseGoFiles parses all non-test .go files in a directory.
func parseGoFiles(t *testing.T, dir string) (*token.FileSet, map[string]*ast.File) {
	t.Helper()

	fset := token.NewFileSet()
	files := make(map[string]*ast.File)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		path := filepath.Join(dir, name)
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		files[name] = f
	}

	return fset, files
}

// findRepoRoot walks up from cwd to find the repo root (dir with go.mod).
func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	t.Fatal("cannot find repository root (no go.mod found)")
	return ""
}
