package test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// baseFieldNames are the field names canonically defined in attackconfig.Base.
var baseFieldNames = map[string]bool{
	"Timeout":     true,
	"UserAgent":   true,
	"Client":      true,
	"MaxPayloads": true,
	"MaxParams":   true,
	"Concurrency": true,
}

// attackConfigAllowlist contains package names that legitimately
// define their own Config without embedding attackconfig.Base.
// Infrastructure packages, not attack packages.
var attackConfigAllowlist = map[string]bool{
	"attackconfig": true, // the canonical definition itself
	"cli":          true, // top-level CLI config
	"config":       true, // configuration management
	"output":       true, // output formatter config
	"httpclient":   true, // HTTP client factory
	"tls":          true, // JA3 TLS config
	"mcpserver":    true, // MCP server config
	"health":       true, // health check config
	"overrides":    true, // override config
	"override":     true, // override config
	"filter":       true, // filter config
	"wordlist":     true, // wordlist config
	"paranoia":     true, // paranoia level config
	"intelligence": true, // intelligence config
	"crawler":      true, // crawler config
	"headless":     true, // headless browser config
	"runner":       true, // runner config
	"placeholder":  true, // placeholder config
	"ratelimit":    true, // rate limiter config
	"workflow":     true, // workflow config
	"ui":           true, // UI config
	"cloud":        true, // cloud config
	"distributed":  true, // distributed config
	"benchmark":    true, // benchmark config
	"cicd":         true, // CI/CD config
	"discovery":    true, // discovery config
	"openapi":      true, // OpenAPI config
	"learning":     true, // learning config
	"exploit":      true, // exploit config (special structure)
	"falsepositive": true, // false positive config (special structure)
}

// TestNoRedundantBaseFields walks pkg/ and ensures no Config/TesterConfig
// struct outside the allowlist declares 3+ fields that belong in
// attackconfig.Base without actually embedding it.
//
// This prevents regression — new attack packages should embed Base
// rather than re-declaring Timeout, Client, Concurrency, etc.
func TestNoRedundantBaseFields(t *testing.T) {
	t.Parallel()

	repoRoot := getRepoRoot(t)
	pkgDir := filepath.Join(repoRoot, "pkg")

	var violations []string

	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !isGoSource(path) || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil
		}

		pkgName := f.Name.Name
		if attackConfigAllowlist[pkgName] {
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
				name := ts.Name.Name
				if name != "Config" && name != "TesterConfig" &&
					name != "ScanConfig" && name != "ScannerConfig" {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					continue
				}

				var overlap int
				hasBase := false
				for _, field := range st.Fields.List {
					// Check for embedded attackconfig.Base
					if len(field.Names) == 0 {
						if sel, ok := field.Type.(*ast.SelectorExpr); ok {
							if sel.Sel.Name == "Base" {
								hasBase = true
							}
						}
					}
					for _, ident := range field.Names {
						if baseFieldNames[ident.Name] {
							overlap++
						}
					}
				}

				if !hasBase && overlap >= 3 {
					violations = append(violations, rel+": "+name+
						" has "+string(rune('0'+overlap))+" base fields without embedding attackconfig.Base")
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("found Config structs that should embed attackconfig.Base:\n")
		for _, v := range violations {
			t.Errorf("  - %s", v)
		}
	}
}
