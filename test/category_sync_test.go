package test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// =============================================================================
// CATEGORY SYNCHRONIZATION TESTS
// =============================================================================
//
// These tests detect hardcoded category maps that have drifted from the
// single source of truth in pkg/payloadprovider/mapper.go.
//
// When you add a new category via register() in mapper.go, these tests
// tell you exactly which metadata maps need updating.

// extractMapKeys parses a Go file and returns all string-literal keys from
// the first top-level map[string]... composite literal whose variable name
// matches varName. Returns nil if not found.
func extractMapKeys(t *testing.T, filePath, varName string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filePath, err)
	}

	var keys []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || vs.Names[0].Name != varName {
				continue
			}
			if len(vs.Values) == 0 {
				continue
			}
			cl, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				lit, ok := kv.Key.(*ast.BasicLit)
				if !ok {
					continue
				}
				// Strip quotes from string literal
				key := strings.Trim(lit.Value, "\"")
				keys = append(keys, key)
			}
			return keys
		}
	}
	return keys
}

// extractRegisterCalls parses mapper.go and returns all first-tag arguments
// from m.register("Category", "tag1", ...) calls. These are the primary
// short names that form the canonical category set.
func extractRegisterCalls(t *testing.T, mapperPath string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mapperPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", mapperPath, err)
	}

	var tags []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "register" {
			return true
		}
		// register(canonicalCategory, tag1, tag2, ...)
		// We want tag1 (the primary short name) — it's the second argument
		if len(call.Args) < 2 {
			return true
		}
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok {
			return true
		}
		tags = append(tags, strings.Trim(lit.Value, "\""))
		return true
	})
	return tags
}

// TestCategorySyncMetadataMaps verifies that key metadata maps across the
// codebase cover all categories registered in the CategoryMapper.
//
// This test catches the common drift pattern: a new category is added to
// mapper.go but the developer forgets to add corresponding entries in
// metadata maps used by reports, output writers, and the MCP server.
func TestCategorySyncMetadataMaps(t *testing.T) {
	repoRoot := getRepoRoot(t)
	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")

	// Extract canonical primary tags from register() calls
	primaryTags := extractRegisterCalls(t, mapperPath)
	if len(primaryTags) == 0 {
		t.Fatal("no register() calls found in mapper.go")
	}
	t.Logf("Found %d registered categories in mapper.go", len(primaryTags))

	// Maps to check: each entry is {file, varName, description, minCoverage%}
	type mapCheck struct {
		relPath     string
		varName     string
		description string
		// minCoverage is the minimum fraction of categories that must be present.
		// 1.0 means all categories must be covered.
		// Lower values allow for maps that intentionally cover a subset.
		minCoverage float64
	}

	checks := []mapCheck{
		{
			relPath:     filepath.Join("pkg", "defaults", "owasp.go"),
			varName:     "OWASPCategoryMapping",
			description: "OWASP category mapping (used for compliance reporting)",
			minCoverage: 0.5,
		},
		{
			relPath:     filepath.Join("pkg", "defaults", "owasp.go"),
			varName:     "CategoryReadableNames",
			description: "Human-readable category names (used by reports, CLI output)",
			minCoverage: 0.7,
		},
		{
			relPath:     filepath.Join("pkg", "mcpserver", "tools.go"),
			varName:     "categoryDescriptions",
			description: "MCP tool category metadata (returned to AI agents)",
			minCoverage: 1.0,
		},
	}

	for _, check := range checks {
		t.Run(check.varName, func(t *testing.T) {
			fullPath := filepath.Join(repoRoot, check.relPath)
			if _, err := os.Stat(fullPath); os.IsNotExist(err) {
				t.Skipf("file not found: %s", check.relPath)
			}

			mapKeys := extractMapKeys(t, fullPath, check.varName)
			if len(mapKeys) == 0 {
				t.Fatalf("no keys found for %s in %s", check.varName, check.relPath)
			}

			keySet := make(map[string]bool, len(mapKeys))
			for _, k := range mapKeys {
				keySet[strings.ToLower(k)] = true
			}

			var missing []string
			for _, tag := range primaryTags {
				if !keySet[strings.ToLower(tag)] {
					missing = append(missing, tag)
				}
			}

			coverage := float64(len(primaryTags)-len(missing)) / float64(len(primaryTags))
			t.Logf("%s: %d/%d categories covered (%.0f%%)", check.varName, len(primaryTags)-len(missing), len(primaryTags), coverage*100)

			if coverage < check.minCoverage {
				sort.Strings(missing)
				t.Errorf("%s in %s is below %.0f%% coverage (%.0f%%)\n  Missing categories: %s\n  Description: %s",
					check.varName, check.relPath,
					check.minCoverage*100, coverage*100,
					strings.Join(missing, ", "),
					check.description)
			} else if len(missing) > 0 {
				sort.Strings(missing)
				t.Logf("  Missing (below threshold, non-blocking): %s", strings.Join(missing, ", "))
			}
		})
	}
}

// TestNoDuplicateCategoryDisplayNames verifies that CategoryDisplayNames
// in html_vulndb.go is not a hardcoded duplicate of defaults.CategoryReadableNames.
// If someone re-introduces a hardcoded map, this test catches it.
func TestNoDuplicateCategoryDisplayNames(t *testing.T) {
	repoRoot := getRepoRoot(t)
	vulndbPath := filepath.Join(repoRoot, "pkg", "report", "html_vulndb.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, vulndbPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", vulndbPath, err)
	}

	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || vs.Names[0].Name != "CategoryDisplayNames" {
				continue
			}
			if len(vs.Values) == 0 {
				continue
			}
			// If it's a composite literal (map[string]string{...}), it's hardcoded
			if _, ok := vs.Values[0].(*ast.CompositeLit); ok {
				t.Error("CategoryDisplayNames in html_vulndb.go is a hardcoded map literal.\n" +
					"  It should reference defaults.CategoryReadableNames instead.\n" +
					"  Fix: var CategoryDisplayNames = defaults.CategoryReadableNames")
			}
		}
	}
}

// TestCWEMapCoverage verifies that CWE mapping tables cover the primary
// attack categories. Multiple CWE maps exist across the codebase; this
// test ensures they don't fall too far behind.
func TestCWEMapCoverage(t *testing.T) {
	repoRoot := getRepoRoot(t)
	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")
	primaryTags := extractRegisterCalls(t, mapperPath)

	// CWE-related categories (categories that represent specific vulnerability types,
	// not meta-categories like "owasp-top10" or "regression")
	cweRelevant := make(map[string]bool)
	metaCategories := map[string]bool{
		"owasp-top10": true, "regression": true, "waf-bypass": true,
		"waf-validation": true, "fuzz": true, "obfuscation": true,
		"polyglot": true, "service-specific": true, "media": true,
		"ratelimit": true, "protocol": true,
	}
	for _, tag := range primaryTags {
		if !metaCategories[tag] {
			cweRelevant[tag] = true
		}
	}

	type cweCheck struct {
		relPath     string
		varName     string
		minCoverage float64
	}

	checks := []cweCheck{
		{
			relPath:     filepath.Join("pkg", "output", "writers", "cyclonedx.go"),
			varName:     "cweMap",
			minCoverage: 0.3,
		},
	}

	for _, check := range checks {
		t.Run(check.varName+"_in_"+filepath.Base(check.relPath), func(t *testing.T) {
			fullPath := filepath.Join(repoRoot, check.relPath)
			if _, err := os.Stat(fullPath); os.IsNotExist(err) {
				t.Skipf("file not found: %s", check.relPath)
			}

			// CWE maps are often local variables inside functions, not top-level.
			// Scan the file for map literal keys using a simpler regex approach.
			data, err := os.ReadFile(fullPath)
			if err != nil {
				t.Fatalf("read %s: %v", check.relPath, err)
			}

			// Extract keys from the first map literal containing the varName
			content := string(data)
			idx := strings.Index(content, check.varName)
			if idx < 0 {
				t.Skipf("%s not found in %s", check.varName, check.relPath)
			}

			// Parse the function containing the variable to find map keys
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, fullPath, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", check.relPath, err)
			}

			keySet := make(map[string]bool)
			ast.Inspect(f, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assign.Lhs {
					ident, ok := lhs.(*ast.Ident)
					if !ok || ident.Name != check.varName {
						continue
					}
					// Found the assignment, extract composite literal keys
					for _, rhs := range assign.Rhs {
						cl, ok := rhs.(*ast.CompositeLit)
						if !ok {
							continue
						}
						for _, elt := range cl.Elts {
							kv, ok := elt.(*ast.KeyValueExpr)
							if !ok {
								continue
							}
							lit, ok := kv.Key.(*ast.BasicLit)
							if !ok {
								continue
							}
							keySet[strings.Trim(lit.Value, "\"")] = true
						}
					}
				}
				return true
			})

			if len(keySet) == 0 {
				t.Skipf("no map keys found for %s", check.varName)
			}

			var missing []string
			for cat := range cweRelevant {
				if !keySet[cat] {
					missing = append(missing, cat)
				}
			}

			coverage := float64(len(cweRelevant)-len(missing)) / float64(len(cweRelevant))
			t.Logf("%s: %d/%d CWE-relevant categories covered (%.0f%%)",
				check.varName, len(cweRelevant)-len(missing), len(cweRelevant), coverage*100)

			if coverage < check.minCoverage {
				sort.Strings(missing)
				t.Errorf("%s in %s is below %.0f%% CWE coverage (%.0f%%)\n  Missing: %s",
					check.varName, check.relPath,
					check.minCoverage*100, coverage*100,
					strings.Join(missing, ", "))
			}
		})
	}
}

// TestAllCategoriesInPayloadJSON verifies that every category used in
// payload JSON files has a corresponding mapper registration.
// This is a structural scan — it reads JSON files and ensures the
// "category" field values are all recognized.
func TestAllCategoriesInPayloadJSON(t *testing.T) {
	repoRoot := getRepoRoot(t)
	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")

	// Build the set of all recognized tags and aliases from mapper.go
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mapperPath, nil, 0)
	if err != nil {
		t.Fatalf("parse mapper.go: %v", err)
	}

	recognized := make(map[string]bool)
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "register":
			// All args after first are tags
			for i := 1; i < len(call.Args); i++ {
				if lit, ok := call.Args[i].(*ast.BasicLit); ok {
					recognized[strings.ToLower(strings.Trim(lit.Value, "\""))] = true
				}
			}
			// The canonical name itself
			if len(call.Args) > 0 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok {
					recognized[strings.ToLower(strings.Trim(lit.Value, "\""))] = true
				}
			}
		case "alias":
			// alias(aliasName, canonicalCategory) — both are recognized
			for _, arg := range call.Args {
				if lit, ok := arg.(*ast.BasicLit); ok {
					recognized[strings.ToLower(strings.Trim(lit.Value, "\""))] = true
				}
			}
		}
		return true
	})

	if len(recognized) == 0 {
		t.Fatal("no categories extracted from mapper.go")
	}
	t.Logf("Mapper has %d recognized category names/tags/aliases", len(recognized))

	// Scan payload JSON files
	payloadsDir := filepath.Join(repoRoot, "payloads")
	communityDir := filepath.Join(payloadsDir, "community")

	var unrecognized []string
	for _, dir := range []string{payloadsDir, communityDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			if entry.Name() == "ids-map.json" || entry.Name() == "version.json" {
				continue
			}

			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Errorf("read %s: %v", entry.Name(), err)
				continue
			}

			var payloads []struct {
				Category string `json:"category"`
			}
			if err := json.Unmarshal(data, &payloads); err != nil {
				continue // Not a payload array
			}

			seen := make(map[string]bool)
			for _, p := range payloads {
				cat := strings.ToLower(p.Category)
				if cat == "" || seen[cat] {
					continue
				}
				seen[cat] = true
				if !recognized[cat] {
					unrecognized = append(unrecognized, p.Category+" (in "+entry.Name()+")")
				}
			}
		}
	}

	if len(unrecognized) > 0 {
		sort.Strings(unrecognized)
		t.Errorf("payload JSON files contain %d unrecognized categories:\n  %s\n"+
			"Fix: add register() or alias() calls in pkg/payloadprovider/mapper.go",
			len(unrecognized), strings.Join(unrecognized, "\n  "))
	}
}

// =============================================================================
// NEGATIVE / ADVERSARIAL TESTS
// =============================================================================

// TestExtractMapKeys_NonexistentVar verifies extractMapKeys returns nil when
// the requested variable does not exist in the file.
func TestExtractMapKeys_NonexistentVar(t *testing.T) {
	repoRoot := getRepoRoot(t)
	owasp := filepath.Join(repoRoot, "pkg", "defaults", "owasp.go")

	keys := extractMapKeys(t, owasp, "ThisVariableDoesNotExist")
	if keys != nil {
		t.Errorf("extractMapKeys for nonexistent var returned %v, want nil", keys)
	}
}

// TestExtractRegisterCalls_NonMapperFile verifies extractRegisterCalls returns
// empty when pointed at a file with no register() calls.
func TestExtractRegisterCalls_NonMapperFile(t *testing.T) {
	repoRoot := getRepoRoot(t)
	owasp := filepath.Join(repoRoot, "pkg", "defaults", "owasp.go")

	tags := extractRegisterCalls(t, owasp)
	if len(tags) != 0 {
		t.Errorf("extractRegisterCalls on owasp.go returned %d tags, want 0", len(tags))
	}
}

// TestMapperPrimaryTags_NoDuplicates verifies no two register() calls share
// the same primary tag (first tag argument), which would mean ShortNames
// collision.
func TestMapperPrimaryTags_NoDuplicates(t *testing.T) {
	repoRoot := getRepoRoot(t)
	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")

	tags := extractRegisterCalls(t, mapperPath)
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if seen[lower] {
			t.Errorf("duplicate primary tag in mapper.go register() calls: %q", tag)
		}
		seen[lower] = true
	}
}

// TestMapperCanonicalNames_NoDuplicates verifies that the first argument
// (canonical category name) of each register() call is unique.
func TestMapperCanonicalNames_NoDuplicates(t *testing.T) {
	repoRoot := getRepoRoot(t)
	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mapperPath, nil, 0)
	if err != nil {
		t.Fatalf("parse mapper.go: %v", err)
	}

	seen := make(map[string]bool)
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "register" {
			return true
		}
		if len(call.Args) < 1 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		canonical := strings.Trim(lit.Value, "\"")
		lower := strings.ToLower(canonical)
		if seen[lower] {
			t.Errorf("duplicate canonical name in register(): %q", canonical)
		}
		seen[lower] = true
		return true
	})
}

// TestCategoryDescriptionKeys_AllRecognized verifies that every key in
// categoryDescriptions maps to a valid mapper category (catches typos).
func TestCategoryDescriptionKeys_AllRecognized(t *testing.T) {
	repoRoot := getRepoRoot(t)
	toolsPath := filepath.Join(repoRoot, "pkg", "mcpserver", "tools.go")
	if _, err := os.Stat(toolsPath); os.IsNotExist(err) {
		t.Skip("tools.go not found")
	}

	descKeys := extractMapKeys(t, toolsPath, "categoryDescriptions")
	if len(descKeys) == 0 {
		t.Fatal("no keys in categoryDescriptions")
	}

	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mapperPath, nil, 0)
	if err != nil {
		t.Fatalf("parse mapper.go: %v", err)
	}

	// Build set of all recognized names from register() and alias() calls.
	recognized := make(map[string]bool)
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "register":
			for _, arg := range call.Args {
				if lit, ok := arg.(*ast.BasicLit); ok {
					recognized[strings.ToLower(strings.Trim(lit.Value, "\""))] = true
				}
			}
		case "alias":
			for _, arg := range call.Args {
				if lit, ok := arg.(*ast.BasicLit); ok {
					recognized[strings.ToLower(strings.Trim(lit.Value, "\""))] = true
				}
			}
		}
		return true
	})

	var unrecognized []string
	for _, key := range descKeys {
		if !recognized[strings.ToLower(key)] {
			unrecognized = append(unrecognized, key)
		}
	}
	if len(unrecognized) > 0 {
		t.Errorf("categoryDescriptions has keys not recognized by mapper: %v\n"+
			"These may be typos or missing register/alias calls in mapper.go",
			unrecognized)
	}
}

// TestOWASPMapping_NoEmptyValues verifies that OWASPCategoryMapping has
// no empty-string values (which would indicate a forgotten placeholder).
func TestOWASPMapping_NoEmptyValues(t *testing.T) {
	repoRoot := getRepoRoot(t)
	owaspPath := filepath.Join(repoRoot, "pkg", "defaults", "owasp.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, owaspPath, nil, 0)
	if err != nil {
		t.Fatalf("parse owasp.go: %v", err)
	}

	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || vs.Names[0].Name != "OWASPCategoryMapping" {
				continue
			}
			if len(vs.Values) == 0 {
				continue
			}
			cl, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				valLit, ok := kv.Value.(*ast.BasicLit)
				if !ok {
					continue
				}
				val := strings.Trim(valLit.Value, "\"")
				if val == "" {
					keyLit, _ := kv.Key.(*ast.BasicLit)
					key := ""
					if keyLit != nil {
						key = strings.Trim(keyLit.Value, "\"")
					}
					t.Errorf("OWASPCategoryMapping[%q] has empty value", key)
				}
			}
		}
	}
}

// TestCategoryReadableNames_NoEmptyValues verifies that CategoryReadableNames
// has no empty-string values.
func TestCategoryReadableNames_NoEmptyValues(t *testing.T) {
	repoRoot := getRepoRoot(t)
	owaspPath := filepath.Join(repoRoot, "pkg", "defaults", "owasp.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, owaspPath, nil, 0)
	if err != nil {
		t.Fatalf("parse owasp.go: %v", err)
	}

	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || vs.Names[0].Name != "CategoryReadableNames" {
				continue
			}
			if len(vs.Values) == 0 {
				continue
			}
			cl, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				valLit, ok := kv.Value.(*ast.BasicLit)
				if !ok {
					continue
				}
				val := strings.Trim(valLit.Value, "\"")
				if val == "" {
					keyLit, _ := kv.Key.(*ast.BasicLit)
					key := ""
					if keyLit != nil {
						key = strings.Trim(keyLit.Value, "\"")
					}
					t.Errorf("CategoryReadableNames[%q] has empty value", key)
				}
			}
		}
	}
}

// TestPayloadJSON_NoEmptyCategories verifies that no payload JSON file
// contains a payload with an empty or whitespace-only category.
func TestPayloadJSON_NoEmptyCategories(t *testing.T) {
	repoRoot := getRepoRoot(t)
	payloadsDir := filepath.Join(repoRoot, "payloads")

	for _, dir := range []string{payloadsDir, filepath.Join(payloadsDir, "community")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			if entry.Name() == "ids-map.json" || entry.Name() == "version.json" {
				continue
			}

			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Errorf("read %s: %v", entry.Name(), err)
				continue
			}

			var payloads []struct {
				Category string `json:"category"`
			}
			if err := json.Unmarshal(data, &payloads); err != nil {
				continue
			}

			for i, p := range payloads {
				if strings.TrimSpace(p.Category) == "" {
					t.Errorf("%s[%d]: empty or whitespace-only category", entry.Name(), i)
				}
			}
		}
	}
}

// TestPayloadJSON_NoDuplicateIDs verifies that no two payloads across all
// JSON files share the same ID (structural check, no runtime dependency).
func TestPayloadJSON_NoDuplicateIDs(t *testing.T) {
	repoRoot := getRepoRoot(t)
	payloadsDir := filepath.Join(repoRoot, "payloads")

	allIDs := make(map[string]string) // id → file

	for _, dir := range []string{payloadsDir, filepath.Join(payloadsDir, "community")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			if entry.Name() == "ids-map.json" || entry.Name() == "version.json" {
				continue
			}

			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Errorf("read %s: %v", entry.Name(), err)
				continue
			}

			var payloads []struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(data, &payloads); err != nil {
				continue
			}

			for _, p := range payloads {
				if p.ID == "" {
					continue
				}
				if file, exists := allIDs[p.ID]; exists {
					t.Errorf("duplicate payload ID %q: first in %s, also in %s", p.ID, file, entry.Name())
				}
				allIDs[p.ID] = entry.Name()
			}
		}
	}
}

// TestPayloadJSON_NoEmptyPayloads verifies that no payload JSON file contains
// entries with empty or whitespace-only payload strings. Such entries fail
// Payload.Validate() at runtime and produce WARN log noise.
func TestPayloadJSON_NoEmptyPayloads(t *testing.T) {
	repoRoot := getRepoRoot(t)
	payloadsDir := filepath.Join(repoRoot, "payloads")

	err := filepath.Walk(payloadsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return err
		}
		if info.Name() == "ids-map.json" || info.Name() == "version.json" {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read %s: %v", path, readErr)
			return nil
		}

		var payloads []struct {
			ID      string `json:"id"`
			Payload string `json:"payload"`
		}
		if jsonErr := json.Unmarshal(data, &payloads); jsonErr != nil {
			return nil // skip non-payload JSON files
		}

		rel, _ := filepath.Rel(payloadsDir, path)
		for i, p := range payloads {
			if strings.TrimSpace(p.Payload) == "" {
				t.Errorf("%s[%d] (id=%s): empty or whitespace-only payload", rel, i, p.ID)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk payloads: %v", err)
	}
}

// =============================================================================
// SCANNER ↔ MAPPER COMPLETENESS TESTS
// =============================================================================

// extractAllMapperNames parses mapper.go and builds a set of every string
// that the mapper recognizes: canonical names, tags, and aliases — all
// lowercased. This mirrors ValidCategories() without importing the package.
func extractAllMapperNames(t *testing.T, mapperPath string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mapperPath, nil, 0)
	if err != nil {
		t.Fatalf("parse mapper.go: %v", err)
	}

	recognized := make(map[string]bool)
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "register":
			for _, arg := range call.Args {
				if lit, ok := arg.(*ast.BasicLit); ok {
					recognized[strings.ToLower(strings.Trim(lit.Value, "\""))] = true
				}
			}
		case "alias":
			for _, arg := range call.Args {
				if lit, ok := arg.(*ast.BasicLit); ok {
					recognized[strings.ToLower(strings.Trim(lit.Value, "\""))] = true
				}
			}
		}
		return true
	})
	return recognized
}

// pkgEmbedsAttackconfigBase returns true if any .go file in the directory
// defines a struct that embeds attackconfig.Base — the structural marker for
// WAFtester attack scanner packages.
func pkgEmbedsAttackconfigBase(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return false
		}

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			continue
		}

		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					continue
				}
				for _, field := range st.Fields.List {
					if len(field.Names) != 0 {
						continue
					}
					sel, ok := field.Type.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					ident, ok := sel.X.(*ast.Ident)
					if !ok {
						continue
					}
					if ident.Name == "attackconfig" && sel.Sel.Name == "Base" {
						return true
					}
				}
			}
		}
	}
	return false
}

// TestScannerPackages_HaveMapperEntries verifies that every pkg/<name>
// attack scanner package (identified by embedding attackconfig.Base) has
// a corresponding entry in the CategoryMapper.
//
// When someone creates a new scanner package, this test fails and tells
// them to add register()/alias() calls in mapper.go.
func TestScannerPackages_HaveMapperEntries(t *testing.T) {
	repoRoot := getRepoRoot(t)
	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")
	recognized := extractAllMapperNames(t, mapperPath)
	if len(recognized) == 0 {
		t.Fatal("no categories extracted from mapper.go")
	}

	pkgDir := filepath.Join(repoRoot, "pkg")
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read pkg/: %v", err)
	}

	// Manual mappings: package directory name → mapper tag/alias/canonical.
	// Some package names don't match their category tags (e.g. "cmdi" → rce).
	// This map tells the test how to verify these packages.
	pkgToMapperKey := map[string]string{
		"cmdi":              "cmdi",
		"cors":              "cors",
		"crlf":              "crlf",
		"csrf":              "csrf",
		"hostheader":        "hostheader",
		"hpp":               "hpp",
		"lfi":               "lfi",
		"nosqli":            "nosqli",
		"rce":               "rce",
		"redirect":          "redirect",
		"smuggling":         "smuggling",
		"sqli":              "sqli",
		"ssrf":              "ssrf",
		"ssti":              "ssti",
		"xss":               "xss",
		"xxe":               "xxe",
		"graphql":           "graphql",
		"xpath":             "xpath",
		"websocket":         "websocket",
		"upload":            "upload",
		"race":              "race",
		"clickjack":         "clickjack",
		"accesscontrol":     "accesscontrol",
		"subtakeover":       "subtakeover",
		"sessionfixation":   "sessionfixation",
		"massassignment":    "massassignment",
		"responsesplit":     "response-splitting",
		"ssi":               "ssi",
		"prototype":         "prototype",
		"deserialize":       "deserialize",
		"bizlogic":          "bizlogic",
		"brokenauth":        "brokenauth",
		"securitymisconfig": "securitymisconfig",
		"sensitivedata":     "sensitivedata",
		"cryptofailure":     "cryptofailure",
		"apiabuse":          "apiabuse",
		"xmlinjection":      "xml-injection",
	}

	// Operational packages that embed attackconfig.Base for shared config
	// but are not attack categories themselves.
	operationalPackages := map[string]bool{
		"apifuzz":    true, // API fuzzing engine (uses Fuzz category)
		"assessment": true, // assessment orchestrator
		"dnsbrute":   true, // DNS enumeration utility
		"leakypaths": true, // path discovery utility
		"params":     true, // parameter discovery utility
		"recon":      true, // reconnaissance utility
		"recursive":  true, // recursive scanning utility
		"screenshot": true, // screenshot utility
	}

	var missing []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if operationalPackages[entry.Name()] {
			continue
		}
		dir := filepath.Join(pkgDir, entry.Name())
		if !pkgEmbedsAttackconfigBase(dir) {
			continue
		}

		key := entry.Name()
		if mapped, ok := pkgToMapperKey[entry.Name()]; ok {
			key = mapped
		}

		if !recognized[strings.ToLower(key)] {
			missing = append(missing, entry.Name())
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("scanner packages embedding attackconfig.Base have no mapper entry:\n  %s\n"+
			"Fix: add register()/alias() calls in pkg/payloadprovider/mapper.go\n"+
			"Then add to pkgToMapperKey in this test if pkg name != category tag",
			strings.Join(missing, "\n  "))
	}
}

// TestCommunityPayloadDirs_HaveMapperEntries verifies that every subdirectory
// under payloads/community/ maps to a recognized category. Community payload
// directories are organized by category; if a directory exists without a mapper
// entry, payloads in it cannot be discovered by category search.
func TestCommunityPayloadDirs_HaveMapperEntries(t *testing.T) {
	repoRoot := getRepoRoot(t)
	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")
	recognized := extractAllMapperNames(t, mapperPath)

	communityDir := filepath.Join(repoRoot, "payloads", "community")
	entries, err := os.ReadDir(communityDir)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("payloads/community/ not found")
		}
		t.Fatalf("read payloads/community/: %v", err)
	}

	// Map community directory names to mapper keys when they differ.
	dirToMapperKey := map[string]string{
		"rate-limit": "ratelimit",
		"services":   "service-specific",
	}

	var unmapped []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		key := entry.Name()
		if mapped, ok := dirToMapperKey[key]; ok {
			key = mapped
		}
		if !recognized[strings.ToLower(key)] {
			unmapped = append(unmapped, entry.Name())
		}
	}

	if len(unmapped) > 0 {
		sort.Strings(unmapped)
		t.Errorf("community payload directories have no mapper entry:\n  %s\n"+
			"Fix: add register()/alias() calls in pkg/payloadprovider/mapper.go\n"+
			"Or add to dirToMapperKey in this test if dir name != category tag",
			strings.Join(unmapped, "\n  "))
	}
}

// TestCategoryDescriptions_FullCoverage verifies that categoryDescriptions
// in tools.go has an entry resolvable for every primary tag in mapper.go.
// Every category exposed through ShortNames() must have metadata for MCP
// agents — partial coverage is not acceptable.
func TestCategoryDescriptions_FullCoverage(t *testing.T) {
	repoRoot := getRepoRoot(t)
	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")
	toolsPath := filepath.Join(repoRoot, "pkg", "mcpserver", "tools.go")

	if _, err := os.Stat(toolsPath); os.IsNotExist(err) {
		t.Skip("tools.go not found")
	}

	// Get all primary tags from register() calls
	primaryTags := extractRegisterCalls(t, mapperPath)
	if len(primaryTags) == 0 {
		t.Fatal("no register() calls found in mapper.go")
	}

	// Get all keys from categoryDescriptions
	descKeys := extractMapKeys(t, toolsPath, "categoryDescriptions")
	descKeySet := make(map[string]bool, len(descKeys))
	for _, k := range descKeys {
		descKeySet[strings.ToLower(k)] = true
	}

	// Also build the full mapper recognized set (includes aliases)
	recognized := extractAllMapperNames(t, mapperPath)

	// For each primary tag, check if categoryDescriptions has EITHER:
	// 1. The primary tag itself as a key, OR
	// 2. Any tag from the same canonical category as a key
	//    (simulates lookupCategoryMeta resolution)
	//
	// To do this without runtime, we parse all register() calls and build
	// a map from each tag to all tags in the same category.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mapperPath, nil, 0)
	if err != nil {
		t.Fatalf("parse mapper.go: %v", err)
	}

	// categoryTags: canonical_lower → []tags
	categoryTags := make(map[string][]string)
	// primaryToCanonical: primary_tag → canonical_lower
	primaryToCanonical := make(map[string]string)

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "register" {
			return true
		}
		if len(call.Args) < 2 {
			return true
		}
		canonicalLit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		canonical := strings.ToLower(strings.Trim(canonicalLit.Value, "\""))
		var tags []string
		for i := 1; i < len(call.Args); i++ {
			if lit, ok := call.Args[i].(*ast.BasicLit); ok {
				tags = append(tags, strings.ToLower(strings.Trim(lit.Value, "\"")))
			}
		}
		categoryTags[canonical] = tags
		if len(tags) > 0 {
			primaryToCanonical[tags[0]] = canonical
		}
		return true
	})

	// Also extract the wellKnown aliases from ShortNames()
	// These are primary tags too, but they're aliases.
	// They resolve through the mapper, so we need to check their canonical
	// category's tags against categoryDescriptions.
	//
	// Parse the wellKnown slice literal
	wellKnown := extractWellKnownAliases(t, mapperPath)
	_ = wellKnown // informational: tested via recognized set

	var missing []string
	for _, tag := range primaryTags {
		lower := strings.ToLower(tag)
		// Direct match
		if descKeySet[lower] {
			continue
		}
		// Check all sibling tags in the same category
		canonical := primaryToCanonical[lower]
		found := false
		for _, sibling := range categoryTags[canonical] {
			if descKeySet[sibling] {
				found = true
				break
			}
		}
		if found {
			continue
		}
		// Also check canonical name itself
		if descKeySet[canonical] {
			continue
		}
		missing = append(missing, tag)
	}

	_ = recognized // suppress unused

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("categoryDescriptions in tools.go missing entries for %d primary tags:\n  %s\n"+
			"Fix: add entries to categoryDescriptions in pkg/mcpserver/tools.go\n"+
			"Each entry needs at least the primary tag or a sibling tag as key",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// extractWellKnownAliases parses ShortNames() in mapper.go and returns
// the wellKnown string slice literal values.
func extractWellKnownAliases(t *testing.T, mapperPath string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mapperPath, nil, 0)
	if err != nil {
		t.Fatalf("parse mapper.go: %v", err)
	}

	var aliases []string
	ast.Inspect(f, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || ident.Name != "wellKnown" {
				continue
			}
			for _, rhs := range assign.Rhs {
				cl, ok := rhs.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, elt := range cl.Elts {
					lit, ok := elt.(*ast.BasicLit)
					if !ok {
						continue
					}
					aliases = append(aliases, strings.Trim(lit.Value, "\""))
				}
			}
		}
		return true
	})
	return aliases
}

// TestWellKnownAliases_AllResolve verifies that every entry in the
// wellKnown slice in ShortNames() resolves to a valid category through
// the mapper's alias or tag tables.
func TestWellKnownAliases_AllResolve(t *testing.T) {
	repoRoot := getRepoRoot(t)
	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")
	recognized := extractAllMapperNames(t, mapperPath)

	wellKnown := extractWellKnownAliases(t, mapperPath)
	if len(wellKnown) == 0 {
		t.Fatal("no wellKnown aliases found in ShortNames()")
	}

	var unresolvable []string
	for _, alias := range wellKnown {
		if !recognized[strings.ToLower(alias)] {
			unresolvable = append(unresolvable, alias)
		}
	}
	if len(unresolvable) > 0 {
		t.Errorf("wellKnown aliases in ShortNames() do not resolve:\n  %s\n"+
			"Fix: add register() or alias() calls in mapper.go for each",
			strings.Join(unresolvable, "\n  "))
	}
}

// TestMapperAliases_TargetValidCanonical verifies that every alias()
// call in mapper.go points to a canonical name that was previously
// registered. Catches typos in alias target names.
func TestMapperAliases_TargetValidCanonical(t *testing.T) {
	repoRoot := getRepoRoot(t)
	mapperPath := filepath.Join(repoRoot, "pkg", "payloadprovider", "mapper.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mapperPath, nil, 0)
	if err != nil {
		t.Fatalf("parse mapper.go: %v", err)
	}

	// Collect canonical names from register() calls
	canonicals := make(map[string]bool)
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "register" {
			return true
		}
		if len(call.Args) < 1 {
			return true
		}
		if lit, ok := call.Args[0].(*ast.BasicLit); ok {
			canonicals[strings.Trim(lit.Value, "\"")] = true
		}
		return true
	})

	// Verify each alias() target is a known canonical name
	var bad []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "alias" {
			return true
		}
		if len(call.Args) < 2 {
			return true
		}
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok {
			return true
		}
		target := strings.Trim(lit.Value, "\"")
		if !canonicals[target] {
			aliasLit, _ := call.Args[0].(*ast.BasicLit)
			aliasName := "?"
			if aliasLit != nil {
				aliasName = strings.Trim(aliasLit.Value, "\"")
			}
			bad = append(bad, aliasName+" → "+target)
		}
		return true
	})

	if len(bad) > 0 {
		t.Errorf("alias() calls point to unregistered canonical names:\n  %s\n"+
			"Fix: register the canonical name first, or fix the typo",
			strings.Join(bad, "\n  "))
	}
}

// =============================================================================
// WAVE 2 STRUCTURAL TESTS
// =============================================================================

// TestOpenAPIDeprecationMessage verifies that the openapi command in main.go
// shows a deprecation message pointing users to 'auto --spec' instead.
func TestOpenAPIDeprecationMessage(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "main.go"))
	if err != nil {
		t.Fatalf("cannot read main.go: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, `"openapi"`) {
		t.Error("main.go should handle the 'openapi' command (even if deprecated)")
	}
	if !strings.Contains(content, "auto --spec") {
		t.Error("openapi deprecation message should point users to 'auto --spec'")
	}
}

// TestNoDebugKeepComments verifies that production code in cmd/cli/ does not
// contain leftover // debug:keep markers on output statements.
func TestNoDebugKeepComments(t *testing.T) {
	repoRoot := getRepoRoot(t)
	cliDir := filepath.Join(repoRoot, "cmd", "cli")
	err := filepath.Walk(cliDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "// debug:keep") {
				rel, _ := filepath.Rel(repoRoot, path)
				t.Errorf("%s:%d contains '// debug:keep' marker — remove from production code", rel, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk error: %v", err)
	}
}

// TestAnalyzeStartTimeBeforeAnalyze verifies that cmd_analyze.go sets
// analyzeStartTime BEFORE calling analyzer.Analyze(), not after.
func TestAnalyzeStartTimeBeforeAnalyze(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_analyze.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_analyze.go: %v", err)
	}
	content := string(data)
	startTimeIdx := strings.Index(content, "analyzeStartTime")
	analyzeIdx := strings.Index(content, "analyzer.Analyze(")
	if startTimeIdx < 0 {
		t.Fatal("analyzeStartTime not found in cmd_analyze.go")
	}
	if analyzeIdx < 0 {
		t.Fatal("analyzer.Analyze( not found in cmd_analyze.go")
	}
	if startTimeIdx > analyzeIdx {
		t.Error("analyzeStartTime is set AFTER analyzer.Analyze() — duration will be near-zero; move it before the call")
	}
}

// TestTemplateFlagsNotDiscarded verifies that cmd_template.go does not contain
// the pattern `_ = *concurrency` (or similar) which silently discards flag values.
func TestTemplateFlagsNotDiscarded(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_template.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_template.go: %v", err)
	}
	content := string(data)
	discardedFlags := []string{"_ = *concurrency", "_ = *rateLimit", "_ = *timeout", "_ = *retries"}
	for _, pattern := range discardedFlags {
		if strings.Contains(content, pattern) {
			t.Errorf("cmd_template.go contains %q — flag value is silently discarded instead of being used", pattern)
		}
	}
}

// TestAutoscanANSICleanupStreamGuard verifies that the standalone ANSI cleanup
// lines (\033[2A\033[J) in cmd_autoscan.go that appear outside of goroutines
// are guarded by !cfg.Out.StreamMode. The goroutine bodies are already
// guarded by the outer if-block that starts the goroutine.
func TestAutoscanANSICleanupStreamGuard(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_autoscan.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_autoscan.go: %v", err)
	}
	lines := strings.Split(string(data), "\n")

	// Find standalone if-guarded ANSI cleanup blocks (not inside goroutines).
	// Pattern: if !quietMode && StderrIsTerminal() { ... \033[2A\033[J }
	// These MUST also include !cfg.Out.StreamMode.
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Match only the if-guard lines that control ANSI cleanup
		if !strings.HasPrefix(trimmed, "if ") || !strings.Contains(line, "StderrIsTerminal()") {
			continue
		}
		// Check if the next line (or line after) contains the ANSI cleanup
		hasANSI := false
		for fwd := 1; fwd <= 3 && i+fwd < len(lines); fwd++ {
			if strings.Contains(lines[i+fwd], `\033[2A\033[J`) {
				hasANSI = true
				break
			}
		}
		if !hasANSI {
			continue
		}
		// This is an if-guard for ANSI cleanup — it must include StreamMode
		if !strings.Contains(line, "StreamMode") {
			t.Errorf("cmd_autoscan.go:%d has ANSI cleanup guard without StreamMode check: %s",
				i+1, trimmed)
		}
	}
}

// =============================================================================
// Wave 3 Runtime Audit Regression Tests
// =============================================================================

// TestProbeRateLimitMinuteCeilingDivision verifies that cmd_probe.go uses
// ceiling integer division when converting --rlm (rate-limit-per-minute) to
// per-second rate. Without ceiling division, values < 60 truncate to 0.
func TestProbeRateLimitMinuteCeilingDivision(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_probe.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_probe.go: %v", err)
	}
	content := string(data)
	// Must use ceiling division pattern: (value + 59) / 60
	if !strings.Contains(content, "+ 59) / 60") {
		t.Error("cmd_probe.go --rlm conversion must use ceiling division: (value + 59) / 60")
	}
	// Must NOT have bare integer division: / 60 without the +59 adjustment
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "RateLimitMinute") &&
			strings.Contains(trimmed, "/ 60") &&
			!strings.Contains(trimmed, "+ 59") {
			t.Errorf("cmd_probe.go:%d has bare integer division of RateLimitMinute/60 (truncates <60 to 0): %s",
				i+1, trimmed)
		}
	}
}

// TestTemplateBreakInSelectUsesGoto verifies that cmd_template.go uses
// goto (or labeled break) instead of bare break inside select{} for context
// cancellation. A bare break only exits the select, not the enclosing for loop.
func TestTemplateBreakInSelectUsesGoto(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_template.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_template.go: %v", err)
	}
	content := string(data)
	// Must have "goto done" for breaking out of the task dispatch loop
	if !strings.Contains(content, "goto done") {
		t.Error("cmd_template.go must use 'goto done' (not bare break) to exit the task dispatch loop on context cancellation")
	}
}

// TestAutoscanDivisionByZeroGuard verifies that cmd_autoscan.go guards
// against division by zero when computing progress percentage for param
// discovery. Without the guard, totalEndpoints==0 causes float64 +Inf
// which can panic in strings.Repeat with a negative count.
func TestAutoscanDivisionByZeroGuard(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_autoscan.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_autoscan.go: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "totalEndpoints > 0") {
		t.Error("cmd_autoscan.go must guard param-discovery progress division with 'totalEndpoints > 0'")
	}
}

// TestNoDeadFlagRespectNoFollow verifies that cmd_crawl.go does not define
// a respectNoFollow flag (the crawler has no NoFollow support, so the flag
// was parsed but silently ignored).
func TestNoDeadFlagRespectNoFollow(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_crawl.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_crawl.go: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "respectNoFollow") || strings.Contains(content, "respect-nofollow") {
		t.Error("cmd_crawl.go contains dead flag 'respectNoFollow' — crawler has no NoFollow support")
	}
}

// TestNoDeadFlagsFuzz verifies that cmd_fuzz.go does not define dead flags
// for fuzzPosition or calibrationWords (neither is wired to the fuzzer).
func TestNoDeadFlagsFuzz(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_fuzz.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_fuzz.go: %v", err)
	}
	content := string(data)
	deadFlags := []struct {
		varName  string
		flagName string
	}{
		{"fuzzPosition", "fuzz-position"},
		{"calibrationWords", "calibration-words"},
	}
	for _, df := range deadFlags {
		if strings.Contains(content, df.varName) {
			t.Errorf("cmd_fuzz.go contains dead flag variable %q (defined but never wired to fuzzer)", df.varName)
		}
	}
}

// TestAssessUsesSignalContext verifies that assess.go creates its root context
// from cli.SignalContext (for graceful Ctrl+C handling) instead of bare
// context.Background().
func TestAssessUsesSignalContext(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "assess.go"))
	if err != nil {
		t.Fatalf("cannot read assess.go: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "cli.SignalContext") {
		t.Error("assess.go must use cli.SignalContext for graceful Ctrl+C handling instead of bare context.Background()")
	}
}

// TestFinalizeScanOutputReturnsExitCode verifies that finalizeScanOutput in
// cmd_scan_output.go returns an int exit code instead of calling os.Exit()
// directly. Calling os.Exit() inside a helper skips all deferred cleanup
// in the caller.
func TestFinalizeScanOutputReturnsExitCode(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_scan_output.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_scan_output.go: %v", err)
	}
	content := string(data)
	// Signature must return int
	if !strings.Contains(content, "finalizeScanOutput(") {
		t.Fatal("finalizeScanOutput function not found")
	}
	// Find the function and check it returns int
	funcIdx := strings.Index(content, "func finalizeScanOutput(")
	if funcIdx < 0 {
		t.Fatal("finalizeScanOutput function not found")
	}
	// Check the signature line includes ") int {"
	sigEnd := strings.Index(content[funcIdx:], "{")
	if sigEnd < 0 {
		t.Fatal("cannot find opening brace of finalizeScanOutput")
	}
	sig := content[funcIdx : funcIdx+sigEnd+1]
	if !strings.Contains(sig, "int") {
		t.Error("finalizeScanOutput must return int exit code, not void")
	}
}

// TestProgressStopWaitsForGoroutine verifies that Progress.Stop() and
// StatsDisplay.Stop() in pkg/ui/progress.go call wg.Wait() to ensure
// the render goroutine has fully exited before returning. Without this,
// the goroutine leaks and may write to a closed channel.
func TestProgressStopWaitsForGoroutine(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "pkg", "ui", "progress.go"))
	if err != nil {
		t.Fatalf("cannot read progress.go: %v", err)
	}
	content := string(data)

	// Both types must have a WaitGroup field
	for _, typeName := range []string{"Progress", "StatsDisplay"} {
		typeStart := strings.Index(content, fmt.Sprintf("type %s struct {", typeName))
		if typeStart < 0 {
			t.Fatalf("type %s struct not found", typeName)
		}
		typeEnd := strings.Index(content[typeStart:], "\n}")
		if typeEnd < 0 {
			t.Fatalf("end of type %s not found", typeName)
		}
		typeBody := content[typeStart : typeStart+typeEnd]
		if !strings.Contains(typeBody, "sync.WaitGroup") {
			t.Errorf("type %s must have a sync.WaitGroup field to track render goroutine lifecycle", typeName)
		}
	}

	// Stop methods must call wg.Wait()
	if !strings.Contains(content, "p.wg.Wait()") {
		t.Error("Progress.Stop() must call p.wg.Wait() to ensure render goroutine has exited")
	}
	if !strings.Contains(content, "s.wg.Wait()") {
		t.Error("StatsDisplay.Stop() must call s.wg.Wait() to ensure render goroutine has exited")
	}
}

// =============================================================================
// WAVE 4 RUNTIME BUG REGRESSION TESTS
// =============================================================================

// TestSOAPFuzzBlockedNotOverwritten verifies cmd_soap.go uses "else if" (not
// bare "if") for resp handling, so error-path fr.Blocked=true is not overwritten.
func TestSOAPFuzzBlockedNotOverwritten(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_soap.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_soap.go: %v", err)
	}
	content := string(data)

	// The error path sets fr.Blocked = true. A bare "if resp != nil" after it
	// would overwrite that. The correct pattern is "} else if resp != nil {".
	if strings.Contains(content, "fr.Blocked = true\n\t\t}\n\n\t\tif resp != nil") ||
		strings.Contains(content, "fr.Blocked = true\r\n\t\t}\r\n\r\n\t\tif resp != nil") {
		t.Error("cmd_soap.go uses bare 'if resp != nil' after error path — must use 'else if' to prevent overwriting fr.Blocked")
	}
	if !strings.Contains(content, "} else if resp != nil {") {
		t.Error("cmd_soap.go must use '} else if resp != nil {' to guard response handling")
	}
}

// TestFPEmitSummaryArgOrder verifies fp.go EmitSummary call passes
// FalsePositives as the blocked argument (3rd arg) and TotalTests-FalsePositives
// as the bypassed argument (4th arg).
func TestFPEmitSummaryArgOrder(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "fp.go"))
	if err != nil {
		t.Fatalf("cannot read fp.go: %v", err)
	}
	content := string(data)

	// Correct order: EmitSummary(ctx, total, blocked=FalsePositives, bypassed=TotalTests-FalsePositives, elapsed)
	if strings.Contains(content, "TotalTests-result.FalsePositives), int(result.FalsePositives)") {
		t.Error("fp.go EmitSummary has blocked/bypassed arguments swapped — FalsePositives should be the blocked arg")
	}
	if !strings.Contains(content, "int(result.FalsePositives), int(result.TotalTests-result.FalsePositives)") {
		t.Error("fp.go EmitSummary must pass FalsePositives as blocked (3rd) and TotalTests-FalsePositives as bypassed (4th)")
	}
}

// TestHeadlessUsesSignalContext verifies the headless browser command in
// cmd_misc.go uses cli.SignalContext instead of context.Background() so
// Ctrl+C can cancel it.
func TestHeadlessUsesSignalContext(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_misc.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_misc.go: %v", err)
	}
	content := string(data)

	// Find the headless section and check it uses SignalContext
	headlessIdx := strings.Index(content, "HEADLESS")
	if headlessIdx < 0 {
		t.Fatal("cannot find HEADLESS section in cmd_misc.go")
	}
	headlessSection := content[headlessIdx:]
	// Truncate to just the headless function (next section marker or EOF)
	if nextSection := strings.Index(headlessSection[1:], "// ===="); nextSection > 0 {
		headlessSection = headlessSection[:nextSection+1]
	}
	if strings.Contains(headlessSection, "ctx := context.Background()") ||
		strings.Contains(headlessSection, "ctx = context.Background()") {
		t.Error("headless command must use cli.SignalContext instead of context.Background()")
	}
}

// TestSmartModeChecksAllAliases verifies that scan and fuzz Visit callbacks
// check all flag aliases (including short forms) for smart mode detection.
func TestSmartModeChecksAllAliases(t *testing.T) {
	repoRoot := getRepoRoot(t)

	// Check scan
	scanData, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_scan.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_scan.go: %v", err)
	}
	scanContent := string(scanData)
	if !strings.Contains(scanContent, `f.Name == "concurrency" || f.Name == "c"`) {
		t.Error("cmd_scan.go smart mode must check both 'concurrency' and 'c' aliases")
	}

	// Check fuzz
	fuzzData, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_fuzz.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_fuzz.go: %v", err)
	}
	fuzzContent := string(fuzzData)
	if !strings.Contains(fuzzContent, `f.Name == "rate" || f.Name == "rl"`) {
		t.Error("cmd_fuzz.go smart mode must check both 'rate' and 'rl' aliases")
	}
	if !strings.Contains(fuzzContent, `f.Name == "t" || f.Name == "c"`) {
		t.Error("cmd_fuzz.go smart mode must check both 't' and 'c' aliases for concurrency")
	}
}

// TestBypassTimeoutWiredToConfig verifies cmd_bypass.go wires the --timeout
// flag to cfg.Timeout so the executor actually uses the user-specified timeout.
func TestBypassTimeoutWiredToConfig(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_bypass.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_bypass.go: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "cfg.Timeout") {
		t.Error("cmd_bypass.go must wire --timeout flag to cfg.Timeout")
	}
}

// TestNoDeadFuzzFlagsWave4 verifies cmd_fuzz.go doesn't contain dead flag
// definitions that were removed in wave 4 (recursion, mode, extract, store, etc.).
func TestNoDeadFuzzFlagsWave4(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_fuzz.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_fuzz.go: %v", err)
	}
	content := string(data)
	// Check for variable names from removed flag definitions
	deadVars := []string{
		"recursion :=", "recursionDepth :=",
		"fuzzMode :=",
		"extractRegex :=", "extractPreset :=",
		"storeResponse :=", "storeResponseDir :=", "storeOnlyMatches :=",
		"retries :=", "jitter :=",
		"debugRequest :=", "debugResponse :=",
	}
	for _, v := range deadVars {
		if strings.Contains(content, v) {
			t.Errorf("cmd_fuzz.go still contains dead flag variable %q — should have been removed", v)
		}
	}
}

// TestOutputFileFailureCausesExit verifies cmd_misc.go output file error paths
// call os.Exit(1) instead of silently continuing.
func TestOutputFileFailureCausesExit(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_misc.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_misc.go: %v", err)
	}
	content := string(data)

	// Every "Failed to create output file" must be followed by os.Exit(1) within a few lines
	parts := strings.Split(content, "Failed to create output file")
	if len(parts) < 2 {
		t.Fatal("expected at least one 'Failed to create output file' in cmd_misc.go")
	}
	for i := 1; i < len(parts); i++ {
		// Check the next ~100 chars for os.Exit(1)
		snippet := parts[i]
		if len(snippet) > 100 {
			snippet = snippet[:100]
		}
		if !strings.Contains(snippet, "os.Exit(1)") {
			t.Errorf("output file creation failure #%d in cmd_misc.go missing os.Exit(1) after error", i)
		}
	}
}

// TestFPPayloadNoDoubleEllipsis verifies fp.go doesn't use the %.60s... pattern
// with strutil.Truncate (which already appends "..."), preventing double ellipsis.
func TestFPPayloadNoDoubleEllipsis(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "fp.go"))
	if err != nil {
		t.Fatalf("cannot read fp.go: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "%.60s...") {
		t.Error("fp.go uses percent-60s-ellipsis with strutil.Truncate — causes double ellipsis; use bare percent-s instead")
	}
}

// TestVendorCategoryListDynamic verifies vendor.go doesn't hardcode the category
// slice for displaying vendor lists, using sorted map keys instead.
func TestVendorCategoryListDynamic(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "vendor.go"))
	if err != nil {
		t.Fatalf("cannot read vendor.go: %v", err)
	}
	content := string(data)
	// The old hardcoded pattern had all categories in a single slice literal
	if strings.Contains(content, `[]string{"cloud", "cdn-integrated"`) {
		t.Error("vendor.go still hardcodes category list — should derive from map keys dynamically")
	}
	if !strings.Contains(content, "sort.Strings") && !strings.Contains(content, "strutil.SortedMapKeys") {
		t.Error("vendor.go should sort category keys for deterministic output")
	}
}

// TestScanResumeWarning verifies cmd_scan.go --resume flag prints a "not yet
// implemented" warning instead of misleading checkpoint messages.
func TestScanResumeWarning(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_scan.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_scan.go: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "not yet implemented") {
		t.Error("cmd_scan.go --resume handler must warn that resume is not yet implemented")
	}
	if strings.Contains(content, "Resuming from checkpoint") {
		t.Error("cmd_scan.go should not print misleading 'Resuming from checkpoint' message")
	}
}

// TestVendorNoDoubleClose verifies vendor.go error path doesn't explicitly
// close the dispatcher after a defer already handles it.
func TestVendorNoDoubleClose(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "vendor.go"))
	if err != nil {
		t.Fatalf("cannot read vendor.go: %v", err)
	}
	content := string(data)
	// The error path should emit error but NOT call Close() explicitly
	errIdx := strings.Index(content, "Vendor detection error")
	if errIdx < 0 {
		t.Fatal("cannot find error handling section in vendor.go")
	}
	// Check a 200-char window after the error emit for explicit Close()
	window := content[errIdx:]
	if len(window) > 200 {
		window = window[:200]
	}
	if strings.Contains(window, "vendorDispCtx.Close()") {
		t.Error("vendor.go error path explicitly calls Close() after defer already handles it — remove double close")
	}
}

// TestWorkflowUsesSignalContext verifies the workflow command in cmd_misc.go
// uses cli.SignalContext as the parent context (not context.Background).
func TestWorkflowUsesSignalContext(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_misc.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_misc.go: %v", err)
	}
	content := string(data)

	// Find the workflow section (skip past the header block)
	workflowIdx := strings.Index(content, "WORKFLOW COMMAND")
	if workflowIdx < 0 {
		t.Fatal("cannot find WORKFLOW COMMAND section in cmd_misc.go")
	}
	// Skip 200 chars past header to avoid matching the header's own ===== lines
	searchStart := workflowIdx + 200
	if searchStart > len(content) {
		searchStart = len(content)
	}
	workflowSection := content[workflowIdx:searchStart]
	remainder := content[searchStart:]
	if nextSection := strings.Index(remainder, "// ===="); nextSection > 0 {
		workflowSection += remainder[:nextSection]
	} else {
		workflowSection += remainder
	}
	if !strings.Contains(workflowSection, "cli.SignalContext") {
		t.Error("workflow command must use cli.SignalContext for signal-aware context")
	}
}

// TestHookDispatcherUsesParentContext verifies that cmd_misc.go hook dispatcher
// contexts use the parent signal-aware context, not context.Background().
func TestHookDispatcherUsesParentContext(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_misc.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_misc.go: %v", err)
	}
	content := string(data)

	// Look for dispatcher context assignments using context.Background()
	// These should use the parent signal-aware ctx instead
	dispatcherBgPatterns := []string{
		"smugglerCtx := context.Background()",
		"raceCtx := context.Background()",
		"workflowCtx := context.Background()",
	}
	for _, pattern := range dispatcherBgPatterns {
		if strings.Contains(content, pattern) {
			t.Errorf("cmd_misc.go contains '%s' — hook dispatchers must use parent signal context", pattern)
		}
	}
}

// =============================================================================
// WAVE 5 REGRESSION TESTS
// =============================================================================
//
// These tests guard against the 25 bugs found in the Wave 5 runtime audit.

// TestExecutorBodySliceSafe ensures pkg/mutation/executor.go doesn't use
// a hardcoded bodyBytes[:300] that panics when body is 201-299 bytes.
func TestExecutorBodySliceSafe(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "pkg", "mutation", "executor.go"))
	if err != nil {
		t.Fatalf("cannot read executor.go: %v", err)
	}
	content := string(data)

	// Should NOT contain hardcoded bodyBytes[:300] — must use safe upper-bound
	if strings.Contains(content, "bodyBytes[:300]") {
		t.Error("executor.go contains hardcoded bodyBytes[:300] — panics when body is 201-299 bytes")
	}
	// Should contain safe slicing pattern
	if !strings.Contains(content, "upper := len(bodyBytes)") {
		t.Error("executor.go missing safe upper-bound calculation for body snippet")
	}
}

// TestProbeOutputDirErrorChecked ensures cmd_probe.go checks os.MkdirAll errors.
func TestProbeOutputDirErrorChecked(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_probe.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_probe.go: %v", err)
	}
	content := string(data)

	// Count MkdirAll calls vs error checks
	mkdirCount := strings.Count(content, "os.MkdirAll(")
	if mkdirCount == 0 {
		t.Skip("no MkdirAll calls found in cmd_probe.go")
	}
	// Every MkdirAll should have its error checked (err, mkErr, etc.)
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "os.MkdirAll(") &&
			!strings.Contains(trimmed, "if ") &&
			!strings.Contains(trimmed, "Err :=") &&
			!strings.Contains(trimmed, "err :=") &&
			!strings.Contains(trimmed, "err =") {
			t.Errorf("cmd_probe.go line ~%d: os.MkdirAll without error check", i+1)
		}
	}
}

// TestFuzzProgressCountsExtensions ensures cmd_fuzz.go multiplies wordlist
// size by (extensions + 1) for accurate progress tracking.
func TestFuzzProgressCountsExtensions(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_fuzz.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_fuzz.go: %v", err)
	}
	content := string(data)

	// Should contain the extension multiplier pattern
	if !strings.Contains(content, "(len(cfg.Extensions) + 1)") {
		t.Error("cmd_fuzz.go missing extensions multiplier — progress total will be wrong")
	}
}

// TestCalibrationThresholdFloor ensures fuzzer.go uses max(1, ...) for
// sizeThreshold to prevent zero-threshold from filtering nothing.
func TestCalibrationThresholdFloor(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "pkg", "fuzz", "fuzzer.go"))
	if err != nil {
		t.Fatalf("cannot read fuzzer.go: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "max(1,") {
		t.Error("fuzzer.go sizeThreshold missing max(1, ...) floor — zero baseline causes no filtering")
	}
}

// TestNoContextBackgroundInCLI ensures no context.Background() remains in
// CLI command files that should use signal-aware contexts.
func TestNoContextBackgroundInCLI(t *testing.T) {
	repoRoot := getRepoRoot(t)
	files := []string{
		filepath.Join(repoRoot, "cmd", "cli", "cmd_analyze.go"),
		filepath.Join(repoRoot, "cmd", "cli", "cmd_discover.go"),
		filepath.Join(repoRoot, "cmd", "cli", "cmd_soap.go"),
		filepath.Join(repoRoot, "cmd", "cli", "tampers.go"),
		filepath.Join(repoRoot, "cmd", "cli", "cmd_admin.go"),
		filepath.Join(repoRoot, "cmd", "cli", "fp.go"),
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("cannot read %s: %v", f, err)
		}
		if strings.Contains(string(data), "context.Background()") {
			t.Errorf("%s still contains context.Background() — should use cli.SignalContext or parent ctx",
				filepath.Base(f))
		}
	}
}

// TestProbeDeadFlagsWarning ensures dead probe flags have deprecation warnings.
func TestProbeDeadFlagsWarning(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_probe.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_probe.go: %v", err)
	}
	content := string(data)

	deadFlags := []string{"--rr", "--im", "--ehb"}
	for _, flag := range deadFlags {
		if !strings.Contains(content, flag) {
			t.Errorf("cmd_probe.go missing deprecation warning for dead flag %s", flag)
		}
	}
}

// TestScanTimeoutUsesContextMax ensures cmd_scan.go uses duration.ContextMax
// instead of confusing minutes-based timeout arithmetic.
func TestScanTimeoutUsesContextMax(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_scan.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_scan.go: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "duration.ContextMax") {
		t.Error("cmd_scan.go should use duration.ContextMax for overall scan timeout")
	}
	// Should NOT contain the old confusing minutes-based pattern
	if strings.Contains(content, "time.Duration(cfg.Common.Timeout)*time.Minute") {
		t.Error("cmd_scan.go still uses confusing timeout*Minute — should use duration.ContextMax")
	}
}

// TestFuzzWordlistSkipBounds ensures cmd_fuzz.go errors when skip >= wordlist size.
func TestFuzzWordlistSkipBounds(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_fuzz.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_fuzz.go: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "wordlistSkip >= len(words)") &&
		!strings.Contains(content, "*wordlistSkip >= len(words)") {
		t.Error("cmd_fuzz.go missing bounds check for wordlist skip >= wordlist size")
	}
}

// TestAnalyzeUsesSignalContext ensures cmd_analyze.go uses SignalContext
// for both HTTP fetch and hook emission (not context.Background()).
func TestAnalyzeUsesSignalContext(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_analyze.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_analyze.go: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "cli.SignalContext") {
		t.Error("cmd_analyze.go missing cli.SignalContext — HTTP fetch cannot be cancelled")
	}
	if strings.Contains(content, "context.Background()") {
		t.Error("cmd_analyze.go still uses context.Background() — should use signal-aware context")
	}
}

// TestCrawlFuzzFatalExitUsesParentCtx ensures cmd_crawl.go and cmd_fuzz.go
// fatal-exit paths use the parent ctx, not context.Background().
func TestCrawlFuzzFatalExitUsesParentCtx(t *testing.T) {
	repoRoot := getRepoRoot(t)

	for _, file := range []string{"cmd_crawl.go", "cmd_fuzz.go"} {
		data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", file))
		if err != nil {
			t.Fatalf("cannot read %s: %v", file, err)
		}
		if strings.Contains(string(data), "context.Background()") {
			t.Errorf("%s still contains context.Background() — fatal-exit paths should use parent ctx", file)
		}
	}
}

// TestVendorProtocolTestSignalContext ensures vendor.go protocol-test uses
// signal-aware context, not context.Background().
func TestVendorProtocolTestSignalContext(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "vendor.go"))
	if err != nil {
		t.Fatalf("cannot read vendor.go: %v", err)
	}
	if strings.Contains(string(data), "context.Background()") {
		t.Error("vendor.go still contains context.Background() — protocol test should use signal context")
	}
}

// TestBypassTimeoutWiredToExecutor ensures cmd_bypass.go passes timeout
// to the executor config.
func TestBypassTimeoutWiredToExecutor(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_bypass.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_bypass.go: %v", err)
	}
	if !strings.Contains(string(data), "cfg.Timeout") {
		t.Error("cmd_bypass.go doesn't wire timeout to executor config")
	}
}

// =============================================================================
// WAVE 6 REGRESSION TESTS
// =============================================================================

// TestFuzzBypassCrawlMutateDiscoverValidation ensures numeric validation
// guards are present in all five commands that accept concurrency/timeout flags.
func TestFuzzBypassCrawlMutateDiscoverValidation(t *testing.T) {
	repoRoot := getRepoRoot(t)
	cases := []struct {
		file   string
		marker string
	}{
		{"cmd/cli/cmd_fuzz.go", "must be at least 1"},
		{"cmd/cli/cmd_bypass.go", "must be at least 1"},
		{"cmd/cli/cmd_crawl.go", "must be at least 1"},
		{"cmd/cli/cmd_mutate.go", "must be at least 1"},
		{"cmd/cli/cmd_discover.go", "must be at least 1"},
	}
	for _, tc := range cases {
		data, err := os.ReadFile(filepath.Join(repoRoot, tc.file))
		if err != nil {
			t.Fatalf("cannot read %s: %v", tc.file, err)
		}
		if !strings.Contains(string(data), tc.marker) {
			t.Errorf("%s missing numeric validation marker %q", tc.file, tc.marker)
		}
	}
}

// TestEnumFlagsValidated ensures enum flags have validation in six files.
func TestEnumFlagsValidated(t *testing.T) {
	repoRoot := getRepoRoot(t)
	cases := []struct {
		file   string
		marker string
	}{
		{"cmd/cli/cmd_misc.go", `"double_submit", "token_reuse", "limit_bypass", "toctou"`},
		{"cmd/cli/cmd_mutate.go", `exitWithError("--mode`},
		{"cmd/cli/cmd_cloud.go", "at least one valid provider"},
		{"cmd/cli/cmd_autoscan_flags.go", `"quick", "normal", "deep", "paranoid"`},
		{"cmd/cli/cmd_smart_flags.go", `func (sf *SmartModeFlags) Validate()`},
		{"cmd/cli/cmd_scan_flags.go", `validFormats`},
	}
	for _, tc := range cases {
		data, err := os.ReadFile(filepath.Join(repoRoot, tc.file))
		if err != nil {
			t.Fatalf("cannot read %s: %v", tc.file, err)
		}
		if !strings.Contains(string(data), tc.marker) {
			t.Errorf("%s missing enum validation marker %q", tc.file, tc.marker)
		}
	}
}

// TestPeakRPSAtomic verifies that peakRPS uses atomic.Uint64 + Float64bits
// to prevent data races.
func TestPeakRPSAtomic(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "pkg", "ui", "progress.go"))
	if err != nil {
		t.Fatalf("cannot read progress.go: %v", err)
	}
	src := string(data)
	if !strings.Contains(src, "peakRPS") {
		t.Fatal("peakRPS field not found in progress.go")
	}
	if !strings.Contains(src, "atomic.Uint64") {
		t.Error("peakRPS should use atomic.Uint64 for lock-free concurrency")
	}
	if !strings.Contains(src, "Float64bits") {
		t.Error("peakRPS should use math.Float64bits for atomic float storage")
	}
}

// TestAutoscanFrameIdxLocal verifies that jsFrameIdx and paramFrameIdx are
// declared inside their goroutines to prevent data races on the closure capture.
func TestAutoscanFrameIdxLocal(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_autoscan.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_autoscan.go: %v", err)
	}
	src := string(data)

	// The pattern should be: "go func() {\n\t\t\t\t\tjsFrameIdx := 0"
	// NOT: "jsFrameIdx := 0\n\n\t\tif ... {\n\t\t\tgo func()"
	if strings.Contains(src, "jsFrameIdx := 0\n\t\tjsStartTime") {
		t.Error("jsFrameIdx should be declared inside the goroutine, not outside")
	}
	if strings.Contains(src, "paramFrameIdx := 0\n\t\t\ttotalEndpoints") {
		t.Error("paramFrameIdx should be declared inside the goroutine, not outside")
	}
}

// TestMutateEncodeErrorChecked verifies that writer.Encode errors are checked
// in cmd_mutate.go.
func TestMutateEncodeErrorChecked(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "cli", "cmd_mutate.go"))
	if err != nil {
		t.Fatalf("cannot read cmd_mutate.go: %v", err)
	}
	src := string(data)
	// Should not have bare "writer.Encode(r)" without error check
	if strings.Contains(src, "writer.Encode(r)\n") {
		t.Error("cmd_mutate.go has unchecked writer.Encode(r) — error must be handled")
	}
}

// TestUIPrintfStderr verifies that ui.Printf writes to os.Stderr, not os.Stdout.
func TestUIPrintfStderr(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "pkg", "ui", "terminal.go"))
	if err != nil {
		t.Fatalf("cannot read terminal.go: %v", err)
	}
	src := string(data)
	// Printf should write to os.Stderr
	if strings.Contains(src, "func Printf(") && !strings.Contains(src, "fmt.Fprint(os.Stderr") {
		t.Error("ui.Printf should write to os.Stderr, not os.Stdout")
	}
}

// TestNoStatusOnStdout verifies that cmd_analyze.go and cmd_scan_reports.go
// don't have bare fmt.Println() calls that would pollute stdout.
func TestNoStatusOnStdout(t *testing.T) {
	repoRoot := getRepoRoot(t)
	files := []string{
		"cmd/cli/cmd_analyze.go",
		"cmd/cli/cmd_scan_reports.go",
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(repoRoot, file))
		if err != nil {
			t.Fatalf("cannot read %s: %v", file, err)
		}
		src := string(data)
		// Look for bare fmt.Println() — these should be fmt.Fprintln(os.Stderr)
		for i, line := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "fmt.Println()" {
				t.Errorf("%s:%d has bare fmt.Println() — should be fmt.Fprintln(os.Stderr)", file, i+1)
			}
		}
	}
}

// =============================================================================
// CATEGORICAL REGRESSION GUARDS
// =============================================================================
// These broad sweeps catch entire bug classes across the codebase.
// New files automatically get coverage — no per-wave additions needed.

// TestNoContextIgnoringDNS scans all Go files under pkg/ for net.LookupIP
// and net.LookupHost calls which ignore context cancellation. All DNS
// resolution must use net.DefaultResolver.LookupIPAddr(ctx, ...) instead.
func TestNoContextIgnoringDNS(t *testing.T) {
	repoRoot := getRepoRoot(t)
	banned := []string{
		"net.LookupIP(",
		"net.LookupHost(",
		"net.LookupCNAME(",
		"net.LookupMX(",
		"net.LookupTXT(",
		"net.LookupNS(",
	}
	// Scan both pkg/ and cmd/cli/
	for _, dir := range []string{
		filepath.Join(repoRoot, "pkg"),
		filepath.Join(repoRoot, "cmd", "cli"),
	} {
		scanGoFiles(t, dir, banned,
			"uses context-ignoring DNS — should use net.DefaultResolver methods with ctx")
	}
}

// TestNoContextIgnoringTLS scans all Go files under pkg/ for
// tls.DialWithDialer which ignores context cancellation. All TLS dials
// must use tls.Dialer{}.DialContext(ctx, ...) instead.
func TestNoContextIgnoringTLS(t *testing.T) {
	repoRoot := getRepoRoot(t)
	banned := []string{"tls.DialWithDialer("}
	scanGoFiles(t, filepath.Join(repoRoot, "pkg"), banned,
		"uses tls.DialWithDialer which ignores context — should use tls.Dialer.DialContext")
}

// TestNoStdoutPollution scans all CLI command files for fmt.Printf and
// fmt.Println calls that write status/progress/help to stdout. Only JSON/CSV
// data output belongs on stdout; everything else must use os.Stderr.
//
// Allowed stdout patterns: enc.Encode, fmt.Println(string(json)), fmt.Println(output)
func TestNoStdoutPollution(t *testing.T) {
	repoRoot := getRepoRoot(t)
	cliDir := filepath.Join(repoRoot, "cmd", "cli")

	// Skip files whose primary output IS stdout data:
	// - cmd_docs.go: documentation text (the data IS the docs)
	// - cmd_crawl.go: markdown/text output modes
	// - cmd_fuzz.go: markdown output mode
	// - cmd_plugin.go: plugin listing
	// - tampers.go: tamper listing/matrix display (listing funcs stay on stdout per Wave 6)
	skip := map[string]bool{
		"cmd_docs.go":   true,
		"cmd_crawl.go":  true,
		"cmd_fuzz.go":   true,
		"cmd_plugin.go": true,
		"tampers.go":    true,
	}

	entries, err := os.ReadDir(cliDir)
	if err != nil {
		t.Fatalf("cannot read cmd/cli dir: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") || skip[e.Name()] {
			continue
		}
		data, err := os.ReadFile(filepath.Join(cliDir, e.Name()))
		if err != nil {
			t.Fatalf("cannot read %s: %v", e.Name(), err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			// Bare fmt.Println() separators must go to stderr
			if trimmed == "fmt.Println()" {
				t.Errorf("%s:%d has bare fmt.Println() — should be fmt.Fprintln(os.Stderr)", e.Name(), i+1)
			}
			// Carriage-return progress bars must go to stderr
			if strings.HasPrefix(trimmed, "fmt.Printf(\"\\r") {
				t.Errorf("%s:%d has stdout progress bar — should use fmt.Fprintf(os.Stderr, ...)", e.Name(), i+1)
			}
		}
	}
}

// TestDNSResolutionCapped verifies that OSINT clients that resolve subdomains
// in bulk have a maxResolve cap to prevent unbounded DNS queries.
func TestDNSResolutionCapped(t *testing.T) {
	repoRoot := getRepoRoot(t)
	// Any file that iterates subdomains for DNS resolution needs a cap
	files := []string{
		"pkg/osint/crtsh.go",
		"pkg/osint/chaos.go",
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(repoRoot, file))
		if err != nil {
			t.Fatalf("cannot read %s: %v", file, err)
		}
		if !strings.Contains(string(data), "maxResolve") {
			t.Errorf("%s does DNS resolution in a loop but lacks maxResolve cap", file)
		}
	}
}

// TestDiscoveryStatisticsUseSafeCopy verifies that discovery statistics are
// computed from the mutex-protected copy, not from the shared d.endpoints slice.
func TestDiscoveryStatisticsUseSafeCopy(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "pkg", "discovery", "discovery.go"))
	if err != nil {
		t.Fatalf("cannot read discovery.go: %v", err)
	}
	src := string(data)
	if strings.Contains(src, "TotalEndpoints = len(d.endpoints)") {
		t.Error("discovery.go computes TotalEndpoints from d.endpoints after mutex unlock — should use result.Endpoints")
	}
}

// TestPluginErrorsJoined verifies that plugin LoadFromDirectory uses
// errors.Join to preserve all errors, not just the last one.
func TestPluginErrorsJoined(t *testing.T) {
	repoRoot := getRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "pkg", "plugin", "plugin.go"))
	if err != nil {
		t.Fatalf("cannot read plugin.go: %v", err)
	}
	if strings.Contains(string(data), "loadErr = err") {
		t.Error("plugin.go LoadFromDirectory overwrites errors — should use errors.Join")
	}
}

// scanGoFiles walks a directory tree and checks every non-test .go file for
// banned string patterns. Helper for categorical regression tests.
func scanGoFiles(t *testing.T, dir string, banned []string, errMsg string) {
	t.Helper()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(data)
		rel, _ := filepath.Rel(dir, path)
		for _, pat := range banned {
			if strings.Contains(src, pat) {
				t.Errorf("%s %s", rel, errMsg)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}
