package test

import (
	"encoding/json"
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
		"cmdi":            "cmdi",
		"cors":            "cors",
		"crlf":            "crlf",
		"csrf":            "csrf",
		"hostheader":      "hostheader",
		"hpp":             "hpp",
		"lfi":             "lfi",
		"nosqli":          "nosqli",
		"rce":             "rce",
		"redirect":        "redirect",
		"smuggling":       "smuggling",
		"sqli":            "sqli",
		"ssrf":            "ssrf",
		"ssti":            "ssti",
		"xss":             "xss",
		"xxe":             "xxe",
		"graphql":         "graphql",
		"xpath":           "xpath",
		"websocket":       "websocket",
		"upload":          "upload",
		"race":            "race",
		"clickjack":       "clickjack",
		"accesscontrol":   "accesscontrol",
		"subtakeover":     "subtakeover",
		"sessionfixation": "sessionfixation",
		"massassignment":  "massassignment",
		"responsesplit":   "response-splitting",
		"ssi":             "ssi",
		"prototype":       "prototype",
		"deserialize":     "deserialize",
		"bizlogic":        "bizlogic",
		"brokenauth":      "brokenauth",
		"securitymisconfig": "securitymisconfig",
		"sensitivedata":   "sensitivedata",
		"cryptofailure":   "cryptofailure",
		"apiabuse":        "apiabuse",
		"xmlinjection":    "xml-injection",
	}

	// Operational packages that embed attackconfig.Base for shared config
	// but are not attack categories themselves.
	operationalPackages := map[string]bool{
		"apifuzz":     true, // API fuzzing engine (uses Fuzz category)
		"assessment":  true, // assessment orchestrator
		"dnsbrute":    true, // DNS enumeration utility
		"leakypaths":  true, // path discovery utility
		"params":      true, // parameter discovery utility
		"recon":       true, // reconnaissance utility
		"recursive":   true, // recursive scanning utility
		"screenshot":  true, // screenshot utility
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
	_ = wellKnown  // informational: tested via recognized set

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
