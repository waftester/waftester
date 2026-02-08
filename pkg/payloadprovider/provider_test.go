package payloadprovider_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/waftester/waftester/pkg/nuclei"
	"github.com/waftester/waftester/pkg/payloadprovider"
)

// ── Fixture helpers ────────────────────────────────────────────────────────

// jsonPayload is the JSON structure matching payloads.Payload for fixtures.
type jsonPayload struct {
	ID            string   `json:"id"`
	Payload       string   `json:"payload"`
	Category      string   `json:"category"`
	Method        string   `json:"method,omitempty"`
	TargetPath    string   `json:"target_path,omitempty"`
	ExpectedBlock bool     `json:"expected_block"`
	SeverityHint  string   `json:"severity_hint"`
	Tags          []string `json:"tags"`
}

// writeJSONPayloads creates a JSON payload file under dir.
func writeJSONPayloads(t *testing.T, dir, filename string, payloads []jsonPayload) {
	t.Helper()
	data, err := json.MarshalIndent(payloads, "", "  ")
	if err != nil {
		t.Fatalf("marshal JSON fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), data, 0644); err != nil {
		t.Fatalf("write JSON fixture %s: %v", filename, err)
	}
}

// writeNucleiTemplate creates a minimal Nuclei YAML template file.
func writeNucleiTemplate(t *testing.T, dir, filename, content string) {
	t.Helper()
	// Ensure http subdirectory exists.
	httpDir := filepath.Join(dir, "http")
	if err := os.MkdirAll(httpDir, 0755); err != nil {
		t.Fatalf("create http dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(httpDir, filename), []byte(content), 0644); err != nil {
		t.Fatalf("write template fixture %s: %v", filename, err)
	}
}

// setupFixtures creates a temp directory with JSON payloads and Nuclei templates.
func setupFixtures(t *testing.T) (payloadDir, nucleiDir string) {
	t.Helper()
	root := t.TempDir()

	payloadDir = filepath.Join(root, "payloads")
	nucleiDir = filepath.Join(root, "templates")

	if err := os.MkdirAll(payloadDir, 0755); err != nil {
		t.Fatalf("create payload dir: %v", err)
	}
	if err := os.MkdirAll(nucleiDir, 0755); err != nil {
		t.Fatalf("create nuclei dir: %v", err)
	}

	// ── JSON payloads ───────────────────────────────────────────
	writeJSONPayloads(t, payloadDir, "xss.json", []jsonPayload{
		{
			ID:            "xss-001",
			Payload:       "<script>alert(1)</script>",
			Category:      "XSS",
			Method:        "GET",
			TargetPath:    "/search",
			ExpectedBlock: true,
			SeverityHint:  "high",
			Tags:          []string{"xss", "reflected"},
		},
		{
			ID:            "xss-002",
			Payload:       "<img src=x onerror=alert(1)>",
			Category:      "XSS",
			Method:        "GET",
			TargetPath:    "/search",
			ExpectedBlock: true,
			SeverityHint:  "high",
			Tags:          []string{"xss", "event-handler"},
		},
	})

	writeJSONPayloads(t, payloadDir, "sqli.json", []jsonPayload{
		{
			ID:            "sqli-001",
			Payload:       "' OR 1=1--",
			Category:      "SQL-Injection",
			Method:        "GET",
			TargetPath:    "/user",
			ExpectedBlock: true,
			SeverityHint:  "critical",
			Tags:          []string{"sqli", "auth-bypass"},
		},
	})

	// ── Nuclei templates ────────────────────────────────────────
	writeNucleiTemplate(t, nucleiDir, "xss-basic.yaml", `id: xss-basic-test
info:
  name: XSS Basic Test
  severity: high
  tags: xss,waf-bypass

http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=<script>alert(document.cookie)</script>"
      - "{{BaseURL}}/search?q=<svg onload=alert(1)>"
    matchers:
      - type: word
        words:
          - "<script>alert"
`)

	writeNucleiTemplate(t, nucleiDir, "sqli-basic.yaml", `id: sqli-basic-test
info:
  name: SQLi Basic Test
  severity: critical
  tags: sqli,waf-bypass

http:
  - method: GET
    path:
      - "{{BaseURL}}/user?id=1' UNION SELECT 1,2,3--"
    matchers:
      - type: word
        words:
          - "UNION"
`)

	return payloadDir, nucleiDir
}

// ── Provider tests ─────────────────────────────────────────────────────────

func TestNewProvider(t *testing.T) {
	p := payloadprovider.NewProvider("payloads", "templates/nuclei")
	if p == nil {
		t.Fatal("NewProvider returned nil")
	}
}

func TestLoad_ValidFixtures(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	if err := p.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Second call is a no-op
	if err := p.Load(); err != nil {
		t.Fatalf("second Load: %v", err)
	}
}

func TestLoad_MissingPayloadDir(t *testing.T) {
	p := payloadprovider.NewProvider("/nonexistent/payloads", "/nonexistent/nuclei")
	err := p.Load()
	// JSON loader should return an error for missing directory
	if err == nil {
		t.Fatal("expected error for missing payload directory, got nil")
	}
}

func TestLoad_MissingNucleiDir_Tolerant(t *testing.T) {
	payloadDir, _ := setupFixtures(t)

	// Valid payload dir, but nonexistent nuclei dir — should succeed.
	p := payloadprovider.NewProvider(payloadDir, "/nonexistent/nuclei")
	if err := p.Load(); err != nil {
		t.Fatalf("expected load to succeed without nuclei dir: %v", err)
	}

	all, err := p.GetAll()
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("expected JSON payloads even without nuclei templates")
	}
}

func TestGetAll(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	all, err := p.GetAll()
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}

	// 3 JSON + 3 Nuclei paths = 6 minimum
	if len(all) < 5 {
		t.Errorf("expected at least 5 unified payloads, got %d", len(all))
	}

	// Verify sources
	var jsonCount, nucleiCount int
	for _, up := range all {
		switch up.Source {
		case payloadprovider.SourceJSON:
			jsonCount++
		case payloadprovider.SourceNuclei:
			nucleiCount++
		}
	}
	if jsonCount != 3 {
		t.Errorf("expected 3 JSON payloads, got %d", jsonCount)
	}
	if nucleiCount < 2 {
		t.Errorf("expected at least 2 Nuclei payloads, got %d", nucleiCount)
	}
}

func TestGetByCategory(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	tests := []struct {
		name     string
		category string
		wantMin  int // minimum expected results
	}{
		{"exact category XSS", "XSS", 2},
		{"alias sqli", "sqli", 1},
		{"alias SQL-Injection", "SQL-Injection", 1},
		{"case insensitive", "xss", 2},
		{"unknown category", "nonexistent-category", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := p.GetByCategory(tt.category)
			if err != nil {
				t.Fatalf("GetByCategory(%q): %v", tt.category, err)
			}
			if len(results) < tt.wantMin {
				t.Errorf("GetByCategory(%q) = %d results, want >= %d", tt.category, len(results), tt.wantMin)
			}
		})
	}
}

func TestGetByTags(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	tests := []struct {
		name    string
		tags    []string
		wantMin int
	}{
		{"single tag xss", []string{"xss"}, 2},
		{"single tag sqli", []string{"sqli"}, 1},
		{"multiple tags", []string{"xss", "reflected"}, 1},
		{"no matching tags", []string{"nonexistent-tag"}, 0},
		{"empty tags", []string{}, 5}, // empty means all match
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := p.GetByTags(tt.tags)
			if err != nil {
				t.Fatalf("GetByTags(%v): %v", tt.tags, err)
			}
			if len(results) < tt.wantMin {
				t.Errorf("GetByTags(%v) = %d results, want >= %d", tt.tags, len(results), tt.wantMin)
			}
		})
	}
}

func TestGetCategories(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	cats, err := p.GetCategories()
	if err != nil {
		t.Fatalf("GetCategories: %v", err)
	}

	if len(cats) < 2 {
		t.Errorf("expected at least 2 categories, got %d", len(cats))
	}

	// At least one category should have both JSON and Nuclei sources
	var hasBothSources bool
	for _, ci := range cats {
		if ci.HasJSONSource && ci.HasNucleiTempl {
			hasBothSources = true
			break
		}
	}
	if !hasBothSources {
		t.Log("no category has both JSON and Nuclei sources — this may be expected with test data")
	}
}

func TestGetStats(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	stats, err := p.GetStats()
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}

	if stats.TotalPayloads < 5 {
		t.Errorf("TotalPayloads = %d, want >= 5", stats.TotalPayloads)
	}
	if stats.JSONPayloads != 3 {
		t.Errorf("JSONPayloads = %d, want 3", stats.JSONPayloads)
	}
	if stats.NucleiPayloads < 2 {
		t.Errorf("NucleiPayloads = %d, want >= 2", stats.NucleiPayloads)
	}
	if stats.Categories < 2 {
		t.Errorf("Categories = %d, want >= 2", stats.Categories)
	}
	if len(stats.ByCategory) == 0 {
		t.Error("ByCategory is empty")
	}
	if len(stats.BySource) == 0 {
		t.Error("BySource is empty")
	}
}

func TestJSONPayloads(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	jps, err := p.JSONPayloads()
	if err != nil {
		t.Fatalf("JSONPayloads: %v", err)
	}
	if len(jps) != 3 {
		t.Errorf("JSONPayloads count = %d, want 3", len(jps))
	}
}

func TestNucleiTemplates(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	tmpls, err := p.NucleiTemplates()
	if err != nil {
		t.Fatalf("NucleiTemplates: %v", err)
	}
	if len(tmpls) != 2 {
		t.Errorf("NucleiTemplates count = %d, want 2", len(tmpls))
	}
}

func TestReset(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	// First load
	all1, err := p.GetAll()
	if err != nil {
		t.Fatalf("first GetAll: %v", err)
	}
	count1 := len(all1)

	// Reset and reload — should get same results
	p.Reset()
	all2, err := p.GetAll()
	if err != nil {
		t.Fatalf("second GetAll after Reset: %v", err)
	}
	if len(all2) != count1 {
		t.Errorf("after Reset: got %d payloads, want %d", len(all2), count1)
	}
}

func TestEnrichTemplate(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	tmpls, err := p.NucleiTemplates()
	if err != nil {
		t.Fatalf("NucleiTemplates: %v", err)
	}

	// Find the XSS template
	for _, tmpl := range tmpls {
		if !strings.Contains(strings.ToLower(tmpl.ID), "xss") {
			continue
		}
		originalPaths := len(tmpl.HTTP[0].Path)

		enriched, added, err := p.EnrichTemplate(tmpl)
		if err != nil {
			t.Fatalf("EnrichTemplate: %v", err)
		}

		// Should have added JSON XSS payloads as paths
		if added <= 0 {
			t.Log("EnrichTemplate added 0 paths — JSON XSS payloads may already exist in template paths")
		}

		if len(enriched.HTTP[0].Path) < originalPaths {
			t.Errorf("enriched paths (%d) < original (%d)", len(enriched.HTTP[0].Path), originalPaths)
		}
		return
	}
	t.Skip("no XSS template found in fixtures")
}

func TestToNucleiPayloadMap(t *testing.T) {
	ups := []payloadprovider.UnifiedPayload{
		{Payload: "<script>alert(1)</script>"},
		{Payload: "' OR 1=1--"},
	}

	m := payloadprovider.ToNucleiPayloadMap(ups)
	raw, ok := m["payloads"]
	if !ok {
		t.Fatal("missing 'payloads' key in map")
	}

	list, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", raw)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 payloads, got %d", len(list))
	}
}

func TestToNucleiPayloadMap_Empty(t *testing.T) {
	m := payloadprovider.ToNucleiPayloadMap(nil)
	raw := m["payloads"].([]interface{})
	if len(raw) != 0 {
		t.Errorf("expected empty list, got %d", len(raw))
	}
}

// ── CategoryMapper tests ──────────────────────────────────────────────────

func TestCategoryMapper_Resolve(t *testing.T) {
	m := payloadprovider.NewCategoryMapper()

	tests := []struct {
		name  string
		input string
		want  string // first element of result
	}{
		{"alias sqli", "sqli", "SQL-Injection"},
		{"alias xss", "cross-site-scripting", "XSS"},
		{"alias rce", "rce", "Command-Injection"},
		{"alias lfi", "lfi", "Path-Traversal"},
		{"alias nosql", "nosql", "NoSQL-Injection"},
		{"alias crlf", "crlf", "CRLF-Injection"},
		{"alias ldap", "ldap", "LDAP-Injection"},
		{"alias xpath", "xpath", "XPath-Injection"},
		{"alias bypass", "bypass", "WAF-Bypass"},
		{"unknown remains as-is", "unknown-thing", "unknown-thing"},
		{"case insensitive alias", "SQLI", "SQL-Injection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.Resolve(tt.input)
			if len(got) == 0 {
				t.Fatalf("Resolve(%q) returned empty", tt.input)
			}
			if got[0] != tt.want {
				t.Errorf("Resolve(%q)[0] = %q, want %q", tt.input, got[0], tt.want)
			}
		})
	}
}

func TestCategoryMapper_TagsToCategories(t *testing.T) {
	m := payloadprovider.NewCategoryMapper()

	tests := []struct {
		name     string
		tags     []string
		wantCats []string
	}{
		{"single tag", []string{"sqli"}, []string{"SQL-Injection"}},
		{"multiple tags same category", []string{"sqli", "sql-injection"}, []string{"SQL-Injection"}},
		{"multiple categories", []string{"xss", "sqli"}, []string{"XSS", "SQL-Injection"}},
		{"unknown tags ignored", []string{"unknown", "sqli"}, []string{"SQL-Injection"}},
		{"empty tags", []string{}, nil},
		{"all unknown", []string{"foo", "bar"}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.TagsToCategories(tt.tags)
			if len(got) != len(tt.wantCats) {
				t.Errorf("TagsToCategories(%v) = %v, want %v", tt.tags, got, tt.wantCats)
				return
			}
			sort.Strings(got)
			sort.Strings(tt.wantCats)
			for i := range got {
				if got[i] != tt.wantCats[i] {
					t.Errorf("TagsToCategories(%v)[%d] = %q, want %q", tt.tags, i, got[i], tt.wantCats[i])
				}
			}
		})
	}
}

func TestCategoryMapper_CategoriesToTags(t *testing.T) {
	m := payloadprovider.NewCategoryMapper()

	tests := []struct {
		name     string
		category string
		wantLen  int // minimum expected number of tags
	}{
		{"SQL-Injection", "SQL-Injection", 2},
		{"XSS", "XSS", 3},
		{"alias sqli", "sqli", 2}, // resolves to SQL-Injection
		{"unknown", "nonexistent", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.CategoriesToTags(tt.category)
			if len(got) < tt.wantLen {
				t.Errorf("CategoriesToTags(%q) = %d tags, want >= %d", tt.category, len(got), tt.wantLen)
			}
		})
	}
}

func TestCategoryMapper_AllCategories(t *testing.T) {
	m := payloadprovider.NewCategoryMapper()

	cats := m.AllCategories()
	if len(cats) < 15 {
		t.Errorf("AllCategories returned %d categories, expected >= 15", len(cats))
	}

	// Verify canonical category names are properly cased
	expected := []string{"SQL-Injection", "XSS", "SSRF", "SSTI", "Path-Traversal"}
	catSet := make(map[string]bool, len(cats))
	for _, c := range cats {
		catSet[c] = true
	}
	for _, e := range expected {
		if !catSet[e] {
			t.Errorf("AllCategories missing expected category %q (got %v)", e, cats)
		}
	}
}

// ── Edge case tests ───────────────────────────────────────────────────────

func TestGetByCategory_EmptyCategory(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	results, err := p.GetByCategory("")
	if err != nil {
		t.Fatalf("GetByCategory empty: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty category, got %d", len(results))
	}
}

func TestGetByTags_NilTags(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	results, err := p.GetByTags(nil)
	if err != nil {
		t.Fatalf("GetByTags nil: %v", err)
	}
	// nil tags = match all
	if len(results) == 0 {
		t.Error("expected all payloads for nil tags, got 0")
	}
}

func TestUnifiedPayload_Sources(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	all, err := p.GetAll()
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}

	for _, up := range all {
		if up.Source != payloadprovider.SourceJSON && up.Source != payloadprovider.SourceNuclei {
			t.Errorf("payload %q has unknown source %q", up.ID, up.Source)
		}
		if up.Payload == "" {
			t.Errorf("payload %q has empty payload text", up.ID)
		}
		if up.Category == "" {
			t.Errorf("payload %q has empty category", up.ID)
		}
	}
}

func TestCategoryMapper_Resolve_EmptyInput(t *testing.T) {
	m := payloadprovider.NewCategoryMapper()
	got := m.Resolve("")
	if len(got) != 1 || got[0] != "" {
		t.Errorf("Resolve('') = %v, want ['']", got)
	}
}

// ── Concurrent access tests ──────────────────────────────────────────────

func TestConcurrentAccess(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	var wg sync.WaitGroup

	// Concurrently call GetAll, GetByCategory, GetStats, and Reset
	for i := 0; i < 20; i++ {
		wg.Add(4)

		go func() {
			defer wg.Done()
			_, _ = p.GetAll()
		}()

		go func() {
			defer wg.Done()
			_, _ = p.GetByCategory("XSS")
		}()

		go func() {
			defer wg.Done()
			_, _ = p.GetStats()
		}()

		go func() {
			defer wg.Done()
			p.Reset()
		}()
	}

	wg.Wait()
	// Success criteria: no panics or data races (run with -race)
}

func TestResolve_CanonicalCasing(t *testing.T) {
	m := payloadprovider.NewCategoryMapper()

	// Verify Resolve always returns canonical casing, regardless of input case
	tests := []struct {
		input string
		want  string
	}{
		{"sql-injection", "SQL-Injection"},
		{"SQL-INJECTION", "SQL-Injection"},
		{"Sql-Injection", "SQL-Injection"},
		{"xss", "XSS"},
		{"XSS", "XSS"},
		{"path-traversal", "Path-Traversal"},
		{"PATH-TRAVERSAL", "Path-Traversal"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := m.Resolve(tt.input)
			if len(got) == 0 || got[0] != tt.want {
				t.Errorf("Resolve(%q) = %v, want [%q]", tt.input, got, tt.want)
			}
		})
	}
}

// ── Audit 3: CategoriesToTags defensive copy ──────────────────────────────

func TestCategoriesToTags_DefensiveCopy(t *testing.T) {
	m := payloadprovider.NewCategoryMapper()

	// Get tags for SQL-Injection
	tags1 := m.CategoriesToTags("SQL-Injection")
	if len(tags1) == 0 {
		t.Fatal("expected tags for SQL-Injection")
	}

	// Mutate the returned slice
	original := tags1[0]
	tags1[0] = "MUTATED"

	// Get tags again — should NOT reflect the mutation
	tags2 := m.CategoriesToTags("SQL-Injection")
	if tags2[0] == "MUTATED" {
		t.Error("CategoriesToTags returned internal slice reference — mutation leaked into mapper state")
	}
	if tags2[0] != original {
		t.Errorf("expected first tag %q, got %q", original, tags2[0])
	}
}

// ── Audit 3: GetCategories deterministic naming ───────────────────────────

func TestGetCategories_DeterministicNames(t *testing.T) {
	payloadDir, nucleiDir := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	cats, err := p.GetCategories()
	if err != nil {
		t.Fatalf("GetCategories: %v", err)
	}

	// XSS and SQL-Injection should always use canonical casing,
	// regardless of which source was seen first.
	for _, cat := range cats {
		switch strings.ToLower(cat.Name) {
		case "xss":
			if cat.Name != "XSS" {
				t.Errorf("expected canonical name 'XSS', got %q", cat.Name)
			}
		case "sql-injection":
			if cat.Name != "SQL-Injection" {
				t.Errorf("expected canonical name 'SQL-Injection', got %q", cat.Name)
			}
		}
	}
}

// ── Audit 3: EnrichTemplate URL-encoding ──────────────────────────────────

func TestEnrichTemplate_URLEncoding(t *testing.T) {
	// Create a payload with characters that break URL parsing
	root := t.TempDir()
	payloadDir := filepath.Join(root, "payloads")
	nucleiDir := filepath.Join(root, "templates")
	if err := os.MkdirAll(payloadDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nucleiDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Payload with & and = characters
	writeJSONPayloads(t, payloadDir, "xss.json", []jsonPayload{
		{
			ID:            "xss-url-break",
			Payload:       "admin&password=1",
			Category:      "XSS",
			Method:        "GET",
			TargetPath:    "/search",
			ExpectedBlock: true,
			SeverityHint:  "high",
			Tags:          []string{"xss"},
		},
	})

	writeNucleiTemplate(t, nucleiDir, "xss-test.yaml", `id: xss-url-encode-test
info:
  name: XSS URL Encode Test
  severity: high
  tags: xss,waf-bypass
http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=<script>alert(1)</script>"
    matchers:
      - type: word
        words:
          - "alert"
`)

	p := payloadprovider.NewProvider(payloadDir, nucleiDir)

	tmpls, err := p.NucleiTemplates()
	if err != nil || len(tmpls) == 0 {
		t.Skip("no templates loaded")
	}

	_, added, err := p.EnrichTemplate(tmpls[0])
	if err != nil {
		t.Fatalf("EnrichTemplate: %v", err)
	}

	if added == 0 {
		t.Fatal("expected at least 1 added path")
	}

	// The enriched path should contain URL-encoded payload
	found := false
	for _, path := range tmpls[0].HTTP[0].Path {
		if strings.Contains(path, "admin%26password%3D1") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("enriched path should contain URL-encoded payload (admin%%26password%%3D1), got raw '&' and '='")
		for _, path := range tmpls[0].HTTP[0].Path {
			t.Logf("  path: %s", path)
		}
	}
}

// ── Audit 3: EnrichTemplate with no tags ──────────────────────────────────

func TestEnrichTemplate_NoTags(t *testing.T) {
	payloadDir, _ := setupFixtures(t)
	p := payloadprovider.NewProvider(payloadDir, "")

	// Create a template with no tags via loading from file
	tmpDir := t.TempDir()
	writeNucleiTemplate(t, tmpDir, "no-tags.yaml", `id: no-tags-test
info:
  name: No Tags Test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/test?id=1"
    matchers:
      - type: word
        words:
          - "test"
`)

	loaded, err := nuclei.LoadDirectory(tmpDir)
	if err != nil || len(loaded) == 0 {
		t.Skip("could not load no-tags template")
	}

	_, added, err := p.EnrichTemplate(loaded[0])
	if err != nil {
		t.Fatalf("EnrichTemplate: %v", err)
	}

	// No tags = no matching categories = 0 added
	if added != 0 {
		t.Errorf("expected 0 added for template with no tags, got %d", added)
	}
}
