package payloads

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDatabase(t *testing.T) {
	db := NewDatabase()

	// Should have loaded built-in payloads
	assert.Greater(t, db.Count(), 100, "Should have 100+ payloads")
}

func TestDatabaseCategories(t *testing.T) {
	db := NewDatabase()

	cats := db.Categories()
	assert.NotEmpty(t, cats)

	// Should have common categories
	assert.Contains(t, cats, "sqli")
	assert.Contains(t, cats, "xss")
	assert.Contains(t, cats, "lfi")
	assert.Contains(t, cats, "rce")
}

func TestDatabaseByCategory(t *testing.T) {
	db := NewDatabase()

	sqli := db.ByCategory("sqli")
	assert.NotEmpty(t, sqli)
	assert.Greater(t, len(sqli), 30, "Should have 30+ SQLi payloads")

	xss := db.ByCategory("xss")
	assert.NotEmpty(t, xss)
	assert.Greater(t, len(xss), 30, "Should have 30+ XSS payloads")
}

func TestDatabaseByCategoryCaseInsensitive(t *testing.T) {
	db := NewDatabase()

	sqli1 := db.ByCategory("sqli")
	sqli2 := db.ByCategory("SQLI")
	sqli3 := db.ByCategory("SQLi")

	assert.Equal(t, len(sqli1), len(sqli2))
	assert.Equal(t, len(sqli1), len(sqli3))
}

func TestDatabaseByVendor(t *testing.T) {
	db := NewDatabase()

	vendors := db.Vendors()
	assert.NotEmpty(t, vendors)

	modsec := db.ByVendor("modsecurity")
	assert.NotEmpty(t, modsec)

	mysql := db.ByVendor("mysql")
	assert.NotEmpty(t, mysql)
}

func TestDatabaseByTag(t *testing.T) {
	db := NewDatabase()

	tags := db.Tags()
	assert.NotEmpty(t, tags)

	evasion := db.ByTag("evasion")
	assert.NotEmpty(t, evasion)

	// All evasion payloads should have the evasion tag
	for _, p := range evasion {
		hasEvasionTag := false
		for _, tag := range p.Tags {
			if tag == "evasion" {
				hasEvasionTag = true
				break
			}
		}
		assert.True(t, hasEvasionTag, "Payload %s should have evasion tag", p.ID)
	}
}

func TestDatabaseBySeverity(t *testing.T) {
	db := NewDatabase()

	critical := db.BySeverity("critical")
	assert.NotEmpty(t, critical)

	high := db.BySeverity("high")
	assert.NotEmpty(t, high)
}

func TestDatabaseSearch(t *testing.T) {
	db := NewDatabase()

	// Search for UNION
	results := db.Search("UNION")
	assert.NotEmpty(t, results)

	for _, p := range results {
		combined := strings.ToLower(p.Payload + " " + p.Notes)
		assert.Contains(t, combined, "union", "Search result should contain UNION")
	}

	// Search for passwd
	passwdResults := db.Search("passwd")
	assert.NotEmpty(t, passwdResults)
}

func TestDatabaseFilter(t *testing.T) {
	db := NewDatabase()

	// Filter by category
	sqli := db.Filter(WithCategories("sqli"))
	assert.NotEmpty(t, sqli)
	for _, p := range sqli {
		assert.Equal(t, "sqli", p.Category)
	}

	// Filter by vendor
	modsec := db.Filter(WithVendors("modsecurity"))
	assert.NotEmpty(t, modsec)

	// Filter by tag
	bypass := db.Filter(WithTags("bypass"))
	assert.NotEmpty(t, bypass)

	// Filter evasion only
	evasion := db.Filter(EvasionOnly())
	assert.NotEmpty(t, evasion)
	for _, p := range evasion {
		hasEvasionTag := false
		for _, tag := range p.Tags {
			if tag == "evasion" {
				hasEvasionTag = true
				break
			}
		}
		assert.True(t, hasEvasionTag)
	}

	// Combined filter
	sqliEvasion := db.Filter(WithCategories("sqli"), EvasionOnly())
	assert.NotEmpty(t, sqliEvasion)
	for _, p := range sqliEvasion {
		assert.Equal(t, "sqli", p.Category)
		hasEvasionTag := false
		for _, tag := range p.Tags {
			if tag == "evasion" {
				hasEvasionTag = true
				break
			}
		}
		assert.True(t, hasEvasionTag)
	}
}

func TestDatabaseFilterBySeverity(t *testing.T) {
	db := NewDatabase()

	critical := db.Filter(WithSeverities("critical"))
	assert.NotEmpty(t, critical)

	for _, p := range critical {
		assert.Equal(t, "critical", p.SeverityHint)
	}
}

func TestDatabaseAdd(t *testing.T) {
	db := NewDatabase()
	initialCount := db.Count()

	payload := Payload{
		ID:           "custom-001",
		Payload:      "custom payload",
		Category:     "custom",
		SeverityHint: "low",
		Tags:         []string{"test"},
	}

	db.Add(payload)

	assert.Equal(t, initialCount+1, db.Count())

	custom := db.ByCategory("custom")
	assert.Len(t, custom, 1)
	assert.Equal(t, "custom payload", custom[0].Payload)
}

func TestDatabaseAddBatch(t *testing.T) {
	db := NewDatabase()
	initialCount := db.Count()

	payloads := []Payload{
		{ID: "batch-001", Payload: "batch1", Category: "batch"},
		{ID: "batch-002", Payload: "batch2", Category: "batch"},
		{ID: "batch-003", Payload: "batch3", Category: "batch"},
	}

	db.AddBatch(payloads)

	assert.Equal(t, initialCount+3, db.Count())

	batch := db.ByCategory("batch")
	assert.Len(t, batch, 3)
}

func TestDatabaseAll(t *testing.T) {
	db := NewDatabase()

	all := db.All()
	assert.Equal(t, db.Count(), len(all))
}

func TestDatabaseLoadFromJSON(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}

	jsonData := `[
		{"id": "json-001", "payload": "test1", "category": "test", "severity_hint": "high"},
		{"id": "json-002", "payload": "test2", "category": "test", "severity_hint": "low"}
	]`

	err := db.LoadFromJSON([]byte(jsonData))
	require.NoError(t, err)

	assert.Equal(t, 2, db.Count())
	testPayloads := db.ByCategory("test")
	assert.Len(t, testPayloads, 2)
}

func TestDatabaseLoadFromJSONInvalid(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}

	err := db.LoadFromJSON([]byte("not json"))
	assert.Error(t, err)
}

func TestDatabaseExportJSON(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}

	db.Add(Payload{ID: "export-001", Payload: "test", Category: "export"})

	data, err := db.ExportJSON()
	require.NoError(t, err)

	assert.Contains(t, string(data), "export-001")
	assert.Contains(t, string(data), "test")
}

func TestDefaultDatabase(t *testing.T) {
	db := DefaultDatabase()

	assert.NotNil(t, db)
	assert.Greater(t, db.Count(), 100)
}

func TestPayloadFields(t *testing.T) {
	db := NewDatabase()

	// Get a specific payload to check fields
	sqli := db.ByCategory("sqli")
	require.NotEmpty(t, sqli)

	// Check first payload has required fields
	first := sqli[0]
	assert.NotEmpty(t, first.ID)
	assert.NotEmpty(t, first.Payload)
	assert.NotEmpty(t, first.Category)
	assert.NotEmpty(t, first.Notes)
	assert.NotEmpty(t, first.SeverityHint)
}

func TestEvasionPayloadsExist(t *testing.T) {
	db := NewDatabase()

	evasion := db.ByTag("evasion")
	assert.Greater(t, len(evasion), 20, "Should have 20+ evasion payloads")
}

func TestCriticalPayloadsExist(t *testing.T) {
	db := NewDatabase()

	critical := db.BySeverity("critical")
	assert.Greater(t, len(critical), 50, "Should have 50+ critical payloads")
}

func TestEmptyFilter(t *testing.T) {
	db := NewDatabase()

	// Empty filter should return all payloads
	all := db.Filter()
	assert.Equal(t, db.Count(), len(all))
}

func TestFilterMultipleCategories(t *testing.T) {
	db := NewDatabase()

	sqliAndXss := db.Filter(WithCategories("sqli", "xss"))

	for _, p := range sqliAndXss {
		assert.True(t, p.Category == "sqli" || p.Category == "xss")
	}
}

func TestFilterNonExistentCategory(t *testing.T) {
	db := NewDatabase()

	results := db.Filter(WithCategories("nonexistent"))
	assert.Empty(t, results)
}

func TestPayloadCountByCategory(t *testing.T) {
	db := NewDatabase()

	// Verify minimum counts for each major category
	categories := map[string]int{
		"sqli":  30,
		"xss":   30,
		"lfi":   15,
		"rce":   15,
		"ssrf":  10,
		"xxe":   5,
		"ssti":  10,
		"nosql": 5,
		"ldap":  5,
	}

	for cat, minCount := range categories {
		payloads := db.ByCategory(cat)
		assert.GreaterOrEqual(t, len(payloads), minCount, "Category %s should have at least %d payloads", cat, minCount)
	}
}

func TestDatabase_AllReturnsCopy(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}
	db.Add(Payload{ID: "copy-1", Payload: "test-1", Category: "sqli"})
	db.Add(Payload{ID: "copy-2", Payload: "test-2", Category: "sqli"})

	all := db.All()
	originalLen := len(all)

	// Mutate the returned slice
	all[0].Payload = "MUTATED"

	// Original must be unchanged
	fresh := db.All()
	if fresh[0].Payload == "MUTATED" {
		t.Error("All() returned internal slice — caller mutation leaked into database")
	}
	if len(fresh) != originalLen {
		t.Errorf("database length changed: got %d, want %d", len(fresh), originalLen)
	}
}

func TestDatabase_ByCategoryReturnsCopy(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}
	db.Add(Payload{ID: "cat-copy-1", Payload: "test-1", Category: "sqli"})

	result := db.ByCategory("sqli")
	result[0].Payload = "MUTATED"

	fresh := db.ByCategory("sqli")
	if fresh[0].Payload == "MUTATED" {
		t.Error("ByCategory() returned internal slice — caller mutation leaked into database")
	}
}

func TestDatabase_ByVendorReturnsCopy(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}
	db.Add(Payload{ID: "vnd-copy-1", Payload: "test-1", Category: "sqli", Vendor: "cloudflare"})

	result := db.ByVendor("cloudflare")
	result[0].Payload = "MUTATED"

	fresh := db.ByVendor("cloudflare")
	if fresh[0].Payload == "MUTATED" {
		t.Error("ByVendor() returned internal slice — caller mutation leaked into database")
	}
}

func TestDatabase_ByTagReturnsCopy(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}
	db.Add(Payload{ID: "tag-copy-1", Payload: "test-1", Category: "sqli", Tags: []string{"evasion"}})

	result := db.ByTag("evasion")
	result[0].Payload = "MUTATED"

	fresh := db.ByTag("evasion")
	if fresh[0].Payload == "MUTATED" {
		t.Error("ByTag() returned internal slice — caller mutation leaked into database")
	}
}

func TestDatabase_BySeverityReturnsCopy(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}
	db.Add(Payload{ID: "sev-copy-1", Payload: "test-1", Category: "sqli", SeverityHint: "high"})

	result := db.BySeverity("high")
	result[0].Payload = "MUTATED"

	fresh := db.BySeverity("high")
	if fresh[0].Payload == "MUTATED" {
		t.Error("BySeverity() returned internal slice — caller mutation leaked into database")
	}
}

func TestDatabase_VendorFilterMatchesVendorField(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}
	db.Add(Payload{
		ID:       "vendor-field-1",
		Payload:  "test-vendor-field",
		Category: "sqli",
		Vendor:   "cloudflare",
		Notes:    "some notes without vendor tag",
	})

	// Vendor field match
	results := db.Filter(WithVendors("cloudflare"))
	if len(results) == 0 {
		t.Error("Filter(WithVendors) did not match payload with Vendor field set")
	}

	// Case-insensitive match on Vendor field
	results = db.Filter(WithVendors("CLOUDFLARE"))
	if len(results) == 0 {
		t.Error("Filter(WithVendors) should match case-insensitively on Vendor field")
	}
}

func TestDatabase_VendorFilterNotesFallback(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}
	// Payload with NO Vendor field, only Notes tag
	db.Add(Payload{
		ID:       "vendor-notes-1",
		Payload:  "test-notes-vendor",
		Category: "sqli",
		Notes:    "vendor:modsecurity bypass technique",
	})

	results := db.Filter(WithVendors("modsecurity"))
	if len(results) == 0 {
		t.Error("Filter(WithVendors) should fall back to Notes vendor: tags")
	}

	// Should NOT match a different vendor
	results = db.Filter(WithVendors("akamai"))
	if len(results) != 0 {
		t.Error("Filter(WithVendors) matched wrong vendor via Notes fallback")
	}
}

func TestDatabase_ConcurrentAccess(t *testing.T) {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}

	// Pre-populate
	for i := 0; i < 100; i++ {
		db.Add(Payload{
			ID:           fmt.Sprintf("pre-%d", i),
			Payload:      fmt.Sprintf("test-%d", i),
			Category:     "sqli",
			Vendor:       "cloudflare",
			Tags:         []string{"evasion"},
			SeverityHint: "high",
		})
	}

	var wg sync.WaitGroup

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			db.Add(Payload{
				ID:       fmt.Sprintf("concurrent-%d", i),
				Payload:  fmt.Sprintf("concurrent-%d", i),
				Category: "xss",
				Vendor:   "akamai",
			})
		}
	}()

	// Reader goroutines — exercise all read methods
	for _, fn := range []func(){
		func() { db.Categories() },
		func() { db.Vendors() },
		func() { db.Tags() },
		func() { db.Search("test") },
		func() { db.Filter(WithCategories("sqli")) },
		func() { db.All() },
		func() { db.ByCategory("sqli") },
		func() { db.ByVendor("cloudflare") },
		func() { db.ByTag("evasion") },
		func() { db.BySeverity("high") },
		func() { db.Count() },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				fn()
			}
		}()
	}

	wg.Wait()
}
