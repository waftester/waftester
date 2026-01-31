package overrides

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActionValid(t *testing.T) {
	tests := []struct {
		action Action
		valid  bool
	}{
		{Skip, true},
		{Modify, true},
		{Invert, true},
		{Force, true},
		{Action("invalid"), false},
		{Action(""), false},
	}

	for _, tt := range tests {
		if got := tt.action.Valid(); got != tt.valid {
			t.Errorf("Action(%q).Valid() = %v, want %v", tt.action, got, tt.valid)
		}
	}
}

func TestMatcherCompile(t *testing.T) {
	// Valid patterns
	m := &Matcher{
		TestIDPattern:  "^sqli-.*",
		PayloadPattern: "(?i)select.*from",
		PathPattern:    "/api/.*",
	}

	if err := m.Compile(); err != nil {
		t.Errorf("Valid patterns should compile: %v", err)
	}

	if m.testIDRegex == nil {
		t.Error("testIDRegex should be compiled")
	}
	if m.payloadRegex == nil {
		t.Error("payloadRegex should be compiled")
	}
	if m.pathRegex == nil {
		t.Error("pathRegex should be compiled")
	}
}

func TestMatcherCompileInvalid(t *testing.T) {
	tests := []struct {
		name    string
		matcher *Matcher
	}{
		{"invalid test_id_pattern", &Matcher{TestIDPattern: "[invalid"}},
		{"invalid payload_pattern", &Matcher{PayloadPattern: "(unclosed"}},
		{"invalid path_pattern", &Matcher{PathPattern: "*bad*"}},
	}

	for _, tt := range tests {
		if err := tt.matcher.Compile(); err == nil {
			t.Errorf("%s: expected compile error", tt.name)
		}
	}
}

func TestMatcherMatchesTestID(t *testing.T) {
	m := &Matcher{TestID: []string{"test-001", "test-002"}}

	test1 := &Test{ID: "test-001"}
	test2 := &Test{ID: "test-003"}

	if !m.Matches(test1) {
		t.Error("Should match test-001")
	}
	if m.Matches(test2) {
		t.Error("Should not match test-003")
	}
}

func TestMatcherMatchesTestIDPattern(t *testing.T) {
	m := &Matcher{TestIDPattern: "^sqli-.*"}
	m.Compile()

	test1 := &Test{ID: "sqli-001"}
	test2 := &Test{ID: "xss-001"}

	if !m.Matches(test1) {
		t.Error("Should match sqli-001")
	}
	if m.Matches(test2) {
		t.Error("Should not match xss-001")
	}
}

func TestMatcherMatchesCategory(t *testing.T) {
	m := &Matcher{Category: []string{"sqli", "xss"}}

	test1 := &Test{Category: "sqli"}
	test2 := &Test{Category: "rce"}

	if !m.Matches(test1) {
		t.Error("Should match sqli category")
	}
	if m.Matches(test2) {
		t.Error("Should not match rce category")
	}
}

func TestMatcherMatchesTags(t *testing.T) {
	m := &Matcher{Tags: []string{"slow", "flaky"}}

	test1 := &Test{Tags: []string{"fast", "slow"}}
	test2 := &Test{Tags: []string{"fast", "stable"}}

	if !m.Matches(test1) {
		t.Error("Should match test with 'slow' tag")
	}
	if m.Matches(test2) {
		t.Error("Should not match test without matching tags")
	}
}

func TestMatcherMatchesPayload(t *testing.T) {
	m := &Matcher{Payload: "' OR 1=1"}

	test1 := &Test{Payload: "admin' OR 1=1--"}
	test2 := &Test{Payload: "normal input"}

	if !m.Matches(test1) {
		t.Error("Should match payload containing substring")
	}
	if m.Matches(test2) {
		t.Error("Should not match payload without substring")
	}
}

func TestMatcherMatchesPayloadPattern(t *testing.T) {
	m := &Matcher{PayloadPattern: "(?i)union.*select"}
	m.Compile()

	test1 := &Test{Payload: "1 UNION SELECT 1,2,3"}
	test2 := &Test{Payload: "normal input"}

	if !m.Matches(test1) {
		t.Error("Should match union select pattern")
	}
	if m.Matches(test2) {
		t.Error("Should not match normal input")
	}
}

func TestMatcherMatchesMethod(t *testing.T) {
	m := &Matcher{Method: []string{"POST", "PUT"}}

	test1 := &Test{Method: "post"} // Case insensitive
	test2 := &Test{Method: "GET"}

	if !m.Matches(test1) {
		t.Error("Should match POST (case insensitive)")
	}
	if m.Matches(test2) {
		t.Error("Should not match GET")
	}
}

func TestMatcherMatchesPath(t *testing.T) {
	m := &Matcher{Path: []string{"/api/users", "/api/admin"}}

	test1 := &Test{Path: "/api/users"}
	test2 := &Test{Path: "/api/products"}

	if !m.Matches(test1) {
		t.Error("Should match /api/users")
	}
	if m.Matches(test2) {
		t.Error("Should not match /api/products")
	}
}

func TestMatcherMatchesPathPattern(t *testing.T) {
	m := &Matcher{PathPattern: "^/admin/.*"}
	m.Compile()

	test1 := &Test{Path: "/admin/users"}
	test2 := &Test{Path: "/api/users"}

	if !m.Matches(test1) {
		t.Error("Should match /admin/ paths")
	}
	if m.Matches(test2) {
		t.Error("Should not match /api/ paths")
	}
}

func TestMatcherEmpty(t *testing.T) {
	m := &Matcher{}

	test := &Test{ID: "test-001"}

	if m.Matches(test) {
		t.Error("Empty matcher should not match anything")
	}
}

func TestMatcherNilTest(t *testing.T) {
	m := &Matcher{TestID: []string{"test-001"}}

	if m.Matches(nil) {
		t.Error("Should not match nil test")
	}
}

func TestModifications(t *testing.T) {
	payload := "new payload"
	method := "PUT"
	path := "/new/path"
	expectBlock := true

	m := &Modifications{
		ExpectBlock: &expectBlock,
		Payload:     &payload,
		Method:      &method,
		Path:        &path,
		Headers:     map[string]string{"X-Custom": "value"},
		AddTags:     []string{"modified"},
		RemoveTags:  []string{"original"},
	}

	if *m.ExpectBlock != true {
		t.Error("ExpectBlock should be true")
	}
	if *m.Payload != "new payload" {
		t.Error("Payload mismatch")
	}
	if *m.Method != "PUT" {
		t.Error("Method mismatch")
	}
	if *m.Path != "/new/path" {
		t.Error("Path mismatch")
	}
	if len(m.Headers) != 1 {
		t.Error("Headers should have 1 entry")
	}
	if len(m.AddTags) != 1 {
		t.Error("AddTags should have 1 entry")
	}
	if len(m.RemoveTags) != 1 {
		t.Error("RemoveTags should have 1 entry")
	}
}

func TestOverride(t *testing.T) {
	o := &Override{
		ID:          "skip-flaky",
		Description: "Skip flaky tests",
		Matcher:     &Matcher{Tags: []string{"flaky"}},
		Action:      Skip,
		Priority:    10,
		Enabled:     true,
	}

	if o.ID != "skip-flaky" {
		t.Error("ID mismatch")
	}
	if o.Action != Skip {
		t.Error("Action should be Skip")
	}
	if o.Priority != 10 {
		t.Error("Priority mismatch")
	}
	if !o.Enabled {
		t.Error("Should be enabled")
	}
}

func TestNewConfig(t *testing.T) {
	cfg := NewConfig()

	if cfg == nil {
		t.Fatal("NewConfig returned nil")
	}
	if cfg.Version != "1.0" {
		t.Errorf("Version = %s, want 1.0", cfg.Version)
	}
	if cfg.Overrides == nil {
		t.Error("Overrides should be initialized")
	}
}

func TestConfigAdd(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{ID: "test-1", Action: Skip, Matcher: &Matcher{}, Enabled: true})
	cfg.Add(&Override{ID: "test-2", Action: Modify, Matcher: &Matcher{}, Modifications: &Modifications{}, Enabled: true})

	if len(cfg.Overrides) != 2 {
		t.Errorf("Expected 2 overrides, got %d", len(cfg.Overrides))
	}
}

func TestConfigValidate(t *testing.T) {
	// Valid config
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "valid",
		Action:  Skip,
		Matcher: &Matcher{TestID: []string{"test-1"}},
		Enabled: true,
	})

	if err := cfg.Validate(); err != nil {
		t.Errorf("Valid config should not error: %v", err)
	}
}

func TestConfigValidateNoID(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		Action:  Skip,
		Matcher: &Matcher{},
		Enabled: true,
	})

	if err := cfg.Validate(); err == nil {
		t.Error("Should error on missing ID")
	}
}

func TestConfigValidateInvalidAction(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "test",
		Action:  Action("invalid"),
		Matcher: &Matcher{},
		Enabled: true,
	})

	if err := cfg.Validate(); err == nil {
		t.Error("Should error on invalid action")
	}
}

func TestConfigValidateNoMatcher(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "test",
		Action:  Skip,
		Enabled: true,
	})

	if err := cfg.Validate(); err == nil {
		t.Error("Should error on missing matcher")
	}
}

func TestConfigValidateModifyWithoutModifications(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "test",
		Action:  Modify,
		Matcher: &Matcher{TestID: []string{"test-1"}},
		Enabled: true,
	})

	if err := cfg.Validate(); err == nil {
		t.Error("Should error on modify action without modifications")
	}
}

func TestConfigEnabledOverrides(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{ID: "enabled", Enabled: true, Action: Skip, Matcher: &Matcher{}})
	cfg.Add(&Override{ID: "disabled", Enabled: false, Action: Skip, Matcher: &Matcher{}})
	cfg.Add(&Override{ID: "enabled2", Enabled: true, Action: Skip, Matcher: &Matcher{}})

	enabled := cfg.EnabledOverrides()
	if len(enabled) != 2 {
		t.Errorf("Expected 2 enabled overrides, got %d", len(enabled))
	}
}

func TestLoadFromReader(t *testing.T) {
	yaml := `
version: "1.0"
overrides:
  - id: skip-flaky
    description: Skip flaky tests
    match:
      tags: [flaky]
    action: skip
    enabled: true
`
	cfg, err := Load(strings.NewReader(yaml), "test.yaml")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(cfg.Overrides) != 1 {
		t.Fatalf("Expected 1 override, got %d", len(cfg.Overrides))
	}

	o := cfg.Overrides[0]
	if o.ID != "skip-flaky" {
		t.Errorf("ID = %s, want skip-flaky", o.ID)
	}
	if o.Action != Skip {
		t.Errorf("Action = %s, want skip", o.Action)
	}
}

func TestLoadJSON(t *testing.T) {
	json := `{
  "version": "1.0",
  "overrides": [
    {
      "id": "test-override",
      "match": {"test_id": ["test-001"]},
      "action": "invert",
      "enabled": true
    }
  ]
}`
	cfg, err := Load(strings.NewReader(json), "test.json")
	if err != nil {
		t.Fatalf("Load JSON failed: %v", err)
	}

	if len(cfg.Overrides) != 1 {
		t.Fatalf("Expected 1 override")
	}
	if cfg.Overrides[0].Action != Invert {
		t.Error("Action should be invert")
	}
}

func TestLoadFromFileYAML(t *testing.T) {
	content := `
version: "1.0"
overrides:
  - id: test-1
    match:
      category: [sqli]
    action: skip
    enabled: true
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "overrides.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if len(cfg.Overrides) != 1 {
		t.Error("Expected 1 override")
	}
}

func TestLoadFromFileNotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/file.yaml")
	if err == nil {
		t.Error("Should error on nonexistent file")
	}
}

func TestSaveToFile(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "test",
		Action:  Skip,
		Matcher: &Matcher{TestID: []string{"test-001"}},
		Enabled: true,
	})

	// Test YAML
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "overrides.yaml")
	if err := cfg.SaveToFile(yamlPath); err != nil {
		t.Fatalf("SaveToFile YAML failed: %v", err)
	}

	loaded, err := LoadFromFile(yamlPath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if len(loaded.Overrides) != 1 {
		t.Error("Loaded config should have 1 override")
	}

	// Test JSON
	jsonPath := filepath.Join(tmpDir, "overrides.json")
	if err := cfg.SaveToFile(jsonPath); err != nil {
		t.Fatalf("SaveToFile JSON failed: %v", err)
	}

	loadedJSON, err := LoadFromFile(jsonPath)
	if err != nil {
		t.Fatalf("LoadFromFile JSON failed: %v", err)
	}
	if len(loadedJSON.Overrides) != 1 {
		t.Error("Loaded JSON config should have 1 override")
	}
}

func TestNewEngine(t *testing.T) {
	cfg := NewConfig()
	engine := NewEngine(cfg)

	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
	if engine.config != cfg {
		t.Error("Engine config mismatch")
	}
}

func TestEngineApplySkip(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:          "skip-flaky",
		Description: "Skip flaky tests",
		Action:      Skip,
		Matcher:     &Matcher{Tags: []string{"flaky"}},
		Enabled:     true,
	})
	cfg.Compile()

	engine := NewEngine(cfg)
	test := &Test{ID: "test-001", Tags: []string{"flaky"}}

	result := engine.Apply(test)
	if !result.Skipped {
		t.Error("Test should be skipped")
	}
	if result.SkipReason != "Skip flaky tests" {
		t.Errorf("SkipReason = %s", result.SkipReason)
	}
	if len(result.AppliedOverrides) != 1 {
		t.Error("Should have 1 applied override")
	}
}

func TestEngineApplyModify(t *testing.T) {
	newPayload := "modified payload"
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "modify-sqli",
		Action:  Modify,
		Matcher: &Matcher{Category: []string{"sqli"}},
		Modifications: &Modifications{
			Payload: &newPayload,
			AddTags: []string{"modified"},
		},
		Enabled: true,
	})
	cfg.Compile()

	engine := NewEngine(cfg)
	test := &Test{ID: "test-001", Category: "sqli", Payload: "original", Tags: []string{}}

	result := engine.Apply(test)
	if !result.Modified {
		t.Error("Test should be modified")
	}
	if test.Payload != "modified payload" {
		t.Errorf("Payload = %s, want 'modified payload'", test.Payload)
	}
	if !containsString(test.Tags, "modified") {
		t.Error("Test should have 'modified' tag")
	}
}

func TestEngineApplyInvert(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "invert-fp",
		Action:  Invert,
		Matcher: &Matcher{Tags: []string{"false-positive"}},
		Enabled: true,
	})
	cfg.Compile()

	engine := NewEngine(cfg)
	test := &Test{ID: "test-001", Tags: []string{"false-positive"}}

	result := engine.Apply(test)
	if !result.Inverted {
		t.Error("Test should be inverted")
	}
}

func TestEngineApplyForce(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "force-critical",
		Action:  Force,
		Matcher: &Matcher{Tags: []string{"critical"}},
		Enabled: true,
	})
	cfg.Compile()

	engine := NewEngine(cfg)
	test := &Test{ID: "test-001", Tags: []string{"critical"}}

	result := engine.Apply(test)
	if !result.Forced {
		t.Error("Test should be forced")
	}
}

func TestEngineApplyPriority(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:       "low-priority",
		Action:   Skip,
		Matcher:  &Matcher{TestID: []string{"test-001"}},
		Priority: 1,
		Enabled:  true,
	})
	cfg.Add(&Override{
		ID:       "high-priority",
		Action:   Force,
		Matcher:  &Matcher{TestID: []string{"test-001"}},
		Priority: 10,
		Enabled:  true,
	})
	cfg.Compile()

	engine := NewEngine(cfg)
	test := &Test{ID: "test-001"}

	result := engine.Apply(test)
	// High priority should be applied first
	if len(result.AppliedOverrides) != 2 {
		t.Errorf("Should have 2 applied overrides, got %d", len(result.AppliedOverrides))
	}
	if result.AppliedOverrides[0] != "high-priority" {
		t.Error("High priority should be first")
	}
}

func TestEngineApplyNoMatch(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "skip-flaky",
		Action:  Skip,
		Matcher: &Matcher{Tags: []string{"flaky"}},
		Enabled: true,
	})

	engine := NewEngine(cfg)
	test := &Test{ID: "test-001", Tags: []string{"stable"}}

	result := engine.Apply(test)
	if result.Skipped {
		t.Error("Test should not be skipped")
	}
	if len(result.AppliedOverrides) != 0 {
		t.Error("Should have no applied overrides")
	}
}

func TestEngineApplyDisabled(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "disabled-override",
		Action:  Skip,
		Matcher: &Matcher{TestID: []string{"test-001"}},
		Enabled: false, // Disabled
	})

	engine := NewEngine(cfg)
	test := &Test{ID: "test-001"}

	result := engine.Apply(test)
	if result.Skipped {
		t.Error("Disabled override should not skip test")
	}
}

func TestEngineApplyToAll(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "skip-xss",
		Action:  Skip,
		Matcher: &Matcher{Category: []string{"xss"}},
		Enabled: true,
	})
	cfg.Compile()

	engine := NewEngine(cfg)
	tests := []*Test{
		{ID: "test-1", Category: "sqli"},
		{ID: "test-2", Category: "xss"},
		{ID: "test-3", Category: "xss"},
	}

	results := engine.ApplyToAll(tests)
	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	skipped := 0
	for _, r := range results {
		if r.Skipped {
			skipped++
		}
	}
	if skipped != 2 {
		t.Errorf("Expected 2 skipped tests, got %d", skipped)
	}
}

func TestEngineFilter(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "skip-slow",
		Action:  Skip,
		Matcher: &Matcher{Tags: []string{"slow"}},
		Enabled: true,
	})
	cfg.Compile()

	engine := NewEngine(cfg)
	tests := []*Test{
		{ID: "test-1", Tags: []string{"fast"}},
		{ID: "test-2", Tags: []string{"slow"}},
		{ID: "test-3", Tags: []string{"fast"}},
	}

	filtered := engine.Filter(tests)
	if len(filtered) != 2 {
		t.Errorf("Expected 2 filtered tests, got %d", len(filtered))
	}
}

func TestEngineFilterForced(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:       "skip-all",
		Action:   Skip,
		Matcher:  &Matcher{Category: []string{"sqli"}},
		Priority: 1,
		Enabled:  true,
	})
	cfg.Add(&Override{
		ID:       "force-critical",
		Action:   Force,
		Matcher:  &Matcher{Tags: []string{"critical"}},
		Priority: 10,
		Enabled:  true,
	})
	cfg.Compile()

	engine := NewEngine(cfg)
	tests := []*Test{
		{ID: "test-1", Category: "sqli", Tags: []string{"normal"}},
		{ID: "test-2", Category: "sqli", Tags: []string{"critical"}}, // Should run despite skip
	}

	filtered := engine.Filter(tests)
	if len(filtered) != 1 {
		t.Errorf("Expected 1 filtered test (forced), got %d", len(filtered))
	}
	if filtered[0].ID != "test-2" {
		t.Error("Forced test should be included")
	}
}

func TestEngineGetStats(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "skip-slow",
		Action:  Skip,
		Matcher: &Matcher{Tags: []string{"slow"}},
		Enabled: true,
	})
	cfg.Add(&Override{
		ID:      "invert-fp",
		Action:  Invert,
		Matcher: &Matcher{Tags: []string{"fp"}},
		Enabled: true,
	})
	cfg.Compile()

	engine := NewEngine(cfg)
	tests := []*Test{
		{ID: "test-1", Tags: []string{}},
		{ID: "test-2", Tags: []string{"slow"}},
		{ID: "test-3", Tags: []string{"fp"}},
		{ID: "test-4", Tags: []string{"slow", "fp"}},
	}

	stats := engine.GetStats(tests)
	if stats.TotalTests != 4 {
		t.Errorf("TotalTests = %d, want 4", stats.TotalTests)
	}
	if stats.SkippedTests != 2 {
		t.Errorf("SkippedTests = %d, want 2", stats.SkippedTests)
	}
	if stats.InvertedTests != 2 {
		t.Errorf("InvertedTests = %d, want 2", stats.InvertedTests)
	}
	if stats.OverrideMatches["skip-slow"] != 2 {
		t.Errorf("skip-slow matches = %d, want 2", stats.OverrideMatches["skip-slow"])
	}
}

func TestResult(t *testing.T) {
	test := &Test{ID: "test-001"}
	result := &Result{
		Test:             test,
		Skipped:          true,
		SkipReason:       "Flaky test",
		Modified:         false,
		Inverted:         false,
		Forced:           false,
		AppliedOverrides: []string{"skip-flaky"},
	}

	if result.Test.ID != "test-001" {
		t.Error("Test ID mismatch")
	}
	if !result.Skipped {
		t.Error("Should be skipped")
	}
	if result.SkipReason != "Flaky test" {
		t.Error("SkipReason mismatch")
	}
	if len(result.AppliedOverrides) != 1 {
		t.Error("Should have 1 applied override")
	}
}

func TestStats(t *testing.T) {
	stats := &Stats{
		TotalTests:    100,
		SkippedTests:  10,
		ModifiedTests: 5,
		InvertedTests: 3,
		ForcedTests:   2,
		OverrideMatches: map[string]int{
			"skip-slow":   10,
			"modify-sqli": 5,
		},
	}

	if stats.TotalTests != 100 {
		t.Error("TotalTests mismatch")
	}
	if stats.SkippedTests != 10 {
		t.Error("SkippedTests mismatch")
	}
	if len(stats.OverrideMatches) != 2 {
		t.Error("OverrideMatches should have 2 entries")
	}
}

func TestApplyModificationsRemoveTags(t *testing.T) {
	cfg := NewConfig()
	cfg.Add(&Override{
		ID:      "remove-slow",
		Action:  Modify,
		Matcher: &Matcher{TestID: []string{"test-001"}},
		Modifications: &Modifications{
			RemoveTags: []string{"slow"},
		},
		Enabled: true,
	})
	cfg.Compile()

	engine := NewEngine(cfg)
	test := &Test{ID: "test-001", Tags: []string{"slow", "important"}}

	engine.Apply(test)
	if containsString(test.Tags, "slow") {
		t.Error("'slow' tag should be removed")
	}
	if !containsString(test.Tags, "important") {
		t.Error("'important' tag should remain")
	}
}

func TestSortByPriority(t *testing.T) {
	overrides := []*Override{
		{ID: "low", Priority: 1},
		{ID: "high", Priority: 10},
		{ID: "medium", Priority: 5},
	}

	sortByPriority(overrides)

	if overrides[0].ID != "high" {
		t.Error("High priority should be first")
	}
	if overrides[1].ID != "medium" {
		t.Error("Medium priority should be second")
	}
	if overrides[2].ID != "low" {
		t.Error("Low priority should be last")
	}
}

func TestContainsString(t *testing.T) {
	slice := []string{"a", "b", "c"}

	if !containsString(slice, "b") {
		t.Error("Should contain 'b'")
	}
	if containsString(slice, "d") {
		t.Error("Should not contain 'd'")
	}
}

func TestRemoveString(t *testing.T) {
	slice := []string{"a", "b", "c"}

	result := removeString(slice, "b")
	if len(result) != 2 {
		t.Errorf("Expected 2 elements, got %d", len(result))
	}
	if containsString(result, "b") {
		t.Error("'b' should be removed")
	}

	// Remove non-existent
	result = removeString(slice, "d")
	if len(result) != 3 {
		t.Error("Removing non-existent should not change length")
	}
}

func TestTest(t *testing.T) {
	test := &Test{
		ID:       "test-001",
		Category: "sqli",
		Tags:     []string{"critical", "regression"},
		Payload:  "' OR 1=1--",
		Method:   "POST",
		Path:     "/api/login",
	}

	if test.ID != "test-001" {
		t.Error("ID mismatch")
	}
	if test.Category != "sqli" {
		t.Error("Category mismatch")
	}
	if len(test.Tags) != 2 {
		t.Error("Tags should have 2 elements")
	}
	if test.Payload != "' OR 1=1--" {
		t.Error("Payload mismatch")
	}
	if test.Method != "POST" {
		t.Error("Method mismatch")
	}
	if test.Path != "/api/login" {
		t.Error("Path mismatch")
	}
}
