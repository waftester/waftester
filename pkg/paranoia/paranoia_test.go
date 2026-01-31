package paranoia

import (
	"testing"
)

func TestLevelString(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{PL1, "PL1"},
		{PL2, "PL2"},
		{PL3, "PL3"},
		{PL4, "PL4"},
		{Level(0), "Unknown"},
		{Level(5), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("Level(%d).String() = %s, want %s", tt.level, got, tt.expected)
		}
	}
}

func TestLevelValid(t *testing.T) {
	tests := []struct {
		level Level
		valid bool
	}{
		{PL1, true},
		{PL2, true},
		{PL3, true},
		{PL4, true},
		{Level(0), false},
		{Level(5), false},
		{Level(-1), false},
	}

	for _, tt := range tests {
		if got := tt.level.Valid(); got != tt.valid {
			t.Errorf("Level(%d).Valid() = %v, want %v", tt.level, got, tt.valid)
		}
	}
}

func TestLevelDescription(t *testing.T) {
	// All valid levels should have non-empty descriptions
	for l := PL1; l <= PL4; l++ {
		desc := l.Description()
		if desc == "" {
			t.Errorf("Level(%d).Description() is empty", l)
		}
		if desc == "Unknown paranoia level" {
			t.Errorf("Level(%d).Description() should not be 'Unknown paranoia level'", l)
		}
	}

	// Invalid level should return unknown
	if Level(0).Description() != "Unknown paranoia level" {
		t.Error("Invalid level should return 'Unknown paranoia level'")
	}
}

func TestLevelRuleCategories(t *testing.T) {
	// PL1 should have base categories
	pl1Cats := PL1.RuleCategories()
	if len(pl1Cats) < 5 {
		t.Errorf("PL1 should have at least 5 categories, got %d", len(pl1Cats))
	}
	if !containsString(pl1Cats, "sqli") {
		t.Error("PL1 should include sqli")
	}
	if !containsString(pl1Cats, "xss") {
		t.Error("PL1 should include xss")
	}

	// Higher levels should have more categories
	pl2Cats := PL2.RuleCategories()
	if len(pl2Cats) <= len(pl1Cats) {
		t.Error("PL2 should have more categories than PL1")
	}
	if !containsString(pl2Cats, "session-fixation") {
		t.Error("PL2 should include session-fixation")
	}

	pl3Cats := PL3.RuleCategories()
	if len(pl3Cats) <= len(pl2Cats) {
		t.Error("PL3 should have more categories than PL2")
	}
	if !containsString(pl3Cats, "ssrf") {
		t.Error("PL3 should include ssrf")
	}

	pl4Cats := PL4.RuleCategories()
	if len(pl4Cats) <= len(pl3Cats) {
		t.Error("PL4 should have more categories than PL3")
	}
	if !containsString(pl4Cats, "nosql") {
		t.Error("PL4 should include nosql")
	}
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func TestDefaultConfig(t *testing.T) {
	for l := PL1; l <= PL4; l++ {
		cfg := DefaultConfig(l)
		if cfg.Level != l {
			t.Errorf("DefaultConfig(%d).Level = %d, want %d", l, cfg.Level, l)
		}
		if !cfg.BlockingMode {
			t.Errorf("DefaultConfig(%d).BlockingMode should be true", l)
		}
		if cfg.ThresholdAnomalyScore <= 0 {
			t.Errorf("DefaultConfig(%d).ThresholdAnomalyScore should be > 0", l)
		}
	}

	// Higher paranoia levels should have lower thresholds
	pl1 := DefaultConfig(PL1)
	pl4 := DefaultConfig(PL4)
	if pl4.ThresholdAnomalyScore >= pl1.ThresholdAnomalyScore {
		t.Error("PL4 should have lower anomaly threshold than PL1")
	}
}

func TestNewConfig(t *testing.T) {
	cfg := NewConfig(PL3,
		WithAnomalyThreshold(10),
		WithBlockingMode(false),
		WithExcludedRules([]int{920350, 932100}),
	)

	if cfg.Level != PL3 {
		t.Errorf("NewConfig level = %d, want PL3", cfg.Level)
	}
	if cfg.ThresholdAnomalyScore != 10 {
		t.Errorf("ThresholdAnomalyScore = %d, want 10", cfg.ThresholdAnomalyScore)
	}
	if cfg.BlockingMode {
		t.Error("BlockingMode should be false")
	}
	if len(cfg.ExcludedRules) != 2 {
		t.Errorf("ExcludedRules should have 2 rules, got %d", len(cfg.ExcludedRules))
	}
}

func TestConfigOptions(t *testing.T) {
	cfg := NewConfig(PL1)

	// WithAnomalyThreshold
	WithAnomalyThreshold(15)(cfg)
	if cfg.ThresholdAnomalyScore != 15 {
		t.Errorf("WithAnomalyThreshold failed, got %d", cfg.ThresholdAnomalyScore)
	}

	// WithBlockingMode
	WithBlockingMode(false)(cfg)
	if cfg.BlockingMode {
		t.Error("WithBlockingMode(false) failed")
	}

	// WithExcludedRules
	WithExcludedRules([]int{1, 2, 3})(cfg)
	if len(cfg.ExcludedRules) != 3 {
		t.Errorf("WithExcludedRules failed, got %d rules", len(cfg.ExcludedRules))
	}
}

func TestTestCase(t *testing.T) {
	tc := TestCase{
		ID:            "sqli-001",
		Description:   "SQL Injection test",
		Payload:       "' OR 1=1--",
		MinLevel:      PL1,
		Category:      "sqli",
		ExpectedAtPL1: true,
		ExpectedAtPL2: true,
		ExpectedAtPL3: true,
		ExpectedAtPL4: true,
	}

	if tc.ID != "sqli-001" {
		t.Error("TestCase ID mismatch")
	}
	if tc.MinLevel != PL1 {
		t.Error("TestCase MinLevel mismatch")
	}
}

func TestTestCaseExpectedBlock(t *testing.T) {
	// PL1 attack - should be blocked at all levels
	pl1Attack := TestCase{
		ExpectedAtPL1: true,
		ExpectedAtPL2: true,
		ExpectedAtPL3: true,
		ExpectedAtPL4: true,
	}

	for l := PL1; l <= PL4; l++ {
		if !pl1Attack.ExpectedBlock(l) {
			t.Errorf("PL1 attack should be blocked at %s", l.String())
		}
	}

	// PL3 attack - should only be blocked at PL3+
	pl3Attack := TestCase{
		ExpectedAtPL1: false,
		ExpectedAtPL2: false,
		ExpectedAtPL3: true,
		ExpectedAtPL4: true,
	}

	if pl3Attack.ExpectedBlock(PL1) {
		t.Error("PL3 attack should not be blocked at PL1")
	}
	if pl3Attack.ExpectedBlock(PL2) {
		t.Error("PL3 attack should not be blocked at PL2")
	}
	if !pl3Attack.ExpectedBlock(PL3) {
		t.Error("PL3 attack should be blocked at PL3")
	}
	if !pl3Attack.ExpectedBlock(PL4) {
		t.Error("PL3 attack should be blocked at PL4")
	}

	// Invalid level
	if pl1Attack.ExpectedBlock(Level(0)) {
		t.Error("Invalid level should return false")
	}
}

func TestResult(t *testing.T) {
	tc := &TestCase{ID: "test-001"}
	r := Result{
		TestCase: tc,
		Level:    PL2,
		Blocked:  true,
		Expected: true,
		Passed:   true,
		Message:  "Test passed",
	}

	if r.TestCase.ID != "test-001" {
		t.Error("Result TestCase mismatch")
	}
	if r.Level != PL2 {
		t.Error("Result Level mismatch")
	}
	if !r.Passed {
		t.Error("Result should be passed")
	}
}

func TestSummary(t *testing.T) {
	s := &Summary{
		Level:          PL2,
		TotalTests:     100,
		Passed:         95,
		Failed:         5,
		FalsePositives: 2,
		FalseNegatives: 3,
	}

	if s.Level != PL2 {
		t.Error("Summary Level mismatch")
	}
	if s.PassRate() != 95.0 {
		t.Errorf("PassRate = %f, want 95.0", s.PassRate())
	}

	// Test zero total
	empty := &Summary{TotalTests: 0}
	if empty.PassRate() != 0 {
		t.Error("PassRate with 0 total should be 0")
	}
}

func TestNewGenerator(t *testing.T) {
	gen := NewGenerator()
	if gen == nil {
		t.Fatal("NewGenerator returned nil")
	}
	if gen.payloads == nil {
		t.Error("Generator payloads map should be initialized")
	}
}

func TestGeneratorAddPayloads(t *testing.T) {
	gen := NewGenerator()
	gen.AddPayloads("sqli", []string{"' OR 1=1--", "1' AND '1'='1"})
	gen.AddPayloads("xss", []string{"<script>alert(1)</script>"})

	// Add more to same category
	gen.AddPayloads("sqli", []string{"UNION SELECT 1,2,3"})

	if len(gen.payloads["sqli"]) != 3 {
		t.Errorf("Expected 3 sqli payloads, got %d", len(gen.payloads["sqli"]))
	}
	if len(gen.payloads["xss"]) != 1 {
		t.Errorf("Expected 1 xss payload, got %d", len(gen.payloads["xss"]))
	}
}

func TestGeneratorGenerateForLevel(t *testing.T) {
	gen := NewGenerator()
	gen.AddPayloads("sqli", []string{"' OR 1=1--"})
	gen.AddPayloads("xss", []string{"<script>"})
	gen.AddPayloads("ssrf", []string{"http://localhost"}) // PL3+

	// PL1 should only have sqli and xss tests
	pl1Tests := gen.GenerateForLevel(PL1)
	if len(pl1Tests) != 2 {
		t.Errorf("PL1 should have 2 tests, got %d", len(pl1Tests))
	}

	// PL3 should have ssrf too
	pl3Tests := gen.GenerateForLevel(PL3)
	if len(pl3Tests) != 3 {
		t.Errorf("PL3 should have 3 tests, got %d", len(pl3Tests))
	}
}

func TestGeneratorGenerateSuite(t *testing.T) {
	gen := NewGenerator()
	gen.AddPayloads("sqli", []string{"' OR 1=1--", "1' AND '1'='1"})
	gen.AddPayloads("xss", []string{"<script>alert(1)</script>"})

	suite := gen.GenerateSuite(PL2)
	if suite == nil {
		t.Fatal("GenerateSuite returned nil")
	}
	if suite.Level != PL2 {
		t.Errorf("Suite Level = %d, want PL2", suite.Level)
	}
	if suite.Name == "" {
		t.Error("Suite Name should not be empty")
	}
	if len(suite.Tests) == 0 {
		t.Error("Suite should have tests")
	}
	if len(suite.Payloads) != 3 {
		t.Errorf("Suite should have 3 payloads, got %d", len(suite.Payloads))
	}
}

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if v.results == nil {
		t.Error("Validator results should be initialized")
	}
}

func TestValidatorAddResult(t *testing.T) {
	v := NewValidator()

	v.AddResult(PL1, Result{Passed: true})
	v.AddResult(PL1, Result{Passed: false})
	v.AddResult(PL2, Result{Passed: true})

	if len(v.results[PL1]) != 2 {
		t.Errorf("Expected 2 PL1 results, got %d", len(v.results[PL1]))
	}
	if len(v.results[PL2]) != 1 {
		t.Errorf("Expected 1 PL2 result, got %d", len(v.results[PL2]))
	}
}

func TestValidatorGetSummary(t *testing.T) {
	v := NewValidator()

	// Add mixed results
	v.AddResult(PL1, Result{Passed: true, Blocked: true, Expected: true})
	v.AddResult(PL1, Result{Passed: true, Blocked: false, Expected: false})
	v.AddResult(PL1, Result{Passed: false, Blocked: true, Expected: false}) // FP
	v.AddResult(PL1, Result{Passed: false, Blocked: false, Expected: true}) // FN

	summary := v.GetSummary(PL1)
	if summary.TotalTests != 4 {
		t.Errorf("TotalTests = %d, want 4", summary.TotalTests)
	}
	if summary.Passed != 2 {
		t.Errorf("Passed = %d, want 2", summary.Passed)
	}
	if summary.Failed != 2 {
		t.Errorf("Failed = %d, want 2", summary.Failed)
	}
	if summary.FalsePositives != 1 {
		t.Errorf("FalsePositives = %d, want 1", summary.FalsePositives)
	}
	if summary.FalseNegatives != 1 {
		t.Errorf("FalseNegatives = %d, want 1", summary.FalseNegatives)
	}
}

func TestValidatorGetResults(t *testing.T) {
	v := NewValidator()
	v.AddResult(PL2, Result{Passed: true})

	results := v.GetResults(PL2)
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	// Empty level
	empty := v.GetResults(PL4)
	if len(empty) != 0 {
		t.Errorf("Expected 0 results for empty level")
	}
}

func TestValidatorAllSummaries(t *testing.T) {
	v := NewValidator()
	v.AddResult(PL1, Result{Passed: true})
	v.AddResult(PL3, Result{Passed: true})

	summaries := v.AllSummaries()
	if len(summaries) != 2 {
		t.Errorf("Expected 2 summaries, got %d", len(summaries))
	}
}

func TestValidatorCompare(t *testing.T) {
	v := NewValidator()

	// Add results for multiple levels
	for i := 0; i < 10; i++ {
		v.AddResult(PL1, Result{Passed: true})
	}
	for i := 0; i < 8; i++ {
		v.AddResult(PL2, Result{Passed: true})
	}
	for i := 0; i < 2; i++ {
		v.AddResult(PL2, Result{Passed: false})
	}

	comparison := v.Compare()
	if comparison == nil {
		t.Fatal("Compare returned nil")
	}
	if len(comparison.Levels) != 2 {
		t.Errorf("Expected 2 levels in comparison, got %d", len(comparison.Levels))
	}
	if comparison.Coverage[PL1] != 100.0 {
		t.Errorf("PL1 coverage = %f, want 100.0", comparison.Coverage[PL1])
	}
	if comparison.Coverage[PL2] != 80.0 {
		t.Errorf("PL2 coverage = %f, want 80.0", comparison.Coverage[PL2])
	}
}

func TestComparisonHighestCoverage(t *testing.T) {
	c := &Comparison{
		Coverage: map[Level]float64{
			PL1: 95.0,
			PL2: 98.0,
			PL3: 90.0,
		},
	}

	if c.HighestCoverage() != PL2 {
		t.Errorf("HighestCoverage = %s, want PL2", c.HighestCoverage().String())
	}
}

func TestComparisonRecommendedLevel(t *testing.T) {
	// Scenario: PL4 has high FP rate, PL3 is acceptable
	c := &Comparison{
		Levels: map[Level]*Summary{
			PL1: {TotalTests: 100, Passed: 100, Failed: 0, FalsePositives: 0},
			PL2: {TotalTests: 100, Passed: 98, Failed: 2, FalsePositives: 1},
			PL3: {TotalTests: 100, Passed: 95, Failed: 5, FalsePositives: 2},
			PL4: {TotalTests: 100, Passed: 80, Failed: 20, FalsePositives: 15},
		},
		Coverage: map[Level]float64{
			PL1: 100.0,
			PL2: 98.0,
			PL3: 95.0,
			PL4: 80.0,
		},
	}

	recommended := c.RecommendedLevel()
	if recommended != PL3 {
		t.Errorf("RecommendedLevel = %s, want PL3", recommended.String())
	}
}

func TestComparisonRecommendedLevelFallback(t *testing.T) {
	// All levels have high FP rate - fallback to PL1
	c := &Comparison{
		Levels: map[Level]*Summary{
			PL1: {TotalTests: 100, Passed: 60, Failed: 40, FalsePositives: 30},
			PL2: {TotalTests: 100, Passed: 50, Failed: 50, FalsePositives: 40},
		},
		Coverage: map[Level]float64{
			PL1: 60.0,
			PL2: 50.0,
		},
	}

	recommended := c.RecommendedLevel()
	if recommended != PL1 {
		t.Errorf("RecommendedLevel = %s, want PL1 fallback", recommended.String())
	}
}

func TestTestSuite(t *testing.T) {
	suite := &TestSuite{
		Level: PL2,
		Name:  "Test Suite",
		Tests: []TestCase{
			{ID: "test-001"},
			{ID: "test-002"},
		},
		Payloads: []string{"payload1", "payload2"},
	}

	if suite.Level != PL2 {
		t.Error("Suite Level mismatch")
	}
	if len(suite.Tests) != 2 {
		t.Error("Suite should have 2 tests")
	}
	if len(suite.Payloads) != 2 {
		t.Error("Suite should have 2 payloads")
	}
}

func TestSetExpectations(t *testing.T) {
	// PL1 category
	tc1 := TestCase{MinLevel: PL1}
	setExpectations(&tc1)
	if !tc1.ExpectedAtPL1 || !tc1.ExpectedAtPL2 || !tc1.ExpectedAtPL3 || !tc1.ExpectedAtPL4 {
		t.Error("PL1 min should be expected at all levels")
	}

	// PL3 category
	tc3 := TestCase{MinLevel: PL3}
	setExpectations(&tc3)
	if tc3.ExpectedAtPL1 || tc3.ExpectedAtPL2 {
		t.Error("PL3 min should not be expected at PL1 or PL2")
	}
	if !tc3.ExpectedAtPL3 || !tc3.ExpectedAtPL4 {
		t.Error("PL3 min should be expected at PL3 and PL4")
	}
}

func TestDetermineMinLevel(t *testing.T) {
	tests := []struct {
		category string
		expected Level
	}{
		{"sqli", PL1},
		{"xss", PL1},
		{"rce", PL1},
		{"session-fixation", PL2},
		{"http-splitting", PL2},
		{"ssrf", PL3},
		{"xxe", PL3},
		{"nosql", PL4},
		{"ldap", PL4},
		{"unknown", PL1},
	}

	for _, tt := range tests {
		got := determineMinLevel(tt.category)
		if got != tt.expected {
			t.Errorf("determineMinLevel(%s) = %s, want %s", tt.category, got.String(), tt.expected.String())
		}
	}
}

func TestGenerateID(t *testing.T) {
	id := generateID("sqli", 1)
	if id != "sqli-001" {
		t.Errorf("generateID = %s, want sqli-001", id)
	}

	id = generateID("xss", 42)
	if id != "xss-042" {
		t.Errorf("generateID = %s, want xss-042", id)
	}

	id = generateID("test", 100)
	if id != "test-100" {
		t.Errorf("generateID = %s, want test-100", id)
	}
}

func TestGenerateDescription(t *testing.T) {
	desc := generateDescription("sqli", "' OR 1=1--")
	if desc != "sqli attack: ' OR 1=1--" {
		t.Errorf("generateDescription mismatch: %s", desc)
	}

	// Test truncation
	longPayload := "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeefffffffff" // 59 chars
	desc = generateDescription("test", longPayload)
	if len(desc) > 70 { // "test attack: " + 50 + "..."
		t.Errorf("Description should be truncated, got %d chars", len(desc))
	}
}
