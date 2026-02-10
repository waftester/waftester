package falsepositive

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waftester/waftester/pkg/finding"
)

func TestCategoryConstants(t *testing.T) {
	assert.Equal(t, Category("known"), CategoryKnown)
	assert.Equal(t, Category("suspected"), CategorySuspected)
	assert.Equal(t, Category("confirmed"), CategoryConfirmed)
	assert.Equal(t, Category("dismissed"), CategoryDismissed)
}

func TestSeverityConstants(t *testing.T) {
	assert.Equal(t, finding.Severity("low"), finding.Low)
	assert.Equal(t, finding.Severity("medium"), finding.Medium)
	assert.Equal(t, finding.Severity("high"), finding.High)
	assert.Equal(t, finding.Severity("critical"), finding.Critical)
}

func TestFalsePositiveFingerprint(t *testing.T) {
	fp1 := &FalsePositive{
		RuleID:   "942100",
		Payload:  "' OR '1'='1",
		Endpoint: "/api/search",
		Method:   "GET",
	}

	fp2 := &FalsePositive{
		RuleID:   "942100",
		Payload:  "' OR '1'='1",
		Endpoint: "/api/search",
		Method:   "GET",
	}

	fp3 := &FalsePositive{
		RuleID:   "942100",
		Payload:  "' OR '1'='1",
		Endpoint: "/api/other",
		Method:   "GET",
	}

	assert.Equal(t, fp1.Fingerprint(), fp2.Fingerprint())
	assert.NotEqual(t, fp1.Fingerprint(), fp3.Fingerprint())
}

func TestFalsePositiveIsRecent(t *testing.T) {
	fp := &FalsePositive{
		LastSeen: time.Now(),
	}
	assert.True(t, fp.IsRecent(1*time.Hour))

	fp2 := &FalsePositive{
		LastSeen: time.Now().Add(-2 * time.Hour),
	}
	assert.False(t, fp2.IsRecent(1*time.Hour))
}

func TestPatternMatches(t *testing.T) {
	pattern := &Pattern{
		ID:      "test",
		Enabled: true,
		RuleIDs: []string{"942100"},
		Methods: []string{"GET", "POST"},
	}

	result := &TestResult{
		RuleID: "942100",
		Method: "GET",
	}
	assert.True(t, pattern.Matches(result))

	result2 := &TestResult{
		RuleID: "941100",
		Method: "GET",
	}
	assert.False(t, pattern.Matches(result2))

	pattern.Enabled = false
	assert.False(t, pattern.Matches(result))
}

func TestPatternMatchesEndpoints(t *testing.T) {
	pattern := &Pattern{
		ID:        "test",
		Enabled:   true,
		Endpoints: []string{"/api/"},
	}

	result := &TestResult{
		Endpoint: "/api/users",
		Method:   "GET",
	}
	assert.True(t, pattern.Matches(result))

	result2 := &TestResult{
		Endpoint: "/admin/users",
		Method:   "GET",
	}
	assert.False(t, pattern.Matches(result2))
}

func TestTestResultIsFalsePositive(t *testing.T) {
	result := &TestResult{
		Blocked:     true,
		ExpectBlock: false,
	}
	assert.True(t, result.IsFalsePositive())
	assert.False(t, result.IsFalseNegative())

	result2 := &TestResult{
		Blocked:     false,
		ExpectBlock: true,
	}
	assert.False(t, result2.IsFalsePositive())
	assert.True(t, result2.IsFalseNegative())
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.True(t, config.EnablePatterns)
	assert.True(t, config.EnableHeuristics)
	assert.Equal(t, 0.8, config.SimilarityThresh)
	assert.Equal(t, 24*time.Hour, config.RecentThreshold)
}

func TestNewDetector(t *testing.T) {
	detector := NewDetector(nil)
	assert.NotNil(t, detector)
	assert.NotNil(t, detector.patterns)
	assert.NotNil(t, detector.knownFPs)
	assert.NotNil(t, detector.config)
}

func TestDetectorAddPattern(t *testing.T) {
	detector := NewDetector(nil)
	pattern := &Pattern{ID: "test", Enabled: true}
	detector.AddPattern(pattern)
	assert.Len(t, detector.patterns, 1)
}

func TestDetectorAddKnownFP(t *testing.T) {
	detector := NewDetector(nil)
	fp := &FalsePositive{
		RuleID:   "942100",
		Payload:  "test",
		Endpoint: "/",
		Method:   "GET",
	}
	detector.AddKnownFP(fp)
	assert.Len(t, detector.knownFPs, 1)
}

func TestDetectorAnalyze(t *testing.T) {
	detector := NewDetector(nil)

	results := []*TestResult{
		{
			TestID:      "test-1",
			RuleID:      "942100",
			Payload:     "' OR '1'='1",
			Endpoint:    "/api/search",
			Method:      "GET",
			Blocked:     true,
			ExpectBlock: false, // False positive
		},
		{
			TestID:      "test-2",
			RuleID:      "942100",
			Payload:     "DROP TABLE",
			Endpoint:    "/api/search",
			Method:      "GET",
			Blocked:     true,
			ExpectBlock: true, // True positive
		},
	}

	fps := detector.Analyze(results)
	assert.Len(t, fps, 1) // Only one false positive
}

func TestDetectorWithKnownFP(t *testing.T) {
	detector := NewDetector(nil)

	knownFP := &FalsePositive{
		RuleID:      "942100",
		Payload:     "' OR '1'='1",
		Endpoint:    "/api/search",
		Method:      "GET",
		Category:    CategoryConfirmed,
		Severity:    finding.Low,
		Description: "Known false positive",
		Count:       5,
		FirstSeen:   time.Now().Add(-48 * time.Hour),
	}
	detector.AddKnownFP(knownFP)

	results := []*TestResult{
		{
			TestID:      "test-1",
			RuleID:      "942100",
			Payload:     "' OR '1'='1",
			Endpoint:    "/api/search",
			Method:      "GET",
			Blocked:     true,
			ExpectBlock: false,
		},
	}

	fps := detector.Analyze(results)
	require.Len(t, fps, 1)
	assert.Equal(t, CategoryConfirmed, fps[0].Category)
	assert.Equal(t, 6, fps[0].Count)
}

func TestDetectorWithPattern(t *testing.T) {
	detector := NewDetector(nil)

	pattern := &Pattern{
		ID:          "api-fp",
		Name:        "API False Positive",
		Description: "Known API false positive pattern",
		RuleIDs:     []string{"942100"},
		Endpoints:   []string{"/api/"},
		Enabled:     true,
		Tags:        []string{"api", "known"},
	}
	detector.AddPattern(pattern)

	results := []*TestResult{
		{
			TestID:      "test-1",
			RuleID:      "942100",
			Payload:     "test",
			Endpoint:    "/api/search",
			Method:      "GET",
			Blocked:     true,
			ExpectBlock: false,
		},
	}

	fps := detector.Analyze(results)
	require.Len(t, fps, 1)
	assert.Equal(t, CategoryKnown, fps[0].Category)
	assert.Contains(t, fps[0].Tags, "api")
}

func TestDetectorGetStats(t *testing.T) {
	detector := NewDetector(nil)

	fp1 := &FalsePositive{RuleID: "1", Payload: "a", Endpoint: "/a", Method: "GET", Category: CategoryKnown, Severity: finding.Low}
	fp2 := &FalsePositive{RuleID: "2", Payload: "b", Endpoint: "/b", Method: "GET", Category: CategoryConfirmed, Severity: finding.High}
	detector.AddKnownFP(fp1)
	detector.AddKnownFP(fp2)

	stats := detector.GetStats()
	assert.Equal(t, 2, stats.KnownFPs)
	assert.Equal(t, 1, stats.ByCategory[CategoryKnown])
	assert.Equal(t, 1, stats.BySeverity[finding.High])
}

func TestNewDatabase(t *testing.T) {
	db := NewDatabase()
	assert.NotNil(t, db)
	assert.Empty(t, db.FalsePositives)
}

func TestDatabaseAdd(t *testing.T) {
	db := NewDatabase()
	fp := &FalsePositive{
		RuleID:   "942100",
		Payload:  "test",
		Endpoint: "/api",
		Method:   "GET",
	}

	db.Add(fp)
	assert.Equal(t, 1, db.Count())

	// Add duplicate
	db.Add(fp)
	assert.Equal(t, 1, db.Count()) // Should not add duplicate
}

func TestDatabaseAddPattern(t *testing.T) {
	db := NewDatabase()
	pattern := &Pattern{ID: "test"}
	db.AddPattern(pattern)
	assert.Len(t, db.Patterns, 1)
}

func TestDatabaseGet(t *testing.T) {
	db := NewDatabase()
	fp := &FalsePositive{
		RuleID:   "942100",
		Payload:  "test",
		Endpoint: "/api",
		Method:   "GET",
	}

	db.Add(fp)

	found := db.Get(fp.Fingerprint())
	assert.NotNil(t, found)

	notFound := db.Get("nonexistent")
	assert.Nil(t, notFound)
}

func TestDatabaseList(t *testing.T) {
	db := NewDatabase()
	fp1 := &FalsePositive{RuleID: "1", Payload: "a", Endpoint: "/a", Method: "GET"}
	fp2 := &FalsePositive{RuleID: "2", Payload: "b", Endpoint: "/b", Method: "GET"}

	db.Add(fp1)
	db.Add(fp2)

	list := db.List()
	assert.Len(t, list, 2)
}

func TestDatabaseListByCategory(t *testing.T) {
	db := NewDatabase()
	fp1 := &FalsePositive{RuleID: "1", Payload: "a", Endpoint: "/a", Method: "GET", Category: CategoryKnown}
	fp2 := &FalsePositive{RuleID: "2", Payload: "b", Endpoint: "/b", Method: "GET", Category: CategorySuspected}

	db.Add(fp1)
	db.Add(fp2)

	known := db.ListByCategory(CategoryKnown)
	assert.Len(t, known, 1)
}

func TestDatabaseRemove(t *testing.T) {
	db := NewDatabase()
	fp := &FalsePositive{
		RuleID:   "942100",
		Payload:  "test",
		Endpoint: "/api",
		Method:   "GET",
	}

	db.Add(fp)
	assert.Equal(t, 1, db.Count())

	removed := db.Remove(fp.Fingerprint())
	assert.True(t, removed)
	assert.Equal(t, 0, db.Count())

	removed2 := db.Remove("nonexistent")
	assert.False(t, removed2)
}

func TestDatabaseUpdateCategory(t *testing.T) {
	db := NewDatabase()
	fp := &FalsePositive{
		RuleID:   "942100",
		Payload:  "test",
		Endpoint: "/api",
		Method:   "GET",
		Category: CategorySuspected,
	}

	db.Add(fp)
	updated := db.UpdateCategory(fp.Fingerprint(), CategoryConfirmed)
	assert.True(t, updated)

	found := db.Get(fp.Fingerprint())
	assert.Equal(t, CategoryConfirmed, found.Category)
}

func TestDatabaseSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "fps.json")

	db := NewDatabase()
	fp := &FalsePositive{
		RuleID:   "942100",
		Payload:  "test",
		Endpoint: "/api",
		Method:   "GET",
	}
	db.Add(fp)

	err := db.Save(path)
	require.NoError(t, err)

	db2 := NewDatabase()
	err = db2.Load(path)
	require.NoError(t, err)
	assert.Equal(t, 1, db2.Count())
}

func TestDatabaseLoadNotFound(t *testing.T) {
	db := NewDatabase()
	err := db.Load("/nonexistent/file.json")
	assert.Error(t, err)
}

func TestGenerateReport(t *testing.T) {
	db := NewDatabase()

	fp1 := &FalsePositive{
		RuleID:   "942100",
		Payload:  "a",
		Endpoint: "/api",
		Method:   "GET",
		Category: CategoryKnown,
		Severity: finding.Low,
		LastSeen: time.Now(),
	}
	fp2 := &FalsePositive{
		RuleID:   "941100",
		Payload:  "b",
		Endpoint: "/api",
		Method:   "GET",
		Category: CategorySuspected,
		Severity: finding.Medium,
		LastSeen: time.Now().Add(-48 * time.Hour),
	}

	db.Add(fp1)
	db.Add(fp2)

	report := GenerateReport(db)
	assert.Equal(t, 2, report.TotalFPs)
	assert.Equal(t, 1, report.ByCategory[CategoryKnown])
	assert.Len(t, report.RecentFPs, 1)
}

func TestIsStaticFile(t *testing.T) {
	assert.True(t, isStaticFile("/assets/style.css"))
	assert.True(t, isStaticFile("/logo.png"))
	assert.False(t, isStaticFile("/api/users"))
}

func TestIsHealthEndpoint(t *testing.T) {
	assert.True(t, isHealthEndpoint("/health"))
	assert.True(t, isHealthEndpoint("/-/health/ready"))
	assert.False(t, isHealthEndpoint("/api/users"))
}

func TestGetCommonFPInfo(t *testing.T) {
	info := getCommonFPInfo("942100")
	assert.NotEmpty(t, info)

	info2 := getCommonFPInfo("unknown")
	assert.Empty(t, info2)
}

func TestContains(t *testing.T) {
	slice := []string{"a", "b", "c"}
	assert.True(t, contains(slice, "a"))
	assert.False(t, contains(slice, "d"))
}

func TestContainsPattern(t *testing.T) {
	patterns := []string{"/api", "^/admin"}
	assert.True(t, containsPattern(patterns, "/api/users"))
	assert.True(t, containsPattern(patterns, "/admin/panel"))
	assert.False(t, containsPattern(patterns, "/public"))
}

func TestNewAnalyzer(t *testing.T) {
	detector := NewDetector(nil)
	db := NewDatabase()
	analyzer := NewAnalyzer(detector, db)
	assert.NotNil(t, analyzer)
}

func TestAnalyzerAnalyzeAndStore(t *testing.T) {
	detector := NewDetector(nil)
	db := NewDatabase()
	analyzer := NewAnalyzer(detector, db)

	results := []*TestResult{
		{
			TestID:      "test-1",
			RuleID:      "942100",
			Payload:     "test",
			Endpoint:    "/api",
			Method:      "GET",
			Blocked:     true,
			ExpectBlock: false,
		},
	}

	fps := analyzer.AnalyzeAndStore(results)
	assert.Len(t, fps, 1)
	assert.Equal(t, 1, db.Count())
}

func TestAnalyzerGetAnalysis(t *testing.T) {
	detector := NewDetector(nil)
	db := NewDatabase()
	analyzer := NewAnalyzer(detector, db)

	for i := 0; i < 12; i++ {
		fp := &FalsePositive{
			RuleID:   "942100",
			Payload:  string(rune('a' + i)),
			Endpoint: "/api",
			Method:   "GET",
		}
		db.Add(fp)
	}

	analysis := analyzer.GetAnalysis("942100")
	assert.Equal(t, 12, analysis.FPCount)
	assert.NotEmpty(t, analysis.Recommendation)
}

func TestHeuristicsStaticFile(t *testing.T) {
	detector := NewDetector(nil)

	results := []*TestResult{
		{
			TestID:      "test-1",
			RuleID:      "941100",
			Payload:     "test",
			Endpoint:    "/assets/style.css",
			Method:      "GET",
			Blocked:     true,
			ExpectBlock: false,
		},
	}

	fps := detector.Analyze(results)
	require.Len(t, fps, 1)
	assert.Equal(t, finding.Low, fps[0].Severity)
	assert.Contains(t, fps[0].Reason, "Static file")
}

func TestHeuristicsHealthEndpoint(t *testing.T) {
	detector := NewDetector(nil)

	results := []*TestResult{
		{
			TestID:      "test-1",
			RuleID:      "941100",
			Payload:     "test",
			Endpoint:    "/healthz",
			Method:      "GET",
			Blocked:     true,
			ExpectBlock: false,
		},
	}

	fps := detector.Analyze(results)
	require.Len(t, fps, 1)
	assert.Equal(t, finding.Low, fps[0].Severity)
	assert.Contains(t, fps[0].Reason, "Health check")
}

func TestSaveLoadCycle(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.json")

	db := NewDatabase()
	db.Add(&FalsePositive{RuleID: "1", Payload: "a", Endpoint: "/a", Method: "GET", Category: CategoryKnown})
	db.AddPattern(&Pattern{ID: "p1", Name: "Test Pattern", Enabled: true})

	err := db.Save(tmpFile)
	require.NoError(t, err)

	_, err = os.Stat(tmpFile)
	require.NoError(t, err)

	db2 := NewDatabase()
	err = db2.Load(tmpFile)
	require.NoError(t, err)

	assert.Equal(t, 1, db2.Count())
	assert.Len(t, db2.Patterns, 1)
}
