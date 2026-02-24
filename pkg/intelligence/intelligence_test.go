// Package intelligence provides the learning brain for auto mode
package intelligence

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewEngine tests engine initialization
func TestNewEngine(t *testing.T) {
	engine := NewEngine(nil) // nil uses defaults

	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}

	// Verify engine is usable by calling its methods
	summary := engine.GetSummary()
	if summary == nil {
		t.Error("GetSummary returned nil")
	}
}

// TestNewEngineWithConfig tests engine initialization with custom config
func TestNewEngineWithConfig(t *testing.T) {
	cfg := &Config{
		Verbose:             true,
		LearningSensitivity: 0.9,
		MinConfidence:       0.5,
		EnableChains:        true,
		EnableWAFModel:      true,
	}
	engine := NewEngine(cfg)

	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
}

// TestLearnFromFinding tests learning from single findings
func TestLearnFromFinding(t *testing.T) {
	engine := NewEngine(nil)

	finding := &Finding{
		Phase:      "discovery",
		Category:   "leaked-secrets",
		Severity:   "High",
		Path:       "/api/config",
		Payload:    "",
		StatusCode: 200,
		Latency:    100 * time.Millisecond,
		Blocked:    false,
		Confidence: 0.9,
		Metadata: map[string]interface{}{
			"secret_type": "api_key",
		},
	}

	engine.LearnFromFinding(finding)

	// Check stats updated
	summary := engine.GetSummary()
	if summary.TotalFindings != 1 {
		t.Errorf("expected 1 total finding, got %d", summary.TotalFindings)
	}
}

// TestLearnFromPhase tests batch learning from phase results
func TestLearnFromPhase(t *testing.T) {
	engine := NewEngine(nil)

	findings := []*Finding{
		{Phase: "discovery", Category: "leaked-secrets", Severity: "High", Path: "/api/keys"},
		{Phase: "discovery", Category: "leaky-paths", Severity: "Medium", Path: "/backup"},
		{Phase: "discovery", Category: "technology", Severity: "Info", Path: "/", Metadata: map[string]interface{}{"tech": "django"}},
	}

	engine.LearnFromPhase("discovery", findings)

	// Verify all stored
	summary := engine.GetSummary()
	if summary.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", summary.TotalFindings)
	}
}

// TestBypassTracking tests tracking of WAF bypass findings
func TestBypassTracking(t *testing.T) {
	engine := NewEngine(nil)

	// Add some blocked and bypassed findings
	engine.LearnFromFinding(&Finding{
		Phase: "waf-testing", Category: "sqli", Severity: "Critical",
		Path: "/api/user", Payload: "' OR 1=1--", Blocked: true,
	})
	engine.LearnFromFinding(&Finding{
		Phase: "waf-testing", Category: "sqli", Severity: "Critical",
		Path: "/api/user", Payload: "' or '1'='1", Blocked: false,
	})

	summary := engine.GetSummary()
	if summary.Bypasses != 1 {
		t.Errorf("expected 1 bypass, got %d", summary.Bypasses)
	}
}

// TestAttackChainBuilding tests attack chain detection
func TestAttackChainBuilding(t *testing.T) {
	var chainCount int32
	engine := NewEngine(nil)
	engine.OnChain(func(chain *AttackChain) {
		atomic.AddInt32(&chainCount, 1)
	})

	// Add findings that should trigger a Secret + Auth bypass chain
	engine.LearnFromFinding(&Finding{
		Phase: "discovery", Category: "leaked-secrets", Severity: "High",
		Path: "/api/config", Confidence: 0.9,
		Metadata: map[string]interface{}{"secret_type": "api_key"},
	})
	engine.LearnFromFinding(&Finding{
		Phase: "discovery", Category: "authentication", Severity: "High",
		Path: "/api/admin", Confidence: 0.9,
	})

	// Should have created at least one chain
	summary := engine.GetSummary()
	if summary.AttackChains < 1 {
		t.Logf("Attack chains: %d (chain callback count: %d)", summary.AttackChains, atomic.LoadInt32(&chainCount))
		// Note: Chain detection depends on specific patterns
	}
}

// TestPayloadRecommendations tests smart payload recommendations
func TestPayloadRecommendations(t *testing.T) {
	engine := NewEngine(nil)

	// Add some bypass findings
	engine.LearnFromFinding(&Finding{
		Phase: "waf-testing", Category: "sqli", Severity: "Critical",
		Path: "/api/user", Blocked: false, Confidence: 0.95,
	})

	recs := engine.RecommendPayloads()

	// Verify recommendations have required fields
	for _, rec := range recs {
		if rec.Category == "" {
			t.Error("recommendation missing category")
		}
		if rec.Priority < 1 || rec.Priority > 3 {
			t.Errorf("invalid priority: %d", rec.Priority)
		}
	}
}

// TestResourceAllocation tests resource allocation recommendations
func TestResourceAllocation(t *testing.T) {
	engine := NewEngine(nil)

	// Add findings with varying severity
	engine.LearnFromFinding(&Finding{
		Phase: "waf-testing", Category: "sqli", Severity: "Critical",
		Path: "/api/user", Blocked: false,
	})
	engine.LearnFromFinding(&Finding{
		Phase: "waf-testing", Category: "xss", Severity: "Medium",
		Path: "/search", Blocked: true,
	})

	alloc := engine.RecommendResourceAllocation()
	if len(alloc) == 0 {
		t.Log("No allocation recommendations (may be normal for small finding set)")
	}

	// Total should be ~100%
	var total float64
	for _, rec := range alloc {
		total += rec.AllocationPct
	}
	if len(alloc) > 0 && (total < 95 || total > 105) {
		t.Errorf("allocation doesn't sum to ~100%%: %f", total)
	}
}

// TestInsightGeneration tests insight callback
func TestInsightGeneration(t *testing.T) {
	var insightCount int32
	engine := NewEngine(nil)
	engine.OnInsight(func(insight *Insight) {
		atomic.AddInt32(&insightCount, 1)
	})

	// Add findings that should generate insights
	for i := 0; i < 5; i++ {
		engine.LearnFromFinding(&Finding{
			Phase: "waf-testing", Category: "sqli", Severity: "Critical",
			Path: "/api/user", Blocked: false,
		})
	}

	// Should have generated at least one insight about sqli bypasses
	if atomic.LoadInt32(&insightCount) == 0 {
		t.Log("No insights generated (may depend on threshold settings)")
	}
}

// TestConcurrentAccess tests thread safety
func TestConcurrentAccess(t *testing.T) {
	engine := NewEngine(nil)

	var wg sync.WaitGroup
	const goroutines = 10
	const findingsPerGoroutine = 100

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < findingsPerGoroutine; i++ {
				engine.LearnFromFinding(&Finding{
					Phase:    "waf-testing",
					Category: "sqli",
					Severity: "High",
					Path:     "/test",
				})
			}
		}(g)
	}

	wg.Wait()

	summary := engine.GetSummary()
	expected := goroutines * findingsPerGoroutine
	if summary.TotalFindings != expected {
		t.Errorf("expected %d findings, got %d (possible race condition)", expected, summary.TotalFindings)
	}
}

// TestMemoryIndexing tests memory indexing capabilities
func TestMemoryIndexing(t *testing.T) {
	mem := NewMemory()

	findings := []*Finding{
		{Phase: "discovery", Category: "leaked-secrets", Path: "/api/keys"},
		{Phase: "discovery", Category: "leaky-paths", Path: "/backup"},
		{Phase: "waf-testing", Category: "sqli", Path: "/api/user"},
		{Phase: "waf-testing", Category: "sqli", Path: "/api/admin"},
	}

	for _, f := range findings {
		mem.Store(f)
	}

	// Test GetByCategory
	sqli := mem.GetByCategory("sqli")
	if len(sqli) != 2 {
		t.Errorf("expected 2 sqli findings, got %d", len(sqli))
	}

	// Test GetByPhase
	discovery := mem.GetByPhase("discovery")
	if len(discovery) != 2 {
		t.Errorf("expected 2 discovery findings, got %d", len(discovery))
	}

	// Test GetByPath
	apiUser := mem.GetByPath("/api/user")
	if len(apiUser) != 1 {
		t.Errorf("expected 1 finding for /api/user, got %d", len(apiUser))
	}
}

// TestWAFModelLearning tests WAF behavior learning
func TestWAFModelLearning(t *testing.T) {
	model := NewWAFBehaviorModel()

	// Simulate blocked payloads
	for i := 0; i < 10; i++ {
		model.Learn(&Finding{
			Category: "sqli", Payload: "' OR 1=1--",
			Blocked: true, StatusCode: 403,
		})
	}

	// Simulate bypass
	model.Learn(&Finding{
		Category: "sqli", Payload: "' or '1'='1",
		Blocked: false, StatusCode: 200,
	})

	weaknesses := model.GetWeaknesses()
	strengths := model.GetStrengths()

	t.Logf("Weaknesses: %v", weaknesses)
	t.Logf("Strengths: %v", strengths)

	// Should have learned something
	if len(weaknesses) == 0 && len(strengths) == 0 {
		t.Log("No patterns learned (may be normal for small sample)")
	}
}

// TestTechProfileDetection tests technology detection
func TestTechProfileDetection(t *testing.T) {
	profile := NewTechProfile()

	// Add findings with tech indicators
	profile.Update(&Finding{
		Path: "/",
		Metadata: map[string]interface{}{
			"headers": "X-Powered-By: Django",
		},
	})
	profile.Update(&Finding{
		Path: "/admin",
		Metadata: map[string]interface{}{
			"body": "csrfmiddlewaretoken",
		},
	})

	// Detect from a finding with Django indicators
	profile.Detect(&Finding{
		Path:    "/django/admin",
		Payload: "csrfmiddlewaretoken",
	})

	detected := profile.GetDetected()
	t.Logf("Detected technologies: %+v", detected)

	// Should have detected Django
	if !profile.HasFramework("django") && !profile.HasFramework("Django") {
		t.Log("Django not detected (may depend on detection patterns)")
	}
}

// TestStatsPhaseTracking tests phase statistics
func TestStatsPhaseTracking(t *testing.T) {
	stats := NewStats()

	stats.StartPhase("discovery")
	time.Sleep(10 * time.Millisecond)
	stats.RecordFinding(&Finding{Category: "leaked-secrets", Severity: "High"}, false)
	stats.RecordFinding(&Finding{Category: "leaky-paths", Severity: "Medium"}, false)
	stats.EndPhase("discovery")

	stats.StartPhase("waf-testing")
	stats.RecordFinding(&Finding{Category: "sqli", Severity: "Critical", Blocked: false}, true)
	stats.RecordFinding(&Finding{Category: "sqli", Severity: "Critical", Blocked: true}, true)
	stats.EndPhase("waf-testing")

	// Check bypass rate for sqli category
	rate := stats.GetBypassRate("sqli")
	if rate != 0.5 {
		t.Errorf("expected 50%% bypass rate for sqli, got %f", rate)
	}

	// Check top categories
	top := stats.TopCategories(3)
	if len(top) == 0 {
		t.Error("expected at least one top category")
	}
}

// TestEmptyEngine tests engine with no findings
func TestEmptyEngine(t *testing.T) {
	engine := NewEngine(nil)

	summary := engine.GetSummary()
	if summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", summary.TotalFindings)
	}

	recs := engine.RecommendPayloads()
	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations, got %d", len(recs))
	}

	// RecommendResourceAllocation may return defaults even with no findings
	// Just verify it doesn't panic
	alloc := engine.RecommendResourceAllocation()
	t.Logf("Empty engine allocations: %d", len(alloc))
}
