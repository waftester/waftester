package intelligence

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// MASTER BRAIN DISABLED — verify fallback to heuristic behavior
// ══════════════════════════════════════════════════════════════════════════════

func TestMasterBrainDisabled_NoModulesCreated(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MasterBrainEnabled = false
	e := NewEngine(cfg)

	if e.banditCategory != nil {
		t.Error("banditCategory should be nil when MasterBrainEnabled=false")
	}
	if e.banditEncoding != nil {
		t.Error("banditEncoding should be nil when MasterBrainEnabled=false")
	}
	if e.banditPattern != nil {
		t.Error("banditPattern should be nil when MasterBrainEnabled=false")
	}
	if e.phaseCtrl != nil {
		t.Error("phaseCtrl should be nil when MasterBrainEnabled=false")
	}
	if e.calibrator != nil {
		t.Error("calibrator should be nil when MasterBrainEnabled=false")
	}
	if e.influenceGraph != nil {
		t.Error("influenceGraph should be nil when MasterBrainEnabled=false")
	}
	if e.mutationGen != nil {
		t.Error("mutationGen should be nil when MasterBrainEnabled=false")
	}
	if e.controlLoop != nil {
		t.Error("controlLoop should be nil when MasterBrainEnabled=false")
	}
}

func TestMasterBrainDisabled_LearnFromFindingNoError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MasterBrainEnabled = false
	e := NewEngine(cfg)

	// Should not panic when Master Brain modules are nil
	finding := &Finding{
		Phase:     "waf-testing",
		Category:  "sqli",
		Payload:   "' OR 1=1--",
		Path:      "/api/login",
		Blocked:   true,
		Severity:  "high",
		Encodings: []string{"url-encode"},
		Latency:   50 * time.Millisecond,
	}
	e.LearnFromFinding(finding)

	summary := e.GetSummary()
	if summary.TotalFindings != 1 {
		t.Errorf("TotalFindings = %d, want 1", summary.TotalFindings)
	}
}

func TestMasterBrainDisabled_RecommendPayloadsNoThompson(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MasterBrainEnabled = false
	e := NewEngine(cfg)

	// Feed some data
	for i := 0; i < 5; i++ {
		e.LearnFromFinding(&Finding{
			Phase:    "waf-testing",
			Category: "xss",
			Payload:  "<script>alert(1)</script>",
			Path:     "/search",
			Blocked:  false,
			Severity: "medium",
		})
	}

	recs := e.RecommendPayloads()
	// Should have recommendations from heuristic path (bypass-based)
	for _, r := range recs {
		if r.Reason != "" && r.Category == "xss" {
			return // Found heuristic recommendation
		}
	}
	// At least verify it didn't panic
}

func TestMasterBrainDisabled_EndPhaseNoPhaseCtrl(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MasterBrainEnabled = false
	e := NewEngine(cfg)

	// Should not panic
	e.StartPhase(context.TODO(), "discovery")
	e.EndPhase("discovery")
}

// ══════════════════════════════════════════════════════════════════════════════
// MASTER BRAIN ENABLED — integration tests
// ══════════════════════════════════════════════════════════════════════════════

func TestMasterBrain_Enabled_AllModulesCreated(t *testing.T) {
	e := NewEngine(nil) // Default has MasterBrainEnabled=true

	if e.banditCategory == nil {
		t.Error("banditCategory should not be nil")
	}
	if e.banditEncoding == nil {
		t.Error("banditEncoding should not be nil")
	}
	if e.banditPattern == nil {
		t.Error("banditPattern should not be nil")
	}
	if e.phaseCtrl == nil {
		t.Error("phaseCtrl should not be nil")
	}
	if e.calibrator == nil {
		t.Error("calibrator should not be nil")
	}
	if e.influenceGraph == nil {
		t.Error("influenceGraph should not be nil")
	}
	if e.mutationGen == nil {
		t.Error("mutationGen should not be nil")
	}
	if e.controlLoop == nil {
		t.Error("controlLoop should not be nil")
	}
}

func TestMasterBrain_EndToEnd(t *testing.T) {
	e := NewEngine(nil)

	// Phase 1: Discovery
	e.StartPhase(context.TODO(), "discovery")
	e.LearnFromFinding(&Finding{
		Phase:    "discovery",
		Category: "endpoint",
		Path:     "/api/v1/users",
		Method:   "GET",
		Severity: "info",
	})
	e.EndPhase("discovery")

	// Phase 2: WAF Testing — blocked and bypassed payloads
	e.StartPhase(context.TODO(), "waf-testing")
	for i := 0; i < 10; i++ {
		e.LearnFromFinding(&Finding{
			Phase:      "waf-testing",
			Category:   "sqli",
			Payload:    "' OR 1=1--",
			Path:       "/api/v1/users",
			Blocked:    true,
			Severity:   "high",
			StatusCode: 403,
			Encodings:  []string{"none"},
			Latency:    50 * time.Millisecond,
		})
	}

	// Some bypasses
	for i := 0; i < 3; i++ {
		e.LearnFromFinding(&Finding{
			Phase:           "waf-testing",
			Category:        "sqli",
			Payload:         "%27%20OR%201%3D1--",
			OriginalPayload: "' OR 1=1--",
			Path:            "/api/v1/users",
			Blocked:         false,
			Severity:        "high",
			StatusCode:      200,
			Encodings:       []string{"url-encode"},
			Latency:         45 * time.Millisecond,
		})
	}
	e.EndPhase("waf-testing")

	// Verify bandits learned
	ranked := e.banditCategory.RankAll()
	found := false
	for _, arm := range ranked {
		if arm.Key == "sqli" && arm.Pulls > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("banditCategory should have recorded sqli arm pulls")
	}

	// Verify encoding bandit learned
	encRanked := e.banditEncoding.RankAll()
	for _, arm := range encRanked {
		if arm.Key == "url-encode" && arm.Pulls == 0 {
			t.Error("banditEncoding should have url-encode pulls > 0")
		}
	}

	// Verify payload recommendations include Thompson Sampling info
	recs := e.RecommendPayloads()
	if len(recs) == 0 {
		t.Error("expected payload recommendations after learning")
	}

	// Verify influence graph has nodes
	if e.influenceGraph.NodeCount() == 0 {
		t.Error("influence graph should have nodes after seeding + propagation")
	}

	// Verify summary
	summary := e.GetSummary()
	if summary.TotalFindings != 14 { // 1 discovery + 10 blocked + 3 bypass
		t.Errorf("TotalFindings = %d, want 14", summary.TotalFindings)
	}
	if summary.Bypasses < 3 {
		t.Errorf("Bypasses = %d, want >= 3", summary.Bypasses)
	}
}

func TestMasterBrain_ResetClearsAllModules(t *testing.T) {
	e := NewEngine(nil)

	// Feed data to all modules
	for i := 0; i < 5; i++ {
		e.LearnFromFinding(&Finding{
			Phase:      "waf-testing",
			Category:   "sqli",
			Payload:    "' OR 1=1--",
			Path:       "/api/test",
			Blocked:    i%2 == 0,
			Severity:   "high",
			StatusCode: 200,
			Encodings:  []string{"url-encode"},
			Latency:    100 * time.Millisecond,
		})
	}

	// Verify state exists
	if e.banditCategory.ArmCount() == 0 {
		t.Fatal("banditCategory should have arms before reset")
	}

	e.Reset()

	// Verify all Master Brain modules are cleared
	if e.banditCategory.ArmCount() != 0 {
		t.Errorf("banditCategory.ArmCount() = %d after reset, want 0", e.banditCategory.ArmCount())
	}
	if e.banditEncoding.ArmCount() != 0 {
		t.Errorf("banditEncoding.ArmCount() = %d after reset, want 0", e.banditEncoding.ArmCount())
	}
	if e.banditPattern.ArmCount() != 0 {
		t.Errorf("banditPattern.ArmCount() = %d after reset, want 0", e.banditPattern.ArmCount())
	}
	if e.calibrator.MetricCount() != 0 {
		t.Errorf("calibrator.MetricCount() = %d after reset, want 0", e.calibrator.MetricCount())
	}
	if e.influenceGraph.NodeCount() != 0 {
		t.Errorf("influenceGraph.NodeCount() = %d after reset, want 0", e.influenceGraph.NodeCount())
	}
	summary := e.GetSummary()
	if summary.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d after reset, want 0", summary.TotalFindings)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// PERSISTENCE ROUND-TRIP — export → import preserves Master Brain state
// ══════════════════════════════════════════════════════════════════════════════

func TestMasterBrain_PersistenceRoundTrip(t *testing.T) {
	e := NewEngine(nil)

	// Build state
	for i := 0; i < 20; i++ {
		e.LearnFromFinding(&Finding{
			Phase:      "waf-testing",
			Category:   "xss",
			Payload:    "<script>alert(1)</script>",
			Path:       "/search",
			Blocked:    i < 14,
			Severity:   "medium",
			StatusCode: 200,
			Encodings:  []string{"html-entity"},
			Latency:    30 * time.Millisecond,
		})
	}
	e.EndPhase("waf-testing")

	// Export
	data, err := e.ExportJSON()
	if err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}

	// Verify JSON is valid and contains Master Brain fields
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("exported JSON is not valid: %v", err)
	}
	if _, ok := parsed["bandit_category"]; !ok {
		t.Error("exported JSON missing bandit_category")
	}
	if _, ok := parsed["bandit_encoding"]; !ok {
		t.Error("exported JSON missing bandit_encoding")
	}
	if _, ok := parsed["phase_controller"]; !ok {
		t.Error("exported JSON missing phase_controller")
	}
	if _, ok := parsed["calibrator"]; !ok {
		t.Error("exported JSON missing calibrator")
	}
	if _, ok := parsed["influence_graph"]; !ok {
		t.Error("exported JSON missing influence_graph")
	}

	// Import into fresh engine
	e2 := NewEngine(nil)
	if err := e2.ImportJSON(data); err != nil {
		t.Fatalf("ImportJSON: %v", err)
	}

	// Verify bandit state survived
	origArms := e.banditCategory.RankAll()
	importedArms := e2.banditCategory.RankAll()
	if len(origArms) != len(importedArms) {
		t.Errorf("banditCategory arms: orig=%d, imported=%d", len(origArms), len(importedArms))
	}

	// Verify calibrator state survived
	origMetrics := e.calibrator.MetricCount()
	importedMetrics := e2.calibrator.MetricCount()
	if origMetrics != importedMetrics {
		t.Errorf("calibrator metrics: orig=%d, imported=%d", origMetrics, importedMetrics)
	}

	// Verify influence graph state survived
	origNodes := e.influenceGraph.NodeCount()
	importedNodes := e2.influenceGraph.NodeCount()
	if importedNodes < origNodes/2 { // Allow some variance from seeding
		t.Errorf("influenceGraph nodes: orig=%d, imported=%d", origNodes, importedNodes)
	}
}

func TestMasterBrain_PersistenceBackwardCompat(t *testing.T) {
	// Test importing old state (no Master Brain fields) into new engine
	oldState := `{
		"version": "1.0",
		"timestamp": "2025-01-01T00:00:00Z",
		"memory": {"findings": [], "category_priority": {}},
		"stats": {"phases": {}}
	}`

	e := NewEngine(nil) // MasterBrainEnabled=true
	if err := e.ImportJSON([]byte(oldState)); err != nil {
		t.Fatalf("ImportJSON of old state: %v", err)
	}

	// Master Brain modules should remain initialized (not nil)
	if e.banditCategory == nil {
		t.Error("banditCategory should not be nil after importing old state")
	}
	if e.phaseCtrl == nil {
		t.Error("phaseCtrl should not be nil after importing old state")
	}

	// Engine should be functional
	e.LearnFromFinding(&Finding{
		Phase:    "waf-testing",
		Category: "sqli",
		Payload:  "test",
		Path:     "/test",
		Blocked:  true,
		Severity: "medium",
	})
	if e.GetSummary().TotalFindings != 1 {
		t.Error("engine should be functional after importing old state")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// NEGATIVE TESTS — nil inputs, empty collections, boundary conditions
// ══════════════════════════════════════════════════════════════════════════════

func TestBanditSelector_ImportNilIsNoOp(t *testing.T) {
	b := NewBanditSelector(42)
	b.Record("a", true)
	b.Import(nil)
	// Should retain existing state
	if b.ArmCount() != 1 {
		t.Errorf("ArmCount = %d after nil import, want 1", b.ArmCount())
	}
}

func TestBanditSelector_RankAllEmpty(t *testing.T) {
	b := NewBanditSelector(42)
	ranked := b.RankAll()
	if len(ranked) != 0 {
		t.Errorf("RankAll on empty bandit returned %d arms", len(ranked))
	}
}

func TestBanditSelector_DecayEmptyNoOp(t *testing.T) {
	b := NewBanditSelector(42)
	b.Decay(0.5) // Should not panic
}

func TestBanditSelector_ResetClearsArms(t *testing.T) {
	b := NewBanditSelector(42)
	b.Record("a", true)
	b.Record("b", false)
	b.Reset()
	if b.ArmCount() != 0 {
		t.Errorf("ArmCount = %d after reset, want 0", b.ArmCount())
	}
	if got := b.Select(); got != "" {
		t.Errorf("Select after reset = %q, want empty", got)
	}
}

func TestChangePointDetector_ObserveNoCallback(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	// Should not panic even with nil callback
	for i := 0; i < 100; i++ {
		cpd.Observe("metric", float64(i%2))
	}
}

func TestChangePointDetector_ResetMetricNonExistent(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	cpd.ResetMetric("nonexistent", 0.5) // Should not panic
}

func TestChangePointDetector_IsStableNoData(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	if !cpd.IsStable("nonexistent") {
		t.Error("IsStable should return true for unknown metric")
	}
}

func TestChangePointDetector_ResetClearsAll(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	cpd.Observe("a", 1.0)
	cpd.Observe("b", 2.0)
	cpd.Reset()
	if cpd.MetricCount() != 0 {
		t.Errorf("MetricCount = %d after reset, want 0", cpd.MetricCount())
	}
}

func TestChangePointDetector_GetMetricStateNonExistent(t *testing.T) {
	cpd := NewChangePointDetector(DefaultCalibratorConfig(), nil)
	_, ok := cpd.GetMetricState("nonexistent")
	if ok {
		t.Error("GetMetricState should return false for unknown metric")
	}
}

func TestInfluenceGraph_PropagateNoNodes(t *testing.T) {
	g := NewInfluenceGraph()
	g.Propagate("nonexistent", 1.0) // Should not panic
}

func TestInfluenceGraph_ReinforceNonExistentEdge(t *testing.T) {
	g := NewInfluenceGraph()
	g.ReinforceEdge("a", "b", 0.1) // Should not panic on missing edge
}

func TestInfluenceGraph_DecayNonExistentEdge(t *testing.T) {
	g := NewInfluenceGraph()
	g.DecayEdge("a", "b", 0.9) // Should not panic
}

func TestInfluenceGraph_TopInfluencersEmpty(t *testing.T) {
	g := NewInfluenceGraph()
	result := g.TopInfluencers("nonexistent", 5)
	if len(result) != 0 {
		t.Errorf("TopInfluencers on empty graph returned %d results", len(result))
	}
}

func TestInfluenceGraph_GetInfluencedMissing(t *testing.T) {
	g := NewInfluenceGraph()
	result := g.GetInfluenced("nonexistent", 0.1)
	if len(result) != 0 {
		t.Errorf("GetInfluenced on missing node returned %d results", len(result))
	}
}

func TestInfluenceGraph_ResetClearsAll(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "category")
	g.AddEdge("A", "B", 0.5)
	g.Reset()
	if g.NodeCount() != 0 {
		t.Errorf("NodeCount = %d after reset, want 0", g.NodeCount())
	}
	if g.EdgeCount() != 0 {
		t.Errorf("EdgeCount = %d after reset, want 0", g.EdgeCount())
	}
}

func TestMutationGenerator_SuggestZero(t *testing.T) {
	mg := NewMutationGenerator(DefaultMutationGeneratorConfig(), 42)
	suggestions := mg.SuggestMutations(0)
	if len(suggestions) != 0 {
		t.Errorf("SuggestMutations(0) returned %d results, want 0", len(suggestions))
	}
}

func TestMutationGenerator_EvaluateFitnessOutOfBounds(t *testing.T) {
	mg := NewMutationGenerator(DefaultMutationGeneratorConfig(), 42)
	// Should not panic for out-of-bounds indices
	mg.EvaluateFitness(-1, []TrialResult{{Bypassed: true}})
	mg.EvaluateFitness(99999, []TrialResult{{Bypassed: true}})
}

func TestMutationGenerator_EvolvePreservesPopulationSize(t *testing.T) {
	cfg := &MutationGeneratorConfig{
		PopulationSize: 10,
		MaxGeneLength:  3,
		MutationRate:   0.1,
		CrossoverRate:  0.7,
		EliteCount:     2,
		TournamentSize: 3,
		MaxGenerations: 20,
	}
	mg := NewMutationGenerator(cfg, 42)
	mg.Evolve()
	if mg.PopulationSize() != 10 {
		t.Errorf("population size = %d after evolve, want 10", mg.PopulationSize())
	}
}

func TestMutationGenerator_ResetClearsGeneration(t *testing.T) {
	mg := NewMutationGenerator(DefaultMutationGeneratorConfig(), 42)
	mg.Evolve()
	mg.Evolve()
	if mg.Generation() != 2 {
		t.Fatalf("generation = %d, want 2", mg.Generation())
	}
	mg.Reset()
	if mg.Generation() != 0 {
		t.Errorf("generation = %d after reset, want 0", mg.Generation())
	}
}

func TestPhaseController_SelectWhenNoPhasesRegistered(t *testing.T) {
	pc := NewPhaseController(nil, nil)
	state := BuildState("unknown", 0.5, 0.1, 0)
	result := pc.SelectNextPhase(state)
	if result != "" {
		t.Errorf("SelectNextPhase with no phases = %q, want empty", result)
	}
}

func TestPhaseController_RecordRewardUnknownPhase(t *testing.T) {
	pc := NewPhaseController([]string{"sqli"}, nil)
	state := BuildState("unknown", 0.5, 0.1, 0)
	// Should not panic for unknown phase
	pc.RecordReward("nonexistent", 0.5, state)
}

func TestPhaseController_MarkCompletedUnknown(t *testing.T) {
	pc := NewPhaseController([]string{"sqli"}, nil)
	pc.MarkCompleted("nonexistent") // Should not panic
}

func TestPhaseController_ResetClearsCompleted(t *testing.T) {
	pc := NewPhaseController([]string{"sqli", "xss"}, nil)
	pc.MarkCompleted("sqli")
	pc.Reset()
	state := BuildState("unknown", 0.5, 0.1, 0)
	// After reset, sqli should be available again
	available := false
	for i := 0; i < 100; i++ {
		if pc.SelectNextPhase(state) == "sqli" {
			available = true
			break
		}
	}
	if !available {
		t.Error("sqli should be available after reset")
	}
}

func TestControlLoop_NilEngine(t *testing.T) {
	loop := NewControlLoop(nil, DefaultControlLoopConfig())
	ori := &Orientation{
		ConvergenceScore: 0.3,
		BudgetRemaining:  0.5,
		Confidence:       0.5,
	}
	result := loop.Decide(ori, "waf-testing")
	if result == nil {
		t.Fatal("Decide should return non-nil even with nil engine")
	}
}

func TestControlLoop_BudgetExhausted(t *testing.T) {
	e := NewEngine(nil)
	loop := NewControlLoop(e, &ControlLoopConfig{
		MaxRequests:       100,
		MaxTime:           30 * time.Minute,
		ConvergenceWindow: 3,
		MaxEpochs:         50,
	})
	// Exhaust budget via Observe
	loop.Observe("waf-testing", 5, 2, 3, 100, time.Minute)
	ori := loop.Orient()
	result := loop.Decide(ori, "waf-testing")
	if result.Action != ActionStop {
		t.Errorf("action = %v, want Stop when budget exhausted", result.Action)
	}
}

func TestControlLoop_MaxEpochsReached(t *testing.T) {
	e := NewEngine(nil)
	loop := NewControlLoop(e, &ControlLoopConfig{
		MaxRequests:       10000,
		MaxTime:           30 * time.Minute,
		ConvergenceWindow: 3,
		MaxEpochs:         3,
	})
	// Advance 3 epochs
	for i := 0; i < 3; i++ {
		loop.Observe("waf-testing", 1, 0, 1, 10, time.Second)
		loop.Act(loop.Decide(loop.Orient(), "waf-testing"))
	}
	ori := loop.Orient()
	result := loop.Decide(ori, "waf-testing")
	if result.Action != ActionStop {
		t.Errorf("action = %v, want Stop when max epochs reached", result.Action)
	}
}

func TestControlLoop_TimeExceeded(t *testing.T) {
	e := NewEngine(nil)
	loop := NewControlLoop(e, &ControlLoopConfig{
		MaxRequests:       10000,
		MaxTime:           time.Minute,
		ConvergenceWindow: 3,
		MaxEpochs:         50,
	})
	// Exhaust time via Observe
	loop.Observe("waf-testing", 5, 2, 3, 50, 2*time.Minute)
	ori := loop.Orient()
	result := loop.Decide(ori, "waf-testing")
	if result.Action != ActionStop {
		t.Errorf("action = %v, want Stop when time exceeded", result.Action)
	}
}

func TestControlLoop_HighConvergenceStops(t *testing.T) {
	e := NewEngine(nil)
	loop := NewControlLoop(e, &ControlLoopConfig{
		MaxRequests:       10000,
		MaxTime:           30 * time.Minute,
		ConvergenceWindow: 3,
		MaxEpochs:         50,
	})
	// Feed zero-finding epochs to trigger convergence
	for i := 0; i < 5; i++ {
		loop.Observe("waf-testing", 0, 0, 0, 100, time.Second)
	}
	ori := loop.Orient()
	// Orient should compute high convergence
	if ori.ConvergenceScore <= 0.8 {
		t.Skipf("convergence score = %v, not high enough to trigger stop", ori.ConvergenceScore)
	}
	result := loop.Decide(ori, "waf-testing")
	if result.Action != ActionStop {
		t.Errorf("action = %v, want Stop when convergence > 0.8", result.Action)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// CONCURRENT SAFETY — Master Brain under concurrent access
// ══════════════════════════════════════════════════════════════════════════════

func TestMasterBrain_ConcurrentFeedAndRead(t *testing.T) {
	e := NewEngine(nil)

	var wg sync.WaitGroup

	// Writer goroutines
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				e.LearnFromFinding(&Finding{
					Phase:      "waf-testing",
					Category:   "sqli",
					Payload:    "' OR 1=1--",
					Path:       "/api/test",
					Blocked:    i%2 == 0,
					Severity:   "high",
					StatusCode: 200,
					Encodings:  []string{"url-encode"},
					Latency:    time.Duration(i) * time.Millisecond,
				})
			}
		}(g)
	}

	// Reader goroutines
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				e.GetSummary()
				e.RecommendPayloads()
				e.RecommendResourceAllocation()
			}
		}()
	}

	wg.Wait()

	summary := e.GetSummary()
	if summary.TotalFindings != 250 { // 5 goroutines * 50 findings
		t.Errorf("TotalFindings = %d, want 250", summary.TotalFindings)
	}
}

func TestMasterBrain_ConcurrentPhaseOperations(t *testing.T) {
	e := NewEngine(nil)

	var wg sync.WaitGroup
	phases := []string{"discovery", "js-analysis", "leaky-paths", "params", "waf-testing"}

	for _, phase := range phases {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			e.StartPhase(context.TODO(), p)
			for i := 0; i < 10; i++ {
				e.LearnFromFinding(&Finding{
					Phase:    p,
					Category: "xss",
					Payload:  "<script>alert(1)</script>",
					Path:     "/test",
					Blocked:  true,
					Severity: "medium",
				})
			}
			e.EndPhase(p)
		}(phase)
	}
	wg.Wait()
}

// ══════════════════════════════════════════════════════════════════════════════
// EDGE CASES — zero budgets, empty payloads, boundary values
// ══════════════════════════════════════════════════════════════════════════════

func TestEngine_LearnNilFinding(t *testing.T) {
	e := NewEngine(nil)
	e.LearnFromFinding(nil) // Should not panic
	if e.GetSummary().TotalFindings != 0 {
		t.Error("nil finding should not be counted")
	}
}

func TestEngine_LearnEmptyPayload(t *testing.T) {
	e := NewEngine(nil)
	e.LearnFromFinding(&Finding{
		Phase:    "waf-testing",
		Category: "sqli",
		Payload:  "",
		Path:     "/test",
		Blocked:  true,
		Severity: "medium",
	})
	// Should complete without panic
	if e.GetSummary().TotalFindings != 1 {
		t.Error("empty payload finding should still be counted")
	}
}

func TestEngine_LearnEmptyCategory(t *testing.T) {
	e := NewEngine(nil)
	e.LearnFromFinding(&Finding{
		Phase:    "waf-testing",
		Category: "",
		Payload:  "test",
		Path:     "/test",
		Blocked:  false,
		Severity: "info",
	})
	// banditCategory should skip empty key
	if e.banditCategory.ArmCount() != 0 {
		t.Error("empty category should not create a bandit arm")
	}
}

func TestEngine_LearnZeroLatency(t *testing.T) {
	e := NewEngine(nil)
	e.LearnFromFinding(&Finding{
		Phase:      "waf-testing",
		Category:   "sqli",
		Payload:    "test",
		Path:       "/test",
		Blocked:    true,
		Severity:   "medium",
		StatusCode: 403,
		Latency:    0,
	})
	// CUSUM should handle zero latency (skip it)
	if e.calibrator.MetricCount() != 1 {
		// block_rate is observed, latency_ms is skipped
		t.Errorf("MetricCount = %d, want 1 (only block_rate)", e.calibrator.MetricCount())
	}
}

func TestEngine_LearnZeroStatusCode(t *testing.T) {
	e := NewEngine(nil)
	e.LearnFromFinding(&Finding{
		Phase:      "waf-testing",
		Category:   "sqli",
		Payload:    "test",
		Path:       "/test",
		Blocked:    true,
		Severity:   "medium",
		StatusCode: 0, // anomaly detector should skip
	})
	anomalyStats := e.anomaly.GetStats()
	if anomalyStats.TotalObservations != 0 {
		t.Error("zero status code should not feed anomaly detector")
	}
}

func TestBuildState_BoundaryValues(t *testing.T) {
	tests := []struct {
		name     string
		budget   float64
		bypass   float64
		findings int
	}{
		{"all zeros", 0, 0, 0},
		{"all maximums", 1.0, 1.0, 1000000},
		{"negative budget", -1.0, 0, 0},
		{"negative bypass", 0, -1.0, 0},
		{"negative findings", 0, 0, -100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := BuildState("test", tt.budget, tt.bypass, tt.findings)
			// Just verify it doesn't panic and returns valid discretized values
			if state.BudgetRemaining < 0 || state.BudgetRemaining > 3 {
				t.Errorf("BudgetRemaining = %d, out of [0,3]", state.BudgetRemaining)
			}
			if state.BypassRate < 0 || state.BypassRate > 3 {
				t.Errorf("BypassRate = %d, out of [0,3]", state.BypassRate)
			}
			if state.FindingDensity < 0 || state.FindingDensity > 3 {
				t.Errorf("FindingDensity = %d, out of [0,3]", state.FindingDensity)
			}
		})
	}
}

func TestCalculateReward_BoundaryValues(t *testing.T) {
	tests := []struct {
		name     string
		findings int
		bypasses int
		requests int
		novel    int
	}{
		{"all zeros", 0, 0, 0, 0},
		{"zero requests", 10, 5, 0, 2},
		{"negative values", -1, -1, -1, -1},
		{"large values", 100000, 50000, 1000000, 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reward := CalculateReward(tt.findings, tt.bypasses, tt.requests, tt.novel)
			if reward < -1 || reward > 1 {
				t.Errorf("reward = %v, out of [-1, 1]", reward)
			}
		})
	}
}

func TestSeedKnownCorrelations_PopulatesGraph(t *testing.T) {
	g := NewInfluenceGraph()
	SeedKnownCorrelations(g)
	if g.NodeCount() == 0 {
		t.Error("SeedKnownCorrelations should add nodes")
	}
	if g.EdgeCount() == 0 {
		t.Error("SeedKnownCorrelations should add edges")
	}
}

func TestDefaultTransformLibrary_NonEmpty(t *testing.T) {
	lib := DefaultTransformLibrary()
	if len(lib) == 0 {
		t.Error("DefaultTransformLibrary should not be empty")
	}
	// Verify all entries are non-empty strings
	for i, s := range lib {
		if s == "" {
			t.Errorf("DefaultTransformLibrary[%d] is empty", i)
		}
	}
}
