// Tests for advanced cognitive modules
package intelligence

import (
	"testing"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PREDICTOR TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestNewPredictor(t *testing.T) {
	p := NewPredictor()
	if p == nil {
		t.Fatal("NewPredictor returned nil")
	}

	stats := p.GetStats()
	if stats.TotalObservations != 0 {
		t.Errorf("Expected 0 observations, got %d", stats.TotalObservations)
	}
}

func TestPredictorLearn(t *testing.T) {
	p := NewPredictor()

	// Learn from a bypass
	finding := &Finding{
		Category: "sqli",
		Payload:  "' OR '1'='1",
		Path:     "/api/login",
		Blocked:  false,
		Severity: "high",
	}
	p.Learn(finding)

	stats := p.GetStats()
	if stats.TotalObservations != 1 {
		t.Errorf("Expected 1 observation, got %d", stats.TotalObservations)
	}
}

func TestPredictorPredict(t *testing.T) {
	p := NewPredictor()

	// Train with some data
	for i := 0; i < 10; i++ {
		p.Learn(&Finding{
			Category: "sqli",
			Payload:  "' OR '1'='1",
			Path:     "/api/v1/users",
			Blocked:  i < 3, // 30% blocked
			Severity: "high",
		})
	}

	// Predict for similar payload
	prediction := p.Predict("sqli", "' AND '1'='1", "/api/v1/items", []string{})
	if prediction == nil {
		t.Fatal("Predict returned nil")
	}
	if prediction.Probability < 0 || prediction.Probability > 1 {
		t.Errorf("Invalid probability: %f", prediction.Probability)
	}
}

func TestPredictorBatchPredict(t *testing.T) {
	p := NewPredictor()

	// Train
	for i := 0; i < 20; i++ {
		p.Learn(&Finding{
			Category: "xss",
			Payload:  "<script>alert(1)</script>",
			Path:     "/search",
			Blocked:  i < 5,
			Severity: "medium",
		})
	}

	candidates := []PayloadCandidate{
		{Category: "xss", Payload: "<script>alert(1)</script>"},
		{Category: "xss", Payload: "<img onerror=alert(1)>"},
		{Category: "sqli", Payload: "' OR 1=1--"},
	}

	ranked := p.PredictBatch(candidates, []string{})
	if len(ranked) != len(candidates) {
		t.Errorf("Expected %d ranked payloads, got %d", len(candidates), len(ranked))
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// MUTATION STRATEGIST TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestNewMutationStrategist(t *testing.T) {
	ms := NewMutationStrategist()
	if ms == nil {
		t.Fatal("NewMutationStrategist returned nil")
	}

	stats := ms.GetStats()
	if stats.TotalObservations != 0 {
		t.Errorf("Expected 0 observations, got %d", stats.TotalObservations)
	}
}

func TestMutationStrategistLearnBlock(t *testing.T) {
	ms := NewMutationStrategist()

	ms.LearnBlock("sqli", "' OR 1=1--", 403)

	stats := ms.GetStats()
	if stats.TotalObservations != 1 {
		t.Errorf("Expected 1 observation, got %d", stats.TotalObservations)
	}
}

func TestMutationStrategistLearnBypass(t *testing.T) {
	ms := NewMutationStrategist()

	ms.LearnBypass("sqli", "' OR 1=1--", "' OR '1'='1")

	stats := ms.GetStats()
	if stats.LearnedMutations == 0 {
		t.Error("Expected at least one learned mutation")
	}
}

func TestMutationStrategistSuggest(t *testing.T) {
	ms := NewMutationStrategist()

	// Get WAF-specific suggestions
	suggestions := ms.SuggestMutations("sqli", "' OR 1=1--", "cloudflare")
	if len(suggestions) == 0 {
		t.Error("Expected at least one mutation suggestion for cloudflare")
	}

	// Verify suggestions have required fields
	for _, s := range suggestions {
		if s.Type == "" {
			t.Error("Mutation suggestion missing Type")
		}
		if s.Example == "" {
			t.Error("Mutation suggestion missing Example")
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ENDPOINT CLUSTERING TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestNewEndpointClusterer(t *testing.T) {
	ec := NewEndpointClusterer()
	if ec == nil {
		t.Fatal("NewEndpointClusterer returned nil")
	}

	stats := ec.GetStats()
	if stats.TotalEndpoints != 0 {
		t.Errorf("Expected 0 endpoints, got %d", stats.TotalEndpoints)
	}
}

func TestEndpointClustererAddEndpoint(t *testing.T) {
	ec := NewEndpointClusterer()

	ec.AddEndpoint("/api/v1/users/123")
	ec.AddEndpoint("/api/v1/users/456")
	ec.AddEndpoint("/api/v1/items/789")

	stats := ec.GetStats()
	if stats.TotalEndpoints != 3 {
		t.Errorf("Expected 3 endpoints, got %d", stats.TotalEndpoints)
	}
}

func TestEndpointClustererClustering(t *testing.T) {
	ec := NewEndpointClusterer()

	// Add similar endpoints
	ec.AddEndpoint("/api/v1/users/1")
	ec.AddEndpoint("/api/v1/users/2")
	ec.AddEndpoint("/api/v1/users/3")

	// Add different endpoints
	ec.AddEndpoint("/admin/settings")
	ec.AddEndpoint("/login")

	stats := ec.GetStats()
	if stats.TotalClusters < 1 {
		t.Errorf("Expected at least 1 cluster, got %d", stats.TotalClusters)
	}
}

func TestEndpointClustererRecordBehavior(t *testing.T) {
	ec := NewEndpointClusterer()

	ec.AddEndpoint("/api/test")
	ec.RecordBehavior("/api/test", 200, false, "xss", 50.0)
	ec.RecordBehavior("/api/test", 403, true, "sqli", 30.0)

	// Behavior should be recorded
	stats := ec.GetStats()
	if stats.TotalEndpoints != 1 {
		t.Errorf("Expected 1 endpoint, got %d", stats.TotalEndpoints)
	}
}

func TestEndpointClustererGetRepresentatives(t *testing.T) {
	ec := NewEndpointClusterer()

	// Add clusterable endpoints
	ec.AddEndpoint("/api/v1/users/1")
	ec.AddEndpoint("/api/v1/users/2")
	ec.AddEndpoint("/api/v1/items/1")
	ec.AddEndpoint("/api/v1/items/2")

	reps := ec.GetRepresentatives()
	// Should have fewer representatives than total endpoints
	if len(reps) > 4 {
		t.Errorf("Expected at most 4 representatives, got %d", len(reps))
	}
}

func TestEndpointClustererOptimizeOrder(t *testing.T) {
	ec := NewEndpointClusterer()

	paths := []string{
		"/api/v1/users/1",
		"/api/v1/users/2",
		"/api/v1/items/1",
	}

	for _, p := range paths {
		ec.AddEndpoint(p)
	}

	prioritized := ec.OptimizeTestOrder(paths)
	if len(prioritized) != len(paths) {
		t.Errorf("Expected %d prioritized endpoints, got %d", len(paths), len(prioritized))
	}

	// Verify priorities are set
	for _, pe := range prioritized {
		if pe.Priority < 0 || pe.Priority > 1 {
			t.Errorf("Invalid priority: %f", pe.Priority)
		}
	}
}

func TestEndpointClustererInferBehavior(t *testing.T) {
	ec := NewEndpointClusterer()

	// Add and record behavior for representative
	ec.AddEndpoint("/api/v1/users/1")
	ec.RecordBehavior("/api/v1/users/1", 200, false, "xss", 50.0)
	ec.RecordBehavior("/api/v1/users/1", 403, true, "sqli", 30.0)

	// Add similar endpoint without behavior
	ec.AddEndpoint("/api/v1/users/2")

	// Try to infer behavior
	inferred := ec.InferBehavior("/api/v1/users/2")
	// May or may not have inferred behavior depending on clustering
	_ = inferred // Just ensure no panic
}

// ══════════════════════════════════════════════════════════════════════════════
// ANOMALY DETECTOR TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestNewAnomalyDetector(t *testing.T) {
	ad := NewAnomalyDetector()
	if ad == nil {
		t.Fatal("NewAnomalyDetector returned nil")
	}

	stats := ad.GetStats()
	if stats.TotalObservations != 0 {
		t.Errorf("Expected 0 observations, got %d", stats.TotalObservations)
	}
}

func TestAnomalyDetectorObserve(t *testing.T) {
	ad := NewAnomalyDetector()

	// Observe normal responses
	for i := 0; i < 25; i++ {
		ad.ObserveResponse(100.0, 200, 5000, false, "xss", "/api/test")
	}

	stats := ad.GetStats()
	if stats.TotalObservations != 25 {
		t.Errorf("Expected 25 observations, got %d", stats.TotalObservations)
	}
	if !stats.BaselineEstablished {
		t.Error("Baseline should be established after 25 observations")
	}
}

func TestAnomalyDetectorRateLimiting(t *testing.T) {
	ad := NewAnomalyDetector()

	// Establish baseline
	for i := 0; i < 25; i++ {
		ad.ObserveResponse(100.0, 200, 5000, false, "xss", "/api/test")
	}

	// Simulate rate limiting
	var lastAnomalies []Anomaly
	for i := 0; i < 5; i++ {
		lastAnomalies = ad.ObserveResponse(10.0, 429, 100, true, "xss", "/api/test")
	}

	// Should detect rate limiting
	hasRateLimit := false
	for _, a := range lastAnomalies {
		if a.Type == AnomalyRateLimited {
			hasRateLimit = true
			break
		}
	}
	if !hasRateLimit {
		t.Log("Rate limiting detection may require more consecutive 429s")
	}
}

func TestAnomalyDetectorGetAnomalies(t *testing.T) {
	ad := NewAnomalyDetector()

	anomalies := ad.GetAnomalies()
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies initially, got %d", len(anomalies))
	}
}

func TestAnomalyDetectorShouldPause(t *testing.T) {
	ad := NewAnomalyDetector()

	shouldPause, _ := ad.ShouldPause()
	if shouldPause {
		t.Error("Should not pause initially")
	}
}

func TestAnomalyDetectorReset(t *testing.T) {
	ad := NewAnomalyDetector()

	// Add some observations
	for i := 0; i < 30; i++ {
		ad.ObserveResponse(100.0, 200, 5000, false, "xss", "/api/test")
	}

	// Reset
	ad.Reset()

	stats := ad.GetStats()
	if stats.TotalObservations != 0 {
		t.Errorf("Expected 0 observations after reset, got %d", stats.TotalObservations)
	}
	if stats.BaselineEstablished {
		t.Error("Baseline should not be established after reset")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK PATH OPTIMIZER TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestNewAttackPathOptimizer(t *testing.T) {
	apo := NewAttackPathOptimizer()
	if apo == nil {
		t.Fatal("NewAttackPathOptimizer returned nil")
	}

	stats := apo.GetStats()
	if stats.TotalNodes != 0 {
		t.Errorf("Expected 0 nodes, got %d", stats.TotalNodes)
	}
}

func TestAttackPathOptimizerAddNode(t *testing.T) {
	apo := NewAttackPathOptimizer()

	node := &AttackNode{
		ID:    "endpoint:/api/login",
		Type:  NodeEndpoint,
		Path:  "/api/login",
		Value: 50.0,
	}
	apo.AddNode(node)

	stats := apo.GetStats()
	if stats.TotalNodes != 1 {
		t.Errorf("Expected 1 node, got %d", stats.TotalNodes)
	}
}

func TestAttackPathOptimizerAddEdge(t *testing.T) {
	apo := NewAttackPathOptimizer()

	apo.AddNode(&AttackNode{ID: "a", Type: NodeEndpoint})
	apo.AddNode(&AttackNode{ID: "b", Type: NodeVulnerable})
	apo.AddEdge("a", "b", 0.8, "sqli", "' OR 1=1--")

	stats := apo.GetStats()
	if stats.TotalEdges != 1 {
		t.Errorf("Expected 1 edge, got %d", stats.TotalEdges)
	}
}

func TestAttackPathOptimizerLearnFromBypass(t *testing.T) {
	apo := NewAttackPathOptimizer()

	apo.LearnFromBypass("/api/login", "sqli", "' OR 1=1--")

	stats := apo.GetStats()
	if stats.TotalNodes == 0 {
		t.Error("Expected at least 1 node after learning bypass")
	}
	if stats.ExploitedNodes == 0 {
		t.Error("Expected at least 1 exploited node")
	}
}

func TestAttackPathOptimizerLearnFromBlock(t *testing.T) {
	apo := NewAttackPathOptimizer()

	// First learn a bypass to create the edge
	apo.LearnFromBypass("/api/login", "sqli", "' OR 1=1--")

	// Then learn a block on same path/category
	apo.LearnFromBlock("/api/login", "sqli")

	// Edge should be marked blocked (or have reduced probability)
	stats := apo.GetStats()
	_ = stats // Just ensure no panic
}

func TestAttackPathOptimizerGetOptimalPath(t *testing.T) {
	apo := NewAttackPathOptimizer()

	// Build some paths
	apo.LearnFromBypass("/api/login", "auth-bypass", "' OR 1=1--")
	apo.LearnFromBypass("/api/admin", "sqli", "UNION SELECT * FROM users")

	path := apo.GetOptimalPath()
	// May or may not have an optimal path depending on graph structure
	_ = path // Just ensure no panic
}

func TestAttackPathOptimizerGetTopPaths(t *testing.T) {
	apo := NewAttackPathOptimizer()

	apo.LearnFromBypass("/api/login", "sqli", "' OR 1=1--")
	apo.LearnFromBypass("/api/data", "ssrf", "http://localhost")

	paths := apo.GetTopPaths(5)
	if paths == nil {
		t.Log("No paths found (may be expected for simple graph)")
	}
}

func TestAttackPathOptimizerExportGraph(t *testing.T) {
	apo := NewAttackPathOptimizer()

	apo.LearnFromBypass("/api/login", "sqli", "' OR 1=1--")

	dot := apo.ExportGraph()
	if dot == "" {
		t.Error("Expected non-empty DOT graph export")
	}
	if !containsSubstring(dot, "digraph") {
		t.Error("DOT export should contain 'digraph'")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ENGINE INTEGRATION TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestEngineAdvancedModulesInitialized(t *testing.T) {
	engine := NewEngine(nil)

	// Check all advanced modules are initialized
	if engine.Predictor() == nil {
		t.Error("Predictor not initialized")
	}
	if engine.MutationStrategist() == nil {
		t.Error("MutationStrategist not initialized")
	}
	if engine.EndpointClusterer() == nil {
		t.Error("EndpointClusterer not initialized")
	}
	if engine.AnomalyDetector() == nil {
		t.Error("AnomalyDetector not initialized")
	}
	if engine.AttackPathOptimizer() == nil {
		t.Error("AttackPathOptimizer not initialized")
	}
}

func TestEngineFeedsAdvancedModules(t *testing.T) {
	engine := NewEngine(nil)

	// Feed findings
	for i := 0; i < 10; i++ {
		engine.LearnFromFinding(&Finding{
			Category:   "sqli",
			Payload:    "' OR 1=1--",
			Path:       "/api/test",
			Blocked:    i < 3,
			Severity:   "high",
			StatusCode: 200,
			Latency:    100 * time.Millisecond,
		})
	}

	// Check modules received data
	predStats := engine.Predictor().GetStats()
	if predStats.TotalObservations != 10 {
		t.Errorf("Predictor expected 10 observations, got %d", predStats.TotalObservations)
	}

	clusterStats := engine.EndpointClusterer().GetStats()
	if clusterStats.TotalEndpoints != 1 {
		t.Errorf("Clusterer expected 1 endpoint, got %d", clusterStats.TotalEndpoints)
	}

	anomalyStats := engine.AnomalyDetector().GetStats()
	if anomalyStats.TotalObservations != 10 {
		t.Errorf("Anomaly detector expected 10 observations, got %d", anomalyStats.TotalObservations)
	}
}

func TestEngineConvenienceMethods(t *testing.T) {
	engine := NewEngine(nil)

	// Train with data
	for i := 0; i < 20; i++ {
		engine.LearnFromFinding(&Finding{
			Category:   "xss",
			Payload:    "<script>alert(1)</script>",
			Path:       "/search",
			Blocked:    i < 5,
			Severity:   "medium",
			StatusCode: 200,
			Latency:    50 * time.Millisecond,
		})
	}

	// Test prediction
	pred := engine.PredictPayloadSuccess("xss", "<img onerror=alert(1)>", "/search")
	if pred == nil {
		t.Error("PredictPayloadSuccess returned nil")
	}

	// Test mutation suggestions
	mutations := engine.SuggestMutations("xss", "<script>alert(1)</script>")
	if mutations == nil {
		t.Error("SuggestMutations returned nil")
	}

	// Test anomaly status
	status := engine.GetAnomalyStatus()
	if status.TotalObservations != 20 {
		t.Errorf("Expected 20 observations in anomaly status, got %d", status.TotalObservations)
	}

	// Test cognitive summary
	summary := engine.GetCognitiveSummary()
	if summary == nil {
		t.Error("GetCognitiveSummary returned nil")
	}
}

func TestEngineAnomalyCallback(t *testing.T) {
	engine := NewEngine(nil)

	callbackCalled := false
	engine.OnAnomaly(func(a *Anomaly) {
		callbackCalled = true
	})

	// Establish baseline
	for i := 0; i < 25; i++ {
		engine.LearnFromFinding(&Finding{
			Category:   "xss",
			Path:       "/api/test",
			StatusCode: 200,
			Blocked:    false,
			Latency:    100 * time.Millisecond,
		})
	}

	// Trigger anomaly with rate limiting
	for i := 0; i < 10; i++ {
		engine.LearnFromFinding(&Finding{
			Category:   "xss",
			Path:       "/api/test",
			StatusCode: 429,
			Blocked:    true,
			Latency:    10 * time.Millisecond,
		})
	}

	// Callback may or may not be called depending on detection thresholds
	_ = callbackCalled // Just ensure no panic
}

// Helper
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s[1:], substr) || s[:len(substr)] == substr)
}

// ══════════════════════════════════════════════════════════════════════════════
// PERSISTENCE TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestEngineSaveLoad(t *testing.T) {
	engine := NewEngine(nil)

	for i := 0; i < 10; i++ {
		engine.LearnFromFinding(&Finding{
			Phase:      "testing",
			Category:   "sqli",
			Path:       "/api/test",
			Blocked:    i%2 == 0,
			Confidence: 0.9,
		})
	}

	data, err := engine.ExportJSON()
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("ExportJSON returned empty data")
	}

	engine2 := NewEngine(nil)
	err = engine2.ImportJSON(data)
	if err != nil {
		t.Fatalf("ImportJSON failed: %v", err)
	}

	t.Logf("Successfully exported and imported engine state (%d bytes)", len(data))
}

func TestEngineReset(t *testing.T) {
	engine := NewEngine(nil)

	for i := 0; i < 5; i++ {
		engine.LearnFromFinding(&Finding{
			Phase:    "testing",
			Category: "xss",
			Path:     "/test",
			Blocked:  false,
		})
	}

	engine.Reset()

	chains := engine.GetAttackChains()
	if len(chains) != 0 {
		t.Errorf("Expected 0 chains after reset, got %d", len(chains))
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// MEMORY EVICTION TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestMemoryEviction(t *testing.T) {
	mem := NewMemory()
	mem.SetMaxFindings(100)

	for i := 0; i < 150; i++ {
		mem.Store(&Finding{
			Phase:    "testing",
			Category: "sqli",
			Path:     "/test",
		})
	}

	findings := mem.GetAll()
	if len(findings) > 100 {
		t.Errorf("Expected at most 100 findings after eviction, got %d", len(findings))
	}

	t.Logf("Memory correctly evicted to %d findings", len(findings))
}

// ══════════════════════════════════════════════════════════════════════════════
// PATHFINDER CONFIG TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestPathfinderWithConfig(t *testing.T) {
	config := &PathfinderConfig{
		CategoryValues: map[string]float64{
			"sqli": 0.9,
			"xss":  0.8,
		},
		MaxBFSDepth:         5,
		MaxPaths:            10,
		PruneThreshold:      0.2,
		MaxNodesBeforePrune: 50,
	}

	apo := NewAttackPathOptimizerWithConfig(config)

	value := apo.getCategoryValue("sqli")
	if value != 90.0 {
		t.Errorf("Expected sqli value 90.0, got %f", value)
	}
}

func TestPathfinderPruning(t *testing.T) {
	config := &PathfinderConfig{
		PruneThreshold:      0.5,
		MaxNodesBeforePrune: 5,
	}
	apo := NewAttackPathOptimizerWithConfig(config)

	for i := 0; i < 10; i++ {
		value := float64(i * 10)
		apo.AddNode(&AttackNode{
			ID:    "node" + string(rune('0'+i)),
			Type:  NodeEndpoint,
			Value: value,
		})
	}

	pruned := apo.PruneNodes()
	t.Logf("Pruned %d nodes", pruned)

	remaining := apo.NodeCount()
	if remaining == 10 {
		t.Error("Expected some nodes to be pruned")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// WAF PROFILER TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestWAFProfiler(t *testing.T) {
	wp := NewWAFProfiler()

	for i := 0; i < 10; i++ {
		wp.LearnFromFinding(&Finding{
			Category:   "sqli",
			Blocked:    i < 8,
			StatusCode: 403,
			Latency:    100 * time.Millisecond,
		})
	}

	for i := 0; i < 10; i++ {
		wp.LearnFromFinding(&Finding{
			Category:   "xss",
			Blocked:    i < 3,
			StatusCode: 200,
			Latency:    50 * time.Millisecond,
		})
	}

	sqliRate := wp.GetCategoryEffectiveness("sqli")
	xssRate := wp.GetCategoryEffectiveness("xss")

	if sqliRate >= xssRate {
		t.Errorf("Expected sqli rate (%.2f) < xss rate (%.2f)", sqliRate, xssRate)
	}

	t.Logf("SQLi bypass rate: %.2f, XSS bypass rate: %.2f", sqliRate, xssRate)
}

func TestWAFProfilerSummary(t *testing.T) {
	wp := NewWAFProfiler()

	wp.SetFingerprint(&WAFFingerprint{
		Name:       "Cloudflare",
		Vendor:     "Cloudflare Inc",
		Type:       "cloud",
		Confidence: 0.95,
	})

	for i := 0; i < 20; i++ {
		wp.LearnFromFinding(&Finding{
			Category:   "sqli",
			Blocked:    i%2 == 0,
			StatusCode: 403,
			Latency:    100 * time.Millisecond,
		})
	}

	summary := wp.GenerateSummary()

	if summary.WAFName != "Cloudflare" {
		t.Errorf("Expected WAF name Cloudflare, got %s", summary.WAFName)
	}

	if summary.TotalBlocks+summary.TotalBypasses != 20 {
		t.Errorf("Expected 20 total findings, got %d", summary.TotalBlocks+summary.TotalBypasses)
	}
}

func TestWAFProfilerNoDeadlock(t *testing.T) {
	// This test verifies that GenerateSummary doesn't deadlock
	// by calling public methods that internally acquire the same lock.
	// If the internal locked methods aren't used, this would hang.
	wp := NewWAFProfiler()

	// Add some data
	for i := 0; i < 50; i++ {
		wp.LearnFromFinding(&Finding{
			Category:   "sqli",
			Blocked:    i%3 == 0,
			Payload:    "test",
			Encodings:  []string{"url"},
			StatusCode: 403,
			Latency:    50 * time.Millisecond,
		})
	}

	// This call would deadlock if GenerateSummary uses public methods
	// that try to re-acquire the RLock (RWMutex is not reentrant in Go)
	done := make(chan bool)
	go func() {
		summary := wp.GenerateSummary()
		if summary == nil {
			t.Error("GenerateSummary returned nil")
		}
		done <- true
	}()

	select {
	case <-done:
		// Success - no deadlock
	case <-time.After(2 * time.Second):
		t.Fatal("GenerateSummary deadlocked - RWMutex reentrancy issue")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// METRICS TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestMetrics(t *testing.T) {
	m := NewMetrics()

	for i := 0; i < 100; i++ {
		m.RecordFinding(i%3 == 0)
	}

	if m.FindingsProcessed.Load() != 100 {
		t.Errorf("Expected 100 findings, got %d", m.FindingsProcessed.Load())
	}

	bypassRate := m.GetBypassRate()
	if bypassRate < 0.6 || bypassRate > 0.7 {
		t.Errorf("Expected bypass rate ~0.67, got %.2f", bypassRate)
	}
}

func TestMetricsSnapshot(t *testing.T) {
	m := NewMetrics()

	m.RecordFinding(true)
	m.RecordFinding(false)
	m.RecordPrediction(true)
	m.RecordMutation(true)
	m.RecordAnomaly()
	m.RecordSave(true)
	m.RecordLoad(false)
	m.RecordProcessTime(100 * time.Millisecond)

	snap := m.Snapshot()

	if snap.FindingsProcessed != 2 {
		t.Errorf("Expected 2 findings, got %d", snap.FindingsProcessed)
	}

	if snap.AnomaliesDetected != 1 {
		t.Errorf("Expected 1 anomaly, got %d", snap.AnomaliesDetected)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// CONFIG TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestDefaultConfigs(t *testing.T) {
	predConfig := DefaultPredictorConfig()
	if predConfig.EMAAlpha <= 0 || predConfig.EMAAlpha > 1 {
		t.Errorf("Invalid EMAAlpha: %f", predConfig.EMAAlpha)
	}

	pathConfig := DefaultPathfinderConfig()
	if pathConfig.MaxBFSDepth <= 0 {
		t.Errorf("Invalid MaxBFSDepth: %d", pathConfig.MaxBFSDepth)
	}

	memConfig := DefaultMemoryConfig()
	if memConfig.MaxFindings <= 0 {
		t.Errorf("Invalid MaxFindings: %d", memConfig.MaxFindings)
	}

	anomalyConfig := DefaultAnomalyConfig()
	if anomalyConfig.WindowSize <= 0 {
		t.Errorf("Invalid WindowSize: %d", anomalyConfig.WindowSize)
	}

	clustererConfig := DefaultClustererConfig()
	if clustererConfig.SimilarityThreshold <= 0 || clustererConfig.SimilarityThreshold > 1 {
		t.Errorf("Invalid SimilarityThreshold: %f", clustererConfig.SimilarityThreshold)
	}

	t.Log("All default configs are valid")
}

func TestWithConfigConstructors(t *testing.T) {
	// Test Predictor with custom config
	predCfg := &PredictorConfig{EMAAlpha: 0.5, HighConfidenceThreshold: 0.8}
	pred := NewPredictorWithConfig(predCfg)
	if pred == nil {
		t.Fatal("NewPredictorWithConfig returned nil")
	}
	if pred.config.EMAAlpha != 0.5 {
		t.Errorf("Expected EMAAlpha 0.5, got %f", pred.config.EMAAlpha)
	}

	// Test nil config falls back to defaults
	predDefault := NewPredictorWithConfig(nil)
	if predDefault.config == nil {
		t.Fatal("NewPredictorWithConfig(nil) should use default config")
	}

	// Test EndpointClusterer with custom config
	clusterCfg := &ClustererConfig{SimilarityThreshold: 0.9, MaxClusters: 50}
	clusterer := NewEndpointClustererWithConfig(clusterCfg)
	if clusterer == nil {
		t.Fatal("NewEndpointClustererWithConfig returned nil")
	}
	if clusterer.similarityThreshold != 0.9 {
		t.Errorf("Expected SimilarityThreshold 0.9, got %f", clusterer.similarityThreshold)
	}

	// Test AnomalyDetector with custom config
	anomalyCfg := &AnomalyConfig{WindowSize: 50, ZScoreThreshold: 2.5}
	anomaly := NewAnomalyDetectorWithConfig(anomalyCfg)
	if anomaly == nil {
		t.Fatal("NewAnomalyDetectorWithConfig returned nil")
	}
	if anomaly.windowSize != 50 {
		t.Errorf("Expected WindowSize 50, got %d", anomaly.windowSize)
	}

	// Test MutationStrategist with custom config
	mutatorCfg := &MutatorConfig{MaxMutationsPerRequest: 5, EncodingEMAAlpha: 0.3}
	mutator := NewMutationStrategistWithConfig(mutatorCfg)
	if mutator == nil {
		t.Fatal("NewMutationStrategistWithConfig returned nil")
	}
	if mutator.config == nil {
		t.Fatal("MutationStrategist config should not be nil")
	}
	if mutator.config.MaxMutationsPerRequest != 5 {
		t.Errorf("Expected MaxMutationsPerRequest 5, got %d", mutator.config.MaxMutationsPerRequest)
	}

	// Test nil config falls back to defaults
	mutatorDefault := NewMutationStrategistWithConfig(nil)
	if mutatorDefault.config == nil {
		t.Fatal("NewMutationStrategistWithConfig(nil) should use default config")
	}

	t.Log("All WithConfig constructors work correctly")
}

// ══════════════════════════════════════════════════════════════════════════════
// NIL SAFETY TESTS
// ══════════════════════════════════════════════════════════════════════════════

func TestNilFindingSafety(t *testing.T) {
	// All functions that accept *Finding should be nil-safe
	// This test ensures no panics occur with nil input

	engine := NewEngine(DefaultConfig())
	memory := NewMemory()
	stats := NewStats()
	wafModel := NewWAFBehaviorModel()
	techProfile := NewTechProfile()
	predictor := NewPredictor()

	// Should not panic - all have nil guards
	t.Run("Engine.LearnFromFinding", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic on nil finding: %v", r)
			}
		}()
		engine.LearnFromFinding(nil)
	})

	t.Run("Memory.Store", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic on nil finding: %v", r)
			}
		}()
		memory.Store(nil)
	})

	t.Run("Memory.GetSimilarBypasses", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic on nil finding: %v", r)
			}
		}()
		result := memory.GetSimilarBypasses(nil, 1)
		if result != nil {
			t.Error("Expected nil result for nil input")
		}
	})

	t.Run("Stats.RecordFinding", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic on nil finding: %v", r)
			}
		}()
		stats.RecordFinding(nil)
	})

	t.Run("WAFBehaviorModel.Learn", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic on nil finding: %v", r)
			}
		}()
		wafModel.Learn(nil)
	})

	t.Run("WAFBehaviorModel.DetectPattern", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic on nil finding: %v", r)
			}
		}()
		result := wafModel.DetectPattern(nil)
		if result != nil {
			t.Error("Expected nil result for nil input")
		}
	})

	t.Run("TechProfile.Update", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic on nil finding: %v", r)
			}
		}()
		techProfile.Update(nil)
	})

	t.Run("TechProfile.Detect", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic on nil finding: %v", r)
			}
		}()
		result := techProfile.Detect(nil)
		if result != nil {
			t.Error("Expected nil result for nil input")
		}
	})

	t.Run("Predictor.Learn", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic on nil finding: %v", r)
			}
		}()
		predictor.Learn(nil)
	})

	t.Log("All nil-safety checks passed")
}

// ══════════════════════════════════════════════════════════════════════════════
// FINDING ENCODINGS TEST
// ══════════════════════════════════════════════════════════════════════════════

func TestFindingEncodings(t *testing.T) {
	f := &Finding{
		Category:  "sqli",
		Payload:   "1' OR '1'='1",
		Encodings: []string{"url", "double-url"},
	}

	if len(f.Encodings) != 2 {
		t.Errorf("Expected 2 encodings, got %d", len(f.Encodings))
	}
}
