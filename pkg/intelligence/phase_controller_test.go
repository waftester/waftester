package intelligence

import (
	"sync"
	"testing"
)

func TestPhaseController_EpsilonGreedy(t *testing.T) {
	phases := []string{"sqli", "xss", "ssrf", "lfi"}
	cfg := &PhaseControllerConfig{
		LearningRate:   0.1,
		DiscountFactor: 0.9,
		EpsilonStart:   1.0, // Always explore
		EpsilonDecay:   1.0,
		EpsilonMin:     1.0,
	}
	pc := NewPhaseController(phases, cfg)

	// With epsilon=1.0, should explore randomly
	counts := make(map[string]int)
	state := BuildState("unknown", 0.5, 0.1, 0)
	for i := 0; i < 1000; i++ {
		phase := pc.SelectNextPhase(state)
		counts[phase]++
	}

	// Each phase should be selected roughly 250 times (±150)
	for _, phase := range phases {
		if counts[phase] < 100 || counts[phase] > 400 {
			t.Errorf("phase %q selected %d/1000 times, expected ~250", phase, counts[phase])
		}
	}
}

func TestPhaseController_QLearningUpdate(t *testing.T) {
	phases := []string{"sqli", "xss"}
	cfg := &PhaseControllerConfig{
		LearningRate:   0.5,
		DiscountFactor: 0.9,
		EpsilonStart:   0.0, // No exploration
		EpsilonDecay:   1.0,
		EpsilonMin:     0.0,
	}
	pc := NewPhaseController(phases, cfg)

	state := BuildState("cloudflare", 0.75, 0.2, 5)
	newState := BuildState("cloudflare", 0.50, 0.3, 8)

	// Give sqli a high reward repeatedly
	for i := 0; i < 20; i++ {
		pc.SelectNextPhase(state)
		pc.RecordReward("sqli", 1.0, newState)
	}

	// sqli should now have higher Q-value
	rankings := pc.GetPhaseRanking(state)
	if len(rankings) == 0 {
		t.Fatal("no rankings returned")
	}
	if rankings[0].Phase != "sqli" {
		t.Errorf("top phase = %q, want 'sqli'", rankings[0].Phase)
	}
	if rankings[0].QValue <= 0 {
		t.Errorf("sqli Q-value = %v, want > 0", rankings[0].QValue)
	}
}

func TestPhaseController_RewardCalculation(t *testing.T) {
	tests := []struct {
		name     string
		findings int
		bypasses int
		requests int
		novel    int
		wantPos  bool
	}{
		{"high bypass", 5, 3, 100, 1, true},
		{"zero findings", 0, 0, 200, 0, false},
		{"novel categories", 1, 0, 50, 2, true},
		{"pure bypass", 0, 1, 10, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reward := CalculateReward(tt.findings, tt.bypasses, tt.requests, tt.novel)
			if tt.wantPos && reward <= 0 {
				t.Errorf("reward = %v, want positive", reward)
			}
			if !tt.wantPos && reward > 0 {
				t.Errorf("reward = %v, want non-positive", reward)
			}
			if reward < -1 || reward > 1 {
				t.Errorf("reward = %v, out of [-1, 1]", reward)
			}
		})
	}
}

func TestPhaseController_StateDiscretization(t *testing.T) {
	tests := []struct {
		budget   float64
		bypass   float64
		findings int
		wantBR   int
		wantBP   int
		wantFD   int
	}{
		{0.10, 0.05, 0, 0, 0, 0},
		{0.30, 0.15, 2, 1, 1, 1},
		{0.55, 0.40, 7, 2, 2, 2},
		{0.80, 0.70, 20, 3, 3, 3},
	}

	for _, tt := range tests {
		state := BuildState("test", tt.budget, tt.bypass, tt.findings)
		if state.BudgetRemaining != tt.wantBR {
			t.Errorf("BuildState(budget=%v) BudgetRemaining = %d, want %d", tt.budget, state.BudgetRemaining, tt.wantBR)
		}
		if state.BypassRate != tt.wantBP {
			t.Errorf("BuildState(bypass=%v) BypassRate = %d, want %d", tt.bypass, state.BypassRate, tt.wantBP)
		}
		if state.FindingDensity != tt.wantFD {
			t.Errorf("BuildState(findings=%d) FindingDensity = %d, want %d", tt.findings, state.FindingDensity, tt.wantFD)
		}
	}
}

func TestPhaseController_CompletedPhasesExcluded(t *testing.T) {
	phases := []string{"sqli", "xss", "ssrf"}
	pc := NewPhaseController(phases, nil)

	pc.MarkCompleted("sqli")
	pc.MarkCompleted("xss")

	state := BuildState("unknown", 0.5, 0.1, 0)
	phase := pc.SelectNextPhase(state)

	if phase != "ssrf" {
		t.Errorf("SelectNextPhase = %q, want 'ssrf' (only remaining)", phase)
	}
}

func TestPhaseController_AllCompleted(t *testing.T) {
	phases := []string{"sqli", "xss"}
	pc := NewPhaseController(phases, nil)

	pc.MarkCompleted("sqli")
	pc.MarkCompleted("xss")

	state := BuildState("unknown", 0.5, 0.1, 0)
	phase := pc.SelectNextPhase(state)

	if phase != "" {
		t.Errorf("SelectNextPhase = %q, want empty when all completed", phase)
	}
}

func TestPhaseController_ExportImport(t *testing.T) {
	phases := []string{"sqli", "xss", "ssrf"}
	pc := NewPhaseController(phases, nil)

	state := BuildState("cloudflare", 0.5, 0.2, 5)
	for i := 0; i < 10; i++ {
		pc.SelectNextPhase(state)
		pc.RecordReward("sqli", 0.8, state)
	}

	exported := pc.Export()
	pc2 := NewPhaseController(phases, nil)
	pc2.Import(exported)

	rankings1 := pc.GetPhaseRanking(state)
	rankings2 := pc2.GetPhaseRanking(state)

	if len(rankings1) != len(rankings2) {
		t.Fatalf("imported rankings len = %d, want %d", len(rankings2), len(rankings1))
	}
}

func TestPhaseController_ConcurrentSafety(t *testing.T) {
	phases := []string{"sqli", "xss", "ssrf", "lfi", "ssti"}
	pc := NewPhaseController(phases, nil)
	state := BuildState("unknown", 0.5, 0.2, 5)

	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				pc.SelectNextPhase(state)
				pc.RecordReward("sqli", 0.5, state)
				pc.GetPhaseRanking(state)
			}
		}()
	}
	wg.Wait()
}
