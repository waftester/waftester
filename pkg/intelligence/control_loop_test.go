package intelligence

import (
	"sync"
	"testing"
	"time"
)

func TestControlLoop_StopsOnBudgetExhaustion(t *testing.T) {
	cl := NewControlLoop(nil, &ControlLoopConfig{
		MaxRequests:       100,
		MaxTime:           time.Hour,
		ConvergenceWindow: 3,
		MaxEpochs:         50,
	})

	cl.Observe("sqli", 5, 3, 2, 100, time.Second)
	ori := cl.Orient()
	decision := cl.Decide(ori, "sqli")
	cl.Act(decision)

	if decision.Action != ActionStop {
		t.Errorf("action = %v, want ActionStop", decision.Action)
	}
	if cl.ShouldContinue() {
		t.Error("ShouldContinue() = true after budget exhaustion")
	}
}

func TestControlLoop_StopsOnConvergence(t *testing.T) {
	cl := NewControlLoop(nil, &ControlLoopConfig{
		MaxRequests:       10000,
		MaxTime:           time.Hour,
		ConvergenceWindow: 3,
		MaxEpochs:         50,
	})

	// 3 epochs with zero findings → convergence
	for i := 0; i < 3; i++ {
		cl.Observe("phase-"+string(rune('a'+i)), 0, 0, 10, 30, time.Second)
	}
	ori := cl.Orient()
	decision := cl.Decide(ori, "next")
	cl.Act(decision)

	if decision.Action != ActionStop {
		t.Errorf("action = %v, want ActionStop after 3 zero-finding epochs", decision.Action)
	}
}

func TestControlLoop_RepeatsOnHighBypassRate(t *testing.T) {
	cl := NewControlLoop(nil, &ControlLoopConfig{
		MaxRequests:       10000,
		MaxTime:           time.Hour,
		ConvergenceWindow: 5,
		MaxEpochs:         50,
	})

	// First epoch: low bypass rate
	cl.Observe("sqli", 2, 1, 9, 30, time.Second)
	// Second epoch: high bypass rate increase (>20%)
	cl.Observe("xss", 5, 8, 2, 30, time.Second)

	ori := cl.Orient()
	decision := cl.Decide(ori, "xss")
	cl.Act(decision)

	if decision.Action != ActionRepeat {
		t.Errorf("action = %v, want ActionRepeat after bypass rate spike", decision.Action)
	}
}

func TestControlLoop_SkipsLowValuePhase(t *testing.T) {
	cl := NewControlLoop(nil, &ControlLoopConfig{
		MaxRequests:       10000,
		MaxTime:           time.Hour,
		ConvergenceWindow: 10,
		MaxEpochs:         50,
	})

	// Build enough epochs for high confidence but keep convergence window large
	for i := 0; i < 8; i++ {
		cl.Observe("phase-"+string(rune('a'+i)), 5, 3, 2, 30, time.Second)
	}
	// Last epoch: zero findings
	cl.Observe("low-value", 0, 0, 10, 30, time.Second)

	ori := cl.Orient()
	decision := cl.Decide(ori, "low-value")
	cl.Act(decision)

	if decision.Action != ActionSkip {
		t.Errorf("action = %v, want ActionSkip after 0 findings with high confidence", decision.Action)
	}
}

func TestControlLoop_ContinuesByDefault(t *testing.T) {
	cl := NewControlLoop(nil, &ControlLoopConfig{
		MaxRequests:       10000,
		MaxTime:           time.Hour,
		ConvergenceWindow: 5,
		MaxEpochs:         50,
	})

	cl.Observe("sqli", 3, 2, 1, 30, time.Second)
	cl.Observe("xss", 3, 2, 1, 30, time.Second) // Same bypass rate → no spike

	ori := cl.Orient()
	decision := cl.Decide(ori, "next")
	cl.Act(decision)

	if decision.Action != ActionContinue {
		t.Errorf("action = %v, want ActionContinue", decision.Action)
	}
	if !cl.ShouldContinue() {
		t.Error("ShouldContinue() = false, want true")
	}
}

func TestControlLoop_DecisionHistory(t *testing.T) {
	cl := NewControlLoop(nil, DefaultControlLoopConfig())

	for i := 0; i < 3; i++ {
		cl.Observe("phase", 1, 1, 0, 10, time.Second)
		ori := cl.Orient()
		decision := cl.Decide(ori, "phase")
		cl.Act(decision)
	}

	history := cl.GetHistory()
	if len(history) != 3 {
		t.Errorf("GetHistory() returned %d decisions, want 3", len(history))
	}
}

func TestControlLoop_StopsOnMaxEpochs(t *testing.T) {
	cl := NewControlLoop(nil, &ControlLoopConfig{
		MaxRequests:       100000,
		MaxTime:           time.Hour,
		ConvergenceWindow: 100,
		MaxEpochs:         3,
	})

	for i := 0; i < 3; i++ {
		cl.Observe("phase", 5, 3, 2, 10, time.Second)
		ori := cl.Orient()
		decision := cl.Decide(ori, "phase")
		cl.Act(decision)
	}

	// 4th epoch should stop
	cl.Observe("phase", 5, 3, 2, 10, time.Second)
	ori := cl.Orient()
	decision := cl.Decide(ori, "phase")

	if decision.Action != ActionStop {
		t.Errorf("action = %v after max epochs, want ActionStop", decision.Action)
	}
}

func TestControlLoop_ConcurrentSafety(t *testing.T) {
	cl := NewControlLoop(nil, DefaultControlLoopConfig())
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				cl.Observe("phase", 1, 1, 0, 5, time.Millisecond)
				ori := cl.Orient()
				cl.Decide(ori, "phase")
				cl.CurrentBudget()
				cl.GetHistory()
				cl.ShouldContinue()
				cl.Epoch()
			}
		}()
	}
	wg.Wait()
}
