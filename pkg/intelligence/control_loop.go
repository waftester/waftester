// Package intelligence provides advanced cognitive capabilities for WAFtester.
// This file implements the OODA (Observe-Orient-Decide-Act) continuous feedback loop
// that replaces the single-pass feedback in auto scan mode.
package intelligence

import (
	"fmt"
	"sync"
	"time"
)

// LoopState represents the current state of the control loop.
type LoopState int

const (
	LoopObserve LoopState = iota // Collecting results from last action
	LoopOrient                   // Analyzing what results mean
	LoopDecide                   // Choosing next action
	LoopAct                      // Executing chosen action
)

// LoopAction represents a decision made by the control loop.
type LoopAction int

const (
	ActionContinue LoopAction = iota // Proceed to next phase
	ActionRepeat                     // Re-run current phase with different params
	ActionSkip                       // Skip next phase (low expected value)
	ActionInsert                     // Insert an ad-hoc phase
	ActionStop                       // Terminate scan (budget exhausted or converged)
)

// String returns a human-readable name for the action.
func (a LoopAction) String() string {
	switch a {
	case ActionContinue:
		return "continue"
	case ActionRepeat:
		return "repeat"
	case ActionSkip:
		return "skip"
	case ActionInsert:
		return "insert"
	case ActionStop:
		return "stop"
	default:
		return "unknown"
	}
}

// LoopDecision captures a single control loop decision with reasoning.
type LoopDecision struct {
	Action     LoopAction
	Phase      string  // Target phase
	Reason     string  // Human-readable reasoning
	Confidence float64 // 0.0-1.0
	Timestamp  time.Time
}

// BudgetState tracks resource consumption for stopping criteria.
type BudgetState struct {
	TotalRequests     int
	MaxRequests       int
	TotalTime         time.Duration
	MaxTime           time.Duration
	FindingsLastEpoch int
	FindingsTotal     int
	ConvergenceScore  float64 // 0.0 = no convergence, 1.0 = fully converged
}

// ObservationSummary contains metrics from the last phase execution.
type ObservationSummary struct {
	Phase         string
	Findings      int
	Bypasses      int
	Blocks        int
	RequestsMade  int
	Duration      time.Duration
	BypassRate    float64
	NewCategories int
}

// Orientation contains analyzed metrics for decision-making.
type Orientation struct {
	ConvergenceScore float64 // 0.0 = no convergence, 1.0 = fully converged
	MarginalValue    float64 // Expected findings per request for next phase
	BypassRateDelta  float64 // Change in bypass rate from previous phase
	BudgetRemaining  float64 // 0.0-1.0 fraction of budget remaining
	Confidence       float64 // 0.0-1.0 confidence in orientation metrics
}

// ControlLoop implements the OODA continuous feedback loop.
type ControlLoop struct {
	mu sync.Mutex

	engine    *Engine
	budget    BudgetState
	decisions []LoopDecision
	epoch     int
	done      bool
	startTime time.Time

	// Convergence detection: track findings per epoch
	findingsPerEpoch  []int
	convergenceWindow int

	// Track bypass rates for delta calculation
	bypassRates []float64

	// Config
	maxEpochs int
}

// ControlLoopConfig configures the feedback loop.
type ControlLoopConfig struct {
	MaxRequests       int
	MaxTime           time.Duration
	ConvergenceWindow int // Number of zero-finding epochs before stopping
	MaxEpochs         int // Hard cap on epochs to prevent infinite loops
}

// DefaultControlLoopConfig returns sensible defaults.
func DefaultControlLoopConfig() *ControlLoopConfig {
	return &ControlLoopConfig{
		MaxRequests:       10000,
		MaxTime:           30 * time.Minute,
		ConvergenceWindow: 3,
		MaxEpochs:         50,
	}
}

// NewControlLoop creates a control loop wrapping an Engine.
func NewControlLoop(engine *Engine, cfg *ControlLoopConfig) *ControlLoop {
	if cfg == nil {
		cfg = DefaultControlLoopConfig()
	}
	return &ControlLoop{
		engine: engine,
		budget: BudgetState{
			MaxRequests: cfg.MaxRequests,
			MaxTime:     cfg.MaxTime,
		},
		convergenceWindow: cfg.ConvergenceWindow,
		maxEpochs:         cfg.MaxEpochs,
		startTime:         time.Now(),
	}
}

// Observe collects results from the last phase and updates budget state.
func (cl *ControlLoop) Observe(phase string, findings, bypasses, blocks, requestsMade int, duration time.Duration) *ObservationSummary {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	cl.budget.TotalRequests += requestsMade
	cl.budget.TotalTime += duration
	cl.budget.FindingsLastEpoch = findings
	cl.budget.FindingsTotal += findings
	cl.findingsPerEpoch = append(cl.findingsPerEpoch, findings)

	bypassRate := 0.0
	total := bypasses + blocks
	if total > 0 {
		bypassRate = float64(bypasses) / float64(total)
	}
	cl.bypassRates = append(cl.bypassRates, bypassRate)

	return &ObservationSummary{
		Phase:        phase,
		Findings:     findings,
		Bypasses:     bypasses,
		Blocks:       blocks,
		RequestsMade: requestsMade,
		Duration:     duration,
		BypassRate:   bypassRate,
	}
}

// Orient analyzes the current state and computes orientation metrics.
func (cl *ControlLoop) Orient() *Orientation {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	ori := &Orientation{}

	// Convergence score: ratio of zero-finding epochs in the last N
	if len(cl.findingsPerEpoch) >= cl.convergenceWindow {
		window := cl.findingsPerEpoch[len(cl.findingsPerEpoch)-cl.convergenceWindow:]
		zeroCount := 0
		for _, f := range window {
			if f == 0 {
				zeroCount++
			}
		}
		ori.ConvergenceScore = float64(zeroCount) / float64(cl.convergenceWindow)
	}
	cl.budget.ConvergenceScore = ori.ConvergenceScore

	// Bypass rate delta from previous epoch
	if len(cl.bypassRates) >= 2 {
		ori.BypassRateDelta = cl.bypassRates[len(cl.bypassRates)-1] - cl.bypassRates[len(cl.bypassRates)-2]
	}

	// Budget remaining
	if cl.budget.MaxRequests > 0 {
		ori.BudgetRemaining = 1.0 - float64(cl.budget.TotalRequests)/float64(cl.budget.MaxRequests)
		if ori.BudgetRemaining < 0 {
			ori.BudgetRemaining = 0
		}
	}

	// Marginal value: findings per request in last epoch
	if len(cl.findingsPerEpoch) > 0 && cl.budget.TotalRequests > 0 {
		lastFindings := cl.findingsPerEpoch[len(cl.findingsPerEpoch)-1]
		// Use float64 division to avoid integer truncation to zero
		reqsPerEpoch := float64(cl.budget.TotalRequests) / float64(len(cl.findingsPerEpoch))
		if reqsPerEpoch > 0 {
			ori.MarginalValue = float64(lastFindings) / reqsPerEpoch
		}
	}

	// Confidence based on data volume
	ori.Confidence = getConfidenceFromCount(len(cl.findingsPerEpoch))

	return ori
}

// Decide chooses the next action based on orientation metrics.
func (cl *ControlLoop) Decide(ori *Orientation, currentPhase string) *LoopDecision {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	decision := &LoopDecision{
		Phase:     currentPhase,
		Timestamp: time.Now(),
	}

	// Rule 1: Budget exhausted → stop
	if cl.budget.MaxRequests > 0 && cl.budget.TotalRequests >= cl.budget.MaxRequests {
		decision.Action = ActionStop
		decision.Reason = fmt.Sprintf("budget exhausted: %d/%d requests", cl.budget.TotalRequests, cl.budget.MaxRequests)
		decision.Confidence = 1.0
		cl.done = true
		return decision
	}

	// Rule 2: Time exhausted → stop
	if cl.budget.MaxTime > 0 && cl.budget.TotalTime >= cl.budget.MaxTime {
		decision.Action = ActionStop
		decision.Reason = fmt.Sprintf("time exhausted: %v/%v", cl.budget.TotalTime, cl.budget.MaxTime)
		decision.Confidence = 1.0
		cl.done = true
		return decision
	}

	// Rule 3: Max epochs reached → stop
	if cl.maxEpochs > 0 && cl.epoch >= cl.maxEpochs {
		decision.Action = ActionStop
		decision.Reason = fmt.Sprintf("max epochs reached: %d", cl.maxEpochs)
		decision.Confidence = 1.0
		cl.done = true
		return decision
	}

	// Rule 4: Convergence → stop (diminishing returns)
	if ori.ConvergenceScore > 0.8 && ori.Confidence > 0.5 {
		decision.Action = ActionStop
		decision.Reason = fmt.Sprintf("converged: %.0f%% of last %d epochs had zero findings", ori.ConvergenceScore*100, cl.convergenceWindow)
		decision.Confidence = ori.ConvergenceScore
		cl.done = true
		return decision
	}

	// Rule 5: High bypass rate increase → repeat with mutations
	if ori.BypassRateDelta > 0.20 {
		decision.Action = ActionRepeat
		decision.Reason = fmt.Sprintf("bypass rate increased %.0f%% — re-running with mutations", ori.BypassRateDelta*100)
		decision.Confidence = 0.8
		return decision
	}

	// Rule 6: Zero findings with high confidence → skip similar phase
	if cl.budget.FindingsLastEpoch == 0 && ori.Confidence > 0.7 {
		decision.Action = ActionSkip
		decision.Reason = "zero findings with high confidence — skip similar phases"
		decision.Confidence = ori.Confidence
		return decision
	}

	// Default: continue
	decision.Action = ActionContinue
	decision.Reason = "normal progression"
	decision.Confidence = 0.5
	return decision
}

// Act applies the decision and advances the epoch.
func (cl *ControlLoop) Act(decision *LoopDecision) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	cl.decisions = append(cl.decisions, *decision)
	cl.epoch++

	if decision.Action == ActionStop {
		cl.done = true
	}
}

// ShouldContinue returns false when ActionStop decided or budget exceeded.
func (cl *ControlLoop) ShouldContinue() bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return !cl.done
}

// GetHistory returns all decisions for debugging/output.
func (cl *ControlLoop) GetHistory() []LoopDecision {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	history := make([]LoopDecision, len(cl.decisions))
	copy(history, cl.decisions)
	return history
}

// CurrentBudget returns current budget snapshot.
func (cl *ControlLoop) CurrentBudget() BudgetState {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.budget
}

// Epoch returns the current epoch number.
func (cl *ControlLoop) Epoch() int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.epoch
}

// getConfidenceFromCount is a helper for logarithmic confidence from observation count.
func getConfidenceFromCount(count int) float64 {
	if count == 0 {
		return 0.0
	}
	// 3 obs ≈ 0.30, 10 obs ≈ 0.50, 30 obs ≈ 0.74, 100 obs ≈ 1.0
	conf := 0.5 * (1 + (1.0 - 1.0/(1.0+float64(count)/5.0)))
	if conf > 1.0 {
		return 1.0
	}
	return conf
}
