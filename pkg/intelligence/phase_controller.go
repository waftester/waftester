// Package intelligence provides advanced cognitive capabilities for WAFtester.
// This file implements a Q-learning agent for dynamic phase ordering in auto scan mode.
// Replaces the fixed 13-phase pipeline with state-dependent phase selection.
package intelligence

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
)

// PhaseState encodes the observable state for Q-learning.
// Discretized to keep Q-table manageable.
type PhaseState struct {
	WAFType        string // Detected WAF (or "unknown")
	BudgetRemaining int   // Discretized: 0=<25%, 1=25-50%, 2=50-75%, 3=>75%
	BypassRate     int    // Discretized: 0=<10%, 1=10-30%, 2=30-60%, 3=>60%
	FindingDensity int    // Discretized: 0=none, 1=sparse, 2=moderate, 3=dense
}

// StateKey returns a string key for Q-table lookup.
func (s PhaseState) StateKey() string {
	return fmt.Sprintf("%s|%d|%d|%d", s.WAFType, s.BudgetRemaining, s.BypassRate, s.FindingDensity)
}

// PhaseRanking is a phase with its Q-value for display.
type PhaseRanking struct {
	Phase  string
	QValue float64
}

// PhaseController uses Q-learning to select optimal phase ordering.
type PhaseController struct {
	mu sync.RWMutex

	qtable map[string]map[string]float64 // state → phase → Q-value
	rng    *rand.Rand
	config *PhaseControllerConfig

	// All available phases
	phases    []string
	completed map[string]bool

	// Learning parameters (mutable)
	epsilon float64

	// Last state-action for Q-learning update
	lastState  string
	lastAction string
}

// PhaseControllerConfig configures the Q-learning agent.
type PhaseControllerConfig struct {
	LearningRate   float64 // Alpha: 0.0-1.0
	DiscountFactor float64 // Gamma: 0.0-1.0
	EpsilonStart   float64 // Initial exploration rate
	EpsilonDecay   float64 // Multiply epsilon per episode
	EpsilonMin     float64 // Minimum exploration rate
}

// DefaultPhaseControllerConfig returns sensible defaults.
func DefaultPhaseControllerConfig() *PhaseControllerConfig {
	return &PhaseControllerConfig{
		LearningRate:   0.1,
		DiscountFactor: 0.9,
		EpsilonStart:   0.3,
		EpsilonDecay:   0.95,
		EpsilonMin:     0.05,
	}
}

// NewPhaseController creates a phase controller with the given phases.
func NewPhaseController(phases []string, cfg *PhaseControllerConfig) *PhaseController {
	if cfg == nil {
		cfg = DefaultPhaseControllerConfig()
	}
	pc := &PhaseController{
		qtable:    make(map[string]map[string]float64),
		rng:       rand.New(rand.NewSource(42)),
		config:    cfg,
		phases:    append([]string{}, phases...),
		completed: make(map[string]bool),
		epsilon:   cfg.EpsilonStart,
	}
	return pc
}

// SelectNextPhase uses epsilon-greedy to select the next phase.
func (pc *PhaseController) SelectNextPhase(state PhaseState) string {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	available := pc.availablePhases()
	if len(available) == 0 {
		return ""
	}

	stateKey := state.StateKey()

	// Epsilon-greedy exploration
	if pc.rng.Float64() < pc.epsilon {
		choice := available[pc.rng.Intn(len(available))]
		pc.lastState = stateKey
		pc.lastAction = choice
		return choice
	}

	// Exploitation: pick phase with highest Q-value
	best := available[0]
	bestQ := pc.getQ(stateKey, best)
	for _, phase := range available[1:] {
		q := pc.getQ(stateKey, phase)
		if q > bestQ {
			bestQ = q
			best = phase
		}
	}

	pc.lastState = stateKey
	pc.lastAction = best
	return best
}

// RecordReward applies the Q-learning update rule.
// Q(s,a) += alpha * (r + gamma * max_a' Q(s',a') - Q(s,a))
func (pc *PhaseController) RecordReward(phase string, reward float64, newState PhaseState) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.lastState == "" {
		return
	}

	stateKey := pc.lastState
	action := phase
	newStateKey := newState.StateKey()

	// Current Q-value
	currentQ := pc.getQ(stateKey, action)

	// Max Q-value in new state
	maxQ := math.Inf(-1)
	for _, p := range pc.availablePhases() {
		q := pc.getQ(newStateKey, p)
		if q > maxQ {
			maxQ = q
		}
	}
	if math.IsInf(maxQ, -1) {
		maxQ = 0
	}

	// Q-learning update
	newQ := currentQ + pc.config.LearningRate*(reward+pc.config.DiscountFactor*maxQ-currentQ)
	pc.setQ(stateKey, action, newQ)

	// Decay epsilon
	pc.epsilon *= pc.config.EpsilonDecay
	if pc.epsilon < pc.config.EpsilonMin {
		pc.epsilon = pc.config.EpsilonMin
	}
}

// MarkCompleted removes a phase from the available set.
func (pc *PhaseController) MarkCompleted(phase string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.completed[phase] = true
}

// GetPhaseRanking returns phases sorted by Q-value for the given state.
func (pc *PhaseController) GetPhaseRanking(state PhaseState) []PhaseRanking {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	stateKey := state.StateKey()
	available := pc.availablePhases()
	rankings := make([]PhaseRanking, len(available))
	for i, phase := range available {
		rankings[i] = PhaseRanking{
			Phase:  phase,
			QValue: pc.getQ(stateKey, phase),
		}
	}
	sort.Slice(rankings, func(i, j int) bool {
		return rankings[i].QValue > rankings[j].QValue
	})
	return rankings
}

// Reset clears completed phases and resets epsilon.
func (pc *PhaseController) Reset() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.completed = make(map[string]bool)
	pc.epsilon = pc.config.EpsilonStart
	pc.lastState = ""
	pc.lastAction = ""
}

// BuildState discretizes continuous values into a PhaseState.
func BuildState(wafType string, budgetPct, bypassRate float64, findingCount int) PhaseState {
	return PhaseState{
		WAFType:        wafType,
		BudgetRemaining: discretize(budgetPct, []float64{0.25, 0.50, 0.75}),
		BypassRate:     discretize(bypassRate, []float64{0.10, 0.30, 0.60}),
		FindingDensity: discretizeFindingDensity(findingCount),
	}
}

// CalculateReward computes the reward for a completed phase.
func CalculateReward(findings, bypasses, requestsMade int, novelCategories int) float64 {
	reward := 0.0
	reward += float64(bypasses) * 1.0   // +1.0 per bypass
	reward += float64(findings) * 0.5   // +0.5 per finding
	reward += float64(novelCategories) * 2.0 // +2.0 per new category

	// Penalty for wasted requests
	if findings == 0 && requestsMade > 0 {
		reward -= float64(requestsMade) / 100.0 * 0.1
	}

	// Normalize to [-1, +1]
	if reward > 1.0 {
		reward = 1.0
	} else if reward < -1.0 {
		reward = -1.0
	}
	return reward
}

// Export serializes the Q-table for persistence.
func (pc *PhaseController) Export() *PhaseControllerState {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	qtable := make(map[string]map[string]float64, len(pc.qtable))
	for state, actions := range pc.qtable {
		actionsCopy := make(map[string]float64, len(actions))
		for action, q := range actions {
			actionsCopy[action] = q
		}
		qtable[state] = actionsCopy
	}
	return &PhaseControllerState{
		QTable:  qtable,
		Epsilon: pc.epsilon,
	}
}

// Import restores the Q-table from persistence.
func (pc *PhaseController) Import(state *PhaseControllerState) {
	if state == nil {
		return
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.qtable = make(map[string]map[string]float64, len(state.QTable))
	for s, actions := range state.QTable {
		actionsCopy := make(map[string]float64, len(actions))
		for a, q := range actions {
			actionsCopy[a] = q
		}
		pc.qtable[s] = actionsCopy
	}
	pc.epsilon = state.Epsilon
}

// --- internal helpers ---

func (pc *PhaseController) availablePhases() []string {
	available := make([]string, 0, len(pc.phases))
	for _, p := range pc.phases {
		if !pc.completed[p] {
			available = append(available, p)
		}
	}
	return available
}

func (pc *PhaseController) getQ(state, action string) float64 {
	if actions, ok := pc.qtable[state]; ok {
		return actions[action]
	}
	return 0.0
}

func (pc *PhaseController) setQ(state, action string, value float64) {
	if _, ok := pc.qtable[state]; !ok {
		pc.qtable[state] = make(map[string]float64)
	}
	pc.qtable[state][action] = value
}

func discretize(value float64, thresholds []float64) int {
	for i, t := range thresholds {
		if value < t {
			return i
		}
	}
	return len(thresholds)
}

func discretizeFindingDensity(count int) int {
	switch {
	case count == 0:
		return 0
	case count <= 3:
		return 1
	case count <= 10:
		return 2
	default:
		return 3
	}
}
