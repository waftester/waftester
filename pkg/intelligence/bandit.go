// Package intelligence provides advanced cognitive capabilities for WAFtester.
// This file implements Thompson Sampling with Beta-Binomial posteriors for
// exploration-exploitation in payload/category/encoding selection.
package intelligence

import (
	"math"
	"math/rand"
	"sort"
	"sync"
)

// BetaArm represents a single arm in a Thompson Sampling bandit.
// Alpha = successes + 1 (prior), Beta = failures + 1 (prior).
//
// Thread safety: BetaArm fields are NOT individually synchronized.
// All concurrent access must go through BanditSelector methods which
// hold the selector-level mutex. Do not mutate a BetaArm obtained
// via GetOrCreate from multiple goroutines without external synchronization.
type BetaArm struct {
	Alpha float64 // Successes + prior (starts at 1.0 for uniform prior)
	Beta  float64 // Failures + prior (starts at 1.0 for uniform prior)
	Pulls int     // Total observations
}

// Mean returns the expected success rate: alpha / (alpha + beta).
func (a *BetaArm) Mean() float64 {
	return a.Alpha / (a.Alpha + a.Beta)
}

// Variance returns the variance of the Beta distribution.
func (a *BetaArm) Variance() float64 {
	sum := a.Alpha + a.Beta
	return (a.Alpha * a.Beta) / (sum * sum * (sum + 1))
}

// Sample draws a random sample from the Beta distribution using the given RNG.
func (a *BetaArm) Sample(rng *rand.Rand) float64 {
	return betaSample(rng, a.Alpha, a.Beta)
}

// Update records a trial outcome. success=true increments alpha, else beta.
func (a *BetaArm) Update(success bool) {
	if success {
		a.Alpha++
	} else {
		a.Beta++
	}
	a.Pulls++
}

// BanditSelector manages multiple arms with Thompson Sampling.
type BanditSelector struct {
	mu   sync.RWMutex
	arms map[string]*BetaArm
	rng  *rand.Rand
}

// NewBanditSelector creates a BanditSelector with uniform priors.
func NewBanditSelector(seed int64) *BanditSelector {
	return &BanditSelector{
		arms: make(map[string]*BetaArm),
		rng:  rand.New(rand.NewSource(seed)),
	}
}

// GetOrCreate returns the arm for key, creating with uniform prior if new.
func (b *BanditSelector) GetOrCreate(key string) *BetaArm {
	b.mu.Lock()
	defer b.mu.Unlock()
	arm, ok := b.arms[key]
	if !ok {
		arm = &BetaArm{Alpha: 1.0, Beta: 1.0}
		b.arms[key] = arm
	}
	return arm
}

// SampleArm draws a Thompson sample for the given arm key using the selector's RNG.
// Creates the arm with uniform prior if it doesn't exist.
func (b *BanditSelector) SampleArm(key string) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	arm, ok := b.arms[key]
	if !ok {
		arm = &BetaArm{Alpha: 1.0, Beta: 1.0}
		b.arms[key] = arm
	}
	return arm.Sample(b.rng)
}

// Select returns the arm key with the highest Thompson sample.
// Returns empty string if no arms exist.
func (b *BanditSelector) Select() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.arms) == 0 {
		return ""
	}
	bestKey := ""
	bestSample := -1.0
	for key, arm := range b.arms {
		sample := arm.Sample(b.rng)
		if sample > bestSample {
			bestSample = sample
			bestKey = key
		}
	}
	return bestKey
}

// RankAll returns all arms sorted by Thompson sample (descending).
func (b *BanditSelector) RankAll() []RankedArm {
	b.mu.Lock()
	defer b.mu.Unlock()
	ranked := make([]RankedArm, 0, len(b.arms))
	for key, arm := range b.arms {
		ranked = append(ranked, RankedArm{
			Key:    key,
			Sample: arm.Sample(b.rng),
			Mean:   arm.Mean(),
			Pulls:  arm.Pulls,
		})
	}
	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].Sample > ranked[j].Sample
	})
	return ranked
}

// Record records an observation for the given arm.
func (b *BanditSelector) Record(key string, success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	arm, ok := b.arms[key]
	if !ok {
		arm = &BetaArm{Alpha: 1.0, Beta: 1.0}
		b.arms[key] = arm
	}
	arm.Update(success)
}

// Decay multiplies all alpha/beta by factor to slowly forget.
// Keeps minimum of 1.0 to preserve uniform prior floor.
func (b *BanditSelector) Decay(factor float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, arm := range b.arms {
		arm.Alpha = math.Max(1.0, arm.Alpha*factor)
		arm.Beta = math.Max(1.0, arm.Beta*factor)
	}
}

// ArmCount returns the number of arms.
func (b *BanditSelector) ArmCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.arms)
}

// Export serializes bandit state for persistence.
func (b *BanditSelector) Export() *BanditState {
	b.mu.RLock()
	defer b.mu.RUnlock()
	arms := make(map[string]*BetaArmState, len(b.arms))
	for key, arm := range b.arms {
		arms[key] = &BetaArmState{
			Alpha: arm.Alpha,
			Beta:  arm.Beta,
			Pulls: arm.Pulls,
		}
	}
	return &BanditState{Arms: arms}
}

// Import restores bandit state from persistence.
func (b *BanditSelector) Import(state *BanditState) {
	if state == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.arms = make(map[string]*BetaArm, len(state.Arms))
	for key, as := range state.Arms {
		b.arms[key] = &BetaArm{
			Alpha: as.Alpha,
			Beta:  as.Beta,
			Pulls: as.Pulls,
		}
	}
}

// Reset clears all arms, returning the bandit to its initial state.
func (b *BanditSelector) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.arms = make(map[string]*BetaArm)
}

// RankedArm is a single arm with its Thompson sample for sorting.
type RankedArm struct {
	Key    string
	Sample float64
	Mean   float64
	Pulls  int
}

// betaSample draws from Beta(alpha, beta) using gamma ratio method.
// For large parameters, uses normal approximation (CLT).
func betaSample(rng *rand.Rand, alpha, beta float64) float64 {
	if alpha <= 0 {
		alpha = 1.0
	}
	if beta <= 0 {
		beta = 1.0
	}
	// Normal approximation for large parameters (CLT)
	if alpha+beta > 100 {
		mean := alpha / (alpha + beta)
		variance := (alpha * beta) / ((alpha + beta) * (alpha + beta) * (alpha + beta + 1))
		sample := mean + rng.NormFloat64()*math.Sqrt(variance)
		return math.Max(0, math.Min(1, sample))
	}
	// Gamma ratio: Beta(a,b) = Ga/(Ga+Gb)
	x := gammaSample(rng, alpha)
	y := gammaSample(rng, beta)
	if x+y == 0 {
		return 0.5
	}
	return x / (x + y)
}

// gammaSample draws from Gamma(alpha, 1) using Marsaglia-Tsang method.
func gammaSample(rng *rand.Rand, alpha float64) float64 {
	if alpha < 1 {
		// Boost method for alpha < 1
		return gammaSample(rng, alpha+1) * math.Pow(rng.Float64(), 1.0/alpha)
	}
	d := alpha - 1.0/3.0
	c := 1.0 / math.Sqrt(9.0*d)
	for {
		var x, v float64
		for {
			x = rng.NormFloat64()
			v = 1.0 + c*x
			if v > 0 {
				break
			}
		}
		v = v * v * v
		u := rng.Float64()
		if u < 1.0-0.0331*(x*x)*(x*x) {
			return d * v
		}
		if math.Log(u) < 0.5*x*x+d*(1.0-v+math.Log(v)) {
			return d * v
		}
	}
}
