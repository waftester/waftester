// Package intelligence provides advanced cognitive capabilities for WAFtester.
// This file implements a grammar-guided Genetic Algorithm for mutation generation.
// Replaces the hardcoded WAF vendor lookup tables in mutation_strategist.go with
// an evolutionary approach that discovers effective payload transformations.
package intelligence

import (
	"math/rand"
	"sort"
	"sync"
	"time"
)

// MutationGene represents a single transformation step.
type MutationGene struct {
	Transform string // e.g., "url-encode", "double-encode", "case-toggle"
	Position  string // "prefix", "infix", "suffix", "wrap"
	Param     string // Transform-specific parameter
}

// MutationChromosome is a sequence of transformation genes.
type MutationChromosome struct {
	Genes   []MutationGene
	Fitness float64 // Bypass success rate (0.0-1.0)
	Age     int     // Generations survived
}

// TrialResult captures the outcome of applying a mutation in a real scan.
type TrialResult struct {
	Bypassed   bool
	StatusCode int
	Latency    time.Duration
}

// MutationGenerator uses a Genetic Algorithm to evolve effective mutations.
type MutationGenerator struct {
	mu sync.Mutex

	population       []*MutationChromosome
	config           *MutationGeneratorConfig
	rng              *rand.Rand
	generation       int
	transformLibrary []string
	positions        []string
}

// MutationGeneratorConfig configures the GA.
type MutationGeneratorConfig struct {
	PopulationSize int
	MaxGeneLength  int     // Max transforms per chromosome
	MutationRate   float64 // Per-gene mutation probability
	CrossoverRate  float64 // Crossover probability per pair
	EliteCount     int     // Top chromosomes preserved unchanged
	TournamentSize int     // Selection tournament size
	MaxGenerations int     // Stop after N generations without improvement
}

// DefaultMutationGeneratorConfig returns sensible defaults.
func DefaultMutationGeneratorConfig() *MutationGeneratorConfig {
	return &MutationGeneratorConfig{
		PopulationSize: 50,
		MaxGeneLength:  5,
		MutationRate:   0.1,
		CrossoverRate:  0.7,
		EliteCount:     5,
		TournamentSize: 3,
		MaxGenerations: 20,
	}
}

// NewMutationGenerator creates a new GA-based mutation generator.
func NewMutationGenerator(config *MutationGeneratorConfig, seed int64) *MutationGenerator {
	if config == nil {
		config = DefaultMutationGeneratorConfig()
	}

	mg := &MutationGenerator{
		config:           config,
		rng:              rand.New(rand.NewSource(seed)),
		transformLibrary: DefaultTransformLibrary(),
		positions:        []string{"prefix", "infix", "suffix", "wrap"},
	}

	mg.InitPopulation()
	return mg
}

// DefaultTransformLibrary extracts all known transforms from the hardcoded
// WAF mutation maps. These seed the GA's initial population.
func DefaultTransformLibrary() []string {
	return []string{
		// URL encoding variants
		"url-encode",
		"double-url-encode",
		"unicode-encode",
		"hex-encode",

		// Case manipulation
		"case-toggle",
		"upper-case",
		"lower-case",
		"mixed-case",
		"random-case",

		// Comment injection
		"sql-comment",
		"html-comment",
		"js-comment",
		"inline-comment",

		// Whitespace manipulation
		"tab-inject",
		"newline-inject",
		"null-byte",
		"zero-width",

		// Encoding chains
		"base64-encode",
		"base64-url-encode",
		"hex-entity",
		"decimal-entity",

		// Structural evasion
		"concat-split",
		"char-code",
		"string-fromcharcode",
		"template-literal",

		// WAF-specific
		"chunked-transfer",
		"multipart-boundary",
		"content-type-mismatch",
		"header-injection",
		"path-traversal-normalize",
	}
}

// InitPopulation creates the initial random population.
func (mg *MutationGenerator) InitPopulation() {
	mg.mu.Lock()
	defer mg.mu.Unlock()

	mg.population = make([]*MutationChromosome, mg.config.PopulationSize)
	for i := range mg.population {
		mg.population[i] = mg.randomChromosome()
	}
	mg.generation = 0
}

// TournamentSelect selects the best chromosome from k random candidates.
func (mg *MutationGenerator) TournamentSelect(k int) *MutationChromosome {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	return mg.tournamentSelect(k)
}

// tournamentSelect is the internal non-locking version.
func (mg *MutationGenerator) tournamentSelect(k int) *MutationChromosome {
	if len(mg.population) == 0 {
		return mg.randomChromosome()
	}
	if k <= 0 {
		k = 1
	}
	if k > len(mg.population) {
		k = len(mg.population)
	}

	best := mg.population[mg.rng.Intn(len(mg.population))]
	for i := 1; i < k; i++ {
		candidate := mg.population[mg.rng.Intn(len(mg.population))]
		if candidate.Fitness > best.Fitness {
			best = candidate
		}
	}
	return best
}

// Crossover performs single-point crossover on two chromosomes.
// Returns two children.
func (mg *MutationGenerator) Crossover(a, b *MutationChromosome) (*MutationChromosome, *MutationChromosome) {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	return mg.crossover(a, b)
}

func (mg *MutationGenerator) crossover(a, b *MutationChromosome) (*MutationChromosome, *MutationChromosome) {
	if len(a.Genes) == 0 || len(b.Genes) == 0 {
		return mg.cloneChromosome(a), mg.cloneChromosome(b)
	}

	// Single-point crossover
	pointA := mg.rng.Intn(len(a.Genes))
	pointB := mg.rng.Intn(len(b.Genes))

	child1Genes := make([]MutationGene, 0, pointA+len(b.Genes)-pointB)
	child1Genes = append(child1Genes, a.Genes[:pointA]...)
	child1Genes = append(child1Genes, b.Genes[pointB:]...)

	child2Genes := make([]MutationGene, 0, pointB+len(a.Genes)-pointA)
	child2Genes = append(child2Genes, b.Genes[:pointB]...)
	child2Genes = append(child2Genes, a.Genes[pointA:]...)

	// Enforce max gene length
	if len(child1Genes) > mg.config.MaxGeneLength {
		child1Genes = child1Genes[:mg.config.MaxGeneLength]
	}
	if len(child2Genes) > mg.config.MaxGeneLength {
		child2Genes = child2Genes[:mg.config.MaxGeneLength]
	}

	return &MutationChromosome{Genes: child1Genes}, &MutationChromosome{Genes: child2Genes}
}

// Mutate applies random gene mutations to a chromosome.
func (mg *MutationGenerator) Mutate(c *MutationChromosome) {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	mg.mutate(c)
}

func (mg *MutationGenerator) mutate(c *MutationChromosome) {
	if len(c.Genes) == 0 {
		return
	}

	// Collect insertions separately to avoid mutating the slice during iteration
	type insertion struct {
		pos  int
		gene MutationGene
	}
	var inserts []insertion

	n := len(c.Genes)
	for i := 0; i < n; i++ {
		if mg.rng.Float64() < mg.config.MutationRate {
			op := mg.rng.Intn(3)
			switch op {
			case 0: // Swap transform
				c.Genes[i].Transform = mg.transformLibrary[mg.rng.Intn(len(mg.transformLibrary))]
			case 1: // Swap position
				c.Genes[i].Position = mg.positions[mg.rng.Intn(len(mg.positions))]
			case 2: // Insert new gene (if under max length)
				if n+len(inserts) < mg.config.MaxGeneLength {
					inserts = append(inserts, insertion{pos: i, gene: mg.randomGene()})
				}
			}
		}
	}

	// Apply insertions in reverse order to preserve indices
	for j := len(inserts) - 1; j >= 0; j-- {
		ins := inserts[j]
		c.Genes = append(c.Genes[:ins.pos+1], c.Genes[ins.pos:]...)
		c.Genes[ins.pos] = ins.gene
	}

	// Enforce max gene length after insertions
	if len(c.Genes) > mg.config.MaxGeneLength {
		c.Genes = c.Genes[:mg.config.MaxGeneLength]
	}

	// Small chance to delete a gene
	if len(c.Genes) > 1 && mg.rng.Float64() < mg.config.MutationRate {
		idx := mg.rng.Intn(len(c.Genes))
		c.Genes = append(c.Genes[:idx], c.Genes[idx+1:]...)
	}
}

// Evolve runs one generation: select → crossover → mutate → replace.
func (mg *MutationGenerator) Evolve() {
	mg.mu.Lock()
	defer mg.mu.Unlock()

	if len(mg.population) == 0 {
		return
	}

	// Sort by fitness (descending)
	sort.Slice(mg.population, func(i, j int) bool {
		return mg.population[i].Fitness > mg.population[j].Fitness
	})

	newPop := make([]*MutationChromosome, 0, mg.config.PopulationSize)

	// Preserve elites
	eliteCount := mg.config.EliteCount
	if eliteCount > len(mg.population) {
		eliteCount = len(mg.population)
	}
	for i := 0; i < eliteCount; i++ {
		newPop = append(newPop, mg.cloneChromosome(mg.population[i]))
	}

	// Fill rest with offspring
	for len(newPop) < mg.config.PopulationSize {
		parent1 := mg.tournamentSelect(mg.config.TournamentSize)
		parent2 := mg.tournamentSelect(mg.config.TournamentSize)

		var child1, child2 *MutationChromosome
		if mg.rng.Float64() < mg.config.CrossoverRate {
			child1, child2 = mg.crossover(parent1, parent2)
		} else {
			child1, child2 = mg.cloneChromosome(parent1), mg.cloneChromosome(parent2)
		}

		mg.mutate(child1)
		mg.mutate(child2)

		newPop = append(newPop, child1)
		if len(newPop) < mg.config.PopulationSize {
			newPop = append(newPop, child2)
		}
	}

	mg.population = newPop
	mg.generation++

	// Age all chromosomes
	for _, c := range mg.population {
		c.Age++
	}
}

// EvaluateFitness updates a chromosome's fitness based on trial outcomes.
func (mg *MutationGenerator) EvaluateFitness(chromosomeIdx int, results []TrialResult) {
	mg.mu.Lock()
	defer mg.mu.Unlock()

	if chromosomeIdx < 0 || chromosomeIdx >= len(mg.population) {
		return
	}

	if len(results) == 0 {
		return
	}

	bypasses := 0
	for _, r := range results {
		if r.Bypassed {
			bypasses++
		}
	}

	mg.population[chromosomeIdx].Fitness = float64(bypasses) / float64(len(results))
}

// RecordOutcome records the result of applying a specific chromosome.
func (mg *MutationGenerator) RecordOutcome(chromosomeIdx int, result TrialResult) {
	mg.mu.Lock()
	defer mg.mu.Unlock()

	if chromosomeIdx < 0 || chromosomeIdx >= len(mg.population) {
		return
	}

	c := mg.population[chromosomeIdx]
	// Exponential moving average fitness update
	alpha := 0.3
	reward := 0.0
	if result.Bypassed {
		reward = 1.0
	}
	c.Fitness = c.Fitness*(1-alpha) + reward*alpha
}

// SuggestMutations returns the top N chromosomes by fitness.
func (mg *MutationGenerator) SuggestMutations(n int) []MutationChromosome {
	mg.mu.Lock()
	defer mg.mu.Unlock()

	if len(mg.population) == 0 {
		return nil
	}

	// Sort by fitness descending
	sorted := make([]*MutationChromosome, len(mg.population))
	copy(sorted, mg.population)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Fitness > sorted[j].Fitness
	})

	if n > len(sorted) {
		n = len(sorted)
	}

	result := make([]MutationChromosome, n)
	for i := 0; i < n; i++ {
		result[i] = *sorted[i]
	}
	return result
}

// Generation returns the current generation number.
func (mg *MutationGenerator) Generation() int {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	return mg.generation
}

// PopulationSize returns the current population size.
func (mg *MutationGenerator) PopulationSize() int {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	return len(mg.population)
}

// AverageFitness returns the mean fitness across the population.
func (mg *MutationGenerator) AverageFitness() float64 {
	mg.mu.Lock()
	defer mg.mu.Unlock()

	if len(mg.population) == 0 {
		return 0
	}

	total := 0.0
	for _, c := range mg.population {
		total += c.Fitness
	}
	return total / float64(len(mg.population))
}

// BestFitness returns the highest fitness in the population.
func (mg *MutationGenerator) BestFitness() float64 {
	mg.mu.Lock()
	defer mg.mu.Unlock()

	best := 0.0
	for _, c := range mg.population {
		if c.Fitness > best {
			best = c.Fitness
		}
	}
	return best
}

// Export serializes the mutation generator state for persistence.
// Only top N chromosomes are persisted; full population regenerates from elites.
func (mg *MutationGenerator) Export() *MutationGeneratorState {
	mg.mu.Lock()
	defer mg.mu.Unlock()

	// Sort and take top N
	sorted := make([]*MutationChromosome, len(mg.population))
	copy(sorted, mg.population)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Fitness > sorted[j].Fitness
	})

	n := 10 // Persist top 10
	if n > len(sorted) {
		n = len(sorted)
	}

	best := make([]MutationChromosomeState, n)
	for i := 0; i < n; i++ {
		genes := make([]MutationGeneState, len(sorted[i].Genes))
		for j, g := range sorted[i].Genes {
			genes[j] = MutationGeneState{
				Transform: g.Transform,
				Position:  g.Position,
				Param:     g.Param,
			}
		}
		best[i] = MutationChromosomeState{
			Genes:   genes,
			Fitness: sorted[i].Fitness,
		}
	}

	return &MutationGeneratorState{
		BestChromosomes: best,
		Generation:      mg.generation,
	}
}

// Import restores mutation generator state from persistence.
// Elites are placed into the population; rest is randomly generated.
func (mg *MutationGenerator) Import(state *MutationGeneratorState) {
	if state == nil {
		return
	}
	mg.mu.Lock()
	defer mg.mu.Unlock()

	mg.generation = state.Generation

	// Restore elites
	elites := make([]*MutationChromosome, 0, len(state.BestChromosomes))
	for _, cs := range state.BestChromosomes {
		genes := make([]MutationGene, len(cs.Genes))
		for j, gs := range cs.Genes {
			genes[j] = MutationGene{
				Transform: gs.Transform,
				Position:  gs.Position,
				Param:     gs.Param,
			}
		}
		elites = append(elites, &MutationChromosome{
			Genes:   genes,
			Fitness: cs.Fitness,
		})
	}

	// Fill rest of population randomly
	mg.population = make([]*MutationChromosome, 0, mg.config.PopulationSize)
	mg.population = append(mg.population, elites...)
	for len(mg.population) < mg.config.PopulationSize {
		mg.population = append(mg.population, mg.randomChromosome())
	}
}

// randomChromosome creates a random chromosome from the transform library.
func (mg *MutationGenerator) randomChromosome() *MutationChromosome {
	length := 1 + mg.rng.Intn(mg.config.MaxGeneLength)
	genes := make([]MutationGene, length)
	for i := range genes {
		genes[i] = mg.randomGene()
	}
	return &MutationChromosome{Genes: genes}
}

// randomGene creates a random gene from the transform library.
func (mg *MutationGenerator) randomGene() MutationGene {
	return MutationGene{
		Transform: mg.transformLibrary[mg.rng.Intn(len(mg.transformLibrary))],
		Position:  mg.positions[mg.rng.Intn(len(mg.positions))],
	}
}

// Reset clears population and generation counter, re-initializing with random chromosomes.
func (mg *MutationGenerator) Reset() {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	mg.generation = 0
	mg.population = make([]*MutationChromosome, mg.config.PopulationSize)
	for i := range mg.population {
		mg.population[i] = mg.randomChromosome()
	}
}

// cloneChromosome makes a deep copy of a chromosome.
func (mg *MutationGenerator) cloneChromosome(c *MutationChromosome) *MutationChromosome {
	genes := make([]MutationGene, len(c.Genes))
	copy(genes, c.Genes)
	return &MutationChromosome{
		Genes:   genes,
		Fitness: c.Fitness,
		Age:     c.Age,
	}
}
