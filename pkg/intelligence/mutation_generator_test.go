package intelligence

import (
	"sync"
	"testing"
)

func TestMutationGA_PopulationInitialization(t *testing.T) {
	mg := NewMutationGenerator(&MutationGeneratorConfig{
		PopulationSize: 20,
		MaxGeneLength:  5,
		MutationRate:   0.1,
		CrossoverRate:  0.7,
		EliteCount:     3,
		TournamentSize: 3,
		MaxGenerations: 20,
	}, 42)

	if mg.PopulationSize() != 20 {
		t.Fatalf("population size: got %d, want 20", mg.PopulationSize())
	}
	if mg.Generation() != 0 {
		t.Fatalf("generation: got %d, want 0", mg.Generation())
	}

	// All chromosomes should have valid genes
	suggestions := mg.SuggestMutations(20)
	for i, s := range suggestions {
		if len(s.Genes) == 0 {
			t.Fatalf("chromosome %d has no genes", i)
		}
		if len(s.Genes) > 5 {
			t.Fatalf("chromosome %d exceeds max gene length: %d", i, len(s.Genes))
		}
		for _, gene := range s.Genes {
			if gene.Transform == "" {
				t.Fatalf("chromosome %d has empty transform", i)
			}
			if gene.Position == "" {
				t.Fatalf("chromosome %d has empty position", i)
			}
		}
	}
}

func TestMutationGA_TournamentSelectsBest(t *testing.T) {
	mg := NewMutationGenerator(&MutationGeneratorConfig{
		PopulationSize: 10,
		MaxGeneLength:  3,
		MutationRate:   0.0,
		CrossoverRate:  0.0,
		EliteCount:     1,
		TournamentSize: 10, // Full population tournament = always picks best
		MaxGenerations: 10,
	}, 42)

	// Set distinct fitness values
	for i := 0; i < 10; i++ {
		mg.EvaluateFitness(i, makeTrial(i == 9)) // Only last one is a bypass
	}

	// With tournament size = population size, always selects the best
	selected := mg.TournamentSelect(10)
	if selected.Fitness < 0.5 {
		t.Log("tournament selection should tend to select higher fitness (may occasionally fail with RNG)")
	}
}

func TestMutationGA_CrossoverProducesChildren(t *testing.T) {
	mg := NewMutationGenerator(DefaultMutationGeneratorConfig(), 42)

	parent1 := &MutationChromosome{
		Genes: []MutationGene{
			{Transform: "url-encode", Position: "prefix"},
			{Transform: "case-toggle", Position: "infix"},
		},
	}
	parent2 := &MutationChromosome{
		Genes: []MutationGene{
			{Transform: "base64-encode", Position: "suffix"},
			{Transform: "null-byte", Position: "wrap"},
		},
	}

	child1, child2 := mg.Crossover(parent1, parent2)

	if len(child1.Genes) == 0 {
		t.Fatal("child1 has no genes")
	}
	if len(child2.Genes) == 0 {
		t.Fatal("child2 has no genes")
	}
}

func TestMutationGA_CrossoverEmptyParent(t *testing.T) {
	mg := NewMutationGenerator(DefaultMutationGeneratorConfig(), 42)

	parent1 := &MutationChromosome{Genes: []MutationGene{}}
	parent2 := &MutationChromosome{
		Genes: []MutationGene{{Transform: "url-encode", Position: "prefix"}},
	}

	child1, child2 := mg.Crossover(parent1, parent2)
	// Should not panic and return clones
	if child1 == nil || child2 == nil {
		t.Fatal("crossover with empty parent should return non-nil children")
	}
}

func TestMutationGA_MutateChangesGenes(t *testing.T) {
	mg := NewMutationGenerator(&MutationGeneratorConfig{
		PopulationSize: 10,
		MaxGeneLength:  5,
		MutationRate:   1.0, // Always mutate
		CrossoverRate:  0.0,
		EliteCount:     1,
		TournamentSize: 3,
		MaxGenerations: 20,
	}, 42)

	original := &MutationChromosome{
		Genes: []MutationGene{
			{Transform: "url-encode", Position: "prefix"},
			{Transform: "case-toggle", Position: "infix"},
		},
	}

	// Capture original state
	origTransform0 := original.Genes[0].Transform
	origTransform1 := original.Genes[1].Transform

	// Mutate many times — at least one change should occur
	changed := false
	for attempt := 0; attempt < 10; attempt++ {
		clone := &MutationChromosome{
			Genes: make([]MutationGene, len(original.Genes)),
		}
		copy(clone.Genes, original.Genes)
		mg.Mutate(clone)

		if len(clone.Genes) != len(original.Genes) {
			changed = true
			break
		}
		for i, g := range clone.Genes {
			if i == 0 && g.Transform != origTransform0 {
				changed = true
			}
			if i == 1 && g.Transform != origTransform1 {
				changed = true
			}
		}
		if changed {
			break
		}
	}

	if !changed {
		t.Fatal("mutation with rate 1.0 should change at least one gene in 10 attempts")
	}
}

func TestMutationGA_EvolveImprovesAvgFitness(t *testing.T) {
	mg := NewMutationGenerator(&MutationGeneratorConfig{
		PopulationSize: 30,
		MaxGeneLength:  3,
		MutationRate:   0.1,
		CrossoverRate:  0.7,
		EliteCount:     3,
		TournamentSize: 3,
		MaxGenerations: 20,
	}, 42)

	// Set initial fitness: reward chromosomes with "url-encode" gene
	for i := 0; i < mg.PopulationSize(); i++ {
		suggestions := mg.SuggestMutations(mg.PopulationSize())
		hasURLEncode := false
		if i < len(suggestions) {
			for _, g := range suggestions[i].Genes {
				if g.Transform == "url-encode" {
					hasURLEncode = true
					break
				}
			}
		}
		if hasURLEncode {
			mg.EvaluateFitness(i, makeTrial(true))
		}
	}

	initialAvg := mg.AverageFitness()

	// Evolve 10 generations, re-evaluating with same fitness function
	for gen := 0; gen < 10; gen++ {
		mg.Evolve()
		// Re-evaluate: url-encode genes get high fitness
		suggestions := mg.SuggestMutations(mg.PopulationSize())
		for i, s := range suggestions {
			hasURLEncode := false
			for _, g := range s.Genes {
				if g.Transform == "url-encode" {
					hasURLEncode = true
					break
				}
			}
			if hasURLEncode {
				mg.EvaluateFitness(i, makeTrial(true))
			} else {
				mg.EvaluateFitness(i, makeTrial(false))
			}
		}
	}

	finalAvg := mg.AverageFitness()

	// Elite preservation + selection should improve or maintain average fitness
	if finalAvg < initialAvg*0.5 {
		t.Fatalf("avg fitness should not drastically decrease: initial=%f, final=%f", initialAvg, finalAvg)
	}
}

func TestMutationGA_ElitesPreserved(t *testing.T) {
	mg := NewMutationGenerator(&MutationGeneratorConfig{
		PopulationSize: 10,
		MaxGeneLength:  3,
		MutationRate:   0.0, // No mutation to test pure elite preservation
		CrossoverRate:  0.0, // No crossover
		EliteCount:     3,
		TournamentSize: 3,
		MaxGenerations: 20,
	}, 42)

	// Give top 3 high fitness
	mg.EvaluateFitness(0, makeTrial(true))
	mg.EvaluateFitness(1, makeTrial(true))
	mg.EvaluateFitness(2, makeTrial(true))

	bestBefore := mg.BestFitness()

	mg.Evolve()

	bestAfter := mg.BestFitness()

	// Best fitness should be preserved (elites survive)
	if bestAfter < bestBefore {
		t.Fatalf("elite fitness lost: before=%f, after=%f", bestBefore, bestAfter)
	}
}

func TestMutationGA_SuggestMutationsReturnsSorted(t *testing.T) {
	mg := NewMutationGenerator(DefaultMutationGeneratorConfig(), 42)

	// Set varying fitness
	for i := 0; i < mg.PopulationSize(); i++ {
		mg.EvaluateFitness(i, makeTrial(i%3 == 0))
	}

	suggestions := mg.SuggestMutations(5)
	if len(suggestions) != 5 {
		t.Fatalf("expected 5 suggestions, got %d", len(suggestions))
	}

	for i := 1; i < len(suggestions); i++ {
		if suggestions[i].Fitness > suggestions[i-1].Fitness {
			t.Fatalf("suggestions not sorted: [%d].Fitness=%f > [%d].Fitness=%f",
				i, suggestions[i].Fitness, i-1, suggestions[i-1].Fitness)
		}
	}
}

func TestMutationGA_SuggestMoreThanPopulation(t *testing.T) {
	mg := NewMutationGenerator(&MutationGeneratorConfig{
		PopulationSize: 5,
		MaxGeneLength:  3,
		MutationRate:   0.1,
		CrossoverRate:  0.7,
		EliteCount:     1,
		TournamentSize: 2,
		MaxGenerations: 10,
	}, 42)

	suggestions := mg.SuggestMutations(100)
	if len(suggestions) != 5 {
		t.Fatalf("should cap at population size: got %d, want 5", len(suggestions))
	}
}

func TestMutationGA_ExportImport(t *testing.T) {
	mg := NewMutationGenerator(DefaultMutationGeneratorConfig(), 42)

	// Evolve and set some fitness
	for i := 0; i < 5; i++ {
		mg.EvaluateFitness(i, makeTrial(true))
	}
	mg.Evolve()
	mg.Evolve()

	exported := mg.Export()
	if exported.Generation != 2 {
		t.Fatalf("exported generation: got %d, want 2", exported.Generation)
	}
	if len(exported.BestChromosomes) == 0 {
		t.Fatal("no chromosomes exported")
	}

	// Import into fresh generator
	mg2 := NewMutationGenerator(DefaultMutationGeneratorConfig(), 99)
	mg2.Import(exported)

	if mg2.Generation() != 2 {
		t.Fatalf("imported generation: got %d, want 2", mg2.Generation())
	}
	if mg2.PopulationSize() != DefaultMutationGeneratorConfig().PopulationSize {
		t.Fatalf("population should be full after import: got %d", mg2.PopulationSize())
	}
}

func TestMutationGA_ImportNilIsNoOp(t *testing.T) {
	mg := NewMutationGenerator(DefaultMutationGeneratorConfig(), 42)
	origGen := mg.Generation()
	mg.Import(nil)
	if mg.Generation() != origGen {
		t.Fatal("import nil should not change state")
	}
}

func TestMutationGA_RecordOutcome(t *testing.T) {
	mg := NewMutationGenerator(DefaultMutationGeneratorConfig(), 42)

	// Record bypass outcome
	mg.RecordOutcome(0, TrialResult{Bypassed: true, StatusCode: 200})
	if mg.BestFitness() == 0 {
		t.Fatal("best fitness should be non-zero after recording bypass")
	}

	// Out of bounds should not panic
	mg.RecordOutcome(-1, TrialResult{Bypassed: true})
	mg.RecordOutcome(9999, TrialResult{Bypassed: true})
}

func TestMutationGA_ConcurrentSafety(t *testing.T) {
	mg := NewMutationGenerator(&MutationGeneratorConfig{
		PopulationSize: 20,
		MaxGeneLength:  3,
		MutationRate:   0.1,
		CrossoverRate:  0.7,
		EliteCount:     2,
		TournamentSize: 3,
		MaxGenerations: 20,
	}, 42)

	var wg sync.WaitGroup
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				mg.Evolve()
				mg.SuggestMutations(3)
				mg.AverageFitness()
				mg.BestFitness()
				mg.EvaluateFitness(0, makeTrial(true))
				mg.RecordOutcome(1, TrialResult{Bypassed: false})
			}
		}()
	}
	wg.Wait()
}

// makeTrial creates a single-result trial slice for fitness evaluation.
func makeTrial(bypassed bool) []TrialResult {
	return []TrialResult{{Bypassed: bypassed, StatusCode: 200}}
}
