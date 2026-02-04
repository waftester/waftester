package mutation

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	// Registry should be initialized with empty maps
	if len(r.Names()) != 0 {
		t.Error("New registry should have no mutators")
	}
}

func TestRegisterAndGet(t *testing.T) {
	r := NewRegistry()

	// Create a mock mutator
	mock := &mockMutator{
		name:        "test_encoder",
		category:    "encoder",
		description: "Test encoder",
	}

	r.Register(mock)

	// Test Get
	m, ok := r.Get("test_encoder")
	if !ok {
		t.Error("Expected to find registered mutator")
	}
	if m.Name() != "test_encoder" {
		t.Errorf("Expected name 'test_encoder', got '%s'", m.Name())
	}
}

func TestRegisterAllCategories(t *testing.T) {
	r := NewRegistry()

	// Register one of each category
	r.Register(&mockMutator{name: "enc1", category: "encoder"})
	r.Register(&mockMutator{name: "loc1", category: "location"})
	r.Register(&mockMutator{name: "eva1", category: "evasion"})
	r.Register(&mockMutator{name: "pro1", category: "protocol"})

	if len(r.GetByCategory("encoder")) != 1 {
		t.Error("Encoder not registered")
	}
	if len(r.GetByCategory("location")) != 1 {
		t.Error("Location not registered")
	}
	if len(r.GetByCategory("evasion")) != 1 {
		t.Error("Evasion not registered")
	}
	if len(r.GetByCategory("protocol")) != 1 {
		t.Error("Protocol not registered")
	}
}

func TestMutateWithAll(t *testing.T) {
	r := NewRegistry()

	// Register encoders that transform input
	r.Register(&mockMutator{
		name:     "upper",
		category: "encoder",
		mutateFunc: func(p string) []MutatedPayload {
			return []MutatedPayload{{
				Original:    p,
				Mutated:     "UPPER:" + p,
				MutatorName: "upper",
			}}
		},
	})
	r.Register(&mockMutator{
		name:     "lower",
		category: "encoder",
		mutateFunc: func(p string) []MutatedPayload {
			return []MutatedPayload{{
				Original:    p,
				Mutated:     "lower:" + p,
				MutatorName: "lower",
			}}
		},
	})

	results := r.MutateWithAll("test")

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	// Check both mutations exist
	found := make(map[string]bool)
	for _, res := range results {
		found[res.Mutated] = true
	}
	if !found["UPPER:test"] {
		t.Error("Missing UPPER mutation")
	}
	if !found["lower:test"] {
		t.Error("Missing lower mutation")
	}
}

func TestChainMutate(t *testing.T) {
	r := NewRegistry()

	r.Register(&mockMutator{
		name:     "prefix",
		category: "encoder",
		mutateFunc: func(p string) []MutatedPayload {
			return []MutatedPayload{{
				Original:    p,
				Mutated:     "PREFIX_" + p,
				MutatorName: "prefix",
			}}
		},
	})
	r.Register(&mockMutator{
		name:     "suffix",
		category: "encoder",
		mutateFunc: func(p string) []MutatedPayload {
			return []MutatedPayload{{
				Original:    p,
				Mutated:     p + "_SUFFIX",
				MutatorName: "suffix",
			}}
		},
	})

	results := r.ChainMutate("test", []string{"prefix", "suffix"})

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	expected := "PREFIX_test_SUFFIX"
	if results[0].Mutated != expected {
		t.Errorf("Expected '%s', got '%s'", expected, results[0].Mutated)
	}
}

func TestDefaultPipelineConfig(t *testing.T) {
	cfg := DefaultPipelineConfig()

	if cfg == nil {
		t.Fatal("DefaultPipelineConfig returned nil")
	}
	// Empty Encoders means "all encoders"
	if len(cfg.Locations) == 0 {
		t.Error("No default locations")
	}
	if !cfg.IncludeRaw {
		t.Error("IncludeRaw should be true by default")
	}
}

func TestFullCoveragePipelineConfig(t *testing.T) {
	cfg := FullCoveragePipelineConfig()

	if cfg == nil {
		t.Fatal("FullCoveragePipelineConfig returned nil")
	}
	if len(cfg.Encoders) < 10 {
		t.Errorf("Expected at least 10 encoders for full coverage, got %d", len(cfg.Encoders))
	}
	if len(cfg.Locations) < 10 {
		t.Errorf("Expected at least 10 locations for full coverage, got %d", len(cfg.Locations))
	}
	if len(cfg.Evasions) < 5 {
		t.Errorf("Expected at least 5 evasions for full coverage, got %d", len(cfg.Evasions))
	}
}

func TestDefaultRegistryExists(t *testing.T) {
	if DefaultRegistry == nil {
		t.Fatal("DefaultRegistry is nil")
	}
}

// mockMutator implements the Mutator interface for testing
type mockMutator struct {
	name        string
	category    string
	description string
	mutateFunc  func(string) []MutatedPayload
}

func (m *mockMutator) Name() string {
	return m.name
}

func (m *mockMutator) Category() string {
	return m.category
}

func (m *mockMutator) Description() string {
	if m.description != "" {
		return m.description
	}
	return "Mock mutator for testing"
}

func (m *mockMutator) Mutate(payload string) []MutatedPayload {
	if m.mutateFunc != nil {
		return m.mutateFunc(payload)
	}
	return []MutatedPayload{{
		Original:    payload,
		Mutated:     payload,
		MutatorName: m.name,
	}}
}

// TestRegistry_ConcurrentMutateWithAll tests that 50 goroutines can call MutateWithAll simultaneously
// without race conditions or data corruption.
func TestRegistry_ConcurrentMutateWithAll(t *testing.T) {
	r := NewRegistry()

	// Register several mutators
	for i := 0; i < 10; i++ {
		idx := i // capture for closure
		r.Register(&mockMutator{
			name:     "mutator_" + string(rune('a'+idx)),
			category: "encoder",
			mutateFunc: func(p string) []MutatedPayload {
				return []MutatedPayload{{
					Original:    p,
					Mutated:     p + "_mutated",
					MutatorName: "mutator_" + string(rune('a'+idx)),
				}}
			},
		})
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount atomic.Int64

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			results := r.MutateWithAll("payload")
			if len(results) == 10 {
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if successCount.Load() != numGoroutines {
		t.Errorf("Expected %d successful calls, got %d", numGoroutines, successCount.Load())
	}
}

// TestRegistry_ConcurrentRegisterAndMutate tests concurrent registration and mutation
// to ensure thread safety when one goroutine registers while another mutates.
func TestRegistry_ConcurrentRegisterAndMutate(t *testing.T) {
	r := NewRegistry()

	// Pre-register some mutators
	for i := 0; i < 5; i++ {
		idx := i
		r.Register(&mockMutator{
			name:     "initial_" + string(rune('a'+idx)),
			category: "encoder",
			mutateFunc: func(p string) []MutatedPayload {
				return []MutatedPayload{{
					Original:    p,
					Mutated:     p + "_init",
					MutatorName: "initial_" + string(rune('a'+idx)),
				}}
			},
		})
	}

	var wg sync.WaitGroup
	var mutateCount atomic.Int64
	var registerCount atomic.Int64

	// Goroutine that registers new mutators
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			idx := i
			r.Register(&mockMutator{
				name:     "dynamic_" + string(rune('a'+idx%26)),
				category: "encoder",
				mutateFunc: func(p string) []MutatedPayload {
					return []MutatedPayload{{
						Original:    p,
						Mutated:     p + "_dyn",
						MutatorName: "dynamic_" + string(rune('a'+idx%26)),
					}}
				},
			})
			registerCount.Add(1)
		}
	}()

	// Goroutine that mutates
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			results := r.MutateWithAll("test_payload")
			if len(results) > 0 {
				mutateCount.Add(1)
			}
		}
	}()

	wg.Wait()

	if registerCount.Load() != 20 {
		t.Errorf("Expected 20 registrations, got %d", registerCount.Load())
	}
	if mutateCount.Load() != 50 {
		t.Errorf("Expected 50 mutation calls, got %d", mutateCount.Load())
	}
}

// TestChainMutate_ConcurrentChains tests parallel chain execution
// to ensure ChainMutate is thread-safe under concurrent access.
func TestChainMutate_ConcurrentChains(t *testing.T) {
	r := NewRegistry()

	// Register mutators for chaining
	r.Register(&mockMutator{
		name:     "chain_prefix",
		category: "encoder",
		mutateFunc: func(p string) []MutatedPayload {
			return []MutatedPayload{{
				Original:    p,
				Mutated:     "PREFIX_" + p,
				MutatorName: "chain_prefix",
			}}
		},
	})
	r.Register(&mockMutator{
		name:     "chain_suffix",
		category: "encoder",
		mutateFunc: func(p string) []MutatedPayload {
			return []MutatedPayload{{
				Original:    p,
				Mutated:     p + "_SUFFIX",
				MutatorName: "chain_suffix",
			}}
		},
	})
	r.Register(&mockMutator{
		name:     "chain_wrap",
		category: "encoder",
		mutateFunc: func(p string) []MutatedPayload {
			return []MutatedPayload{{
				Original:    p,
				Mutated:     "[" + p + "]",
				MutatorName: "chain_wrap",
			}}
		},
	})

	const numGoroutines = 30
	var wg sync.WaitGroup
	var successCount atomic.Int64

	chains := [][]string{
		{"chain_prefix", "chain_suffix"},
		{"chain_wrap", "chain_prefix"},
		{"chain_suffix", "chain_wrap"},
		{"chain_prefix", "chain_suffix", "chain_wrap"},
	}

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			chain := chains[id%len(chains)]
			results := r.ChainMutate("payload", chain)
			if len(results) > 0 && results[0].Mutated != "" {
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if successCount.Load() != numGoroutines {
		t.Errorf("Expected %d successful chain mutations, got %d", numGoroutines, successCount.Load())
	}
}
