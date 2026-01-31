package mutation

import (
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
