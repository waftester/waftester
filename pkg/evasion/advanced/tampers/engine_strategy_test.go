package tampers

import (
	"testing"
)

func TestEngine_StrategyHints_PrependedToSelection(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	// Register a fake tamper so the hint is recognized
	mock := newMockTamper("case_swap", CategorySQL, PriorityNormal)
	Register(mock)

	engine := NewEngine(&EngineConfig{
		Profile:       ProfileStandard,
		WAFVendor:     "", // No vendor — use defaults
		StrategyHints: []string{"case_swap"},
	})

	selected := engine.GetSelectedTampers()
	if len(selected) == 0 {
		t.Fatal("expected at least one tamper selected")
	}
	if selected[0] != "case_swap" {
		t.Errorf("expected case_swap as first tamper (from strategy hint), got %s", selected[0])
	}
}

func TestEngine_StrategyHints_Empty(t *testing.T) {
	// No hints should behave identically to current behavior
	withHints := NewEngine(&EngineConfig{
		Profile:       ProfileStandard,
		WAFVendor:     "",
		StrategyHints: []string{},
	})
	withoutHints := NewEngine(&EngineConfig{
		Profile:   ProfileStandard,
		WAFVendor: "",
	})

	selectedWith := withHints.GetSelectedTampers()
	selectedWithout := withoutHints.GetSelectedTampers()

	if len(selectedWith) != len(selectedWithout) {
		t.Errorf("empty hints changed selection count: %d vs %d", len(selectedWith), len(selectedWithout))
	}
	for i := range selectedWith {
		if selectedWith[i] != selectedWithout[i] {
			t.Errorf("empty hints changed selection at %d: %s vs %s", i, selectedWith[i], selectedWithout[i])
		}
	}
}

func TestEngine_StrategyHints_NilConfig(t *testing.T) {
	engine := NewEngine(nil)
	if engine == nil {
		t.Fatal("expected non-nil engine from nil config")
	}
	// Should not panic when getting tampers
	selected := engine.GetSelectedTampers()
	if len(selected) == 0 {
		t.Error("expected default tampers with nil config")
	}
}

func TestEngine_StrategyHints_DedupsWithExisting(t *testing.T) {
	// Verify precondition: randomcase must be registered and in the standard set
	if Get("randomcase") == nil {
		t.Skip("randomcase tamper not registered; cannot test dedup")
	}

	// When a hint is already in the vendor-recommended list, it should not appear twice
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileStandard,
		WAFVendor:     "",
		StrategyHints: []string{"randomcase"}, // randomcase is in the default standard set
	})

	selected := engine.GetSelectedTampers()
	count := 0
	for _, name := range selected {
		if name == "randomcase" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected randomcase to appear once (deduped), appeared %d times", count)
	}
}

func TestEngine_StrategyHints_UnregisteredSkipped(t *testing.T) {
	// Hints referencing unregistered tampers should be silently skipped
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileStandard,
		WAFVendor:     "",
		StrategyHints: []string{"nonexistent_tamper_xyz"},
	})

	selected := engine.GetSelectedTampers()
	for _, name := range selected {
		if name == "nonexistent_tamper_xyz" {
			t.Error("unregistered tamper hint should not appear in selection")
		}
	}
}

func TestEngine_StrategyHints_CustomProfileIgnoresHints(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileCustom,
		CustomTampers: []string{"space2comment"},
		StrategyHints: []string{"randomcase"},
	})

	selected := engine.GetSelectedTampers()
	// Custom profile returns exactly the custom list, no hint merging
	if len(selected) != 1 || selected[0] != "space2comment" {
		t.Errorf("custom profile should ignore hints, got %v", selected)
	}
}
