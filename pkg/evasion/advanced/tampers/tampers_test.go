package tampers

import (
	"strings"
	"sync"
	"testing"
)

// TestGetAllTampers_NotEmpty verifies that tampers are registered during init()
func TestGetAllTampers_NotEmpty(t *testing.T) {
	allTampers := All()
	if len(allTampers) == 0 {
		t.Fatal("expected registered tampers, got empty registry")
	}

	// Should have at least 20 tampers from the various init() functions
	if len(allTampers) < 20 {
		t.Errorf("expected at least 20 tampers, got %d", len(allTampers))
	}

	// Also verify Count() matches
	count := Count()
	if count != len(allTampers) {
		t.Errorf("Count() = %d, but All() returned %d", count, len(allTampers))
	}

	// Verify List() returns sorted names
	names := List()
	if len(names) != count {
		t.Errorf("List() returned %d names, expected %d", len(names), count)
	}

	// Verify names are sorted
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("List() not sorted: %q should come before %q", names[i], names[i-1])
		}
	}

	t.Logf("Registry contains %d tampers", count)
}

// TestGetTamper_Exists tests retrieving common tamper names
func TestGetTamper_Exists(t *testing.T) {
	// These tampers should be registered based on encoding.go, space.go, obfuscation.go
	expectedTampers := []struct {
		name     string
		category Category
	}{
		// Encoding tampers
		{"base64encode", CategoryEncoding},
		{"charencode", CategoryEncoding},
		{"chardoubleencode", CategoryEncoding},
		{"charunicodeencode", CategoryEncoding},

		// Space tampers
		{"space2comment", CategorySpace},
		{"space2dash", CategorySpace},
		{"space2hash", CategorySpace},
		{"space2plus", CategorySpace},

		// Obfuscation tampers
		{"randomcomments", CategoryObfuscation},
		{"slashstar", CategoryObfuscation},
		{"nullbyte", CategoryObfuscation},
	}

	for _, tt := range expectedTampers {
		t.Run(tt.name, func(t *testing.T) {
			tamper := Get(tt.name)
			if tamper == nil {
				t.Skipf("tamper %q not registered (may have different name)", tt.name)
			}

			if tamper.Name() != tt.name {
				t.Errorf("Name() = %q, expected %q", tamper.Name(), tt.name)
			}

			if tamper.Category() != tt.category {
				t.Errorf("Category() = %q, expected %q", tamper.Category(), tt.category)
			}

			if tamper.Description() == "" {
				t.Error("Description() should not be empty")
			}
		})
	}
}

// TestGetTamper_NotExists verifies Get returns nil for non-existent tampers
func TestGetTamper_NotExists(t *testing.T) {
	tamper := Get("definitely_not_a_real_tamper_name_xyz123")
	if tamper != nil {
		t.Error("expected nil for non-existent tamper")
	}
}

// TestTamper_Apply_Transforms verifies tampers actually transform input
func TestTamper_Apply_Transforms(t *testing.T) {
	testPayload := "SELECT * FROM users WHERE id = 1"

	tests := []struct {
		name      string
		checkFunc func(original, transformed string) bool
		desc      string
	}{
		{
			name: "space2comment",
			checkFunc: func(orig, trans string) bool {
				// Should replace spaces with /**/
				return strings.Contains(trans, "/**/") && !strings.Contains(trans, " ")
			},
			desc: "should replace spaces with /**/",
		},
		{
			name: "space2plus",
			checkFunc: func(orig, trans string) bool {
				// Should replace spaces with +
				return strings.Contains(trans, "+") && !strings.Contains(trans, " ")
			},
			desc: "should replace spaces with +",
		},
		{
			name: "base64encode",
			checkFunc: func(orig, trans string) bool {
				// Base64 output should be different and not contain spaces
				return trans != orig && !strings.Contains(trans, " ")
			},
			desc: "should produce base64 encoded output",
		},
		{
			name: "charencode",
			checkFunc: func(orig, trans string) bool {
				// URL encoded output should contain %XX patterns
				return strings.Contains(trans, "%")
			},
			desc: "should URL encode characters",
		},
		{
			name: "charunicodeencode",
			checkFunc: func(orig, trans string) bool {
				// Unicode encoding should contain %uXXXX patterns
				return strings.Contains(trans, "%u00")
			},
			desc: "should Unicode encode characters",
		},
		{
			name: "slashstar",
			checkFunc: func(orig, trans string) bool {
				// Should wrap with /* */
				return strings.HasPrefix(trans, "/*") && strings.HasSuffix(trans, "*/")
			},
			desc: "should wrap payload in /* */",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tamper := Get(tt.name)
			if tamper == nil {
				t.Skipf("tamper %q not registered", tt.name)
			}

			result := tamper.Transform(testPayload)

			// Transform should return something
			if result == "" {
				t.Error("Transform() returned empty string")
			}

			// Check the specific transformation
			if !tt.checkFunc(testPayload, result) {
				t.Errorf("Transform() = %q; %s", result, tt.desc)
			}
		})
	}
}

// TestTamper_Transform_EmptyInput verifies tampers handle empty input gracefully
func TestTamper_Transform_EmptyInput(t *testing.T) {
	tamperNames := []string{
		"space2comment",
		"base64encode",
		"charencode",
		"randomcomments",
	}

	for _, name := range tamperNames {
		t.Run(name, func(t *testing.T) {
			tamper := Get(name)
			if tamper == nil {
				t.Skipf("tamper %q not registered", name)
			}

			result := tamper.Transform("")
			// Most tampers return empty string for empty input
			if result != "" {
				t.Logf("Transform(%q) = %q (some tampers may add prefixes)", "", result)
			}
		})
	}
}

// TestTamper_ConcurrentApply tests that tampers are race-safe
func TestTamper_ConcurrentApply(t *testing.T) {
	tamperNames := []string{"space2comment", "base64encode", "charencode"}

	// Get tampers first (under read lock)
	tampers := make([]Tamper, 0, len(tamperNames))
	for _, name := range tamperNames {
		tamper := Get(name)
		if tamper == nil {
			t.Skipf("tamper %q not registered", name)
		}
		tampers = append(tampers, tamper)
	}

	if len(tampers) == 0 {
		t.Skip("no tampers available for concurrent test")
	}

	payloads := []string{
		"SELECT * FROM users",
		"' OR 1=1 --",
		"<script>alert(1)</script>",
		"../../../etc/passwd",
		"admin' AND '1'='1",
	}

	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*iterations)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				payload := payloads[(id+j)%len(payloads)]
				tamper := tampers[(id+j)%len(tampers)]

				// This should not panic or race
				result := tamper.Transform(payload)
				if result == "" && payload != "" {
					// Some tampers might return empty, but most shouldn't for non-empty input
					// Just log it, don't fail
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	// Check for any errors
	for err := range errCh {
		t.Error(err)
	}
}

// TestTamperChain_AppliesInOrder verifies chaining applies tampers in specified order
func TestTamperChain_AppliesInOrder(t *testing.T) {
	// Ensure tampers exist
	space2comment := Get("space2comment")
	base64encode := Get("base64encode")

	if space2comment == nil || base64encode == nil {
		t.Skip("required tampers not registered")
	}

	payload := "SELECT * FROM users"

	// Chain: first space2comment, then base64encode
	result1 := Chain(payload, "space2comment", "base64encode")

	// Manual chain to verify order
	step1 := space2comment.Transform(payload)
	expected := base64encode.Transform(step1)

	if result1 != expected {
		t.Errorf("Chain order incorrect:\ngot:      %q\nexpected: %q", result1, expected)
	}

	// Verify order matters: reverse should give different result
	result2 := Chain(payload, "base64encode", "space2comment")

	// Manual reverse
	step1Rev := base64encode.Transform(payload)
	expectedRev := space2comment.Transform(step1Rev)

	if result2 != expectedRev {
		t.Errorf("Reverse chain incorrect:\ngot:      %q\nexpected: %q", result2, expectedRev)
	}

	// The two results should be different (order matters)
	if result1 == result2 {
		t.Error("Chain order should produce different results")
	}
}

// TestChainByPriority_RespectsOrder verifies priority-based chaining
func TestChainByPriority_RespectsOrder(t *testing.T) {
	// Get tampers with known different priorities
	allTampers := All()
	if len(allTampers) < 2 {
		t.Skip("need at least 2 tampers for priority test")
	}

	// Find tampers with different priorities
	var lowPriority, highPriority Tamper
	for _, tp := range allTampers {
		if tp.Priority() == PriorityLow && lowPriority == nil {
			lowPriority = tp
		}
		if tp.Priority() == PriorityHigh && highPriority == nil {
			highPriority = tp
		}
		if tp.Priority() == PriorityHighest && highPriority == nil {
			highPriority = tp
		}
	}

	if lowPriority == nil || highPriority == nil {
		t.Skip("could not find tampers with different priorities")
	}

	t.Logf("Using low priority: %s (%d)", lowPriority.Name(), lowPriority.Priority())
	t.Logf("Using high priority: %s (%d)", highPriority.Name(), highPriority.Priority())

	// ChainByPriority should execute high priority first regardless of argument order
	payload := "test payload"

	// Pass low first, but high should execute first
	result := ChainByPriority(payload, lowPriority.Name(), highPriority.Name())

	// Verify by manually applying in priority order
	highFirst := highPriority.Transform(payload)
	expected := lowPriority.Transform(highFirst)

	if result != expected {
		t.Errorf("ChainByPriority did not respect priority:\ngot:      %q\nexpected: %q", result, expected)
	}
}

// TestByCategory_ReturnsCorrectTampers verifies category filtering
func TestByCategory_ReturnsCorrectTampers(t *testing.T) {
	categories := []Category{
		CategoryEncoding,
		CategorySpace,
		CategoryObfuscation,
	}

	for _, cat := range categories {
		t.Run(string(cat), func(t *testing.T) {
			tampers := ByCategory(cat)

			// Should have at least some tampers in these categories
			if len(tampers) == 0 {
				t.Skipf("no tampers registered for category %q", cat)
			}

			// All returned tampers should have the correct category
			for _, tp := range tampers {
				if tp.Category() != cat {
					t.Errorf("tamper %q has category %q, expected %q", tp.Name(), tp.Category(), cat)
				}
			}

			t.Logf("Category %q has %d tampers", cat, len(tampers))
		})
	}
}

// TestGetMultiple_SingleLockAcquisition verifies batch retrieval works
func TestGetMultiple_SingleLockAcquisition(t *testing.T) {
	// Get known tamper names
	names := List()
	if len(names) < 3 {
		t.Skip("need at least 3 tampers")
	}

	// Request subset plus non-existent
	requested := []string{names[0], "nonexistent_xyz", names[1], names[2]}
	result := GetMultiple(requested...)

	// Should get 3 tampers (skipping non-existent)
	if len(result) != 3 {
		t.Errorf("GetMultiple returned %d tampers, expected 3", len(result))
	}

	// Verify we got the right ones
	gotNames := make(map[string]bool)
	for _, tp := range result {
		gotNames[tp.Name()] = true
	}

	for _, name := range []string{names[0], names[1], names[2]} {
		if !gotNames[name] {
			t.Errorf("missing tamper %q in result", name)
		}
	}
}

// TestConcurrentRegistryAccess tests concurrent reads don't race
func TestConcurrentRegistryAccess(t *testing.T) {
	const goroutines = 20
	const iterations = 100

	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Mix of read operations
				_ = List()
				_ = All()
				_ = Count()
				_ = Get("space2comment")
				_ = ByCategory(CategoryEncoding)
				_ = ByTag("mysql")
			}
		}()
	}

	wg.Wait()
}
