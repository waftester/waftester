package regexcache

import (
	"regexp"
	"sync"
	"testing"
)

func TestGet_ValidPattern(t *testing.T) {
	Clear()
	re, err := Get(`\d+`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if re == nil {
		t.Fatal("expected non-nil regexp")
	}
	if !re.MatchString("123") {
		t.Error("expected match for '123'")
	}
}

func TestGet_InvalidPattern(t *testing.T) {
	Clear()
	_, err := Get(`[invalid`)
	if err == nil {
		t.Fatal("expected error for invalid pattern")
	}
}

func TestGet_Caching(t *testing.T) {
	Clear()
	pattern := `test\d+`

	re1, _ := Get(pattern)
	re2, _ := Get(pattern)

	if re1 != re2 {
		t.Error("expected same regexp instance from cache")
	}

	if Size() != 1 {
		t.Errorf("expected 1 cached pattern, got %d", Size())
	}
}

func TestMustGet_ValidPattern(t *testing.T) {
	Clear()
	re := MustGet(`\w+`)
	if re == nil {
		t.Fatal("expected non-nil regexp")
	}
}

func TestMustGet_InvalidPattern(t *testing.T) {
	Clear()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid pattern")
		}
	}()
	MustGet(`[invalid`)
}

func TestPrecompile(t *testing.T) {
	Clear()
	patterns := []string{`\d+`, `\w+`, `[a-z]+`}
	errs := Precompile(patterns...)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	if Size() != 3 {
		t.Errorf("expected 3 cached patterns, got %d", Size())
	}
}

func TestPrecompile_WithErrors(t *testing.T) {
	Clear()
	patterns := []string{`\d+`, `[invalid`, `\w+`}
	errs := Precompile(patterns...)

	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}

	// Should still cache valid patterns
	if Size() != 2 {
		t.Errorf("expected 2 cached patterns, got %d", Size())
	}
}

func TestClear(t *testing.T) {
	Clear()
	Get(`pattern1`)
	Get(`pattern2`)
	Get(`pattern3`)

	if Size() != 3 {
		t.Fatalf("expected 3 cached patterns, got %d", Size())
	}

	Clear()

	if Size() != 0 {
		t.Errorf("expected 0 cached patterns after clear, got %d", Size())
	}
}

func TestConcurrentAccess(t *testing.T) {
	Clear()
	patterns := []string{`\d+`, `\w+`, `[a-z]+`, `test\d+`, `foo.*bar`}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pattern := patterns[idx%len(patterns)]
			re, err := Get(pattern)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if re == nil {
				t.Error("expected non-nil regexp")
			}
		}(i)
	}
	wg.Wait()

	// Should have exactly 5 patterns cached
	if Size() != 5 {
		t.Errorf("expected 5 cached patterns, got %d", Size())
	}
}

// Benchmarks

func BenchmarkGet_CacheHit(b *testing.B) {
	Clear()
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	Get(pattern) // warm up cache

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Get(pattern)
	}
}

func BenchmarkCompile_NoCache(b *testing.B) {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		regexp.Compile(pattern)
	}
}

func BenchmarkMustGet_CacheHit(b *testing.B) {
	Clear()
	pattern := `\d{3}-\d{3}-\d{4}`
	Get(pattern) // warm up cache

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MustGet(pattern)
	}
}

func BenchmarkConcurrentGet(b *testing.B) {
	Clear()
	patterns := []string{`\d+`, `\w+`, `[a-z]+`, `test\d+`, `foo.*bar`}
	Precompile(patterns...) // warm up cache

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			Get(patterns[i%len(patterns)])
			i++
		}
	})
}
