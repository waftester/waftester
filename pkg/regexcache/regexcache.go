// Package regexcache provides a thread-safe cache for compiled regular expressions.
// This prevents repeated compilation of the same regex patterns, which is expensive.
//
// Usage:
//
//	re, err := regexcache.Get("pattern")
//	if err != nil {
//	    // handle error
//	}
//	matches := re.FindAllString(input, -1)
package regexcache

import (
	"regexp"
	"sync"
)

// cache holds compiled regular expressions keyed by pattern string.
// Using sync.Map for concurrent access without explicit locking.
var cache sync.Map

// Get returns a compiled regexp for the given pattern.
// If the pattern was previously compiled, it returns the cached version.
// If the pattern is invalid, it returns an error.
func Get(pattern string) (*regexp.Regexp, error) {
	// Fast path: check if already cached
	if cached, ok := cache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}

	// Slow path: compile and cache
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// Store and return (LoadOrStore handles race conditions)
	actual, _ := cache.LoadOrStore(pattern, re)
	return actual.(*regexp.Regexp), nil
}

// MustGet returns a compiled regexp for the given pattern.
// It panics if the pattern is invalid.
func MustGet(pattern string) *regexp.Regexp {
	re, err := Get(pattern)
	if err != nil {
		panic(err)
	}
	return re
}

// Precompile compiles and caches multiple patterns at once.
// This is useful for warming up the cache at program startup.
// Returns a slice of errors for any patterns that failed to compile.
func Precompile(patterns ...string) []error {
	var errs []error
	for _, pattern := range patterns {
		_, err := Get(pattern)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Clear removes all cached regular expressions.
// This is primarily useful for testing.
func Clear() {
	cache.Range(func(key, _ interface{}) bool {
		cache.Delete(key)
		return true
	})
}

// Size returns the number of cached regular expressions.
func Size() int {
	count := 0
	cache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
