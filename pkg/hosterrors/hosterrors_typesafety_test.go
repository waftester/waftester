package hosterrors

// Type safety tests for host error Cache sync.Map — verifies corrupt state
// entries don't cause panics. Would have caught A-04 (Round 4).

import (
	"testing"
	"time"
)

// TestCache_CorruptState_MarkError verifies MarkError doesn't panic
// when the sync.Map contains a non-*hostState value.
func TestCache_CorruptState_MarkError(t *testing.T) {
	t.Parallel()

	c := NewCache(3, 5*time.Minute)

	// Poison the internal sync.Map
	c.hosts.Store("bad-host", "not-a-hostState")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MarkError panicked on corrupt state: %v", r)
		}
	}()

	// Should not panic — should treat as fresh state
	c.MarkError("bad-host")
}

// TestCache_CorruptState_Check verifies Check doesn't panic on corrupt entries.
func TestCache_CorruptState_Check(t *testing.T) {
	t.Parallel()

	c := NewCache(3, 5*time.Minute)
	c.hosts.Store("bad-host", 42) // integer, not *hostState

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Check panicked on corrupt state: %v", r)
		}
	}()

	// Should return false (not errored), not panic
	result := c.Check("bad-host")
	if result {
		t.Error("corrupt entry should not be treated as errored")
	}
}

// TestCache_NilState verifies nil in sync.Map doesn't panic.
func TestCache_NilState(t *testing.T) {
	t.Parallel()

	c := NewCache(3, 5*time.Minute)
	c.hosts.Store("nil-host", nil)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("MarkError panicked on nil state: %v", r)
		}
	}()

	c.MarkError("nil-host")
	c.Check("nil-host")
}

// TestCache_ConcurrentAccess verifies no race conditions on concurrent
// MarkError and Check calls. Would have caught concurrent sync.Map issues.
func TestCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	c := NewCache(5, 5*time.Minute)
	hosts := []string{"h1", "h2", "h3", "h4", "h5"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			c.MarkError(hosts[i%len(hosts)])
		}
	}()

	for i := 0; i < 1000; i++ {
		c.Check(hosts[i%len(hosts)])
	}
	<-done
}
