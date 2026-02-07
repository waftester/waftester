// Regression test for bug: unbuffered stats channel causing goroutine hang
package mutation

import (
"context"
"testing"
"time"
)

// TestStreamResults_ChannelReceivable verifies that StreamResults returns
// channels that are receivable and don't hang. The stats channel should
// receive exactly one value when execution completes.
// Regression test for bug: StreamResults goroutine hangs on stats send
func TestStreamResults_ChannelReceivable(t *testing.T) {
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

config := DefaultExecutorConfig()
config.TargetURL = "http://localhost:0" // non-routable, won't connect
config.RealisticMode = false
config.CollectFingerprint = false
exec := NewExecutor(config)

// Call StreamResults with empty tasks
var tasks []MutationTask
resultChan, statsChan := exec.StreamResults(ctx, tasks)

// Drain result channel — should close quickly with no tasks
resultCount := 0
for range resultChan {
resultCount++
}

// Stats channel must receive exactly one value without hanging
select {
case stats := <-statsChan:
if stats == nil {
t.Fatal("StreamResults stats channel sent nil")
}
if stats.TotalTests != 0 {
t.Errorf("expected 0 total tests for empty tasks, got %d", stats.TotalTests)
}
case <-ctx.Done():
t.Fatal("timed out waiting for stats channel — goroutine likely hung (unbuffered channel bug)")
}
}

// TestStreamResults_StatsChannelBuffered verifies the stats channel has
// buffer size >= 1 so the goroutine doesn't block if nobody reads from it
// immediately.
// Regression test for bug: unbuffered stats channel causing goroutine leak
func TestStreamResults_StatsChannelBuffered(t *testing.T) {
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

config := DefaultExecutorConfig()
config.TargetURL = "http://localhost:0"
config.RealisticMode = false
config.CollectFingerprint = false
exec := NewExecutor(config)

var tasks []MutationTask
resultChan, statsChan := exec.StreamResults(ctx, tasks)

// Drain result channel first (required for goroutine to finish)
for range resultChan {
}

// Wait briefly for the goroutine to complete and send stats
time.Sleep(100 * time.Millisecond)

// The stats value should already be in the buffered channel
// If the channel were unbuffered, the goroutine would be stuck
select {
case stats := <-statsChan:
if stats == nil {
t.Fatal("stats channel sent nil")
}
default:
t.Fatal("stats channel was empty after goroutine completed — channel may be unbuffered")
}
}

// TestStreamResults_WithCancellation verifies that StreamResults respects
// context cancellation and doesn't leak goroutines.
// Regression test for bug: goroutine leak on context cancellation
func TestStreamResults_WithCancellation(t *testing.T) {
ctx, cancel := context.WithCancel(context.Background())

config := DefaultExecutorConfig()
config.TargetURL = "http://localhost:0"
config.RealisticMode = false
config.CollectFingerprint = false
exec := NewExecutor(config)

var tasks []MutationTask
resultChan, statsChan := exec.StreamResults(ctx, tasks)

// Cancel immediately
cancel()

// Both channels should eventually close/send without hanging
timeout := time.After(5 * time.Second)

// Drain results
for {
select {
case _, ok := <-resultChan:
if !ok {
goto drainStats
}
case <-timeout:
t.Fatal("timed out draining result channel after cancellation")
}
}

drainStats:
select {
case <-statsChan:
// Got stats — goroutine completed properly
case <-timeout:
t.Fatal("timed out waiting for stats after cancellation — goroutine leak")
}
}
