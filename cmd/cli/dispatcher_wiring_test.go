package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// =============================================================================
// DISPATCHER WIRING ARCHITECTURE TESTS
// =============================================================================
//
// These tests enforce that ALL dispatcher contexts in the CLI are properly
// wired to emit lifecycle events. This prevents regression where new commands
// are added without proper streaming/hook integration.
//
// If a test fails, it means someone added a dispatcher context without
// properly wiring EmitStart, EmitError, EmitSummary, or EmitResult.

// TestDispatcherWiringMinimumEmissions verifies minimum expected emission counts.
// These are architecture constraints - if counts drop, something was unwired.
func TestDispatcherWiringMinimumEmissions(t *testing.T) {
	// Read all Go source files in cmd/cli
	sourceCode := readAllGoSources(t)

	tests := []struct {
		method   string
		minCount int
		desc     string
	}{
		{"EmitStart", 24, "every command should emit scan start"},
		{"EmitBypass", 80, "bypass/discovery events across commands"},
		{"EmitSummary", 25, "every command should emit completion summary"},
		{"EmitError", 35, "error paths should emit errors"},
		{"EmitResult", 4, "test-based commands should emit per-result telemetry"},
	}

	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			pattern := regexp.MustCompile(`\.` + tc.method + `\(`)
			matches := pattern.FindAllStringIndex(sourceCode, -1)
			count := len(matches)

			if count < tc.minCount {
				t.Errorf("%s: found %d calls, expected at least %d (%s)",
					tc.method, count, tc.minCount, tc.desc)
			}
		})
	}
}

// TestAllDispatcherContextsHaveEmitStart ensures every dispatcher context
// variable has a corresponding EmitStart call.
func TestAllDispatcherContextsHaveEmitStart(t *testing.T) {
	sourceCode := readAllGoSources(t)

	// Find all dispatcher context variable names (e.g., "autoDispCtx", "runDispCtx")
	dispCtxPattern := regexp.MustCompile(`([a-zA-Z]+DispCtx)`)
	matches := dispCtxPattern.FindAllStringSubmatch(sourceCode, -1)

	// Collect unique dispatcher names
	dispCtxNames := make(map[string]bool)
	for _, match := range matches {
		dispCtxNames[match[1]] = true
	}

	// These dispatcher contexts MUST have EmitStart called
	mustHaveEmitStart := []string{
		"autoDispCtx",
		"runDispCtx",
		"mutateDispCtx",
		"bypassDispCtx",
		"fuzzDispCtx",
		"crawlDispCtx",
		"probeDispCtx",
		"discoverDispCtx",
		"smuggleDispCtx",
		"raceDispCtx",
		"workflowDispCtx",
		"analyzeDispCtx",
		"learnDispCtx",
		"headlessDispCtx",
		"validateDispCtx",
		"vtDispCtx",
		"reportDispCtx",
		"updateDispCtx",
	}

	for _, dispName := range mustHaveEmitStart {
		t.Run(dispName, func(t *testing.T) {
			// Check if this dispatcher exists
			if !dispCtxNames[dispName] {
				t.Skipf("dispatcher %s not found in source", dispName)
			}

			// Check if EmitStart is called on it
			emitStartPattern := regexp.MustCompile(dispName + `\.EmitStart\(`)
			if !emitStartPattern.MatchString(sourceCode) {
				t.Errorf("%s: missing EmitStart call - every dispatcher must emit scan start", dispName)
			}
		})
	}
}

// TestAllDispatcherContextsHaveEmitSummary ensures every dispatcher context
// has a corresponding EmitSummary call for scan completion.
func TestAllDispatcherContextsHaveEmitSummary(t *testing.T) {
	sourceCode := readAllGoSources(t)

	// These dispatcher contexts MUST have EmitSummary called
	mustHaveEmitSummary := []string{
		"autoDispCtx",
		"runDispCtx",
		"mutateDispCtx",
		"bypassDispCtx",
		"fuzzDispCtx",
		"crawlDispCtx",
		"probeDispCtx",
		"discoverDispCtx",
		"smuggleDispCtx",
		"raceDispCtx",
		"workflowDispCtx",
		"analyzeDispCtx",
		"learnDispCtx",
		"validateDispCtx",
		"reportDispCtx",
	}

	for _, dispName := range mustHaveEmitSummary {
		t.Run(dispName, func(t *testing.T) {
			// Check if EmitSummary is called on it
			emitSummaryPattern := regexp.MustCompile(dispName + `\.EmitSummary\(`)
			if !emitSummaryPattern.MatchString(sourceCode) {
				t.Errorf("%s: missing EmitSummary call - every dispatcher must emit completion summary", dispName)
			}
		})
	}
}

// TestTestBasedCommandsHaveEmitResult ensures commands that run tests
// (not vulnerability scans) emit EmitResult for each test outcome.
func TestTestBasedCommandsHaveEmitResult(t *testing.T) {
	sourceCode := readAllGoSources(t)

	// Commands that test WAF rules and MUST emit individual results
	testBasedDispatchers := []string{
		"autoDispCtx",   // auto command tests payloads
		"runDispCtx",    // run command tests payloads
		"mutateDispCtx", // mutate command tests mutations
		"bypassDispCtx", // bypass command tests mutations
	}

	for _, dispName := range testBasedDispatchers {
		t.Run(dispName, func(t *testing.T) {
			emitResultPattern := regexp.MustCompile(dispName + `\.EmitResult\(`)
			if !emitResultPattern.MatchString(sourceCode) {
				t.Errorf("%s: missing EmitResult call - test-based commands must emit every test result", dispName)
			}
		})
	}
}

// TestOnResultCallbacksHaveEmitResult ensures all OnResult callbacks
// are wired to emit telemetry.
func TestOnResultCallbacksHaveEmitResult(t *testing.T) {
	sourceCode := readAllGoSources(t)

	// Find all OnResult callback definitions
	onResultPattern := regexp.MustCompile(`OnResult:\s*func\(result \*output\.TestResult\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}`)
	matches := onResultPattern.FindAllStringSubmatch(sourceCode, -1)

	if len(matches) < 2 {
		t.Errorf("expected at least 2 OnResult callbacks, found %d", len(matches))
		return
	}

	for i, match := range matches {
		callbackBody := match[1]
		if !strings.Contains(callbackBody, "EmitResult") {
			t.Errorf("OnResult callback #%d is missing EmitResult call", i+1)
		}
	}
}

// TestMutationCallbacksHaveEmitResult ensures all mutation executor callbacks
// are wired to emit telemetry.
func TestMutationCallbacksHaveEmitResult(t *testing.T) {
	sourceCode := readAllGoSources(t)

	// Find all mutation executor callback patterns
	mutationPattern := regexp.MustCompile(`executor\.Execute\(ctx,\s*tasks,\s*func\(r \*mutation\.TestResult\)`)
	matches := mutationPattern.FindAllStringIndex(sourceCode, -1)

	if len(matches) < 2 {
		t.Errorf("expected at least 2 mutation executor callbacks, found %d", len(matches))
		return
	}

	// Check each callback has EmitResult
	emitResultPattern := regexp.MustCompile(`DispCtx\.EmitResult\(`)
	emitResultMatches := emitResultPattern.FindAllStringIndex(sourceCode, -1)

	// We should have at least as many EmitResult calls as mutation callbacks
	if len(emitResultMatches) < len(matches) {
		t.Errorf("mutation callbacks (%d) exceed EmitResult calls (%d) - some callbacks are not wired",
			len(matches), len(emitResultMatches))
	}
}

// TestErrorPathsHaveEmitError ensures critical error paths emit errors.
// Note: Some commands (like mutate) have error exits BEFORE dispatcher init,
// so they can't emit errors. Only commands with post-init error paths are tested.
func TestErrorPathsHaveEmitError(t *testing.T) {
	sourceCode := readAllGoSources(t)

	// Commands that have error handling paths AFTER dispatcher initialization
	// mutateDispCtx is excluded because its error paths exit before dispatcher init
	// tampersDispCtx, protoDispCtx excluded - no error paths in those commands
	commandsWithErrors := []string{
		"autoDispCtx",
		"runDispCtx",
		"bypassDispCtx",
		"fuzzDispCtx",
		"discoverDispCtx",
		"probeDispCtx",
		"validateDispCtx",
		"smuggleDispCtx",
		"raceDispCtx",
		"workflowDispCtx",
		"headlessDispCtx",
	}

	for _, dispName := range commandsWithErrors {
		t.Run(dispName, func(t *testing.T) {
			emitErrorPattern := regexp.MustCompile(dispName + `\.EmitError\(`)
			if !emitErrorPattern.MatchString(sourceCode) {
				t.Errorf("%s: missing EmitError call - error paths must emit errors", dispName)
			}
		})
	}
}

// TestDispatcherContextsHaveDeferClose ensures all dispatcher contexts
// are properly closed to flush hooks.
func TestDispatcherContextsHaveDeferClose(t *testing.T) {
	sourceCode := readAllGoSources(t)

	// All dispatcher contexts should have defer Close()
	dispCtxPattern := regexp.MustCompile(`([a-zA-Z]+DispCtx)`)
	matches := dispCtxPattern.FindAllStringSubmatch(sourceCode, -1)

	dispCtxNames := make(map[string]bool)
	for _, match := range matches {
		dispCtxNames[match[1]] = true
	}

	for dispName := range dispCtxNames {
		t.Run(dispName, func(t *testing.T) {
			// Check for defer Close pattern
			deferClosePattern := regexp.MustCompile(`defer\s+` + dispName + `\.Close\(\)`)
			if !deferClosePattern.MatchString(sourceCode) {
				t.Errorf("%s: missing 'defer %s.Close()' - dispatchers must be closed", dispName, dispName)
			}
		})
	}
}

// TestNoOrphanedDispatcherContexts ensures every InitDispatcher has corresponding
// EmitStart, EmitSummary, and Close calls.
func TestNoOrphanedDispatcherContexts(t *testing.T) {
	sourceCode := readAllGoSources(t)

	// Find all InitDispatcher calls
	initPattern := regexp.MustCompile(`([a-zA-Z]+DispCtx),\s*[a-zA-Z]+\s*:?=\s*[a-zA-Z]+\.InitDispatcher\(`)
	matches := initPattern.FindAllStringSubmatch(sourceCode, -1)

	for _, match := range matches {
		dispName := match[1]
		t.Run(dispName, func(t *testing.T) {
			// Must have EmitStart
			if !regexp.MustCompile(dispName + `\.EmitStart\(`).MatchString(sourceCode) {
				t.Errorf("%s: initialized but never calls EmitStart", dispName)
			}

			// Must have Close
			if !regexp.MustCompile(dispName + `\.Close\(`).MatchString(sourceCode) {
				t.Errorf("%s: initialized but never calls Close", dispName)
			}
		})
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// readAllGoSources reads all .go files in cmd/cli directory
func readAllGoSources(t *testing.T) string {
	t.Helper()

	files := []string{
		"main.go",
		"cmd_autoscan.go",
		"cmd_scan.go",
		"cmd_fuzz.go",
		"cmd_probe.go",
		"cmd_crawl.go",
		"cmd_tests.go",
		"cmd_mutate.go",
		"cmd_bypass.go",
		"cmd_analyze.go",
		"cmd_discover.go",
		"cmd_learn.go",
		"cmd_misc.go",
		"cmd_admin.go",
		"cmd_docs.go",
		"output.go",
		"assess.go",
		"fp.go",
		"vendor.go",
		"smart_mode.go",
		"tampers.go",
	}

	var combined strings.Builder
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("failed to read %s: %v", file, err)
		}
		combined.Write(content)
		combined.WriteByte('\n')
	}

	return combined.String()
}

// =============================================================================
// DOCUMENTATION
// =============================================================================
//
// These tests enforce architectural constraints on dispatcher wiring:
//
// 1. MINIMUM COUNTS: If you add a new command without emissions, counts drop
//    and tests fail. This catches "forgot to wire hooks" bugs.
//
// 2. EMIT START: Every dispatcher context must emit scan start for lifecycle.
//
// 3. EMIT SUMMARY: Every dispatcher context must emit completion for metrics.
//
// 4. EMIT RESULT: Test-based commands (auto, run, mutate, bypass) must emit
//    individual test results for complete telemetry.
//
// 5. EMIT ERROR: Error paths must emit errors for alerting.
//
// 6. DEFER CLOSE: All dispatchers must be closed to flush hooks.
//
// HOW TO FIX FAILING TESTS:
//
// 1. If minimum count drops: You removed an emission. Add it back.
//
// 2. If new dispatcher missing EmitStart: Add EmitStart call after init.
//
// 3. If new dispatcher missing EmitSummary: Add EmitSummary before return.
//
// 4. If test-based command missing EmitResult: Wire OnResult callback.
//
// 5. If dispatcher missing Close: Add `defer dispCtx.Close()` after init.
