// pkg/ui/ansi_regression_test.go - Ensures no ANSI escape codes leak into
// non-terminal (redirected/piped) output. Test runner stderr is always a
// pipe, so StderrIsTerminal() returns false — matching the exact condition
// that caused the original bug.
package ui

import (
	"bytes"
	"regexp"
	"testing"
	"time"
)

// ansiPattern matches any ANSI escape sequence:
//
//	ESC[ ... final_byte   (CSI sequences: cursor movement, colors, erase)
//	ESC] ...              (OSC sequences)
//	ESC followed by other introducer bytes
var ansiPattern = regexp.MustCompile(`\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]`)

// assertNoANSI fails the test if buf contains any ANSI escape sequence.
func assertNoANSI(t *testing.T, label string, buf *bytes.Buffer) {
	t.Helper()
	if loc := ansiPattern.FindIndex(buf.Bytes()); loc != nil {
		// Show a snippet around the match for context (up to 60 bytes).
		start := loc[0] - 20
		if start < 0 {
			start = 0
		}
		end := loc[1] + 20
		if end > buf.Len() {
			end = buf.Len()
		}
		t.Errorf("%s: ANSI escape at byte %d: %q", label, loc[0], buf.Bytes()[start:end])
	}
}

// TestStderrIsTerminalInTests validates the invariant that the test runner
// stderr is not a terminal. All other tests in this file depend on this.
func TestStderrIsTerminalInTests(t *testing.T) {
	if StderrIsTerminal() {
		t.Skip("stderr is a real terminal; ANSI leak tests require piped stderr")
	}
}

// TestDefaultOutputModeNonTerminal verifies that DefaultOutputMode returns
// Streaming (not Interactive) when stderr is piped.
func TestDefaultOutputModeNonTerminal(t *testing.T) {
	if StderrIsTerminal() {
		t.Skip("stderr is a terminal")
	}
	mode := DefaultOutputMode()
	if mode != OutputModeStreaming {
		t.Errorf("DefaultOutputMode() = %d; want OutputModeStreaming (%d)", mode, OutputModeStreaming)
	}
}

// TestLiveProgressStreamingNoANSI exercises the full LiveProgress render loop
// in streaming mode and asserts zero ANSI codes in the output.
func TestLiveProgressStreamingNoANSI(t *testing.T) {
	var buf bytes.Buffer
	p := NewLiveProgress(LiveProgressConfig{
		Total:          5,
		Title:          "Streaming test",
		Unit:           "items",
		Mode:           OutputModeStreaming,
		Writer:         &buf,
		StreamInterval: 10 * time.Millisecond,
		Metrics: []MetricConfig{
			{Name: "vulns", Label: "Vulns", Icon: "!", Highlight: true},
			{Name: "blocked", Label: "Blocked", Icon: "#", ColorCode: "\033[33m"},
		},
	})
	p.Start()
	for i := 0; i < 5; i++ {
		p.Increment()
		p.AddMetric("vulns")
		time.Sleep(15 * time.Millisecond)
	}
	p.Stop()
	assertNoANSI(t, "LiveProgress/Streaming", &buf)
}

// TestLiveProgressDefaultModeNoANSI uses DefaultOutputMode() (which is
// Streaming in tests) to verify the automatic downgrade works end-to-end.
func TestLiveProgressDefaultModeNoANSI(t *testing.T) {
	if StderrIsTerminal() {
		t.Skip("stderr is a terminal")
	}
	var buf bytes.Buffer
	p := NewLiveProgress(LiveProgressConfig{
		Total:          3,
		Title:          "Default mode test",
		Unit:           "tasks",
		Mode:           DefaultOutputMode(),
		Writer:         &buf,
		StreamInterval: 10 * time.Millisecond,
	})
	p.Start()
	for i := 0; i < 3; i++ {
		p.Increment()
		time.Sleep(15 * time.Millisecond)
	}
	p.Stop()
	assertNoANSI(t, "LiveProgress/DefaultMode", &buf)
}

// TestManifestSimpleNoANSI verifies that the simple (non-boxed) manifest
// layout emits no ANSI when stderr is not a terminal.
func TestManifestSimpleNoANSI(t *testing.T) {
	if StderrIsTerminal() {
		t.Skip("stderr is a terminal")
	}
	var buf bytes.Buffer
	m := &ExecutionManifest{
		Title:       "TEST MANIFEST",
		Description: "Description text",
		Items: []ManifestItem{
			{Label: "Target", Value: "https://example.com"},
			{Label: "Emphasis", Value: "highlighted", Emphasis: true},
			{Icon: "!", Label: "WithIcon", Value: "value"},
		},
		Writer:   &buf,
		BoxStyle: false,
	}
	m.Print()
	assertNoANSI(t, "Manifest/Simple", &buf)
}

// TestManifestBoxedFallbackNoANSI verifies the boxed manifest falls back to
// simple layout on non-Unicode terminals (i.e., test runner) and emits no ANSI.
func TestManifestBoxedFallbackNoANSI(t *testing.T) {
	if StderrIsTerminal() {
		t.Skip("stderr is a terminal")
	}
	var buf bytes.Buffer
	m := &ExecutionManifest{
		Title:       "BOXED MANIFEST",
		Description: "Should fall back to simple",
		Items: []ManifestItem{
			{Label: "Key", Value: "val"},
			{Label: "Emphasized", Value: "em", Emphasis: true},
		},
		Writer:   &buf,
		BoxStyle: true,
	}
	m.Print()
	assertNoANSI(t, "Manifest/Boxed", &buf)
}

// TestLiveProgressWithTipsNoANSI tests three-line progress with tips
// to cover the tip rendering path in streaming mode.
func TestLiveProgressWithTipsNoANSI(t *testing.T) {
	var buf bytes.Buffer
	p := NewLiveProgress(LiveProgressConfig{
		Total:          2,
		DisplayLines:   3,
		Title:          "Tips test",
		Unit:           "items",
		Mode:           OutputModeStreaming,
		Writer:         &buf,
		StreamInterval: 10 * time.Millisecond,
		Tips: []string{
			"Tip one",
			"Tip two with emoji: check (+)",
		},
	})
	p.Start()
	p.Increment()
	time.Sleep(15 * time.Millisecond)
	p.Stop()
	assertNoANSI(t, "LiveProgress/Tips", &buf)
}

// TestLiveProgressInteractiveContainsANSI is a sanity check: interactive mode
// SHOULD contain ANSI codes. If this fails, something stripped all ANSI
// unconditionally (breaking terminal UX).
func TestLiveProgressInteractiveContainsANSI(t *testing.T) {
	var buf bytes.Buffer
	p := NewLiveProgress(LiveProgressConfig{
		Total:        2,
		DisplayLines: 2,
		Title:        "Interactive test",
		Unit:         "items",
		Mode:         OutputModeInteractive,
		Writer:       &buf,
	})
	p.Start()
	p.Increment()
	time.Sleep(150 * time.Millisecond) // Let render loop fire
	p.Stop()

	if !ansiPattern.Match(buf.Bytes()) {
		t.Error("Interactive mode should contain ANSI escape codes but found none")
	}
}
