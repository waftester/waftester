package writers

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// makeTableTestResultEvent creates a test result event for table writer tests.
func makeTableTestResultEvent(id, category string, severity events.Severity, outcome events.Outcome) *events.ResultEvent {
	return &events.ResultEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeResult,
			Time: time.Now(),
			Scan: "test-scan-table-123",
		},
		Test: events.TestInfo{
			ID:       id,
			Name:     id + " test",
			Category: category,
			Severity: severity,
		},
		Target: events.TargetInfo{
			URL:    "https://example.com/api",
			Method: "POST",
		},
		Result: events.ResultInfo{
			Outcome:    outcome,
			StatusCode: 200,
			LatencyMs:  42.5,
		},
		Evidence: &events.Evidence{
			Payload: "test-payload-" + id,
		},
	}
}

// makeTableTestProgressEvent creates a test progress event for table writer tests.
func makeTableTestProgressEvent(phase string, current, total int) *events.ProgressEvent {
	return &events.ProgressEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeProgress,
			Time: time.Now(),
			Scan: "test-scan-table-123",
		},
		Progress: events.ProgressInfo{
			Phase:      phase,
			Current:    current,
			Total:      total,
			Percentage: float64(current) / float64(total) * 100,
		},
		Rate: events.RateInfo{
			RequestsPerSec: 10.5,
			AvgLatencyMs:   45.2,
		},
		Timing: events.TimingInfo{
			ElapsedSec: 30,
			ETASec:     60,
		},
	}
}

// makeTableTestSummaryEvent creates a test summary event for table writer tests.
func makeTableTestSummaryEvent() *events.SummaryEvent {
	return &events.SummaryEvent{
		BaseEvent: events.BaseEvent{
			Type: events.EventTypeSummary,
			Time: time.Now(),
			Scan: "test-scan-table-123",
		},
		Version: "2.5.0",
		Target: events.SummaryTarget{
			URL:         "https://example.com",
			WAFDetected: "Cloudflare",
		},
		Totals: events.SummaryTotals{
			Tests:    100,
			Bypasses: 5,
			Blocked:  90,
			Errors:   3,
			Passes:   2,
			Timeouts: 0,
		},
		Effectiveness: events.EffectivenessInfo{
			BlockRatePct:   90.0,
			Grade:          "B",
			Recommendation: "Enable additional protection rules",
		},
		Breakdown: events.BreakdownInfo{
			BySeverity: map[string]events.CategoryStats{
				"critical": {Total: 10, Bypasses: 2, BlockRate: 80.0},
				"high":     {Total: 30, Bypasses: 2, BlockRate: 93.3},
				"medium":   {Total: 40, Bypasses: 1, BlockRate: 97.5},
				"low":      {Total: 20, Bypasses: 0, BlockRate: 100.0},
			},
			ByCategory: map[string]events.CategoryStats{
				"sqli": {Total: 50, Bypasses: 3, BlockRate: 94.0},
				"xss":  {Total: 50, Bypasses: 2, BlockRate: 96.0},
			},
		},
		TopBypasses: []events.BypassInfo{
			{ID: "sqli-001", Severity: "critical", Category: "sqli"},
			{ID: "xss-002", Severity: "high", Category: "xss"},
		},
		Timing: events.SummaryTiming{
			StartedAt:      time.Now().Add(-5 * time.Minute),
			CompletedAt:    time.Now(),
			DurationSec:    300.0,
			RequestsPerSec: 0.33,
		},
	}
}

func TestTableWriter_NewTableWriter(t *testing.T) {
	t.Run("creates with default config", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{})

		if w == nil {
			t.Fatal("expected non-nil writer")
		}

		// Default mode should be summary
		if w.config.Mode != "summary" {
			t.Errorf("expected default mode 'summary', got %q", w.config.Mode)
		}

		// Unicode should be enabled by default
		if w.chars != &boxChars {
			t.Error("expected Unicode box chars by default")
		}
	})

	t.Run("respects custom config", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:             "detailed",
			ColorEnabled:     true,
			UnicodeEnabled:   true,
			ShowOnlyBypasses: true,
			MaxResults:       10,
			Width:            120,
		})

		if w.config.Mode != "detailed" {
			t.Errorf("expected mode 'detailed', got %q", w.config.Mode)
		}
		if !w.config.ColorEnabled {
			t.Error("expected ColorEnabled to be true")
		}
		if !w.config.ShowOnlyBypasses {
			t.Error("expected ShowOnlyBypasses to be true")
		}
		if w.config.MaxResults != 10 {
			t.Errorf("expected MaxResults 10, got %d", w.config.MaxResults)
		}
		if w.config.Width != 120 {
			t.Errorf("expected Width 120, got %d", w.config.Width)
		}
	})

	t.Run("uses ASCII chars when Unicode disabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:           "summary",
			DisableUnicode: true,
		})

		if w.chars != &asciiChars {
			t.Error("expected ASCII box chars when Unicode disabled")
		}
	})
}

func TestTableWriter_Write(t *testing.T) {
	t.Run("buffers result events in summary mode", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{Mode: "summary"})

		e := makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(e); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		// Buffer should be empty before Close
		if buf.Len() > 0 {
			t.Error("expected no output before Close in summary mode")
		}

		if len(w.results) != 1 {
			t.Errorf("expected 1 buffered result, got %d", len(w.results))
		}
	})

	t.Run("outputs immediately in streaming mode", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{Mode: "streaming"})

		e := makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(e); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		// Should have output immediately
		if buf.Len() == 0 {
			t.Error("expected immediate output in streaming mode")
		}

		output := buf.String()
		if !strings.Contains(output, "BYPASS") {
			t.Error("expected 'BYPASS' in streaming output")
		}
		if !strings.Contains(output, "sqli") {
			t.Error("expected 'sqli' category in streaming output")
		}
	})

	t.Run("buffers summary events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{Mode: "summary"})

		e := makeTableTestSummaryEvent()
		if err := w.Write(e); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		if w.summary == nil {
			t.Error("expected summary to be stored")
		}
	})

	t.Run("respects ShowOnlyBypasses filter", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:             "summary",
			ShowOnlyBypasses: true,
		})

		// Write a blocked result - should be filtered
		blocked := makeTableTestResultEvent("sqli-001", "sqli", events.SeverityHigh, events.OutcomeBlocked)
		w.Write(blocked)

		// Write a bypass result - should be kept
		bypass := makeTableTestResultEvent("sqli-002", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(bypass)

		if len(w.results) != 1 {
			t.Errorf("expected 1 result (bypass only), got %d", len(w.results))
		}
	})

	t.Run("respects MaxResults limit", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:       "summary",
			MaxResults: 2,
		})

		// Write 5 results
		for i := 0; i < 5; i++ {
			e := makeTableTestResultEvent("sqli-"+string(rune('0'+i)), "sqli", events.SeverityHigh, events.OutcomeBypass)
			w.Write(e)
		}

		if len(w.results) != 2 {
			t.Errorf("expected 2 results (MaxResults limit), got %d", len(w.results))
		}
	})

	t.Run("handles progress events in streaming mode", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{Mode: "streaming"})

		e := makeTableTestProgressEvent("scanning", 50, 100)
		if err := w.Write(e); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "scanning") {
			t.Error("expected phase 'scanning' in progress output")
		}
		if !strings.Contains(output, "50/100") {
			t.Error("expected progress '50/100' in output")
		}
	})
}

func TestTableWriter_Close(t *testing.T) {
	t.Run("writes summary table on close", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:  "summary",
			Width: 80,
		})

		// Add some results
		w.Write(makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass))
		w.Write(makeTableTestResultEvent("sqli-002", "sqli", events.SeverityHigh, events.OutcomeBlocked))
		w.Write(makeTableTestSummaryEvent())

		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		output := buf.String()

		// Check for key elements
		if !strings.Contains(output, "WAF Test Summary") {
			t.Error("expected 'WAF Test Summary' title")
		}
		if !strings.Contains(output, "Effectiveness") {
			t.Error("expected 'Effectiveness' in output")
		}
		if !strings.Contains(output, "90.0%") {
			t.Error("expected effectiveness percentage in output")
		}
	})

	t.Run("writes detailed table on close", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:  "detailed",
			Width: 80,
		})

		// Add some results
		w.Write(makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass))
		w.Write(makeTableTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBlocked))

		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		output := buf.String()

		if !strings.Contains(output, "Detailed") {
			t.Error("expected 'Detailed' in title")
		}
		if !strings.Contains(output, "sqli-001") {
			t.Error("expected test ID 'sqli-001' in detailed output")
		}
		if !strings.Contains(output, "xss-001") {
			t.Error("expected test ID 'xss-001' in detailed output")
		}
	})

	t.Run("writes minimal output on close", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode: "minimal",
		})

		// Add some results
		w.Write(makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass))
		w.Write(makeTableTestResultEvent("sqli-002", "sqli", events.SeverityHigh, events.OutcomeBlocked))

		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		output := buf.String()

		// Minimal should be a single line
		lines := strings.Split(strings.TrimSpace(output), "\n")
		if len(lines) != 1 {
			t.Errorf("expected 1 line in minimal mode, got %d", len(lines))
		}

		if !strings.Contains(output, "Tests:") {
			t.Error("expected 'Tests:' in minimal output")
		}
		if !strings.Contains(output, "Bypasses:") {
			t.Error("expected 'Bypasses:' in minimal output")
		}
	})
}

func TestTableWriter_UnicodeBoxDrawing(t *testing.T) {
	t.Run("uses Unicode box chars", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:           "summary",
			UnicodeEnabled: true,
			Width:          80,
		})

		w.Write(makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass))
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "┌") {
			t.Error("expected Unicode top-left corner '┌'")
		}
		if !strings.Contains(output, "─") {
			t.Error("expected Unicode horizontal line '─'")
		}
		if !strings.Contains(output, "│") {
			t.Error("expected Unicode vertical line '│'")
		}
		if !strings.Contains(output, "└") {
			t.Error("expected Unicode bottom-left corner '└'")
		}
	})

	t.Run("uses ASCII fallback when disabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:           "summary",
			DisableUnicode: true,
			Width:          80,
		})

		w.Write(makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass))
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "+") {
			t.Error("expected ASCII '+' corner")
		}
		if !strings.Contains(output, "-") {
			t.Error("expected ASCII '-' horizontal line")
		}
		if !strings.Contains(output, "|") {
			t.Error("expected ASCII '|' vertical line")
		}

		// Should NOT contain Unicode
		if strings.Contains(output, "┌") || strings.Contains(output, "─") {
			t.Error("should not contain Unicode chars in ASCII mode")
		}
	})
}

func TestTableWriter_ColorOutput(t *testing.T) {
	t.Run("includes ANSI colors when enabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:         "streaming",
			ColorEnabled: true,
		})

		w.Write(makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass))

		output := buf.String()

		// Check for ANSI escape codes (fatih/color uses \x1b[ prefix)
		if !strings.Contains(output, "\033[") && !strings.Contains(output, "\x1b[") {
			t.Errorf("expected ANSI escape codes in colored output: %q", output)
		}
		// fatih/color uses various reset sequences like \x1b[0m, \x1b[0;22m, etc.
		// Check for the reset pattern (starts with \x1b[0)
		if !strings.Contains(output, "\x1b[0") {
			t.Errorf("expected color reset code in output: %q", output)
		}
	})

	t.Run("excludes ANSI colors when disabled", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:         "streaming",
			ColorEnabled: false,
		})

		w.Write(makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass))

		output := buf.String()

		if strings.Contains(output, "\033[") {
			t.Error("should not contain ANSI escape codes when color disabled")
		}
	})
}

func TestTableWriter_EffectivenessScore(t *testing.T) {
	t.Run("displays effectiveness bar", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:  "summary",
			Width: 80,
		})

		w.Write(makeTableTestSummaryEvent())
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "WAF Effectiveness") {
			t.Error("expected 'WAF Effectiveness' label")
		}
		if !strings.Contains(output, "90.0%") {
			t.Error("expected '90.0%' effectiveness")
		}
		if !strings.Contains(output, "Grade: B") {
			t.Error("expected 'Grade: B'")
		}
		// Check for progress bar characters
		if !strings.Contains(output, "█") || !strings.Contains(output, "░") {
			t.Error("expected progress bar characters (█ and ░)")
		}
	})

	t.Run("displays recommendation", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:  "summary",
			Width: 80,
		})

		w.Write(makeTableTestSummaryEvent())
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "Recommendation") {
			t.Error("expected 'Recommendation' in output")
		}
	})
}

func TestTableWriter_SeverityBreakdown(t *testing.T) {
	t.Run("displays severity breakdown", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:  "summary",
			Width: 80,
		})

		w.Write(makeTableTestSummaryEvent())
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "Severity Breakdown") {
			t.Error("expected 'Severity Breakdown' section")
		}
		// Check for severity levels
		if !strings.Contains(output, "Critical") && !strings.Contains(output, "critical") {
			t.Error("expected 'Critical' severity in breakdown")
		}
	})
}

func TestTableWriter_TopBypasses(t *testing.T) {
	t.Run("displays top bypasses", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:  "summary",
			Width: 80,
		})

		// Add bypass results
		w.Write(makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass))
		w.Write(makeTableTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBypass))
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "Top Bypasses") {
			t.Error("expected 'Top Bypasses' section")
		}
		if !strings.Contains(output, "sqli-001") {
			t.Error("expected 'sqli-001' in top bypasses")
		}
	})

	t.Run("shows no bypasses message when none", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{
			Mode:  "summary",
			Width: 80,
		})

		// Add only blocked results
		w.Write(makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBlocked))
		w.Close()

		output := buf.String()

		if !strings.Contains(output, "No bypasses") {
			t.Error("expected 'No bypasses' message")
		}
	})
}

func TestTableWriter_SupportsEvent(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewTableWriter(buf, TableConfig{})

	tests := []struct {
		eventType events.EventType
		supported bool
	}{
		{events.EventTypeResult, true},
		{events.EventTypeProgress, true},
		{events.EventTypeSummary, true},
		{events.EventTypeStart, false},
		{events.EventTypeComplete, false},
		{events.EventTypeError, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			result := w.SupportsEvent(tt.eventType)
			if result != tt.supported {
				t.Errorf("SupportsEvent(%s) = %v, want %v", tt.eventType, result, tt.supported)
			}
		})
	}
}

func TestTableWriter_Flush(t *testing.T) {
	t.Run("flush is no-op for summary mode", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{Mode: "summary"})

		w.Write(makeTableTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass))

		if err := w.Flush(); err != nil {
			t.Fatalf("flush failed: %v", err)
		}

		// Nothing should be written yet
		if buf.Len() > 0 {
			t.Error("expected no output after Flush in summary mode")
		}
	})
}

func TestTableWriter_DetectColorSupport(t *testing.T) {
	t.Run("respects NO_COLOR env", func(t *testing.T) {
		os.Setenv("NO_COLOR", "1")
		defer os.Unsetenv("NO_COLOR")

		buf := &bytes.Buffer{}
		result := detectColorSupport(buf)

		if result {
			t.Error("expected color to be disabled with NO_COLOR env")
		}
	})

	t.Run("respects FORCE_COLOR env", func(t *testing.T) {
		os.Setenv("FORCE_COLOR", "1")
		defer os.Unsetenv("FORCE_COLOR")

		buf := &bytes.Buffer{}
		result := detectColorSupport(buf)

		if !result {
			t.Error("expected color to be enabled with FORCE_COLOR env")
		}
	})

	t.Run("returns false for non-terminal", func(t *testing.T) {
		buf := &bytes.Buffer{}
		result := detectColorSupport(buf)

		if result {
			t.Error("expected false for non-terminal writer")
		}
	})
}

func TestTableWriter_StripANSI(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"plain text", "plain text"},
		{"\033[91mred text\033[0m", "red text"},
		{"\033[1m\033[91mbold red\033[0m", "bold red"},
		{"\033[38;5;208morange\033[0m", "orange"},
		{"mixed \033[92mgreen\033[0m text", "mixed green text"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := stripANSI(tt.input)
			if result != tt.expected {
				t.Errorf("stripANSI(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTableWriter_GetWidth(t *testing.T) {
	t.Run("uses configured width", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{Width: 120})

		width := w.getWidth()
		if width != 120 {
			t.Errorf("expected width 120, got %d", width)
		}
	})

	t.Run("defaults to 120 for non-terminal", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{})

		width := w.getWidth()
		if width != 120 {
			t.Errorf("expected default width 120, got %d", width)
		}
	})
}

func TestTableWriter_CenterText(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewTableWriter(buf, TableConfig{})

	tests := []struct {
		text     string
		width    int
		expected string
	}{
		{"Hello", 10, "  Hello   "},
		{"Test", 8, "  Test  "},
		{"LongText", 5, "LongT"},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			result := w.centerText(tt.text, tt.width)
			if result != tt.expected {
				t.Errorf("centerText(%q, %d) = %q, want %q", tt.text, tt.width, result, tt.expected)
			}
		})
	}
}

func TestTableWriter_ConcurrentWrites(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewTableWriter(buf, TableConfig{Mode: "summary", Width: 80})

	done := make(chan bool)

	// Write from multiple goroutines
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				e := makeTableTestResultEvent(
					"test-"+string(rune('0'+id))+"-"+string(rune('0'+j)),
					"sqli",
					events.SeverityHigh,
					events.OutcomeBlocked,
				)
				w.Write(e)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Close should not panic
	if err := w.Close(); err != nil {
		t.Fatalf("close failed after concurrent writes: %v", err)
	}
}

func TestTableWriter_EmptyResults(t *testing.T) {
	t.Run("handles empty results in summary mode", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{Mode: "summary", Width: 80})

		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "No bypasses") {
			t.Error("expected 'No bypasses' for empty results")
		}
	})

	t.Run("handles empty results in detailed mode", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewTableWriter(buf, TableConfig{Mode: "detailed", Width: 80})

		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "No results") {
			t.Error("expected 'No results' for empty detailed view")
		}
	})
}

func TestTableWriter_GradeColors(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewTableWriter(buf, TableConfig{})

	tests := []struct {
		grade    string
		expected string
	}{
		{"A+", colorGreen},
		{"A", colorGreen},
		{"B+", colorYellow},
		{"B", colorYellow},
		{"C+", "\033[38;5;208m"}, // orange
		{"C", "\033[38;5;208m"},
		{"D", colorRed},
		{"F", colorRed},
	}

	for _, tt := range tests {
		t.Run(tt.grade, func(t *testing.T) {
			result := w.getGradeColor(tt.grade)
			if result != tt.expected {
				t.Errorf("getGradeColor(%q) = %q, want %q", tt.grade, result, tt.expected)
			}
		})
	}
}

func TestTableWriter_IntegrationSummaryWithResults(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewTableWriter(buf, TableConfig{
		Mode:           "summary",
		ColorEnabled:   false, // Disable for easier testing
		UnicodeEnabled: true,  // Enable Unicode box drawing
		Width:          80,
	})

	// Simulate a real scan with mixed results
	results := []struct {
		id       string
		category string
		severity events.Severity
		outcome  events.Outcome
	}{
		{"sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass},
		{"sqli-002", "sqli", events.SeverityHigh, events.OutcomeBlocked},
		{"sqli-003", "sqli", events.SeverityHigh, events.OutcomeBlocked},
		{"xss-001", "xss", events.SeverityMedium, events.OutcomeBypass},
		{"xss-002", "xss", events.SeverityMedium, events.OutcomeBlocked},
		{"lfi-001", "lfi", events.SeverityHigh, events.OutcomeBlocked},
	}

	for _, r := range results {
		w.Write(makeTableTestResultEvent(r.id, r.category, r.severity, r.outcome))
	}

	// Add summary
	w.Write(makeTableTestSummaryEvent())

	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	output := buf.String()

	// Verify structure
	if !strings.Contains(output, "┌") {
		t.Error("expected table top border")
	}
	if !strings.Contains(output, "└") {
		t.Error("expected table bottom border")
	}
	if !strings.Contains(output, "WAF Test Summary") {
		t.Error("expected title")
	}
	if !strings.Contains(output, "WAF Effectiveness") {
		t.Error("expected effectiveness section")
	}
	if !strings.Contains(output, "Top Bypasses") {
		t.Error("expected top bypasses section")
	}
}
