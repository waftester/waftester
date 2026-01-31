package ui

import (
	"testing"
	"time"
)

// TestVersion checks version constants
func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if BuildDate == "" {
		t.Error("BuildDate should not be empty")
	}
	if Author == "" {
		t.Error("Author should not be empty")
	}
}

// TestProgressConfig tests ProgressConfig struct
func TestProgressConfig(t *testing.T) {
	cfg := ProgressConfig{
		Total:       100,
		Width:       40,
		ShowPercent: true,
		ShowETA:     true,
		ShowRPS:     true,
		Concurrency: 10,
		TurboMode:   true,
	}

	if cfg.Total != 100 {
		t.Errorf("expected Total 100, got %d", cfg.Total)
	}
	if cfg.Width != 40 {
		t.Errorf("expected Width 40, got %d", cfg.Width)
	}
	if !cfg.ShowPercent {
		t.Error("expected ShowPercent to be true")
	}
	if !cfg.TurboMode {
		t.Error("expected TurboMode to be true")
	}
}

// TestNewProgress tests progress creation
func TestNewProgress(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		p := NewProgress(ProgressConfig{Total: 50})

		if p.config.Width != 40 {
			t.Errorf("expected default Width 40, got %d", p.config.Width)
		}
		if p.config.Concurrency != 25 {
			t.Errorf("expected default Concurrency 25, got %d", p.config.Concurrency)
		}
		if p.config.Total != 50 {
			t.Errorf("expected Total 50, got %d", p.config.Total)
		}
	})

	t.Run("custom values", func(t *testing.T) {
		p := NewProgress(ProgressConfig{
			Total:       200,
			Width:       60,
			Concurrency: 50,
		})

		if p.config.Width != 60 {
			t.Errorf("expected Width 60, got %d", p.config.Width)
		}
		if p.config.Concurrency != 50 {
			t.Errorf("expected Concurrency 50, got %d", p.config.Concurrency)
		}
	})
}

// TestProgressIncrement tests progress increment
func TestProgressIncrement(t *testing.T) {
	p := NewProgress(ProgressConfig{Total: 10})

	// Increment with different outcomes
	p.Increment("Blocked")
	p.Increment("Blocked")
	p.Increment("Pass")
	p.Increment("Fail")
	p.Increment("Error")

	if p.blocked != 2 {
		t.Errorf("expected 2 blocked, got %d", p.blocked)
	}
	if p.passed != 1 {
		t.Errorf("expected 1 passed, got %d", p.passed)
	}
	if p.failed != 1 {
		t.Errorf("expected 1 failed, got %d", p.failed)
	}
	if p.errored != 1 {
		t.Errorf("expected 1 errored, got %d", p.errored)
	}
	if p.current != 5 {
		t.Errorf("expected current 5, got %d", p.current)
	}
}

// TestProgressIncrementWithDetails tests increment with details
func TestProgressIncrementWithDetails(t *testing.T) {
	p := NewProgress(ProgressConfig{Total: 10})

	p.IncrementWithDetails("test-1", "sqli", "Blocked", 42)
	p.IncrementWithDetails("test-2", "xss", "Fail", 100)

	if p.current != 2 {
		t.Errorf("expected current 2, got %d", p.current)
	}
	if p.blocked != 1 {
		t.Errorf("expected 1 blocked, got %d", p.blocked)
	}
	if p.failed != 1 {
		t.Errorf("expected 1 failed, got %d", p.failed)
	}

	// Check recent results
	if len(p.recentResults) != 2 {
		t.Errorf("expected 2 recent results, got %d", len(p.recentResults))
	}
	if p.recentResults[0].ID != "test-1" {
		t.Errorf("expected first ID test-1, got %s", p.recentResults[0].ID)
	}
}

// TestProgressRecentResultsLimit tests that recent results are capped at 5
func TestProgressRecentResultsLimit(t *testing.T) {
	p := NewProgress(ProgressConfig{Total: 10})

	// Add more than 5 results
	for i := 0; i < 10; i++ {
		p.IncrementWithDetails("test", "sqli", "Blocked", 10)
	}

	if len(p.recentResults) > 5 {
		t.Errorf("expected max 5 recent results, got %d", len(p.recentResults))
	}
}

// TestRecentResultStruct tests RecentResult struct
func TestRecentResultStruct(t *testing.T) {
	result := RecentResult{
		ID:       "test-001",
		Category: "sqli",
		Outcome:  "Blocked",
		Latency:  42,
	}

	if result.ID != "test-001" {
		t.Errorf("ID mismatch")
	}
	if result.Latency != 42 {
		t.Errorf("Latency mismatch")
	}
}

// TestProgressStartStop tests start and stop
func TestProgressStartStop(t *testing.T) {
	p := NewProgress(ProgressConfig{Total: 10})

	// Start shouldn't panic
	p.Start()

	// Double start should be safe
	p.Start()

	// Wait briefly
	time.Sleep(50 * time.Millisecond)

	// Stop shouldn't panic
	p.Stop()

	// Double stop should be safe
	p.Stop()
}

// TestBannerConstants tests banner constants exist
func TestBannerConstants(t *testing.T) {
	if bannerArt == "" {
		t.Error("bannerArt should not be empty")
	}
	if compactBanner == "" {
		t.Error("compactBanner should not be empty")
	}
	if miniBanner == "" {
		t.Error("miniBanner should not be empty")
	}
}

// TestPrintBanner tests banner printing functions
func TestPrintBanner(t *testing.T) {
	// These should not panic
	t.Run("PrintBanner", func(t *testing.T) {
		// Call the function - should not panic
		PrintBanner()
	})

	t.Run("PrintCompactBanner", func(t *testing.T) {
		PrintCompactBanner()
	})

	t.Run("PrintMiniBanner", func(t *testing.T) {
		PrintMiniBanner()
	})

	t.Run("PrintDivider", func(t *testing.T) {
		PrintDivider()
	})

	t.Run("PrintSection", func(t *testing.T) {
		PrintSection("Test Section")
	})
}

// TestPrintResult tests result printing
func TestPrintResult(t *testing.T) {
	// Should not panic
	PrintResult("test-001", "sqli", "High", "Blocked", 403, 42, "http://example.com", true)
	PrintResult("test-002", "xss", "Medium", "Fail", 200, 100, "http://example.com", false)
	PrintResult("test-003", "traversal", "Critical", "Error", 500, 50, "", true)
}

// TestPrintMessages tests message printing functions
func TestPrintMessages(t *testing.T) {
	PrintSuccess("Test success message")
	PrintError("Test error message")
	PrintWarning("Test warning message")
	PrintInfo("Test info message")
	PrintHelp("Test help message")
}

// TestOutcomeStyle tests outcome style mapping
func TestOutcomeStyle(t *testing.T) {
	outcomes := []string{"Blocked", "Pass", "Fail", "Error", "Unknown"}
	for _, outcome := range outcomes {
		// Should not panic for any outcome
		_ = OutcomeStyle(outcome)
	}
}

// TestSeverityStyle tests severity style mapping
func TestSeverityStyle(t *testing.T) {
	severities := []string{"Critical", "High", "Medium", "Low", "Info", "Unknown"}
	for _, sev := range severities {
		// Should not panic for any severity
		_ = SeverityStyle(sev)
	}
}

// TestStatusCodeStyle tests status code style mapping
func TestStatusCodeStyle(t *testing.T) {
	codes := []int{200, 301, 403, 404, 500}
	for _, code := range codes {
		_ = StatusCodeStyle(code)
	}
}

// TestSpinnerType tests SpinnerType constants
func TestSpinnerType(t *testing.T) {
	types := []SpinnerType{
		SpinnerDots,
		SpinnerLine,
		SpinnerCircle,
		SpinnerArc,
		SpinnerBounce,
		SpinnerBox,
	}

	for _, st := range types {
		spinner := GetSpinner(st)
		if len(spinner.Frames) == 0 {
			t.Errorf("spinner type %d has no frames", st)
		}
		if spinner.Interval == 0 {
			t.Errorf("spinner type %d has no interval", st)
		}
	}
}

// TestGetSpinnerFallback tests GetSpinner fallback behavior
func TestGetSpinnerFallback(t *testing.T) {
	// Request invalid spinner type should fallback to dots
	spinner := GetSpinner(SpinnerType(999))
	if len(spinner.Frames) == 0 {
		t.Error("fallback spinner should have frames")
	}
}

// TestSpinnersMap tests Spinners map
func TestSpinnersMap(t *testing.T) {
	if len(Spinners) == 0 {
		t.Error("Spinners map should not be empty")
	}

	for spinType, spinner := range Spinners {
		if len(spinner.Frames) == 0 {
			t.Errorf("spinner %d has no frames", spinType)
		}
	}
}

// TestSymbols tests Symbols struct
func TestSymbols(t *testing.T) {
	if Symbols.Success == "" {
		t.Error("Symbols.Success should not be empty")
	}
	if Symbols.Error == "" {
		t.Error("Symbols.Error should not be empty")
	}
	if Symbols.Warning == "" {
		t.Error("Symbols.Warning should not be empty")
	}
	if Symbols.Blocked == "" {
		t.Error("Symbols.Blocked should not be empty")
	}
}

// TestResultFormatter tests ResultFormatter
func TestResultFormatter(t *testing.T) {
	t.Run("basic formatter", func(t *testing.T) {
		rf := NewResultFormatter(false, false)
		if rf == nil {
			t.Fatal("expected formatter, got nil")
		}
		if rf.verbose {
			t.Error("expected verbose false")
		}
	})

	t.Run("verbose formatter", func(t *testing.T) {
		rf := NewResultFormatter(true, true)
		if rf == nil {
			t.Fatal("expected formatter, got nil")
		}
		if !rf.verbose {
			t.Error("expected verbose true")
		}
		if !rf.showPayload {
			t.Error("expected showPayload true")
		}
	})
}

// TestResultFormatterFormatResult tests FormatResult
func TestResultFormatterFormatResult(t *testing.T) {
	rf := NewResultFormatter(true, true)

	result := rf.FormatResult("TEST-001", "sqli", "High", "Blocked", 403, 42, "' OR 1=1 --")
	if result == "" {
		t.Error("expected non-empty result")
	}
	if !contains(result, "TEST-001") {
		t.Error("expected result to contain ID")
	}
}

// TestResultFormatterFormatResultWithoutPayload tests FormatResult without payload
func TestResultFormatterFormatResultWithoutPayload(t *testing.T) {
	rf := NewResultFormatter(false, false)

	result := rf.FormatResult("TEST-002", "xss", "Medium", "Fail", 200, 100, "<script>")
	if result == "" {
		t.Error("expected non-empty result")
	}
}

// TestResultFormatterFormatFailure tests FormatFailure
func TestResultFormatterFormatFailure(t *testing.T) {
	rf := NewResultFormatter(true, true)

	result := rf.FormatFailure("TEST-003", "traversal", "Critical", 200, 50, "../../../etc/passwd")
	if result == "" {
		t.Error("expected non-empty result")
	}
	if !contains(result, "BYPASS") {
		t.Error("expected result to contain BYPASS")
	}
}

// TestResultFormatterFormatError tests FormatError
func TestResultFormatterFormatError(t *testing.T) {
	rf := NewResultFormatter(false, false)

	result := rf.FormatError("TEST-004", "sqli", "connection refused")
	if result == "" {
		t.Error("expected non-empty result")
	}
	if !contains(result, "Error") {
		t.Error("expected result to contain Error")
	}
}

// TestFormatLatency tests formatLatency helper
func TestFormatLatency(t *testing.T) {
	tests := []struct {
		ms       int64
		contains string
	}{
		{50, "ms"},
		{500, "ms"},
		{999, "ms"},
		{1000, "s"},
		{2500, "s"},
	}

	for _, tt := range tests {
		result := formatLatency(tt.ms)
		if !contains(result, tt.contains) {
			t.Errorf("formatLatency(%d) should contain %s, got %s", tt.ms, tt.contains, result)
		}
	}
}

// TestTruncateString tests truncateString helper
func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a longer string", 10, "this is..."},
		{"hello world and more", 15, "hello world ..."},
	}

	for _, tt := range tests {
		result := truncateString(tt.input, tt.maxLen)
		if len(result) > tt.maxLen {
			t.Errorf("truncateString result too long: %d > %d", len(result), tt.maxLen)
		}
	}
}

// TestStatusBracket tests StatusBracket
func TestStatusBracket(t *testing.T) {
	codes := []int{200, 403, 404, 500}
	for _, code := range codes {
		result := StatusBracket(code)
		if result == "" {
			t.Errorf("expected non-empty bracket for %d", code)
		}
	}
}

// TestSummaryStruct tests Summary struct
func TestSummaryStruct(t *testing.T) {
	summary := Summary{
		TotalTests:     100,
		BlockedTests:   80,
		PassedTests:    10,
		FailedTests:    5,
		ErrorTests:     5,
		Duration:       5 * time.Second,
		RequestsPerSec: 20.0,
		TargetURL:      "https://example.com",
		Category:       "sqli",
		Severity:       "High",
	}

	if summary.TotalTests != 100 {
		t.Error("TotalTests mismatch")
	}
	if summary.BlockedTests != 80 {
		t.Error("BlockedTests mismatch")
	}
}

// TestPrintSummary tests PrintSummary
func TestPrintSummary(t *testing.T) {
	summary := Summary{
		TotalTests:     50,
		BlockedTests:   40,
		PassedTests:    5,
		FailedTests:    3,
		ErrorTests:     2,
		Duration:       2 * time.Second,
		RequestsPerSec: 25.0,
		TargetURL:      "http://test.local",
		Category:       "xss",
		Severity:       "Medium",
	}

	// Should not panic
	PrintSummary(summary)
}

// TestPrintSummaryNoFailures tests PrintSummary with no failures
func TestPrintSummaryNoFailures(t *testing.T) {
	summary := Summary{
		TotalTests:     100,
		BlockedTests:   100,
		PassedTests:    0,
		FailedTests:    0,
		ErrorTests:     0,
		Duration:       time.Second,
		RequestsPerSec: 100.0,
		TargetURL:      "http://test.local",
	}

	PrintSummary(summary)
}

// TestPrintSummaryHighErrors tests PrintSummary with high errors
func TestPrintSummaryHighErrors(t *testing.T) {
	summary := Summary{
		TotalTests:     100,
		BlockedTests:   20,
		PassedTests:    0,
		FailedTests:    0,
		ErrorTests:     80, // High error rate
		Duration:       time.Second,
		RequestsPerSec: 100.0,
		TargetURL:      "http://test.local",
	}

	PrintSummary(summary)
}

// TestPrintConfigBanner tests PrintConfigBanner
func TestPrintConfigBanner(t *testing.T) {
	options := map[string]string{
		"Target":      "https://example.com",
		"Method":      "GET",
		"Payload Dir": "/payloads",
		"Category":    "all",
		"Concurrency": "25",
		"Rate Limit":  "100",
		"Custom":      "value",
	}

	// Should not panic
	PrintConfigBanner(options)
}

// TestPrintConfigBannerEmpty tests PrintConfigBanner with empty map
func TestPrintConfigBannerEmpty(t *testing.T) {
	PrintConfigBanner(map[string]string{})
}

// TestPrintConfig tests PrintConfig
func TestPrintConfig(t *testing.T) {
	config := map[string]string{
		"key1":       "value1",
		"longer_key": "value2",
	}
	PrintConfig(config)
}

// TestPrintConfigLine tests PrintConfigLine
func TestPrintConfigLine(t *testing.T) {
	PrintConfigLine("Label", "Value")
}

// TestBracketPart tests BracketPart struct
func TestBracketPart(t *testing.T) {
	part := BracketPart{
		Text:  "test",
		Style: StatValueStyle,
	}

	if part.Text != "test" {
		t.Error("Text mismatch")
	}
}

// TestBracketHelpers tests bracket helper functions
func TestBracketHelpers(t *testing.T) {
	t.Run("SeverityBracket", func(t *testing.T) {
		part := SeverityBracket("High")
		if part.Text != "high" {
			t.Error("expected lowercase severity")
		}
	})

	t.Run("CategoryBracket", func(t *testing.T) {
		part := CategoryBracket("sqli")
		if part.Text != "sqli" {
			t.Error("expected sqli")
		}
	})

	t.Run("OutcomeBracket", func(t *testing.T) {
		part := OutcomeBracket("Blocked")
		if part.Text != "blocked" {
			t.Error("expected lowercase outcome")
		}
	})

	t.Run("TextBracket", func(t *testing.T) {
		part := TextBracket("custom")
		if part.Text != "custom" {
			t.Error("expected custom")
		}
	})

	t.Run("MutedBracket", func(t *testing.T) {
		part := MutedBracket("info")
		if part.Text != "info" {
			t.Error("expected info")
		}
	})
}

// TestPrintBracketedInfo tests PrintBracketedInfo
func TestPrintBracketedInfo(t *testing.T) {
	PrintBracketedInfo(
		SeverityBracket("Critical"),
		CategoryBracket("xss"),
		OutcomeBracket("Fail"),
	)
}

// TestPrintResultCompact tests PrintResultCompact
func TestPrintResultCompact(t *testing.T) {
	PrintResultCompact("test-id", 403, 1234, 45)
}

// TestProgressSetActiveWorkers tests SetActiveWorkers
func TestProgressSetActiveWorkers(t *testing.T) {
	p := NewProgress(ProgressConfig{Total: 100})
	p.SetActiveWorkers(10)

	if p.activeWorkers != 10 {
		t.Errorf("expected 10 active workers, got %d", p.activeWorkers)
	}
}

// TestProgressGetStats tests GetStats
func TestProgressGetStats(t *testing.T) {
	p := NewProgress(ProgressConfig{Total: 100})
	p.Increment("Blocked")
	p.Increment("Pass")
	p.Increment("Fail")
	p.Increment("Error")

	blocked, passed, failed, errored := p.GetStats()
	if blocked != 1 || passed != 1 || failed != 1 || errored != 1 {
		t.Error("stats mismatch")
	}
}

// TestColorConstants tests color constants exist
func TestColorConstants(t *testing.T) {
	// These should be non-empty colors
	colors := []struct {
		name  string
		color interface{}
	}{
		{"Primary", Primary},
		{"Secondary", Secondary},
		{"Critical", Critical},
		{"High", High},
		{"Medium", Medium},
		{"Low", Low},
		{"Info", Info},
		{"Success", Success},
		{"Warning", Warning},
		{"Error", Error},
		{"Blocked", Blocked},
		{"Pass", Pass},
		{"Fail", Fail},
	}

	for _, c := range colors {
		if c.color == nil {
			t.Errorf("%s color should not be nil", c.name)
		}
	}
}

// TestPreConfiguredStyles tests pre-configured styles exist
func TestPreConfiguredStyles(t *testing.T) {
	styles := []struct {
		name  string
		style interface{}
	}{
		{"TitleStyle", TitleStyle},
		{"SubtitleStyle", SubtitleStyle},
		{"BannerStyle", BannerStyle},
		{"VersionStyle", VersionStyle},
		{"SectionStyle", SectionStyle},
		{"ConfigLabelStyle", ConfigLabelStyle},
		{"ConfigValueStyle", ConfigValueStyle},
		{"BlockedStyle", BlockedStyle},
		{"PassStyle", PassStyle},
		{"FailStyle", FailStyle},
		{"ErrorStyle", ErrorStyle},
	}

	for _, s := range styles {
		if s.style == nil {
			t.Errorf("%s should not be nil", s.name)
		}
	}
}

// helper function for string contains
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestProgressBar tests ProgressBar creation and rendering
func TestProgressBar(t *testing.T) {
	pb := NewProgressBar(20)
	if pb == nil {
		t.Fatal("expected progress bar")
	}
	if pb.width != 20 {
		t.Errorf("expected width 20, got %d", pb.width)
	}

	// Test rendering
	t.Run("0 percent", func(t *testing.T) {
		result := pb.Render(0)
		if len(result) == 0 {
			t.Error("expected non-empty render")
		}
	})

	t.Run("50 percent", func(t *testing.T) {
		result := pb.Render(50)
		if len(result) == 0 {
			t.Error("expected non-empty render")
		}
	})

	t.Run("100 percent", func(t *testing.T) {
		result := pb.Render(100)
		if len(result) == 0 {
			t.Error("expected non-empty render")
		}
	})

	t.Run("over 100 percent", func(t *testing.T) {
		result := pb.Render(150)
		if len(result) == 0 {
			t.Error("expected non-empty render")
		}
	})
}

// TestStatsDisplay tests StatsDisplay creation and operation
func TestStatsDisplay(t *testing.T) {
	sd := NewStatsDisplay(100, 1)
	if sd == nil {
		t.Fatal("expected stats display")
	}
	if sd.total != 100 {
		t.Errorf("expected total 100, got %d", sd.total)
	}

	// Test update
	sd.Update("Blocked")
	sd.Update("Pass")
	sd.Update("Fail")
	sd.Update("Error")

	if *sd.current != 4 {
		t.Errorf("expected current 4, got %d", *sd.current)
	}
	if *sd.blocked != 1 {
		t.Errorf("expected blocked 1, got %d", *sd.blocked)
	}
}

// TestStatsDisplayStartStop tests StatsDisplay start and stop
func TestStatsDisplayStartStop(t *testing.T) {
	sd := NewStatsDisplay(100, 10) // 10 second interval

	// Start shouldn't panic
	sd.Start()

	// Double start should be safe
	sd.Start()

	// Wait briefly
	time.Sleep(50 * time.Millisecond)

	// Stop shouldn't panic
	sd.Stop()

	// Double stop should be safe
	sd.Stop()
}

// TestFormatDuration tests formatDuration helper
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{0, "00:00"},
		{30 * time.Second, "00:30"},
		{90 * time.Second, "01:30"},
		{60 * time.Minute, "01:00:00"},
		{61 * time.Minute, "01:01:00"},
		{90 * time.Minute, "01:30:00"},
	}

	for _, tt := range tests {
		result := formatDuration(tt.duration)
		if result != tt.expected {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.duration, result, tt.expected)
		}
	}
}

// TestPrintFinalProgress tests PrintFinalProgress
func TestPrintFinalProgress(t *testing.T) {
	// Should not panic
	PrintFinalProgress(100, 5*time.Second, 20.0, 80, 10, 5, 5)
}

// TestPrintWAFEffectiveness tests PrintWAFEffectiveness
func TestPrintWAFEffectiveness(t *testing.T) {
	// Test various effectiveness levels
	PrintWAFEffectiveness(0)
	PrintWAFEffectiveness(50)
	PrintWAFEffectiveness(75)
	PrintWAFEffectiveness(90)
	PrintWAFEffectiveness(95)
	PrintWAFEffectiveness(100)
}

// TestGetEffectivenessRating tests getEffectivenessRating
func TestGetEffectivenessRating(t *testing.T) {
	ratings := []struct {
		percent float64
	}{
		{0},
		{30},
		{50},
		{70},
		{80},
		{90},
		{95},
		{99},
		{100},
	}

	for _, r := range ratings {
		result := getEffectivenessRating(r.percent)
		if result == "" {
			t.Errorf("expected non-empty rating for %f", r.percent)
		}
	}
}

// TestPadRight tests padRight helper
func TestPadRight(t *testing.T) {
	tests := []struct {
		input    string
		width    int
		expected int
	}{
		{"hello", 10, 10},
		{"hi", 5, 5},
		{"longstring", 5, 10}, // should not truncate
	}

	for _, tt := range tests {
		result := padRight(tt.input, tt.width)
		if len(result) < tt.expected {
			t.Errorf("padRight(%q, %d) length = %d, want >= %d", tt.input, tt.width, len(result), tt.expected)
		}
	}
}

// TestMax tests max helper
func TestMax(t *testing.T) {
	if max(5, 10) != 10 {
		t.Error("max(5, 10) should be 10")
	}
	if max(10, 5) != 10 {
		t.Error("max(10, 5) should be 10")
	}
	if max(5, 5) != 5 {
		t.Error("max(5, 5) should be 5")
	}
}

// TestPrintLiveResult tests PrintLiveResult
func TestPrintLiveResult(t *testing.T) {
	// Should not panic for various outcomes
	PrintLiveResult("Blocked", "test-001", "sqli", "High", 403)
	PrintLiveResult("Fail", "test-002", "xss", "Medium", 200)
	PrintLiveResult("Error", "test-003", "rce", "Critical", 500)
	PrintLiveResult("Pass", "test-004", "traversal", "Low", 200)
}

// TestPrintDivider tests PrintDivider
func TestPrintDivider(t *testing.T) {
	// Should not panic
	PrintDivider()
}

// TestPrintSection tests PrintSection
func TestPrintSection(t *testing.T) {
	// Should not panic
	PrintSection("Test Section")
}

// TestPrintHelp tests PrintHelp
func TestPrintHelp(t *testing.T) {
	PrintHelp("This is help text")
}

// TestPrintSuccess tests PrintSuccess
func TestPrintSuccess(t *testing.T) {
	PrintSuccess("Operation succeeded")
}

// TestPrintError tests PrintError
func TestPrintError(t *testing.T) {
	PrintError("Operation failed")
}

// TestPrintWarning tests PrintWarning
func TestPrintWarning(t *testing.T) {
	PrintWarning("Warning message")
}

// TestPrintInfo tests PrintInfo
func TestPrintInfo(t *testing.T) {
	PrintInfo("Info message")
}

// TestPrintResultWithTimestamp tests PrintResult with timestamp
func TestPrintResultWithTimestamp(t *testing.T) {
	// Test with timestamp
	PrintResult("test-id", "sqli", "High", "Blocked", 403, 42, "http://example.com", true)

	// Test without timestamp
	PrintResult("test-id", "xss", "Medium", "Fail", 200, 100, "http://example.com", false)
}

// TestProgressBuildBar tests Progress.buildBar
func TestProgressBuildBar(t *testing.T) {
	p := NewProgress(ProgressConfig{Total: 100, Width: 30})
	result := p.buildBar(50)
	if result == "" {
		t.Error("expected non-empty bar")
	}
}

// TestProgressBuildTurboBar tests Progress.buildTurboBar
func TestProgressBuildTurboBar(t *testing.T) {
	p := NewProgress(ProgressConfig{Total: 100, Width: 30})

	t.Run("normal RPS", func(t *testing.T) {
		result := p.buildTurboBar(50, 30)
		if result == "" {
			t.Error("expected non-empty bar")
		}
	})

	t.Run("high RPS", func(t *testing.T) {
		result := p.buildTurboBar(75, 75)
		if result == "" {
			t.Error("expected non-empty bar")
		}
	})

	t.Run("very high RPS", func(t *testing.T) {
		result := p.buildTurboBar(90, 150)
		if result == "" {
			t.Error("expected non-empty bar")
		}
	})
}

// TestProgressBuildStats tests Progress.buildStats
func TestProgressBuildStats(t *testing.T) {
	p := NewProgress(ProgressConfig{Total: 100})
	p.Increment("Blocked")
	p.Increment("Fail")

	result := p.buildStats(2, 10.5, 30*time.Second)
	if result == "" {
		t.Error("expected non-empty stats")
	}
}

// TestSeverityStyles tests severity-based styling
func TestSeverityStyles(t *testing.T) {
	severities := []string{"Critical", "High", "Medium", "Low", "Info", "Unknown"}
	for _, sev := range severities {
		style := SeverityStyle(sev)
		if style.String() == "" {
			// Just check it doesn't panic, style might render as empty
		}
	}
}

// TestOutcomeStyles tests outcome-based styling
func TestOutcomeStyles(t *testing.T) {
	outcomes := []string{"Blocked", "Pass", "Fail", "Error", "Unknown"}
	for _, out := range outcomes {
		style := OutcomeStyle(out)
		if style.String() == "" {
			// Just check it doesn't panic
		}
	}
}

// TestStatusCodeStyles tests status code styling
func TestStatusCodeStyles(t *testing.T) {
	codes := []int{200, 201, 301, 400, 403, 404, 500, 502}
	for _, code := range codes {
		style := StatusCodeStyle(code)
		if style.String() == "" {
			// Just check it doesn't panic
		}
	}
}
