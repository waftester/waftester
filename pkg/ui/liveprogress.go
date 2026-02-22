// pkg/ui/liveprogress.go - Unified live progress display for all CLI commands
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/duration"
)

// OutputMode determines how progress is displayed
type OutputMode int

const (
	// OutputModeInteractive - animated terminal output with ANSI escape codes
	OutputModeInteractive OutputMode = iota
	// OutputModeStreaming - line-by-line output for CI/apps, no ANSI codes
	OutputModeStreaming
	// OutputModeSilent - no progress output
	OutputModeSilent
)

// DefaultOutputMode returns Interactive when stderr is a terminal,
// Streaming otherwise. Use this instead of hardcoding OutputModeInteractive
// to avoid ANSI escape codes in redirected output.
func DefaultOutputMode() OutputMode {
	if StderrIsTerminal() {
		return OutputModeInteractive
	}
	return OutputModeStreaming
}

// LiveProgressConfig holds configuration for live progress display
type LiveProgressConfig struct {
	// Total number of items to process (0 = indeterminate)
	Total int

	// DisplayLines is how many lines the progress display uses (default: 2)
	DisplayLines int

	// Output mode
	Mode OutputMode

	// Output writer (default: os.Stdout)
	Writer io.Writer

	// Spinner style (default: SpinnerDots)
	SpinnerType SpinnerType

	// Progress bar width (default: 30)
	BarWidth int

	// Title shown in progress (e.g., "Testing targets", "Analyzing JS files")
	Title string

	// Unit name for items (e.g., "targets", "files", "payloads")
	Unit string

	// Custom metrics to track and display
	Metrics []MetricConfig

	// Tips to rotate during long operations (optional)
	Tips []string

	// TipInterval controls how often tips rotate (default: 5s)
	TipInterval time.Duration

	// StreamFormat is the format string for streaming mode
	// Placeholders: {time}, {completed}, {total}, {percent}, {metric:name}
	StreamFormat string

	// StreamInterval is how often to emit streaming updates (default: 1s)
	StreamInterval time.Duration

	// RateSource, when non-nil, provides the counter for rate calculation
	// instead of using the completed count. Useful when the progress total
	// is coarse (e.g., scanner types) but a finer counter (e.g., HTTP
	// requests) gives a meaningful per-second rate.
	RateSource *int64
}

// MetricConfig defines a custom metric to track
type MetricConfig struct {
	Name      string // Internal name for tracking
	Label     string // Display label (e.g., "Vulns", "Secrets", "FPs")
	Icon      string // Emoji/icon (e.g., "🔴", "🔑", "⚠️")
	ColorCode string // ANSI color code (e.g., "\033[31m" for red)
	Highlight bool   // If true, use highlight color when > 0
}

// LiveProgress provides a unified, reusable progress display
type LiveProgress struct {
	config    LiveProgressConfig
	startTime time.Time

	// Core counters
	completed int64
	total     int64

	// Custom metrics (indexed by name)
	metrics     map[string]*int64
	metricsLock sync.RWMutex

	// Current phase/status text
	status atomic.Value

	// Control
	done    chan struct{}
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex

	// Spinner state
	frameIdx int
}

// DefaultLiveProgressConfig returns sensible defaults
func DefaultLiveProgressConfig() LiveProgressConfig {
	return LiveProgressConfig{
		DisplayLines:   2,
		Mode:           DefaultOutputMode(),
		Writer:         os.Stderr,
		SpinnerType:    SpinnerDots,
		BarWidth:       30,
		Unit:           "items",
		TipInterval:    duration.StreamSlow,
		StreamInterval: duration.StreamFast,
		StreamFormat:   "[{time}] {completed}/{total} ({percent}%) {metrics}",
	}
}

// NewLiveProgress creates a new unified progress display
func NewLiveProgress(config LiveProgressConfig) *LiveProgress {
	// Apply defaults
	if config.DisplayLines == 0 {
		config.DisplayLines = 2
	}
	if config.Writer == nil {
		config.Writer = os.Stderr
	}
	if config.BarWidth == 0 {
		config.BarWidth = 30
	}
	if config.Unit == "" {
		config.Unit = "items"
	}
	if config.TipInterval == 0 {
		config.TipInterval = duration.StreamSlow
	}
	if config.StreamInterval == 0 {
		config.StreamInterval = duration.StreamFast
	}
	if config.StreamFormat == "" {
		config.StreamFormat = "[{time}] {completed}/{total} ({percent}%) {metrics}"
	}

	lp := &LiveProgress{
		config:    config,
		total:     int64(config.Total),
		done:      make(chan struct{}),
		metrics:   make(map[string]*int64),
		startTime: time.Now(),
	}

	// Initialize metrics
	for _, m := range config.Metrics {
		val := int64(0)
		lp.metrics[m.Name] = &val
	}

	lp.status.Store(config.Title)

	return lp
}

// Start begins the progress display
func (lp *LiveProgress) Start() {
	lp.mu.Lock()
	if lp.running {
		lp.mu.Unlock()
		return
	}
	lp.running = true
	lp.startTime = time.Now()
	lp.done = make(chan struct{})
	lp.mu.Unlock()

	// Print initial spacing for interactive mode
	if lp.config.Mode == OutputModeInteractive {
		for i := 0; i < lp.config.DisplayLines; i++ {
			fmt.Fprintln(lp.config.Writer)
		}
	}

	lp.wg.Add(1)
	go lp.renderLoop()
}

// Stop halts the progress display and cleans up
func (lp *LiveProgress) Stop() {
	lp.mu.Lock()
	if !lp.running {
		lp.mu.Unlock()
		return
	}
	lp.running = false
	close(lp.done)
	lp.mu.Unlock()

	lp.wg.Wait()

	// Clear progress lines in interactive mode
	if lp.config.Mode == OutputModeInteractive {
		fmt.Fprintf(lp.config.Writer, "\033[%dA\033[J", lp.config.DisplayLines)
	}
}

// Increment increases the completed count by 1
func (lp *LiveProgress) Increment() {
	atomic.AddInt64(&lp.completed, 1)
}

// IncrementBy increases the completed count by n
func (lp *LiveProgress) IncrementBy(n int) {
	atomic.AddInt64(&lp.completed, int64(n))
}

// SetCompleted sets the completed count directly
func (lp *LiveProgress) SetCompleted(n int) {
	atomic.StoreInt64(&lp.completed, int64(n))
}

// SetTotal updates the total count (for dynamic progress)
func (lp *LiveProgress) SetTotal(n int) {
	atomic.StoreInt64(&lp.total, int64(n))
}

// AddMetric increments a named metric by 1
func (lp *LiveProgress) AddMetric(name string) {
	lp.AddMetricBy(name, 1)
}

// AddMetricBy increments a named metric by n
func (lp *LiveProgress) AddMetricBy(name string, n int) {
	lp.metricsLock.RLock()
	if ptr, ok := lp.metrics[name]; ok {
		atomic.AddInt64(ptr, int64(n))
	}
	lp.metricsLock.RUnlock()
}

// SetMetric sets a named metric to a specific value
func (lp *LiveProgress) SetMetric(name string, value int64) {
	lp.metricsLock.RLock()
	if ptr, ok := lp.metrics[name]; ok {
		atomic.StoreInt64(ptr, value)
	}
	lp.metricsLock.RUnlock()
}

// AddMetricN increments a named metric by n (int64 version)
func (lp *LiveProgress) AddMetricN(name string, n int64) {
	lp.metricsLock.RLock()
	if ptr, ok := lp.metrics[name]; ok {
		atomic.AddInt64(ptr, n)
	}
	lp.metricsLock.RUnlock()
}

// GetMetric returns the current value of a named metric
func (lp *LiveProgress) GetMetric(name string) int64 {
	lp.metricsLock.RLock()
	defer lp.metricsLock.RUnlock()
	if ptr, ok := lp.metrics[name]; ok {
		return atomic.LoadInt64(ptr)
	}
	return 0
}

// SetStatus updates the current status/phase text
func (lp *LiveProgress) SetStatus(status string) {
	lp.status.Store(status)
}

// GetCompleted returns the current completed count
func (lp *LiveProgress) GetCompleted() int64 {
	return atomic.LoadInt64(&lp.completed)
}

// GetTotal returns the current total count
func (lp *LiveProgress) GetTotal() int64 {
	return atomic.LoadInt64(&lp.total)
}

// GetElapsed returns the time since Start was called
func (lp *LiveProgress) GetElapsed() time.Duration {
	return time.Since(lp.startTime)
}

// renderLoop handles the display updates
func (lp *LiveProgress) renderLoop() {
	defer lp.wg.Done()

	interval := 100 * time.Millisecond
	if lp.config.Mode == OutputModeStreaming {
		interval = lp.config.StreamInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	spinner := GetSpinner(lp.config.SpinnerType)

	for {
		select {
		case <-lp.done:
			return
		case <-ticker.C:
			switch lp.config.Mode {
			case OutputModeInteractive:
				lp.renderInteractive(spinner)
			case OutputModeStreaming:
				lp.renderStreaming()
			}
		}
	}
}

// renderInteractive renders animated terminal output
func (lp *LiveProgress) renderInteractive(spinner Spinner) {
	completed := atomic.LoadInt64(&lp.completed)
	total := atomic.LoadInt64(&lp.total)
	elapsed := time.Since(lp.startTime)
	status, _ := lp.status.Load().(string)

	// Calculate progress
	percent := float64(0)
	if total > 0 {
		percent = float64(completed) / float64(total) * 100
	}

	// Calculate rate — prefer RateSource (e.g., HTTP requests) over
	// coarse scanner-level completions for a meaningful per-second value.
	rate := float64(0)
	if elapsed.Seconds() > 0 {
		if lp.config.RateSource != nil {
			rate = float64(atomic.LoadInt64(lp.config.RateSource)) / elapsed.Seconds()
		} else {
			rate = float64(completed) / elapsed.Seconds()
		}
	}

	// Calculate ETA
	eta := "calculating..."
	if rate > 0 && total > 0 && completed < total {
		remaining := float64(total-completed) / rate
		if remaining < 60 {
			eta = fmt.Sprintf("%.0fs", remaining)
		} else if remaining < 3600 {
			eta = fmt.Sprintf("%.1fm", remaining/60)
		} else {
			eta = fmt.Sprintf("%.1fh", remaining/3600)
		}
	} else if completed >= total && total > 0 {
		eta = "done"
	} else if completed == 0 && elapsed.Seconds() > 2 {
		// No items completed yet — show running state instead of stale "calculating"
		eta = "in progress..."
	}

	// Get spinner frame
	spinnerChar := spinner.Frames[lp.frameIdx%len(spinner.Frames)]
	lp.frameIdx++

	// Build progress bar
	bar := lp.buildProgressBar(percent)

	// Build metrics string
	metricsStr := lp.buildMetricsString()

	// Get tip if available
	tipStr := ""
	if len(lp.config.Tips) > 0 {
		tipIdx := int(elapsed.Seconds()/lp.config.TipInterval.Seconds()) % len(lp.config.Tips)
		tipStr = lp.config.Tips[tipIdx]
	}

	// Clear previous lines and render
	fmt.Fprintf(lp.config.Writer, "\033[%dA\033[J", lp.config.DisplayLines)

	// Line 1: Spinner, status, bar, percentage
	if total > 0 {
		fmt.Fprintf(lp.config.Writer, "  %s %s %s %.1f%% (%d/%d %s)\n",
			spinnerChar, status, bar, percent, completed, total, lp.config.Unit)
	} else {
		fmt.Fprintf(lp.config.Writer, "  %s %s... (%d %s)\n",
			spinnerChar, status, completed, lp.config.Unit)
	}

	// Line 2: Metrics, rate, elapsed, ETA
	if metricsStr != "" {
		fmt.Fprintf(lp.config.Writer, "  %s  \033[33m%.1f/s\033[0m  %s %s  ETA: %s\n",
			metricsStr, rate, Icon("⏱️", ""), formatElapsedCompact(elapsed), eta)
	} else {
		fmt.Fprintf(lp.config.Writer, "  %s \033[33m%.1f %s/s\033[0m  %s %s  ETA: %s\n",
			Icon("📊", "#"), rate, lp.config.Unit, Icon("⏱️", ""), formatElapsedCompact(elapsed), eta)
	}

	// Line 3: Tips (if configured for 3 lines)
	if lp.config.DisplayLines >= 3 && tipStr != "" {
		fmt.Fprintf(lp.config.Writer, "  %s %s\n", Icon("💡", "*"), SanitizeString(tipStr))
	}
}

// renderStreaming renders line-by-line output for CI/apps
func (lp *LiveProgress) renderStreaming() {
	completed := atomic.LoadInt64(&lp.completed)
	total := atomic.LoadInt64(&lp.total)
	elapsed := time.Since(lp.startTime)
	status, _ := lp.status.Load().(string)

	percent := float64(0)
	if total > 0 {
		percent = float64(completed) / float64(total) * 100
	}

	// Build metrics string for streaming
	var metricParts []string
	for _, m := range lp.config.Metrics {
		val := lp.GetMetric(m.Name)
		if val > 0 || m.Highlight {
			metricParts = append(metricParts, fmt.Sprintf("%s=%d", m.Label, val))
		}
	}
	metricsStr := strings.Join(metricParts, " ")

	// Format output
	output := lp.config.StreamFormat
	output = strings.ReplaceAll(output, "{time}", formatElapsedCompact(elapsed))
	output = strings.ReplaceAll(output, "{elapsed}", formatElapsedCompact(elapsed))
	output = strings.ReplaceAll(output, "{completed}", fmt.Sprintf("%d", completed))
	output = strings.ReplaceAll(output, "{total}", fmt.Sprintf("%d", total))
	output = strings.ReplaceAll(output, "{percent}", fmt.Sprintf("%.1f", percent))
	output = strings.ReplaceAll(output, "{metrics}", metricsStr)
	output = strings.ReplaceAll(output, "{status}", status)

	// Replace individual metric placeholders {metric:name}
	for _, m := range lp.config.Metrics {
		val := lp.GetMetric(m.Name)
		output = strings.ReplaceAll(output, fmt.Sprintf("{metric:%s}", m.Name), fmt.Sprintf("%d", val))
	}

	// Streaming mode writes to stderr to keep stdout clean for JSON/data output
	fmt.Fprintln(os.Stderr, output)
}

// buildProgressBar creates the visual progress bar.
// Uses block characters on Unicode terminals, ASCII on legacy consoles.
func (lp *LiveProgress) buildProgressBar(percent float64) string {
	width := lp.config.BarWidth
	fillWidth := int(float64(width) * percent / 100)
	if fillWidth > width {
		fillWidth = width
	}

	fill := Icon("\u2588", "#")  // █ or #
	empty := Icon("\u2591", "-") // ░ or -
	return fmt.Sprintf("[%s%s]",
		strings.Repeat(fill, fillWidth),
		strings.Repeat(empty, width-fillWidth))
}

// buildMetricsString creates the colored metrics display
func (lp *LiveProgress) buildMetricsString() string {
	if len(lp.config.Metrics) == 0 {
		return ""
	}

	var parts []string
	for _, m := range lp.config.Metrics {
		val := lp.GetMetric(m.Name)

		// Determine color
		color := m.ColorCode
		reset := "\033[0m"
		if color == "" {
			color = "\033[36m" // Default cyan
		}
		if m.Highlight && val > 0 {
			color = "\033[31m" // Red for highlighted metrics with values
		}

		icon := SanitizeString(m.Icon)
		if icon == "" {
			icon = Icon("•", "-")
		}

		parts = append(parts, fmt.Sprintf("%s%s %s: %d%s", color, icon, m.Label, val, reset))
	}

	return strings.Join(parts, "  ")
}

// formatElapsedCompact formats duration compactly
func formatElapsedCompact(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%ds", mins, secs)
}

// === Convenience Constructors ===

// NewMultiTargetProgress creates a progress display for multi-target operations
func NewMultiTargetProgress(title string, targetCount int, unit string) *LiveProgress {
	return NewLiveProgress(LiveProgressConfig{
		Total:        targetCount,
		DisplayLines: 2,
		Title:        title,
		Unit:         unit,
		Metrics: []MetricConfig{
			{Name: "vulns", Label: "Vulns", Icon: Icon("🚨", "!"), Highlight: true},
		},
	})
}

// NewScanProgress creates a progress display for scanning operations
func NewScanProgress(title string, total int) *LiveProgress {
	return NewLiveProgress(LiveProgressConfig{
		Total:        total,
		DisplayLines: 3,
		Title:        title,
		Unit:         "tests",
		Metrics: []MetricConfig{
			{Name: "blocked", Label: "Blocked", Icon: Icon("🛡️", "#"), ColorCode: "\033[33m"},
			{Name: "vulns", Label: "Vulns", Icon: Icon("🔴", "!"), Highlight: true},
		},
		Tips: []string{
			"Testing WAF rules for bypass opportunities",
			"Analyzing response patterns for vulnerabilities",
			"Each payload tests a specific attack vector",
		},
	})
}

// NewAnalysisProgress creates a progress display for analysis operations (JS, secrets, etc.)
func NewAnalysisProgress(title string, total int, unit string) *LiveProgress {
	return NewLiveProgress(LiveProgressConfig{
		Total:        total,
		DisplayLines: 2,
		Title:        title,
		Unit:         unit,
		Metrics: []MetricConfig{
			{Name: "found", Label: "Found", Icon: Icon("📍", "+"), ColorCode: "\033[32m"},
			{Name: "secrets", Label: "Secrets", Icon: Icon("🔑", "*"), Highlight: true},
		},
	})
}

// NewFPTestProgress creates a progress display for false positive testing
func NewFPTestProgress(total int) *LiveProgress {
	return NewLiveProgress(LiveProgressConfig{
		Total:        total,
		DisplayLines: 2,
		Title:        "Testing false positives",
		Unit:         "tests",
		Metrics: []MetricConfig{
			{Name: "fps", Label: "FPs", Icon: Icon("⚠️", "!"), Highlight: true},
		},
	})
}
