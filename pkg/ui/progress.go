package ui

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ProgressConfig holds progress display settings
type ProgressConfig struct {
	Total       int
	Width       int
	ShowPercent bool
	ShowETA     bool
	ShowRPS     bool
	Concurrency int  // Number of parallel workers
	TurboMode   bool // Enable turbo visualization
}

// RecentResult stores info about recently processed tests
type RecentResult struct {
	ID       string
	Category string
	Outcome  string
	Latency  int64
}

// Progress represents a live-updating progress display
type Progress struct {
	config    ProgressConfig
	startTime time.Time
	current   int64

	// Stats counters
	blocked int64
	passed  int64
	failed  int64
	errored int64

	// Worker activity tracking
	activeWorkers int64
	peakRPS       float64
	recentResults []RecentResult
	resultsMu     sync.Mutex

	// Control
	done    chan struct{}
	mu      sync.Mutex
	running bool
}

// NewProgress creates a new progress display
func NewProgress(config ProgressConfig) *Progress {
	if config.Width == 0 {
		config.Width = 40
	}
	if config.Concurrency == 0 {
		config.Concurrency = 25
	}
	return &Progress{
		config:        config,
		startTime:     time.Now(),
		done:          make(chan struct{}),
		recentResults: make([]RecentResult, 0, 5),
	}
}

// Start begins the progress display
func (p *Progress) Start() {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.startTime = time.Now()
	p.mu.Unlock()

	go p.renderLoop()
}

// Stop halts the progress display
func (p *Progress) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		close(p.done)
		p.running = false
		fmt.Println() // New line after progress
	}
}

// Increment updates the progress
func (p *Progress) Increment(outcome string) {
	atomic.AddInt64(&p.current, 1)

	switch outcome {
	case "Blocked":
		atomic.AddInt64(&p.blocked, 1)
	case "Pass":
		atomic.AddInt64(&p.passed, 1)
	case "Fail":
		atomic.AddInt64(&p.failed, 1)
	case "Error":
		atomic.AddInt64(&p.errored, 1)
	}
}

// IncrementWithDetails updates progress with result details for streaming display
func (p *Progress) IncrementWithDetails(id, category, outcome string, latencyMs int64) {
	p.Increment(outcome)

	// Add to recent results for live streaming display
	p.resultsMu.Lock()
	p.recentResults = append(p.recentResults, RecentResult{
		ID:       id,
		Category: category,
		Outcome:  outcome,
		Latency:  latencyMs,
	})
	// Keep only last 5 results
	if len(p.recentResults) > 5 {
		p.recentResults = p.recentResults[1:]
	}
	p.resultsMu.Unlock()
}

// SetActiveWorkers updates the active worker count
func (p *Progress) SetActiveWorkers(count int) {
	atomic.StoreInt64(&p.activeWorkers, int64(count))
}

// GetStats returns current statistics
func (p *Progress) GetStats() (blocked, passed, failed, errored int64) {
	return atomic.LoadInt64(&p.blocked),
		atomic.LoadInt64(&p.passed),
		atomic.LoadInt64(&p.failed),
		atomic.LoadInt64(&p.errored)
}

// renderLoop continuously updates the progress display
func (p *Progress) renderLoop() {
	ticker := time.NewTicker(80 * time.Millisecond) // Smooth 12.5fps for turbo feel
	defer ticker.Stop()

	// Turbo spinner - faster, more dynamic frames
	turboFrames := []string{"*", "#", "*", "@", "*", "#", "*", "@"}
	// Worker activity indicators
	workerFrames := []string{"###", ".##", "..#", "...", "#..", "##."}
	frameIdx := 0

	for {
		select {
		case <-ticker.C:
			frameIdx = (frameIdx + 1) % len(turboFrames)
			workerFrame := workerFrames[frameIdx%len(workerFrames)]
			p.renderTurbo(turboFrames[frameIdx], workerFrame)
		case <-p.done:
			return
		}
	}
}

// renderTurbo draws the nuclei/ffuf-style progress state
func (p *Progress) renderTurbo(spinner string, workerIndicator string) {
	current := atomic.LoadInt64(&p.current)
	total := int64(p.config.Total)
	elapsed := time.Since(p.startTime)

	// Calculate progress
	percent := float64(current) / float64(total) * 100
	if math.IsNaN(percent) || math.IsInf(percent, 0) {
		percent = 0
	}

	// Calculate RPS
	rps := float64(current) / elapsed.Seconds()
	if math.IsNaN(rps) || math.IsInf(rps, 0) {
		rps = 0
	}

	// Track peak RPS
	if rps > p.peakRPS {
		p.peakRPS = rps
	}

	// Calculate ETA
	eta := time.Duration(0)
	if current > 0 && current < total {
		remaining := total - current
		eta = time.Duration(float64(remaining) / rps * float64(time.Second))
	}

	// Get stats
	blocked := atomic.LoadInt64(&p.blocked)
	passed := atomic.LoadInt64(&p.passed)
	failed := atomic.LoadInt64(&p.failed)
	errored := atomic.LoadInt64(&p.errored)

	// Clear line
	fmt.Print("\033[2K\r")

	// Nuclei-style progress format:
	// [elapsed] [percent%] | Tests: current/total | Blocked: n | Pass: n | Fail: n | Errors: n | RPS: n.n | ETA: mm:ss
	elapsedStr := formatDuration(elapsed)
	etaStr := formatDuration(eta)

	// Build colorized output
	fmt.Printf("[%s] [%s] %s Tests: %s/%d %s Blocked: %s %s Pass: %s %s Fail: %s %s Errors: %s %s RPS: %s %s ETA: %s",
		StatValueStyle.Render(elapsedStr),
		StatValueStyle.Render(fmt.Sprintf("%5.1f%%", percent)),
		BracketStyle.Render("|"),
		StatValueStyle.Render(fmt.Sprintf("%d", current)),
		total,
		BracketStyle.Render("|"),
		BlockedStyle.Render(fmt.Sprintf("%d", blocked)),
		BracketStyle.Render("|"),
		PassStyle.Render(fmt.Sprintf("%d", passed)),
		BracketStyle.Render("|"),
		FailStyle.Render(fmt.Sprintf("%d", failed)),
		BracketStyle.Render("|"),
		ErrorStyle.Render(fmt.Sprintf("%d", errored)),
		BracketStyle.Render("|"),
		StatValueStyle.Render(fmt.Sprintf("%.1f", rps)),
		BracketStyle.Render("|"),
		StatLabelStyle.Render(etaStr),
	)
}

// buildTurboBar creates an animated turbo-style progress bar
func (p *Progress) buildTurboBar(percent float64, rps float64) string {
	width := p.config.Width
	filled := int(float64(width) * percent / 100)
	if filled > width {
		filled = width
	}

	// Use gradient colors for filled portion with animation effect
	bar := strings.Builder{}
	bar.WriteString(BracketStyle.Render("["))

	// Calculate animation offset based on time for "flowing" effect
	offset := int(time.Since(p.startTime).Milliseconds()/50) % 3

	for i := 0; i < width; i++ {
		if i < filled {
			// Gradient from purple to cyan with "pulse" effect
			if (i+offset)%3 == 0 && rps > 50 {
				bar.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#00D4AA")).Render("#"))
			} else {
				bar.WriteString(ProgressFullStyle.Render("#"))
			}
		} else if i == filled {
			// Animated edge
			edges := []string{"=", "-", "."}
			bar.WriteString(ProgressFullStyle.Render(edges[offset]))
		} else {
			bar.WriteString(ProgressEmptyStyle.Render("."))
		}
	}

	bar.WriteString(BracketStyle.Render("]"))

	// Add percentage with RPS indicator
	percentStr := fmt.Sprintf(" %5.1f%%", percent)
	bar.WriteString(StatValueStyle.Render(percentStr))

	// Add flame indicator when going fast
	if rps > 100 {
		bar.WriteString(" [FAST]")
	} else if rps > 50 {
		bar.WriteString(" [!]")
	}

	return bar.String()
}

// buildBar creates the visual progress bar (kept for compatibility)
func (p *Progress) buildBar(percent float64) string {
	return p.buildTurboBar(percent, 0)
}

// buildStats creates the statistics portion with clean alignment
func (p *Progress) buildStats(current int64, rps float64, eta time.Duration) string {
	blocked := atomic.LoadInt64(&p.blocked)
	_ = atomic.LoadInt64(&p.passed) // Reserved for future use
	failed := atomic.LoadInt64(&p.failed)
	errored := atomic.LoadInt64(&p.errored)

	elapsed := time.Since(p.startTime)

	// Format duration
	elapsedStr := formatDuration(elapsed)
	etaStr := formatDuration(eta)

	// Build stats with consistent spacing
	stats := fmt.Sprintf("%s/%d %s RPS: %s %s %s %s %s %s %s",
		StatValueStyle.Render(fmt.Sprintf("%4d", current)),
		p.config.Total,
		BracketStyle.Render("|"),
		StatValueStyle.Render(fmt.Sprintf("%5.1f", rps)),
		BracketStyle.Render("|"),
		BlockedStyle.Render(fmt.Sprintf("+ %-4d", blocked)),
		FailStyle.Render(fmt.Sprintf("x %-4d", failed)),
		ErrorStyle.Render(fmt.Sprintf("! %-4d", errored)),
		BracketStyle.Render("|"),
		StatLabelStyle.Render(fmt.Sprintf("%s -> %s", elapsedStr, etaStr)),
	)

	return stats
}

// formatDuration formats a duration as MM:SS or HH:MM:SS
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// PrintFinalProgress prints a completed progress line
func PrintFinalProgress(total int, elapsed time.Duration, rps float64, blocked, passed, failed, errored int) {
	bar := strings.Builder{}
	bar.WriteString(BracketStyle.Render("["))
	for i := 0; i < 40; i++ {
		bar.WriteString(ProgressFullStyle.Render("#"))
	}
	bar.WriteString(BracketStyle.Render("]"))
	bar.WriteString(StatValueStyle.Render(" 100.0%"))

	// Consistent stats format with final progress
	stats := fmt.Sprintf("%s/%d %s RPS: %s %s %s %s %s %s %s",
		StatValueStyle.Render(fmt.Sprintf("%d", total)),
		total,
		BracketStyle.Render("|"),
		StatValueStyle.Render(fmt.Sprintf("%.1f", rps)),
		BracketStyle.Render("|"),
		BlockedStyle.Render(fmt.Sprintf("+ %d", blocked)),
		FailStyle.Render(fmt.Sprintf("x %d", failed)),
		ErrorStyle.Render(fmt.Sprintf("! %d", errored)),
		BracketStyle.Render("|"),
		StatLabelStyle.Render(formatDuration(elapsed)),
	)

	fmt.Printf("\r  %s %s %s\n", PassStyle.Render("[DONE]"), bar.String(), stats)
}

// ProgressBar is a simple static progress bar
type ProgressBar struct {
	width int
	style lipgloss.Style
}

// NewProgressBar creates a simple progress bar
func NewProgressBar(width int) *ProgressBar {
	return &ProgressBar{
		width: width,
		style: lipgloss.NewStyle(),
	}
}

// Render renders the progress bar at a given percentage
func (pb *ProgressBar) Render(percent float64) string {
	filled := int(float64(pb.width) * percent / 100)
	if filled > pb.width {
		filled = pb.width
	}

	bar := strings.Builder{}
	for i := 0; i < pb.width; i++ {
		if i < filled {
			bar.WriteString(ProgressFullStyle.Render("#"))
		} else {
			bar.WriteString(ProgressEmptyStyle.Render("."))
		}
	}

	return bar.String()
}

// StatsDisplay provides nuclei-style statistics display
type StatsDisplay struct {
	startTime time.Time
	total     int
	current   *int64
	blocked   *int64
	passed    *int64
	failed    *int64
	errored   *int64
	interval  time.Duration
	done      chan struct{}
	running   bool
	mu        sync.Mutex
}

// NewStatsDisplay creates a new statistics display
func NewStatsDisplay(total int, interval int) *StatsDisplay {
	current := int64(0)
	blocked := int64(0)
	passed := int64(0)
	failed := int64(0)
	errored := int64(0)

	return &StatsDisplay{
		startTime: time.Now(),
		total:     total,
		current:   &current,
		blocked:   &blocked,
		passed:    &passed,
		failed:    &failed,
		errored:   &errored,
		interval:  time.Duration(interval) * time.Second,
		done:      make(chan struct{}),
	}
}

// Start begins the statistics display
func (s *StatsDisplay) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.startTime = time.Now()
	s.mu.Unlock()

	go s.renderLoop()
}

// Stop halts the statistics display
func (s *StatsDisplay) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		close(s.done)
		s.running = false
	}
}

// Update updates the statistics counters
func (s *StatsDisplay) Update(outcome string) {
	atomic.AddInt64(s.current, 1)
	switch outcome {
	case "Blocked":
		atomic.AddInt64(s.blocked, 1)
	case "Pass":
		atomic.AddInt64(s.passed, 1)
	case "Fail":
		atomic.AddInt64(s.failed, 1)
	case "Error":
		atomic.AddInt64(s.errored, 1)
	}
}

func (s *StatsDisplay) renderLoop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.render()
		case <-s.done:
			s.render() // Final render
			return
		}
	}
}

func (s *StatsDisplay) render() {
	current := atomic.LoadInt64(s.current)
	blocked := atomic.LoadInt64(s.blocked)
	passed := atomic.LoadInt64(s.passed)
	failed := atomic.LoadInt64(s.failed)
	errored := atomic.LoadInt64(s.errored)

	elapsed := time.Since(s.startTime)
	rps := float64(current) / elapsed.Seconds()
	if elapsed.Seconds() < 1 {
		rps = float64(current)
	}

	percent := float64(current) / float64(s.total) * 100
	remaining := s.total - int(current)
	eta := time.Duration(float64(remaining) / rps * float64(time.Second))
	if rps <= 0 {
		eta = 0
	}

	// Nuclei-style stats output
	fmt.Printf("\r[%s] [%s] Templates: %d/%d | Blocked: %s | Pass: %s | Fail: %s | Errors: %s | RPS: %.0f | ETA: %s",
		StatValueStyle.Render(formatDuration(elapsed)),
		StatValueStyle.Render(fmt.Sprintf("%.0f%%", percent)),
		current, s.total,
		BlockedStyle.Render(fmt.Sprintf("%d", blocked)),
		PassStyle.Render(fmt.Sprintf("%d", passed)),
		FailStyle.Render(fmt.Sprintf("%d", failed)),
		ErrorStyle.Render(fmt.Sprintf("%d", errored)),
		rps,
		formatDuration(eta),
	)
}
