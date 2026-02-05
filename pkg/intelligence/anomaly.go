// Package intelligence provides adaptive learning capabilities for WAFtester.
// This file implements anomaly detection for honeypots, behavior shifts, and silent bans.
package intelligence

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Anomaly detection constants.
const (
	// DefaultAnomalyWindowSize is the default sliding window size for response tracking.
	DefaultAnomalyWindowSize = 100

	// MinBaselineSamples is the minimum samples required to establish baseline.
	MinBaselineSamples = 20

	// MaxAnomalies is the maximum number of anomalies to retain in memory.
	MaxAnomalies = 1000
)

// ══════════════════════════════════════════════════════════════════════════════
// ANOMALY DETECTOR - Detect honeypots, behavior shifts, silent bans
// Protects the scan from misbehaving targets and adaptive defenses
// ══════════════════════════════════════════════════════════════════════════════

// AnomalyDetector detects unusual WAF/server behavior
type AnomalyDetector struct {
	mu sync.RWMutex

	// Baseline metrics (established during calibration)
	baseline *BehaviorBaseline

	// Recent observations (sliding window)
	recentResponses []ResponseMetrics
	windowSize      int

	// Anomaly tracking
	anomalies       []Anomaly
	anomalyCallback func(*Anomaly)

	// Detection thresholds
	thresholds AnomalyThresholds
}

// BehaviorBaseline represents normal server behavior
type BehaviorBaseline struct {
	AvgLatency       float64         // Average response latency
	LatencyStdDev    float64         // Standard deviation of latency
	StatusCodeDist   map[int]float64 // Normal status code distribution
	BlockRate        float64         // Normal block rate
	ResponseSizeDist float64         // Average response size
	Established      bool
	SampleCount      int
}

// ResponseMetrics tracks a single response's metrics
type ResponseMetrics struct {
	Timestamp    time.Time
	LatencyMs    float64
	StatusCode   int
	ResponseSize int
	Blocked      bool
	Category     string
	Path         string
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	Type        AnomalyType
	Severity    string // critical, high, medium, low
	Timestamp   time.Time
	Description string
	Evidence    []string
	Action      string // Recommended action
	Confidence  float64
}

// AnomalyType categorizes anomalies
type AnomalyType string

const (
	AnomalyHoneypot      AnomalyType = "honeypot"       // Too-good-to-be-true bypass rates
	AnomalySilentBan     AnomalyType = "silent_ban"     // Sudden behavior change
	AnomalyRateLimited   AnomalyType = "rate_limited"   // Rate limiting detected
	AnomalyBehaviorShift AnomalyType = "behavior_shift" // WAF rules changed mid-scan
	AnomalyLatencySpike  AnomalyType = "latency_spike"  // Unusual latency patterns
	AnomalyDeception     AnomalyType = "deception"      // Fake success responses
	AnomalyBlindspot     AnomalyType = "blindspot"      // WAF not inspecting certain paths
)

// AnomalyThresholds configures detection sensitivity
type AnomalyThresholds struct {
	// Honeypot detection
	HoneypotBypassThreshold float64 // If bypass rate > this, might be honeypot

	// Silent ban detection
	SilentBanBlockIncrease float64 // Block rate increase indicating silent ban
	SilentBanLatencyDrop   float64 // Latency drop indicating silent ban

	// Rate limiting detection
	RateLimitStatusCodes []int // Status codes indicating rate limiting
	RateLimitConsecutive int   // Consecutive rate limit responses

	// Behavior shift detection
	BehaviorShiftThreshold float64 // % change in behavior to flag

	// Latency anomaly detection
	LatencyZScoreThreshold float64 // Z-score threshold for latency anomaly
}

// DefaultAnomalyThresholds returns sensible defaults
func DefaultAnomalyThresholds() AnomalyThresholds {
	return AnomalyThresholds{
		HoneypotBypassThreshold: 0.95, // >95% bypass = suspicious
		SilentBanBlockIncrease:  0.5,  // 50% increase in blocks
		SilentBanLatencyDrop:    0.7,  // 70% latency drop
		RateLimitStatusCodes:    []int{429, 503, 509},
		RateLimitConsecutive:    3,
		BehaviorShiftThreshold:  0.3, // 30% behavior change
		LatencyZScoreThreshold:  3.0, // 3 std dev
	}
}

// NewAnomalyDetector creates a new AnomalyDetector.
func NewAnomalyDetector() *AnomalyDetector {
	return NewAnomalyDetectorWithConfig(DefaultAnomalyConfig())
}

// NewAnomalyDetectorWithConfig creates a new AnomalyDetector with custom configuration.
func NewAnomalyDetectorWithConfig(cfg *AnomalyConfig) *AnomalyDetector {
	if cfg == nil {
		cfg = DefaultAnomalyConfig()
	}
	// Validate window size to prevent unbounded slice growth
	windowSize := cfg.WindowSize
	if windowSize <= 0 {
		windowSize = DefaultAnomalyWindowSize
	}
	return &AnomalyDetector{
		baseline:        &BehaviorBaseline{StatusCodeDist: make(map[int]float64)},
		recentResponses: make([]ResponseMetrics, 0),
		windowSize:      windowSize,
		anomalies:       make([]Anomaly, 0),
		thresholds:      DefaultAnomalyThresholds(),
	}
}

// SetCallback sets the callback for when anomalies are detected
func (ad *AnomalyDetector) SetCallback(fn func(*Anomaly)) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.anomalyCallback = fn
}

// ObserveResponse records a response and checks for anomalies
func (ad *AnomalyDetector) ObserveResponse(latencyMs float64, statusCode int, responseSize int, blocked bool, category, path string) []Anomaly {
	ad.mu.Lock()

	metrics := ResponseMetrics{
		Timestamp:    time.Now(),
		LatencyMs:    latencyMs,
		StatusCode:   statusCode,
		ResponseSize: responseSize,
		Blocked:      blocked,
		Category:     category,
		Path:         path,
	}

	// Add to sliding window
	ad.recentResponses = append(ad.recentResponses, metrics)
	if len(ad.recentResponses) > ad.windowSize {
		ad.recentResponses = ad.recentResponses[1:]
	}

	// Update baseline if not established
	if !ad.baseline.Established && len(ad.recentResponses) >= MinBaselineSamples {
		ad.establishBaseline()
	}

	// Check for anomalies
	detected := make([]Anomaly, 0)

	// Only check after baseline is established
	if ad.baseline.Established {
		detected = append(detected, ad.checkRateLimiting(metrics)...)
		detected = append(detected, ad.checkLatencyAnomaly(metrics)...)
		detected = append(detected, ad.checkBehaviorShift()...)
		detected = append(detected, ad.checkHoneypot()...)
		detected = append(detected, ad.checkSilentBan()...)
	}

	// Record detected anomalies and get callback reference while holding lock
	callback := ad.anomalyCallback
	for _, anomaly := range detected {
		ad.anomalies = append(ad.anomalies, anomaly)
	}
	// Cap anomaly list to prevent unbounded growth
	if len(ad.anomalies) > MaxAnomalies {
		ad.anomalies = ad.anomalies[len(ad.anomalies)-MaxAnomalies:]
	}

	// Release lock BEFORE invoking callback to prevent deadlock
	ad.mu.Unlock()

	// Invoke callbacks after releasing lock
	for i := range detected {
		if callback != nil {
			callback(&detected[i])
		}
	}

	return detected
}

// establishBaseline establishes normal behavior baseline
func (ad *AnomalyDetector) establishBaseline() {
	if len(ad.recentResponses) < 20 {
		return
	}

	// Calculate average latency
	totalLatency := 0.0
	for _, r := range ad.recentResponses {
		totalLatency += r.LatencyMs
	}
	ad.baseline.AvgLatency = totalLatency / float64(len(ad.recentResponses))

	// Calculate latency standard deviation
	variance := 0.0
	for _, r := range ad.recentResponses {
		diff := r.LatencyMs - ad.baseline.AvgLatency
		variance += diff * diff
	}
	ad.baseline.LatencyStdDev = math.Sqrt(variance / float64(len(ad.recentResponses)))

	// Calculate status code distribution
	statusCounts := make(map[int]int)
	for _, r := range ad.recentResponses {
		statusCounts[r.StatusCode]++
	}
	for code, count := range statusCounts {
		ad.baseline.StatusCodeDist[code] = float64(count) / float64(len(ad.recentResponses))
	}

	// Calculate block rate
	blockedCount := 0
	for _, r := range ad.recentResponses {
		if r.Blocked {
			blockedCount++
		}
	}
	ad.baseline.BlockRate = float64(blockedCount) / float64(len(ad.recentResponses))

	ad.baseline.SampleCount = len(ad.recentResponses)
	ad.baseline.Established = true
}

// checkRateLimiting checks for rate limiting
func (ad *AnomalyDetector) checkRateLimiting(latest ResponseMetrics) []Anomaly {
	// Check if latest response is a rate limit
	isRateLimit := false
	for _, code := range ad.thresholds.RateLimitStatusCodes {
		if latest.StatusCode == code {
			isRateLimit = true
			break
		}
	}

	if !isRateLimit {
		return nil
	}

	// Check for consecutive rate limits
	consecutive := 0
	for i := len(ad.recentResponses) - 1; i >= 0 && consecutive < ad.thresholds.RateLimitConsecutive; i-- {
		isRL := false
		for _, code := range ad.thresholds.RateLimitStatusCodes {
			if ad.recentResponses[i].StatusCode == code {
				isRL = true
				break
			}
		}
		if isRL {
			consecutive++
		} else {
			break
		}
	}

	if consecutive >= ad.thresholds.RateLimitConsecutive {
		return []Anomaly{{
			Type:        AnomalyRateLimited,
			Severity:    "high",
			Timestamp:   time.Now(),
			Description: fmt.Sprintf("Rate limiting detected: %d consecutive %d responses", consecutive, latest.StatusCode),
			Evidence:    []string{fmt.Sprintf("Status code: %d", latest.StatusCode), fmt.Sprintf("Consecutive: %d", consecutive)},
			Action:      "Reduce request rate immediately",
			Confidence:  0.95,
		}}
	}

	return nil
}

// checkLatencyAnomaly checks for unusual latency
func (ad *AnomalyDetector) checkLatencyAnomaly(latest ResponseMetrics) []Anomaly {
	// Robust check for zero, subnormal, or invalid stddev
	if ad.baseline.LatencyStdDev < 1e-9 || math.IsNaN(ad.baseline.LatencyStdDev) {
		return nil
	}

	// Calculate Z-score
	zScore := (latest.LatencyMs - ad.baseline.AvgLatency) / ad.baseline.LatencyStdDev

	// Guard against NaN/Inf from corrupted data
	if math.IsNaN(zScore) || math.IsInf(zScore, 0) {
		return nil
	}

	if math.Abs(zScore) > ad.thresholds.LatencyZScoreThreshold {
		severity := "low"
		if math.Abs(zScore) > 5 {
			severity = "high"
		} else if math.Abs(zScore) > 4 {
			severity = "medium"
		}

		description := ""
		if zScore > 0 {
			description = fmt.Sprintf("Latency spike: %.0fms (%.1f std dev above normal)", latest.LatencyMs, zScore)
		} else {
			description = fmt.Sprintf("Latency drop: %.0fms (%.1f std dev below normal)", latest.LatencyMs, math.Abs(zScore))
		}

		return []Anomaly{{
			Type:        AnomalyLatencySpike,
			Severity:    severity,
			Timestamp:   time.Now(),
			Description: description,
			Evidence: []string{
				fmt.Sprintf("Current: %.0fms", latest.LatencyMs),
				fmt.Sprintf("Baseline: %.0fms ± %.0fms", ad.baseline.AvgLatency, ad.baseline.LatencyStdDev),
			},
			Action:     "Monitor for continued anomalies",
			Confidence: math.Min(1.0, math.Abs(zScore)/10),
		}}
	}

	return nil
}

// checkBehaviorShift checks for WAF behavior changes
func (ad *AnomalyDetector) checkBehaviorShift() []Anomaly {
	if len(ad.recentResponses) < 50 {
		return nil
	}

	// Compare first half vs second half
	midpoint := len(ad.recentResponses) / 2
	firstHalf := ad.recentResponses[:midpoint]
	secondHalf := ad.recentResponses[midpoint:]

	// Calculate block rates for each half
	firstBlocked := 0
	for _, r := range firstHalf {
		if r.Blocked {
			firstBlocked++
		}
	}
	firstRate := float64(firstBlocked) / float64(len(firstHalf))

	secondBlocked := 0
	for _, r := range secondHalf {
		if r.Blocked {
			secondBlocked++
		}
	}
	secondRate := float64(secondBlocked) / float64(len(secondHalf))

	// Check for significant change
	if firstRate > 0 {
		change := (secondRate - firstRate) / firstRate
		if math.Abs(change) > ad.thresholds.BehaviorShiftThreshold {
			direction := "increased"
			if change < 0 {
				direction = "decreased"
			}
			return []Anomaly{{
				Type:        AnomalyBehaviorShift,
				Severity:    "medium",
				Timestamp:   time.Now(),
				Description: fmt.Sprintf("WAF behavior shift: block rate %s by %.0f%%", direction, math.Abs(change)*100),
				Evidence: []string{
					fmt.Sprintf("First half block rate: %.1f%%", firstRate*100),
					fmt.Sprintf("Second half block rate: %.1f%%", secondRate*100),
				},
				Action:     "WAF rules may have been updated - consider recalibrating",
				Confidence: math.Min(1.0, math.Abs(change)),
			}}
		}
	}

	return nil
}

// checkHoneypot checks for honeypot indicators
func (ad *AnomalyDetector) checkHoneypot() []Anomaly {
	if len(ad.recentResponses) < 30 {
		return nil
	}

	// Calculate recent bypass rate
	bypasses := 0
	for _, r := range ad.recentResponses {
		if !r.Blocked {
			bypasses++
		}
	}
	bypassRate := float64(bypasses) / float64(len(ad.recentResponses))

	// Suspiciously high bypass rate
	if bypassRate > ad.thresholds.HoneypotBypassThreshold {
		return []Anomaly{{
			Type:        AnomalyHoneypot,
			Severity:    "critical",
			Timestamp:   time.Now(),
			Description: fmt.Sprintf("Potential honeypot: %.0f%% bypass rate is suspiciously high", bypassRate*100),
			Evidence: []string{
				fmt.Sprintf("Bypass rate: %.1f%%", bypassRate*100),
				"Most WAFs block at least some attacks",
				"This could be a decoy accepting all payloads",
			},
			Action:     "STOP - Verify target is legitimate before continuing",
			Confidence: (bypassRate - ad.thresholds.HoneypotBypassThreshold) / (1 - ad.thresholds.HoneypotBypassThreshold),
		}}
	}

	// Check for deception patterns (all responses identical)
	if len(ad.recentResponses) >= 20 {
		firstResponse := ad.recentResponses[len(ad.recentResponses)-20]
		identical := true
		for _, r := range ad.recentResponses[len(ad.recentResponses)-19:] {
			if r.StatusCode != firstResponse.StatusCode || r.ResponseSize != firstResponse.ResponseSize {
				identical = false
				break
			}
		}
		if identical {
			return []Anomaly{{
				Type:        AnomalyDeception,
				Severity:    "high",
				Timestamp:   time.Now(),
				Description: "All responses identical - possible deception or static response",
				Evidence: []string{
					fmt.Sprintf("Last 20 responses: status %d, size %d", firstResponse.StatusCode, firstResponse.ResponseSize),
					"Legitimate applications have varying responses",
				},
				Action:     "Verify responses are meaningful - may be decoy or cached",
				Confidence: 0.8,
			}}
		}
	}

	return nil
}

// checkSilentBan checks for silent ban indicators
func (ad *AnomalyDetector) checkSilentBan() []Anomaly {
	if len(ad.recentResponses) < 40 {
		return nil
	}

	// Compare last 10 with previous 30
	recent := ad.recentResponses[len(ad.recentResponses)-10:]
	previous := ad.recentResponses[len(ad.recentResponses)-40 : len(ad.recentResponses)-10]

	// Calculate metrics for each period
	recentBlocked := 0
	recentLatency := 0.0
	for _, r := range recent {
		if r.Blocked {
			recentBlocked++
		}
		recentLatency += r.LatencyMs
	}
	recentBlockRate := float64(recentBlocked) / float64(len(recent))
	recentAvgLatency := recentLatency / float64(len(recent))

	prevBlocked := 0
	prevLatency := 0.0
	for _, r := range previous {
		if r.Blocked {
			prevBlocked++
		}
		prevLatency += r.LatencyMs
	}
	prevBlockRate := float64(prevBlocked) / float64(len(previous))
	prevAvgLatency := prevLatency / float64(len(previous))

	// Check for sudden block rate increase + latency drop (classic silent ban)
	blockIncrease := recentBlockRate - prevBlockRate
	latencyChange := 0.0
	if prevAvgLatency > 0 {
		latencyChange = (recentAvgLatency - prevAvgLatency) / prevAvgLatency
	}

	if blockIncrease > ad.thresholds.SilentBanBlockIncrease && latencyChange < -ad.thresholds.SilentBanLatencyDrop {
		return []Anomaly{{
			Type:        AnomalySilentBan,
			Severity:    "critical",
			Timestamp:   time.Now(),
			Description: "Silent ban detected: sudden block increase with latency drop",
			Evidence: []string{
				fmt.Sprintf("Block rate: %.0f%% → %.0f%%", prevBlockRate*100, recentBlockRate*100),
				fmt.Sprintf("Latency: %.0fms → %.0fms", prevAvgLatency, recentAvgLatency),
				"This pattern indicates IP-level blocking without 429",
			},
			Action:     "PAUSE - Your IP may be blocked. Consider rotating.",
			Confidence: 0.9,
		}}
	}

	return nil
}

// GetAnomalies returns all detected anomalies
func (ad *AnomalyDetector) GetAnomalies() []Anomaly {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	result := make([]Anomaly, len(ad.anomalies))
	copy(result, ad.anomalies)
	return result
}

// GetAnomaliesBySeverity returns anomalies filtered by severity
func (ad *AnomalyDetector) GetAnomaliesBySeverity(severity string) []Anomaly {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	result := make([]Anomaly, 0)
	for _, a := range ad.anomalies {
		if a.Severity == severity {
			result = append(result, a)
		}
	}
	return result
}

// GetStats returns anomaly detector statistics
func (ad *AnomalyDetector) GetStats() AnomalyStats {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	stats := AnomalyStats{
		TotalObservations:   len(ad.recentResponses),
		BaselineEstablished: ad.baseline.Established,
		TotalAnomalies:      len(ad.anomalies),
		AnomaliesByType:     make(map[AnomalyType]int),
		AnomaliesBySeverity: make(map[string]int),
	}

	if ad.baseline.Established {
		stats.BaselineLatency = ad.baseline.AvgLatency
		stats.BaselineBlockRate = ad.baseline.BlockRate
	}

	for _, a := range ad.anomalies {
		stats.AnomaliesByType[a.Type]++
		stats.AnomaliesBySeverity[a.Severity]++
	}

	// Determine overall health
	criticalCount := stats.AnomaliesBySeverity["critical"]
	highCount := stats.AnomaliesBySeverity["high"]
	if criticalCount > 0 {
		stats.OverallHealth = "critical"
	} else if highCount > 2 {
		stats.OverallHealth = "warning"
	} else {
		stats.OverallHealth = "healthy"
	}

	return stats
}

// AnomalyStats contains anomaly detector statistics
type AnomalyStats struct {
	TotalObservations   int
	BaselineEstablished bool
	BaselineLatency     float64
	BaselineBlockRate   float64
	TotalAnomalies      int
	AnomaliesByType     map[AnomalyType]int
	AnomaliesBySeverity map[string]int
	OverallHealth       string // healthy, warning, critical
}

// ShouldPause returns true if anomalies warrant pausing the scan
func (ad *AnomalyDetector) ShouldPause() (bool, string) {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	// Check for critical anomalies in last 10
	recentCritical := 0
	for i := len(ad.anomalies) - 1; i >= 0 && i >= len(ad.anomalies)-10; i-- {
		if ad.anomalies[i].Severity == "critical" {
			recentCritical++
		}
	}

	if recentCritical > 0 {
		return true, ad.anomalies[len(ad.anomalies)-1].Action
	}

	// Check for rate limiting
	rateLimitCount := 0
	for _, a := range ad.anomalies {
		if a.Type == AnomalyRateLimited {
			rateLimitCount++
		}
	}
	if rateLimitCount >= 3 {
		return true, "Multiple rate limit detections - reduce request rate"
	}

	return false, ""
}

// Reset clears all state
func (ad *AnomalyDetector) Reset() {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	ad.baseline = &BehaviorBaseline{StatusCodeDist: make(map[int]float64)}
	ad.recentResponses = make([]ResponseMetrics, 0)
	ad.anomalies = make([]Anomaly, 0)
}

// GetRecentTrend returns the trend of recent behavior
func (ad *AnomalyDetector) GetRecentTrend() *BehaviorTrend {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	if len(ad.recentResponses) < 20 {
		return nil
	}

	// Analyze last 20 responses
	recent := ad.recentResponses[len(ad.recentResponses)-20:]

	trend := &BehaviorTrend{
		SampleSize: len(recent),
	}

	// Calculate current metrics
	for _, r := range recent {
		if r.Blocked {
			trend.BlockedCount++
		}
		trend.AvgLatency += r.LatencyMs
	}
	trend.AvgLatency /= float64(len(recent))
	trend.BlockRate = float64(trend.BlockedCount) / float64(len(recent))

	// Compare to baseline
	if ad.baseline.Established {
		trend.LatencyTrend = (trend.AvgLatency - ad.baseline.AvgLatency) / ad.baseline.AvgLatency
		trend.BlockRateTrend = trend.BlockRate - ad.baseline.BlockRate
	}

	// Determine status
	if trend.BlockRate > 0.9 {
		trend.Status = "heavily_blocked"
	} else if trend.BlockRate > 0.7 {
		trend.Status = "mostly_blocked"
	} else if trend.BlockRate < 0.1 {
		trend.Status = "mostly_bypassing"
	} else {
		trend.Status = "normal"
	}

	return trend
}

// BehaviorTrend represents recent behavior trend
type BehaviorTrend struct {
	SampleSize     int
	BlockedCount   int
	BlockRate      float64
	AvgLatency     float64
	LatencyTrend   float64 // % change from baseline
	BlockRateTrend float64 // Absolute change from baseline
	Status         string  // heavily_blocked, mostly_blocked, mostly_bypassing, normal
}

// TopAnomalies returns the top N most severe anomalies
func (ad *AnomalyDetector) TopAnomalies(n int) []Anomaly {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	if len(ad.anomalies) == 0 {
		return nil
	}

	// Copy and sort by severity
	sorted := make([]Anomaly, len(ad.anomalies))
	copy(sorted, ad.anomalies)

	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.Slice(sorted, func(i, j int) bool {
		// Unknown severities sort last (4)
		orderI, okI := severityOrder[sorted[i].Severity]
		if !okI {
			orderI = 4
		}
		orderJ, okJ := severityOrder[sorted[j].Severity]
		if !okJ {
			orderJ = 4
		}
		return orderI < orderJ
	})

	if len(sorted) > n {
		return sorted[:n]
	}
	return sorted
}
