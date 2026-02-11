// Package detection provides types and utilities for detecting connection drops
// and silent bans from WAF and security systems.
package detection

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
)

// keyHeaders are headers tracked for baseline comparison.
var keyHeaders = []string{
	"Server",
	"X-Cache",
	"X-CDN",
	"CF-Ray",
	"X-Request-ID",
	"Set-Cookie",
	"Content-Type",
	"X-Frame-Options",
}

// baseline holds the expected response characteristics for a host.
type baseline struct {
	avgLatency  time.Duration
	avgBodySize int
	statusCode  int
	sampleCount int
	keyHeaders  map[string]string
	capturedAt  time.Time
}

// metrics tracks recent response behavior for ban detection.
type metrics struct {
	samples         []sample
	consecutiveErrs int
	headerChanges   int
	lastCheck       time.Time
}

// sample represents a single response observation.
type sample struct {
	latency    time.Duration
	bodySize   int
	statusCode int
	hasError   bool
	timestamp  time.Time
}

// SilentBanDetector analyzes response patterns to detect silent bans,
// rate limiting, IP blocks, and honeypot behavior.
type SilentBanDetector struct {
	mu            sync.RWMutex
	hostBaselines map[string]*baseline
	hostMetrics   map[string]*metrics
}

// NewSilentBanDetector creates a new SilentBanDetector instance.
func NewSilentBanDetector() *SilentBanDetector {
	return &SilentBanDetector{
		hostBaselines: make(map[string]*baseline),
		hostMetrics:   make(map[string]*metrics),
	}
}

// ClearAll removes all tracking data.
func (d *SilentBanDetector) ClearAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hostBaselines = make(map[string]*baseline)
	d.hostMetrics = make(map[string]*metrics)
}

// CaptureBaseline records baseline response characteristics for a host.
// Uses exponential moving average with alpha=defaults.EMAAlpha for smooth adaptation.
func (d *SilentBanDetector) CaptureBaseline(host string, resp *http.Response, latency time.Duration, bodySize int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	b, exists := d.hostBaselines[host]
	if !exists {
		b = &baseline{
			keyHeaders: make(map[string]string),
		}
		d.hostBaselines[host] = b
	}

	// Update using exponential moving average
	if b.sampleCount == 0 {
		b.avgLatency = latency
		b.avgBodySize = bodySize
	} else {
		// EMA: new_avg = alpha * new_value + (1 - alpha) * old_avg
		b.avgLatency = time.Duration(defaults.EMAAlpha*float64(latency) + (1-defaults.EMAAlpha)*float64(b.avgLatency))
		b.avgBodySize = int(defaults.EMAAlpha*float64(bodySize) + (1-defaults.EMAAlpha)*float64(b.avgBodySize))
	}

	if resp != nil {
		b.statusCode = resp.StatusCode

		// Capture key headers
		for _, h := range keyHeaders {
			if v := resp.Header.Get(h); v != "" {
				b.keyHeaders[h] = v
			}
		}
	}

	b.sampleCount++
	b.capturedAt = time.Now()
}

// RecordSample records a response sample and returns a BanResult if immediate detection is triggered.
func (d *SilentBanDetector) RecordSample(host string, resp *http.Response, latency time.Duration, bodySize int, hasError bool) *BanResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	m, exists := d.hostMetrics[host]
	if !exists {
		m = &metrics{
			samples: make([]sample, 0, 100),
		}
		d.hostMetrics[host] = m
	}

	// Create the sample
	s := sample{
		latency:   latency,
		bodySize:  bodySize,
		hasError:  hasError,
		timestamp: time.Now(),
	}
	if resp != nil {
		s.statusCode = resp.StatusCode
	}

	// Keep max 100 samples
	if len(m.samples) >= 100 {
		m.samples = m.samples[1:]
	}
	m.samples = append(m.samples, s)

	// Track consecutive errors
	if hasError {
		m.consecutiveErrs++
	} else {
		m.consecutiveErrs = 0
		m.headerChanges = 0 // Reset on successful response to avoid monotonic accumulation
	}

	// Count header changes against baseline
	if resp != nil {
		m.headerChanges += d.countHeaderChangesLocked(host, resp)
	}

	m.lastCheck = time.Now()

	// Check for immediate ban conditions (consecutive errors threshold)
	if m.consecutiveErrs >= defaults.SilentBanConsecutiveErrors {
		return &BanResult{
			Banned:          true,
			Type:            BanTypeRateLimit,
			Confidence:      0.6,
			Evidence:        []string{"consecutive errors threshold exceeded"},
			RecommendedWait: defaults.SilentBanCooldownPeriod(),
		}
	}

	return nil
}

// Analyze performs comprehensive ban detection analysis for a host.
func (d *SilentBanDetector) Analyze(host string) *BanResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	b := d.hostBaselines[host]
	m := d.hostMetrics[host]

	// Need both baseline and metrics
	if b == nil || m == nil {
		return &BanResult{Banned: false, Type: BanTypeNone}
	}

	// Need minimum samples
	if len(m.samples) < defaults.SilentBanMinSamples {
		return &BanResult{Banned: false, Type: BanTypeNone}
	}

	var confidence float64
	var evidence []string
	var banType BanType = BanTypeNone
	var latencyDrift, bodySizeDrift float64

	// Check 1: Consecutive errors (0.4 confidence)
	if m.consecutiveErrs >= defaults.SilentBanConsecutiveErrors {
		confidence += 0.4
		evidence = append(evidence, "consecutive errors threshold exceeded")
		banType = BanTypeRateLimit
	}

	// Check 2: Latency drift (0.25 confidence)
	recentLatency := d.recentAvgLatencyLocked(m)
	if b.avgLatency > 0 && recentLatency > 0 {
		latencyDrift = float64(recentLatency) / float64(b.avgLatency)
		if latencyDrift >= defaults.SilentBanLatencyDriftThreshold {
			confidence += 0.25
			evidence = append(evidence, "significant latency increase detected")
			if banType == BanTypeNone {
				banType = BanTypeBehavioral
			}
		}
	}

	// Check 3: Body size drift (0.2 confidence)
	recentBodySize := d.recentAvgBodySizeLocked(m)
	if b.avgBodySize > 0 && recentBodySize > 0 {
		bodySizeDrift = math.Abs(float64(recentBodySize-b.avgBodySize)) / float64(b.avgBodySize)
		if bodySizeDrift >= defaults.SilentBanBodySizeDriftThreshold {
			confidence += 0.2
			evidence = append(evidence, "significant body size change detected")
			if banType == BanTypeNone {
				banType = BanTypeBehavioral
			}
		}

		// Check 5: Body size drift >90% suggests honeypot (0.15 confidence)
		if bodySizeDrift > 0.9 {
			confidence += 0.15
			evidence = append(evidence, "extreme body size change suggests honeypot")
			banType = BanTypeHoneypot
		}
	}

	// Check 4: Header changes (0.15 confidence)
	if m.headerChanges >= defaults.SilentBanHeaderChangeThreshold {
		confidence += 0.15
		evidence = append(evidence, "significant header changes detected")
		if banType == BanTypeNone {
			banType = BanTypeBehavioral
		}
	}

	// Determine if banned (confidence >= 0.4)
	banned := confidence >= 0.4

	result := &BanResult{
		Banned:        banned,
		Type:          banType,
		Confidence:    confidence,
		Evidence:      evidence,
		LatencyDrift:  latencyDrift,
		BodySizeDrift: bodySizeDrift,
	}

	if banned {
		result.RecommendedWait = defaults.SilentBanCooldownPeriod()
	}

	return result
}

// Clear removes all baseline and metrics data for a host.
func (d *SilentBanDetector) Clear(host string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.hostBaselines, host)
	delete(d.hostMetrics, host)
}

// Stats returns statistics about the detector's state.
func (d *SilentBanDetector) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["hosts_tracked"] = len(d.hostBaselines)
	stats["hosts_with_metrics"] = len(d.hostMetrics)

	totalSamples := 0
	for _, m := range d.hostMetrics {
		totalSamples += len(m.samples)
	}
	stats["total_samples"] = totalSamples

	return stats
}

// recentAvgLatencyLocked calculates the average latency of recent samples.
// Caller must hold at least a read lock.
func (d *SilentBanDetector) recentAvgLatencyLocked(m *metrics) time.Duration {
	if len(m.samples) == 0 {
		return 0
	}

	// Use last 10 samples or all if fewer
	count := len(m.samples)
	if count > 10 {
		count = 10
	}

	var total time.Duration
	for i := len(m.samples) - count; i < len(m.samples); i++ {
		total += m.samples[i].latency
	}

	return total / time.Duration(count)
}

// recentAvgBodySizeLocked calculates the average body size of recent samples.
// Caller must hold at least a read lock.
func (d *SilentBanDetector) recentAvgBodySizeLocked(m *metrics) int {
	if len(m.samples) == 0 {
		return 0
	}

	// Use last 10 samples or all if fewer
	count := len(m.samples)
	if count > 10 {
		count = 10
	}

	var total int
	for i := len(m.samples) - count; i < len(m.samples); i++ {
		total += m.samples[i].bodySize
	}

	return total / count
}

// countHeaderChangesLocked counts header differences from baseline.
// Caller must hold at least a read lock.
func (d *SilentBanDetector) countHeaderChangesLocked(host string, resp *http.Response) int {
	b := d.hostBaselines[host]
	if b == nil || resp == nil {
		return 0
	}

	changes := 0
	for _, h := range keyHeaders {
		baselineVal := b.keyHeaders[h]
		currentVal := resp.Header.Get(h)

		// Count as change if header was present in baseline but different/missing now
		// or if header is new (wasn't in baseline but is now present)
		if baselineVal != currentVal {
			changes++
		}
	}

	return changes
}
