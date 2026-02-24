// Package detection provides a unified detector combining connection monitoring
// and silent ban detection for comprehensive WAF behavior analysis.
package detection

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/hosterrors"
)

// Detector combines ConnectionMonitor and SilentBanDetector for unified
// detection of connection drops and silent bans.
type Detector struct {
	connMon   *ConnectionMonitor
	banDetect *SilentBanDetector

	// Callbacks for detection events
	onDropMu sync.RWMutex
	onDrop   func(host string, result *DropResult)

	onBanMu sync.RWMutex
	onBan   func(host string, result *BanResult)
}

// OnDrop registers a callback for connection drop events.
// The callback is invoked when a drop is detected (not for every error).
func (d *Detector) OnDrop(callback func(host string, result *DropResult)) {
	d.onDropMu.Lock()
	defer d.onDropMu.Unlock()
	d.onDrop = callback
}

// OnBan registers a callback for silent ban events.
// The callback is invoked when a ban is detected.
func (d *Detector) OnBan(callback func(host string, result *BanResult)) {
	d.onBanMu.Lock()
	defer d.onBanMu.Unlock()
	d.onBan = callback
}

// New creates a new Detector with both sub-detectors initialized.
func New() *Detector {
	return &Detector{
		connMon:   NewConnectionMonitor(),
		banDetect: NewSilentBanDetector(),
	}
}

var (
	defaultDetector *Detector
	defaultOnce     sync.Once
)

// Default returns the global default Detector instance,
// creating it on first call.
func Default() *Detector {
	defaultOnce.Do(func() {
		defaultDetector = New()
	})
	return defaultDetector
}

// RecordError records a connection error and returns the detection result.
func (d *Detector) RecordError(targetURL string, err error) *DetectionResult {
	host := extractHost(targetURL)

	dropResult := d.connMon.RecordDrop(host, err)

	// Sync with hosterrors when the host crosses the dropping threshold.
	// Uses MarkPermanent so a single call marks the host (rather than
	// incrementally calling MarkError which needs DefaultMaxErrors calls).
	// hosterrors state is cleared when ClearHostErrors is called between
	// scan phases.
	if dropResult.Dropped && dropResult.Consecutive == defaults.DropDetectConsecutiveThreshold {
		hosterrors.MarkPermanent(targetURL)
	}

	// Invoke callback if registered and drop was detected
	if dropResult.Dropped {
		d.onDropMu.RLock()
		cb := d.onDrop
		d.onDropMu.RUnlock()
		if cb != nil {
			cb(host, dropResult)
		}
	}

	return &DetectionResult{
		Drop: dropResult,
		Ban:  &BanResult{Banned: false, Type: BanTypeNone},
		Host: host,
		Time: time.Now(),
	}
}

// RecordResponse records a successful response and returns the detection result.
func (d *Detector) RecordResponse(targetURL string, resp *http.Response, latency time.Duration, bodySize int) *DetectionResult {
	host := extractHost(targetURL)

	// Record success for connection monitoring
	d.connMon.RecordSuccess(host)

	// Check for tarpit behavior
	tarpitResult := d.connMon.CheckTarpit(host, latency)

	// Record sample for silent ban detection
	banResult := d.banDetect.RecordSample(host, resp, latency, bodySize, false)
	if banResult == nil {
		banResult = &BanResult{Banned: false, Type: BanTypeNone}
	}

	// Invoke callback if registered and ban was detected
	if banResult.Banned {
		d.onBanMu.RLock()
		cb := d.onBan
		d.onBanMu.RUnlock()
		if cb != nil {
			cb(host, banResult)
		}
	}

	return &DetectionResult{
		Drop: tarpitResult,
		Ban:  banResult,
		Host: host,
		Time: time.Now(),
	}
}

// CaptureBaseline sets the baseline for both connection monitoring and
// silent ban detection for the given target.
func (d *Detector) CaptureBaseline(targetURL string, resp *http.Response, latency time.Duration, bodySize int) {
	host := extractHost(targetURL)

	// Set baseline latency for connection monitor
	d.connMon.SetBaseline(host, latency)

	// Capture baseline for silent ban detector
	d.banDetect.CaptureBaseline(host, resp, latency, bodySize)
}

// ShouldSkipHost checks if requests to the target should be skipped
// due to detected connection issues or silent bans.
func (d *Detector) ShouldSkipHost(targetURL string) (skip bool, reason string) {
	host := extractHost(targetURL)

	// Check if connection monitor detects dropping
	if d.connMon.IsDropping(host) {
		return true, "connection_dropping"
	}

	// Check if silent ban detector detects ban
	banResult := d.banDetect.Analyze(host)
	if banResult != nil && banResult.Banned {
		return true, "silent_ban_detected"
	}

	return false, ""
}

// Clear removes all tracking data for the target host.
func (d *Detector) Clear(targetURL string) {
	host := extractHost(targetURL)
	d.banDetect.Clear(host)
	d.connMon.Clear(host) // Also clear connection monitor state
}

// ClearAll removes all tracking data for all hosts.
// Call this at the start of a new scan to ensure fresh state.
func (d *Detector) ClearAll() {
	d.connMon.ClearAll()
	d.banDetect.ClearAll()
}

// Stats returns combined statistics from both sub-detectors.
func (d *Detector) Stats() map[string]int {
	stats := make(map[string]int)

	// Get connection monitor stats
	hostsTracked, totalDrops := d.connMon.Stats()
	stats["connmon_hosts_tracked"] = hostsTracked
	stats["connmon_total_drops"] = totalDrops

	// Get silent ban detector stats
	banStats := d.banDetect.Stats()
	if v, ok := banStats["hosts_tracked"].(int); ok {
		stats["silentban_hosts_tracked"] = v
	}
	if v, ok := banStats["hosts_with_metrics"].(int); ok {
		stats["silentban_hosts_with_metrics"] = v
	}
	if v, ok := banStats["total_samples"].(int); ok {
		stats["silentban_total_samples"] = v
	}

	return stats
}

// ClearHostErrors clears both detection state and hosterrors cache for a host.
func (d *Detector) ClearHostErrors(targetURL string) {
	d.Clear(targetURL)
	hosterrors.Clear(targetURL)
}

// extractHost extracts the host from a URL string.
func extractHost(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	return parsed.Host
}
