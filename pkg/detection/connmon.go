// Package detection provides connection monitoring and drop detection.
package detection

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
)

// dropState tracks connection drop state for a single host with atomic counters.
type dropState struct {
	consecutiveDrops  atomic.Int64
	totalDrops        atomic.Int64
	lastDropType      atomic.Int32
	lastDropTime      atomic.Int64 // Unix nano
	recoverySuccesses atomic.Int64
	inRecovery        atomic.Bool
	recoveryStartTime atomic.Int64 // Unix nano
}

// ConnectionMonitor tracks connection drops and recovery across multiple hosts.
type ConnectionMonitor struct {
	mu              sync.RWMutex
	hostDrops       map[string]*dropState
	baselineLatency map[string]time.Duration
}

// NewConnectionMonitor creates a new ConnectionMonitor instance.
func NewConnectionMonitor() *ConnectionMonitor {
	return &ConnectionMonitor{
		hostDrops:       make(map[string]*dropState),
		baselineLatency: make(map[string]time.Duration),
	}
}

// ClearAll removes all tracking data.
func (m *ConnectionMonitor) ClearAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hostDrops = make(map[string]*dropState)
	m.baselineLatency = make(map[string]time.Duration)
}

// Clear removes tracking data for a specific host.
func (m *ConnectionMonitor) Clear(host string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.hostDrops, host)
	delete(m.baselineLatency, host)
}

// ClassifyError determines the type of connection drop from an error.
func ClassifyError(err error) DropType {
	if err == nil {
		return DropTypeNone
	}

	// Check for syscall errors first
	var syscallErr syscall.Errno
	if errors.As(err, &syscallErr) {
		switch syscallErr {
		case syscall.ECONNRESET:
			return DropTypeTCPReset
		case syscall.ECONNREFUSED:
			return DropTypeRefused
		}
	}

	// Check for EOF errors
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return DropTypeEOF
	}

	// Check for timeout via net.Error interface
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return DropTypeTimeout
	}

	// String-based classification for wrapped errors
	errStr := strings.ToLower(err.Error())

	// Check for connection reset
	if strings.Contains(errStr, "connection reset") {
		return DropTypeTCPReset
	}

	// Check for connection refused
	if strings.Contains(errStr, "connection refused") {
		return DropTypeRefused
	}

	// Check for TLS/certificate errors
	if strings.Contains(errStr, "tls") ||
		strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "x509") ||
		strings.Contains(errStr, "handshake") {
		return DropTypeTLSAbort
	}

	// Check for timeout errors
	if strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded") {
		return DropTypeTimeout
	}

	// Check for DNS errors
	if strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "dns") ||
		strings.Contains(errStr, "lookup") {
		return DropTypeDNS
	}

	// Default: treat as EOF if we got here with a non-nil error
	return DropTypeEOF
}

// getOrCreateState returns the dropState for a host, creating it if necessary.
func (cm *ConnectionMonitor) getOrCreateState(host string) *dropState {
	cm.mu.RLock()
	state, exists := cm.hostDrops[host]
	cm.mu.RUnlock()

	if exists {
		return state
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Double-check after acquiring write lock
	if state, exists = cm.hostDrops[host]; exists {
		return state
	}

	state = &dropState{}
	cm.hostDrops[host] = state
	return state
}

// calculateRecoveryWait computes exponential backoff based on consecutive drops.
// Base wait is 5 seconds, max is DropDetectRecoveryWindow.
func calculateRecoveryWait(consecutiveDrops int64) time.Duration {
	if consecutiveDrops <= 0 {
		return 0
	}

	// Exponential backoff: 5s * 2^(drops-1)
	baseWait := 5 * time.Second
	multiplier := int64(1) << (consecutiveDrops - 1) // 2^(drops-1)
	wait := time.Duration(int64(baseWait) * multiplier)

	// Cap at recovery window
	if wait > defaults.DropDetectRecoveryWindow {
		return defaults.DropDetectRecoveryWindow
	}
	return wait
}

// RecordDrop records a connection drop for a host and returns the drop result.
func (cm *ConnectionMonitor) RecordDrop(host string, err error) *DropResult {
	dropType := ClassifyError(err)
	if dropType == DropTypeNone {
		return &DropResult{
			Dropped:     false,
			Type:        DropTypeNone,
			Consecutive: 0,
		}
	}

	state := cm.getOrCreateState(host)

	// Update atomic counters
	consecutive := state.consecutiveDrops.Add(1)
	state.totalDrops.Add(1)
	state.lastDropType.Store(int32(dropType))
	state.lastDropTime.Store(time.Now().UnixNano())

	// Reset recovery state on drop
	state.recoverySuccesses.Store(0)
	state.inRecovery.Store(false)

	return &DropResult{
		Dropped:      true,
		Type:         dropType,
		Consecutive:  int(consecutive),
		Error:        err,
		RecoveryWait: calculateRecoveryWait(consecutive),
	}
}

// RecordSuccess records a successful connection for recovery tracking.
func (cm *ConnectionMonitor) RecordSuccess(host string) {
	cm.mu.RLock()
	state, exists := cm.hostDrops[host]
	cm.mu.RUnlock()

	if !exists {
		return
	}

	// If we're in a dropping state, track recovery
	if state.consecutiveDrops.Load() > 0 {
		if !state.inRecovery.Load() {
			state.inRecovery.Store(true)
			state.recoveryStartTime.Store(time.Now().UnixNano())
		}

		successes := state.recoverySuccesses.Add(1)

		// Full recovery after enough successful probes
		if successes >= int64(defaults.DropDetectRecoveryProbes) {
			state.consecutiveDrops.Store(0)
			state.inRecovery.Store(false)
			state.recoverySuccesses.Store(0)
		}
	}
}

// IsDropping returns true if the host is currently in a dropping state.
func (cm *ConnectionMonitor) IsDropping(host string) bool {
	cm.mu.RLock()
	state, exists := cm.hostDrops[host]
	cm.mu.RUnlock()

	if !exists {
		return false
	}

	return state.consecutiveDrops.Load() >= int64(defaults.DropDetectConsecutiveThreshold)
}

// GetDropState returns the current drop state for a host.
func (cm *ConnectionMonitor) GetDropState(host string) *DropResult {
	cm.mu.RLock()
	state, exists := cm.hostDrops[host]
	cm.mu.RUnlock()

	if !exists {
		return &DropResult{
			Dropped:     false,
			Type:        DropTypeNone,
			Consecutive: 0,
		}
	}

	consecutive := state.consecutiveDrops.Load()
	dropType := DropType(state.lastDropType.Load())

	return &DropResult{
		Dropped:      consecutive >= int64(defaults.DropDetectConsecutiveThreshold),
		Type:         dropType,
		Consecutive:  int(consecutive),
		RecoveryWait: calculateRecoveryWait(consecutive),
	}
}

// SetBaseline sets the baseline latency for a host.
func (cm *ConnectionMonitor) SetBaseline(host string, latency time.Duration) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.baselineLatency[host] = latency
}

// CheckTarpit checks if a response latency indicates tarpit behavior.
// Returns a DropResult with DropTypeTarpit if latency exceeds the threshold.
func (cm *ConnectionMonitor) CheckTarpit(host string, latency time.Duration) *DropResult {
	cm.mu.RLock()
	baseline, exists := cm.baselineLatency[host]
	cm.mu.RUnlock()

	if !exists || baseline <= 0 {
		return &DropResult{
			Dropped:     false,
			Type:        DropTypeNone,
			Consecutive: 0,
		}
	}

	// Check if latency exceeds baseline * multiplier
	threshold := time.Duration(float64(baseline) * defaults.DropDetectTimeoutMultiplier)
	if latency > threshold {
		state := cm.getOrCreateState(host)

		// Record as a drop
		consecutive := state.consecutiveDrops.Add(1)
		state.totalDrops.Add(1)
		state.lastDropType.Store(int32(DropTypeTarpit))
		state.lastDropTime.Store(time.Now().UnixNano())

		// Reset recovery state
		state.recoverySuccesses.Store(0)
		state.inRecovery.Store(false)

		return &DropResult{
			Dropped:      true,
			Type:         DropTypeTarpit,
			Consecutive:  int(consecutive),
			RecoveryWait: calculateRecoveryWait(consecutive),
		}
	}

	return &DropResult{
		Dropped:     false,
		Type:        DropTypeNone,
		Consecutive: 0,
	}
}

// Stats returns aggregate statistics for the connection monitor.
func (cm *ConnectionMonitor) Stats() (hostsTracked, totalDrops int) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	hostsTracked = len(cm.hostDrops)
	for _, state := range cm.hostDrops {
		totalDrops += int(state.totalDrops.Load())
	}
	return hostsTracked, totalDrops
}
