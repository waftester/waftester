package hooks

import (
	"context"
	"log/slog"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/history"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Hook = (*HistoryHook)(nil)

// HistoryHook saves scan results to a historical store for trend analysis.
// It listens for SummaryEvent and creates a permanent record.
type HistoryHook struct {
	store  *history.Store
	tags   []string
	logger *slog.Logger
}

// HistoryHookOptions configures the history hook.
type HistoryHookOptions struct {
	// StorePath is the directory where historical data is stored.
	StorePath string

	// Tags are user-defined labels to attach to each scan record.
	Tags []string

	// Logger for structured logging (default: slog.Default()).
	Logger *slog.Logger
}

// NewHistoryHook creates a new history hook.
func NewHistoryHook(opts HistoryHookOptions) (*HistoryHook, error) {
	store, err := history.NewStore(opts.StorePath)
	if err != nil {
		return nil, err
	}

	return &HistoryHook{
		store:  store,
		tags:   opts.Tags,
		logger: orDefault(opts.Logger),
	}, nil
}

// OnEvent processes events and saves scan results to history.
// Only SummaryEvent is processed to create a complete record.
func (h *HistoryHook) OnEvent(ctx context.Context, event events.Event) error {
	summary, ok := event.(*events.SummaryEvent)
	if !ok {
		return nil
	}

	record := h.buildRecord(summary)
	if err := h.store.Save(record); err != nil {
		h.logger.Warn("failed to save scan record", slog.String("error", err.Error()))
		return nil
	}

	h.logger.Info("saved scan record", slog.String("id", record.ID), slog.String("target", record.TargetURL))
	return nil
}

// EventTypes returns the event types this hook handles.
func (h *HistoryHook) EventTypes() []events.EventType {
	return []events.EventType{
		events.EventTypeSummary,
	}
}

// buildRecord creates a ScanRecord from a SummaryEvent.
func (h *HistoryHook) buildRecord(summary *events.SummaryEvent) *history.ScanRecord {
	// Generate unique ID
	scanID := summary.ScanID()
	if scanID == "" {
		scanID = time.Now().Format("20060102-150405")
	}

	// Build category scores map
	categoryScores := make(map[string]float64)
	for cat, stats := range summary.Breakdown.ByCategory {
		categoryScores[cat] = stats.BlockRate
	}

	return &history.ScanRecord{
		ID:                 scanID,
		Timestamp:          summary.Timestamp(),
		TargetURL:          summary.Target.URL,
		WAFVendor:          summary.Target.WAFDetected,
		Grade:              summary.Effectiveness.Grade,
		DetectionRate:      summary.Effectiveness.BlockRatePct,
		BypassCount:        summary.Totals.Bypasses,
		FalsePositiveCount: 0, // Not tracked in SummaryEvent
		TotalTests:         summary.Totals.Tests,
		BlockedTests:       summary.Totals.Blocked,
		PassedTests:        summary.Totals.Passes,
		Duration:           int64(summary.Timing.DurationSec * 1000),
		AvgLatencyMs:       int(summary.Latency.AvgMs),
		P95LatencyMs:       int(summary.Latency.P95Ms),
		CategoryScores:     categoryScores,
		Version:            defaults.Version,
		Tags:               h.tags,
		Notes:              "",
	}
}
