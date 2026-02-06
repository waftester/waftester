// Package writers provides output writers for various formats.
package writers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/output/dispatcher"
	"github.com/waftester/waftester/pkg/output/events"
)

// Compile-time interface check.
var _ dispatcher.Writer = (*ElasticsearchWriter)(nil)

// ElasticsearchWriter sends events to Elasticsearch using the Bulk API.
// It batches events and sends them when the batch size is reached or on Flush/Close.
type ElasticsearchWriter struct {
	config     ElasticsearchConfig
	httpClient *http.Client
	buffer     []events.Event
	mu         sync.Mutex
}

// ElasticsearchConfig configures the Elasticsearch output.
type ElasticsearchConfig struct {
	// URL is the Elasticsearch URL (e.g., "http://localhost:9200")
	URL string

	// Index is the index name to write to (default: "waftester-YYYY.MM.DD")
	Index string

	// Username for basic auth (optional)
	Username string

	// Password for basic auth (optional)
	Password string

	// APIKey for API key authentication (optional, takes precedence over basic auth)
	APIKey string

	// BatchSize is the number of events to buffer before bulk insert (default: 100)
	BatchSize int

	// Timeout for API requests (default: 30s)
	Timeout time.Duration

	// Pipeline is the ingest pipeline to use (optional)
	Pipeline string

	// InsecureSkipVerify skips TLS verification (default: false)
	InsecureSkipVerify bool
}

// NewElasticsearchWriter creates a new Elasticsearch bulk writer.
func NewElasticsearchWriter(cfg ElasticsearchConfig) *ElasticsearchWriter {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = httpclient.TimeoutFuzzing
	}
	if cfg.Index == "" {
		cfg.Index = fmt.Sprintf("waftester-%s", time.Now().Format("2006.01.02"))
	}

	return &ElasticsearchWriter{
		config: cfg,
		httpClient: httpclient.New(httpclient.Config{
			Timeout:            cfg.Timeout,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}),
		buffer: make([]events.Event, 0, cfg.BatchSize),
	}
}

// SupportsEvent returns true for all event types.
func (ew *ElasticsearchWriter) SupportsEvent(eventType events.EventType) bool {
	return true
}

// Write buffers an event for bulk insert.
// When the batch size is reached, events are automatically flushed.
func (ew *ElasticsearchWriter) Write(event events.Event) error {
	ew.mu.Lock()
	ew.buffer = append(ew.buffer, event)
	shouldFlush := len(ew.buffer) >= ew.config.BatchSize

	if shouldFlush {
		eventsToSend := ew.buffer
		ew.buffer = make([]events.Event, 0, ew.config.BatchSize)
		ew.mu.Unlock()
		return ew.bulkInsert(context.Background(), eventsToSend)
	}

	ew.mu.Unlock()
	return nil
}

// Flush sends all buffered events to Elasticsearch.
func (ew *ElasticsearchWriter) Flush() error {
	ew.mu.Lock()
	if len(ew.buffer) == 0 {
		ew.mu.Unlock()
		return nil
	}
	eventsToSend := ew.buffer
	ew.buffer = make([]events.Event, 0, ew.config.BatchSize)
	ew.mu.Unlock()

	return ew.bulkInsert(context.Background(), eventsToSend)
}

// Close flushes remaining events and closes the writer.
func (ew *ElasticsearchWriter) Close() error {
	return ew.Flush()
}

// bulkInsert sends events using the Elasticsearch Bulk API.
func (ew *ElasticsearchWriter) bulkInsert(ctx context.Context, evts []events.Event) error {
	if len(evts) == 0 {
		return nil
	}

	var buf bytes.Buffer

	for _, evt := range evts {
		// Write action line (index operation)
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": ew.config.Index,
			},
		}
		actionBytes, err := json.Marshal(action)
		if err != nil {
			return fmt.Errorf("elasticsearch: marshal action: %w", err)
		}
		buf.Write(actionBytes)
		buf.WriteByte('\n')

		// Write document with additional metadata
		doc := ew.eventToDocument(evt)
		docBytes, err := json.Marshal(doc)
		if err != nil {
			return fmt.Errorf("elasticsearch: marshal document: %w", err)
		}
		buf.Write(docBytes)
		buf.WriteByte('\n')
	}

	// Build URL
	url := strings.TrimSuffix(ew.config.URL, "/") + "/_bulk"
	if ew.config.Pipeline != "" {
		url += "?pipeline=" + ew.config.Pipeline
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("elasticsearch: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	ew.setAuth(req)

	resp, err := ew.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("elasticsearch: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("elasticsearch: bulk insert failed (%d): %s", resp.StatusCode, string(body))
	}

	// Check for partial failures
	var bulkResp bulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
		return fmt.Errorf("elasticsearch: decode response: %w", err)
	}

	if bulkResp.Errors {
		// Count failures
		var failures int
		for _, item := range bulkResp.Items {
			if item.Index.Error != nil {
				failures++
			}
		}
		return fmt.Errorf("elasticsearch: %d/%d documents failed to index", failures, len(evts))
	}

	return nil
}

// eventToDocument converts an event to an Elasticsearch document.
func (ew *ElasticsearchWriter) eventToDocument(evt events.Event) map[string]interface{} {
	doc := map[string]interface{}{
		"@timestamp": evt.Timestamp().Format(time.RFC3339Nano),
		"event_type": string(evt.EventType()),
		"scan_id":    evt.ScanID(),
		"tool":       defaults.ToolName,
	}

	// Type assert for specific event types to extract payload data
	switch e := evt.(type) {
	case *events.ResultEvent:
		doc["result"] = map[string]interface{}{
			"id":          e.Test.ID,
			"outcome":     string(e.Result.Outcome),
			"severity":    string(e.Test.Severity),
			"category":    e.Test.Category,
			"status_code": e.Result.StatusCode,
			"latency_ms":  e.Result.LatencyMs,
			"request_url": e.Target.URL,
			"blocked":     e.Result.Outcome == events.OutcomeBlocked,
			"bypassed":    e.Result.Outcome == events.OutcomePass,
			"confidence":  string(e.Result.Confidence),
		}
		if e.Evidence != nil {
			doc["payload"] = e.Evidence.Payload
		}
	case *events.SummaryEvent:
		doc["summary"] = map[string]interface{}{
			"target":         e.Target.URL,
			"total_requests": e.Totals.Tests,
			"blocked":        e.Totals.Blocked,
			"bypassed":       e.Totals.Bypasses,
			"errors":         e.Totals.Errors,
			"block_rate":     e.Effectiveness.BlockRatePct,
			"grade":          e.Effectiveness.Grade,
		}
	case *events.ProgressEvent:
		doc["progress"] = map[string]interface{}{
			"current":    e.Progress.Current,
			"total":      e.Progress.Total,
			"percentage": e.Progress.Percentage,
			"phase":      e.Progress.Phase,
		}
	}

	return doc
}

// setAuth sets authentication headers on the request.
func (ew *ElasticsearchWriter) setAuth(req *http.Request) {
	if ew.config.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+ew.config.APIKey)
	} else if ew.config.Username != "" && ew.config.Password != "" {
		req.SetBasicAuth(ew.config.Username, ew.config.Password)
	}
}

// bulkResponse is the Elasticsearch bulk API response.
type bulkResponse struct {
	Took   int  `json:"took"`
	Errors bool `json:"errors"`
	Items  []struct {
		Index struct {
			ID     string                 `json:"_id"`
			Result string                 `json:"result"`
			Status int                    `json:"status"`
			Error  map[string]interface{} `json:"error,omitempty"`
		} `json:"index"`
	} `json:"items"`
}

// TestConnection verifies the Elasticsearch connection.
func (ew *ElasticsearchWriter) TestConnection(ctx context.Context) error {
	url := strings.TrimSuffix(ew.config.URL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("elasticsearch: create request: %w", err)
	}

	ew.setAuth(req)

	resp, err := ew.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("elasticsearch: connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("elasticsearch: health check failed (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}
