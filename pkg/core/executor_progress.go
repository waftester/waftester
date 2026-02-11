package core

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/hosterrors"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/ui"
)

// ExecuteWithProgress runs all payloads with UI progress display
func (e *Executor) ExecuteWithProgress(ctx context.Context, allPayloads []payloads.Payload, writer output.ResultWriter, progress *ui.Progress) output.ExecutionResults {
	results := output.ExecutionResults{
		TotalTests:        len(allPayloads),
		StartTime:         time.Now(),
		StatusCodes:       make(map[int]int),
		SeverityBreakdown: make(map[string]int),
		CategoryBreakdown: make(map[string]int),
		TopErrors:         make([]string, 0),
		EncodingStats:     make(map[string]*output.EncodingEffectiveness),
		OWASPBreakdown:    make(map[string]int),
	}

	// Maps for collecting stats (thread-safe with mutex)
	var statsMu sync.Mutex
	errorCounts := make(map[string]int)

	// Create channels for work distribution
	tasks := make(chan payloads.Payload, e.config.Concurrency*2)
	resultsChan := make(chan *output.TestResult, e.config.Concurrency*2)

	// Atomic counters
	var blocked, passed, failed, errored, skipped int64

	// Death spiral detection: if >80% of the first batch are skipped,
	// the host is unreachable and continuing wastes time.
	const deathSpiralThreshold2 = 50
	var deathSpiralOnce2 sync.Once
	deathSpiralCtx2, deathSpiralCancel2 := context.WithCancel(ctx)
	defer deathSpiralCancel2()

	checkDeathSpiral2 := func() {
		done := atomic.LoadInt64(&blocked) + atomic.LoadInt64(&passed) + atomic.LoadInt64(&failed) + atomic.LoadInt64(&errored) + atomic.LoadInt64(&skipped)
		if done < deathSpiralThreshold2 {
			return
		}
		skip := atomic.LoadInt64(&skipped)
		if float64(skip)/float64(done) > 0.8 {
			deathSpiralOnce2.Do(func() {
				deathSpiralCancel2()
			})
		}
	}

	// Start worker pool
	var wg sync.WaitGroup
	for i := 0; i < e.config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for payload := range tasks {
				select {
				case <-deathSpiralCtx2.Done():
					return
				default:
					// Check skip conditions BEFORE rate limiter to avoid
					// wasting rate-limit tokens on payloads that will be skipped.
					if hosterrors.Check(e.config.TargetURL) {
						result := e.buildSkippedResult(payload, "[HOST_FAILED] Host has exceeded error threshold")
						resultsChan <- result
						progress.Increment(result.Outcome)
						atomic.AddInt64(&skipped, 1)
						checkDeathSpiral2()
						continue
					}
					if e.detector != nil {
						if skip, reason := e.detector.ShouldSkipHost(e.config.TargetURL); skip {
							result := e.buildSkippedResult(payload, fmt.Sprintf("[DETECTION] %s", reason))
							resultsChan <- result
							progress.Increment(result.Outcome)
							atomic.AddInt64(&skipped, 1)
							checkDeathSpiral2()
							continue
						}
					}

					// Rate limit
					e.limiter.Wait(deathSpiralCtx2)

					// Execute test
					result := e.executeTest(ctx, payload)
					resultsChan <- result

					// Update progress
					progress.Increment(result.Outcome)

					// Update atomic counters for final stats
					switch result.Outcome {
					case "Blocked":
						atomic.AddInt64(&blocked, 1)
					case "Pass":
						atomic.AddInt64(&passed, 1)
					case "Fail":
						atomic.AddInt64(&failed, 1)
					case "Error":
						atomic.AddInt64(&errored, 1)
					case "Skipped":
						atomic.AddInt64(&skipped, 1)
					}
				}
			}
		}(i)
	}

	// Result collector goroutine - also collects stats
	var collectorWg sync.WaitGroup
	var filteredCount int64
	var latencies []int64
	var bypassDetails []output.BypassDetail
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for result := range resultsChan {
			// Skip filtered results (don't write to output)
			if result.Filtered {
				atomic.AddInt64(&filteredCount, 1)
				continue
			}

			writer.Write(result)

			// Call OnResult callback for real-time streaming to hooks
			// This enables Slack/Teams/PagerDuty/OTEL notifications as results come in
			if e.config.OnResult != nil {
				e.config.OnResult(result)
			}

			// Collect stats (thread-safe)
			statsMu.Lock()
			results.StatusCodes[result.StatusCode]++
			results.SeverityBreakdown[result.Severity]++
			results.CategoryBreakdown[result.Category]++
			if result.ErrorMessage != "" {
				errorCounts[result.ErrorMessage]++
			}
			// Collect latencies for percentile calculation
			latencies = append(latencies, result.LatencyMs)

			// Track encoding effectiveness
			encoding := result.EncodingUsed
			if encoding == "" {
				encoding = "raw" // Default for unencoded payloads
			}
			if results.EncodingStats[encoding] == nil {
				results.EncodingStats[encoding] = &output.EncodingEffectiveness{Name: encoding}
			}
			stats := results.EncodingStats[encoding]
			stats.TotalTests++
			if result.Outcome == "Fail" {
				stats.Bypasses++
			} else if result.Outcome == "Blocked" {
				stats.BlockedTests++
			}

			// Track OWASP category
			category := strings.ToLower(result.Category)
			if mapping, ok := output.OWASPMapping[category]; ok {
				results.OWASPBreakdown[mapping.OWASP]++
			}

			// Track bypasses (Fail = attack got through)
			if result.Outcome == "Fail" {
				bypassDetails = append(bypassDetails, output.BypassDetail{
					PayloadID:   result.ID,
					Payload:     result.Payload,
					Endpoint:    result.TargetPath,
					Method:      result.Method,
					StatusCode:  result.StatusCode,
					CurlCommand: result.CurlCommand,
					Category:    result.Category,
					Severity:    result.Severity,
				})
			}
			statsMu.Unlock()
		}
	}()

	// Send all payloads to workers
sendLoop2:
	for _, payload := range allPayloads {
		select {
		case <-deathSpiralCtx2.Done():
			break sendLoop2
		case tasks <- payload:
		}
	}
	close(tasks)

	// Wait for workers to complete
	wg.Wait()
	close(resultsChan)

	// Wait for collector
	collectorWg.Wait()

	// Calculate latency percentiles
	if len(latencies) > 0 {
		// Sort latencies for percentile calculation
		sortedLatencies := make([]int64, len(latencies))
		copy(sortedLatencies, latencies)
		// Efficient O(n log n) sort
		sort.Slice(sortedLatencies, func(i, j int) bool {
			return sortedLatencies[i] < sortedLatencies[j]
		})

		results.LatencyStats.Min = sortedLatencies[0]
		results.LatencyStats.Max = sortedLatencies[len(sortedLatencies)-1]

		// Calculate average
		var sum int64
		for _, l := range sortedLatencies {
			sum += l
		}
		results.LatencyStats.Avg = sum / int64(len(sortedLatencies))

		// Percentiles
		results.LatencyStats.P50 = sortedLatencies[len(sortedLatencies)*50/100]
		results.LatencyStats.P95 = sortedLatencies[len(sortedLatencies)*95/100]
		p99Idx := len(sortedLatencies) * 99 / 100
		if p99Idx >= len(sortedLatencies) {
			p99Idx = len(sortedLatencies) - 1
		}
		results.LatencyStats.P99 = sortedLatencies[p99Idx]
	}

	// Calculate encoding bypass rates
	for _, stats := range results.EncodingStats {
		if stats.TotalTests > 0 {
			stats.BypassRate = float64(stats.Bypasses) / float64(stats.TotalTests) * 100
		}
	}

	// Store bypass details
	results.BypassDetails = bypassDetails
	for _, bypass := range bypassDetails {
		results.BypassPayloads = append(results.BypassPayloads, bypass.Payload)
	}

	// Final stats
	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)
	results.BlockedTests = int(atomic.LoadInt64(&blocked))
	results.PassedTests = int(atomic.LoadInt64(&passed))
	results.FailedTests = int(atomic.LoadInt64(&failed))
	results.ErrorTests = int(atomic.LoadInt64(&errored))
	results.HostsSkipped = int(atomic.LoadInt64(&skipped))
	if results.Duration.Seconds() > 0 {
		results.RequestsPerSec = float64(results.TotalTests) / results.Duration.Seconds()
	}

	// Populate top errors (sorted by frequency)
	type errCount struct {
		msg   string
		count int
	}
	errList := make([]errCount, 0, len(errorCounts))
	for msg, count := range errorCounts {
		errList = append(errList, errCount{msg, count})
	}
	// Sort by count descending using efficient O(n log n) sort
	sort.Slice(errList, func(i, j int) bool {
		return errList[i].count > errList[j].count
	})
	// Take top 5
	for i := 0; i < len(errList) && i < 5; i++ {
		results.TopErrors = append(results.TopErrors, fmt.Sprintf("%s (%d)", errList[i].msg, errList[i].count))
	}

	return results
}
