//go:build ignore

// This program generates baseline HTML reports for visual regression testing.
// Run with: go run generate_baseline.go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
	"github.com/waftester/waftester/pkg/output/writers"
)

func main() {
	if err := generateBaselines(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ All baseline files generated successfully")
}

func generateBaselines() error {
	start := time.Now()

	// Generate empty report (0 findings)
	if err := generateReport("baseline_empty.html", 0); err != nil {
		return fmt.Errorf("empty report: %w", err)
	}

	// Generate small report (~50 findings)
	if err := generateReport("baseline_small.html", 50); err != nil {
		return fmt.Errorf("small report: %w", err)
	}

	// Generate large report (500 findings)
	largeStart := time.Now()
	if err := generateReport("baseline_large.html", 500); err != nil {
		return fmt.Errorf("large report: %w", err)
	}
	largeDuration := time.Since(largeStart)

	totalDuration := time.Since(start)

	// Generate metrics JSON
	metrics := map[string]interface{}{
		"generated_at": time.Now().Format(time.RFC3339),
		"files": map[string]interface{}{
			"baseline_empty.html": getFileStats("baseline_empty.html"),
			"baseline_small.html": getFileStats("baseline_small.html"),
			"baseline_large.html": getFileStats("baseline_large.html"),
		},
		"performance": map[string]interface{}{
			"large_report_generation_ms": largeDuration.Milliseconds(),
			"total_generation_ms":        totalDuration.Milliseconds(),
		},
	}

	metricsJSON, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metrics: %w", err)
	}

	if err := os.WriteFile("baseline_metrics.json", metricsJSON, 0644); err != nil {
		return fmt.Errorf("write metrics: %w", err)
	}

	fmt.Printf("Generated metrics: large report in %v\n", largeDuration)
	return nil
}

func generateReport(filename string, numFindings int) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := writers.NewHTMLWriter(f, writers.HTMLConfig{
		Title:                "WAFtester Baseline Report",
		Theme:                "auto",
		IncludeEvidence:      true,
		IncludeJSON:          true,
		ShowExecutiveSummary: true,
	})

	// Write findings
	categories := []string{"sqli", "xss", "ssti", "lfi", "rce"}
	severities := []events.Severity{events.SeverityCritical, events.SeverityHigh, events.SeverityMedium, events.SeverityLow}
	outcomes := []events.Outcome{events.OutcomeBypass, events.OutcomeBlocked, events.OutcomeError}

	for i := 0; i < numFindings; i++ {
		cat := categories[i%len(categories)]
		sev := severities[i%len(severities)]
		outcome := outcomes[i%len(outcomes)]

		e := &events.ResultEvent{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeResult,
				Time: time.Now(),
				Scan: "baseline-scan-001",
			},
			Test: events.TestInfo{
				ID:       fmt.Sprintf("%s-%03d", cat, i),
				Name:     fmt.Sprintf("%s test %d", cat, i),
				Category: cat,
				Severity: sev,
				OWASP:    []string{"A03:2021"},
				CWE:      []int{89},
			},
			Target: events.TargetInfo{
				URL:    fmt.Sprintf("https://example.com/api/v1/%s/%d", cat, i),
				Method: "POST",
			},
			Result: events.ResultInfo{
				Outcome:    outcome,
				StatusCode: 200,
				LatencyMs:  float64(10 + i%100),
			},
			Evidence: &events.Evidence{
				Payload:         fmt.Sprintf("' OR 1=1 -- payload-%d", i),
				CurlCommand:     fmt.Sprintf("curl -X POST 'https://example.com/api' -d 'id=%d'", i),
				ResponsePreview: fmt.Sprintf("<html>Response for test %d</html>", i),
			},
		}

		if err := w.Write(e); err != nil {
			return fmt.Errorf("write event %d: %w", i, err)
		}
	}

	return w.Close()
}

func getFileStats(filename string) map[string]interface{} {
	info, err := os.Stat(filename)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	// Count lines
	content, _ := os.ReadFile(filename)
	lines := 1
	for _, b := range content {
		if b == '\n' {
			lines++
		}
	}

	return map[string]interface{}{
		"size_bytes": info.Size(),
		"size_kb":    float64(info.Size()) / 1024,
		"lines":      lines,
	}
}
