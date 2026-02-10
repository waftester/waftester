package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	detectionoutput "github.com/waftester/waftester/pkg/output/detection"
	"github.com/waftester/waftester/pkg/ui"
)

// LatencyStats holds latency distribution statistics
type LatencyStats struct {
	Min int64 `json:"min_ms"`
	Max int64 `json:"max_ms"`
	Avg int64 `json:"avg_ms"`
	P50 int64 `json:"p50_ms"`
	P95 int64 `json:"p95_ms"`
	P99 int64 `json:"p99_ms"`
}

// ExecutionResults holds aggregate results from test execution
type ExecutionResults struct {
	TotalTests     int
	PassedTests    int
	BlockedTests   int
	FailedTests    int
	ErrorTests     int
	StartTime      time.Time
	EndTime        time.Time
	Duration       time.Duration
	RequestsPerSec float64
	// Enhanced stats (nuclei-style)
	StatusCodes       map[int]int    // Count by status code
	SeverityBreakdown map[string]int // Count by severity
	CategoryBreakdown map[string]int // Count by category
	TopErrors         []string       // Most common errors
	// Latency statistics
	Latencies    []int64      `json:"-"` // Raw latencies for percentile calculation
	LatencyStats LatencyStats `json:"latency_stats"`
	// Bypass tracking
	BypassPayloads []string       `json:"bypass_payloads,omitempty"`
	BypassDetails  []BypassDetail `json:"bypass_details,omitempty"`
	EndpointStats  map[string]int `json:"endpoint_stats,omitempty"` // endpoint → blocked count
	MethodStats    map[string]int `json:"method_stats,omitempty"`   // method → blocked count
	// Encoding effectiveness tracking
	EncodingStats map[string]*EncodingEffectiveness `json:"encoding_stats,omitempty"`
	// OWASP category breakdown
	OWASPBreakdown map[string]int `json:"owasp_breakdown,omitempty"` // A01:2021 → count
	// Detection statistics (v2.5.2)
	DropsDetected  int            `json:"drops_detected,omitempty"`
	BansDetected   int            `json:"bans_detected,omitempty"`
	HostsSkipped   int            `json:"hosts_skipped,omitempty"`
	DetectionStats map[string]int `json:"detection_stats,omitempty"`
}

// EncodingEffectiveness tracks how well each encoding evades the WAF
type EncodingEffectiveness struct {
	Name         string  `json:"name"`
	TotalTests   int     `json:"total_tests"`
	Bypasses     int     `json:"bypasses"`
	BypassRate   float64 `json:"bypass_rate_pct"`
	BlockedTests int     `json:"blocked_tests"`
}

// BypassDetail contains full information about a detected bypass
type BypassDetail struct {
	PayloadID   string `json:"payload_id"`
	Payload     string `json:"payload"`
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	StatusCode  int    `json:"status_code"`
	CurlCommand string `json:"curl_command"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
}

// JSONWriter writes results as JSON array
type JSONWriter struct {
	file    *os.File
	results []*TestResult
	mu      sync.Mutex
}

// JSONLWriter writes results as newline-delimited JSON
type JSONLWriter struct {
	file *os.File
	mu   sync.Mutex
}

// SARIFWriter writes results in SARIF 2.1.0 format for GitHub
type SARIFWriter struct {
	file    *os.File
	results []*TestResult
	mu      sync.Mutex
}

// ConsoleWriter writes results to terminal with colors
type ConsoleWriter struct {
	verbose       bool
	showTimestamp bool
	silent        bool
	target        string
	mu            sync.Mutex
}

// CSVWriter writes results as CSV (ffuf/httpx style)
type CSVWriter struct {
	file   *os.File
	writer *csv.Writer
	mu     sync.Mutex
}

// MarkdownWriter writes results as Markdown table (nuclei style)
type MarkdownWriter struct {
	file    *os.File
	results []*TestResult
	mu      sync.Mutex
}

// HTMLWriter writes results as interactive HTML report (ffuf-style DataTables)
type HTMLWriter struct {
	file    *os.File
	results []*TestResult
	mu      sync.Mutex
}

// WriterOptions configures writer behavior
type WriterOptions struct {
	Verbose       bool
	ShowTimestamp bool
	Silent        bool
	Target        string
}

// NewWriter creates the appropriate writer based on format
func NewWriter(outputFile, format string) (ResultWriter, error) {
	return NewWriterWithOptions(outputFile, format, WriterOptions{Verbose: false, ShowTimestamp: false})
}

// NewWriterWithOptions creates a writer with custom options
func NewWriterWithOptions(outputFile, format string, opts WriterOptions) (ResultWriter, error) {
	// Validate that md/html formats require an output file (they look bad in terminal)
	if (format == "md" || format == "markdown" || format == "html") && outputFile == "" {
		return nil, fmt.Errorf("%s format requires an output file (-o filename.%s)", format, format)
	}

	switch format {
	case "json":
		return newJSONWriter(outputFile)
	case "jsonl":
		return newJSONLWriter(outputFile)
	case "sarif":
		return newSARIFWriter(outputFile)
	case "csv":
		return newCSVWriter(outputFile)
	case "md", "markdown":
		return newMarkdownWriter(outputFile)
	case "html":
		return newHTMLWriter(outputFile)
	case "console":
		return &ConsoleWriter{verbose: opts.Verbose, showTimestamp: opts.ShowTimestamp, silent: opts.Silent, target: opts.Target}, nil
	default:
		return &ConsoleWriter{verbose: opts.Verbose, showTimestamp: opts.ShowTimestamp, silent: opts.Silent, target: opts.Target}, nil
	}
}

func newJSONWriter(path string) (*JSONWriter, error) {
	if path == "" {
		return &JSONWriter{file: os.Stdout}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &JSONWriter{file: file, results: make([]*TestResult, 0)}, nil
}

func (w *JSONWriter) Write(result *TestResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = append(w.results, result)
	return nil
}

func (w *JSONWriter) Close() (retErr error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != os.Stdout {
		defer func() {
			if err := w.file.Close(); err != nil && retErr == nil {
				retErr = err
			}
		}()
	}

	encoder := json.NewEncoder(w.file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(w.results); err != nil {
		return err
	}

	return nil
}

func newJSONLWriter(path string) (*JSONLWriter, error) {
	if path == "" {
		return &JSONLWriter{file: os.Stdout}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &JSONLWriter{file: file}, nil
}

func (w *JSONLWriter) Write(result *TestResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w.file, "%s\n", data)
	return err
}

func (w *JSONLWriter) Close() error {
	if w.file != os.Stdout {
		return w.file.Close()
	}
	return nil
}

func (w *ConsoleWriter) Write(result *TestResult) error {
	// Silent mode - no output
	if w.silent {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// In verbose mode, print all results with nuclei-style formatting
	if w.verbose {
		ui.PrintResult(result.ID, result.Category, result.Severity, result.Outcome,
			result.StatusCode, result.LatencyMs, w.target, w.showTimestamp)
		return nil
	}

	// In non-verbose mode, only print failures and errors
	if result.Outcome == "Blocked" || result.Outcome == "Pass" {
		return nil
	}

	switch result.Outcome {
	case "Fail":
		fmt.Fprintf(os.Stderr, "\033[31m[FAIL] %s - %s (Status: %d)\033[0m\n", result.ID, result.Category, result.StatusCode)
	case "Error":
		fmt.Fprintf(os.Stderr, "\033[33m[ERR]  %s - %s: %s\033[0m\n", result.ID, result.Category, result.ErrorMessage)
	}
	return nil
}

func (w *ConsoleWriter) Close() error {
	return nil
}

// PrintSummary prints the final execution summary
func PrintSummary(results ExecutionResults) {
	separator := strings.Repeat("═", 60)
	fmt.Println("\n" + separator)
	fmt.Println("                    WAF SECURITY TEST SUMMARY")
	fmt.Println(separator)

	fmt.Printf("\n  Total Tests:     %d\n", results.TotalTests)

	// Helper to safely calculate percentage
	pct := func(part, total int) float64 {
		if total == 0 {
			return 0
		}
		return float64(part) / float64(total) * 100
	}

	// Blocked = good (WAF working)
	fmt.Printf("\033[32m  ✓ Blocked:       %d (%.1f%%)\033[0m\n",
		results.BlockedTests,
		pct(results.BlockedTests, results.TotalTests))

	// Pass = safe endpoints
	fmt.Printf("\033[36m  ○ Pass:          %d (%.1f%%)\033[0m\n",
		results.PassedTests,
		pct(results.PassedTests, results.TotalTests))

	// Fail = vulnerabilities!
	if results.FailedTests > 0 {
		fmt.Printf("\033[31m  ✗ FAIL:          %d (%.1f%%)\033[0m\n",
			results.FailedTests,
			pct(results.FailedTests, results.TotalTests))
	} else {
		fmt.Printf("  ✗ Fail:          0 (0.0%%)\n")
	}

	// Errors
	if results.ErrorTests > 0 {
		fmt.Printf("\033[33m  ! Errors:        %d\033[0m\n", results.ErrorTests)
	}

	// Skipped (host unreachable / death spiral)
	if results.HostsSkipped > 0 {
		fmt.Printf("\033[36m  ⏭ Skipped:       %d (host unreachable)\033[0m\n", results.HostsSkipped)
	}

	fmt.Printf("\n  Duration:        %s\n", results.Duration.Round(time.Millisecond))
	fmt.Printf("  Throughput:      %.1f req/sec\n", results.RequestsPerSec)

	// Nuclei-style: Top Status Codes
	if len(results.StatusCodes) > 0 {
		fmt.Println("\n" + strings.Repeat("─", 40))
		fmt.Println("\033[1;34m  Top Status Codes:\033[0m")
		for code, count := range results.StatusCodes {
			var codeANSI string
			switch {
			case code >= 200 && code < 300:
				codeANSI = "\033[32m"
			case code >= 300 && code < 400:
				codeANSI = "\033[34m"
			case code >= 400 && code < 500:
				codeANSI = "\033[33m"
			case code >= 500:
				codeANSI = "\033[31m"
			default:
				codeANSI = "\033[37m"
			}
			fmt.Printf("%s    %d: %d\033[0m\n", codeANSI, code, count)
		}
	}

	// Severity breakdown
	if len(results.SeverityBreakdown) > 0 {
		fmt.Println("\n" + strings.Repeat("─", 40))
		fmt.Println("\033[1;35m  Severity Breakdown:\033[0m")
		severityOrder := []string{"Critical", "High", "Medium", "Low", "Info"}
		for _, sev := range severityOrder {
			if count, ok := results.SeverityBreakdown[sev]; ok && count > 0 {
				var sevANSI string
				switch sev {
				case "Critical":
					sevANSI = "\033[1;31m"
				case "High":
					sevANSI = "\033[91m"
				case "Medium":
					sevANSI = "\033[33m"
				case "Low":
					sevANSI = "\033[32m"
				case "Info":
					sevANSI = "\033[36m"
				default:
					sevANSI = "\033[37m"
				}
				fmt.Printf("%s    %s: %d\033[0m\n", sevANSI, sev, count)
			}
		}
	}

	// Top Errors (if any)
	if len(results.TopErrors) > 0 {
		fmt.Println("\n" + strings.Repeat("─", 40))
		fmt.Println("\033[1;31m  Top Errors:\033[0m")
		for i, err := range results.TopErrors {
			if i >= 5 {
				break
			}
			fmt.Printf("\033[33m    • %s\033[0m\n", err)
		}
	}

	// Detection stats (v2.5.2 - using unified detection output package)
	detStats := detectionoutput.Stats{
		DropsDetected: results.DropsDetected,
		BansDetected:  results.BansDetected,
		HostsSkipped:  results.HostsSkipped,
	}
	if detStats.HasData() {
		detStats.PrintConsole()
	}

	fmt.Println("\n" + strings.Repeat("═", 60))

	// WAF effectiveness = Blocked / (Blocked + Failed)
	// This measures what % of attack payloads were stopped by the WAF
	attackTests := results.BlockedTests + results.FailedTests
	if attackTests > 0 {
		blockRate := float64(results.BlockedTests) / float64(attackTests) * 100
		if blockRate >= 95 {
			fmt.Printf("\033[32m  WAF Effectiveness: %.1f%% - EXCELLENT\033[0m\n", blockRate)
		} else if blockRate >= 80 {
			fmt.Printf("\033[33m  WAF Effectiveness: %.1f%% - GOOD\033[0m\n", blockRate)
		} else {
			fmt.Printf("\033[31m  WAF Effectiveness: %.1f%% - NEEDS ATTENTION\033[0m\n", blockRate)
		}
	}
	fmt.Println()
}

// SARIF Writer implementation

func newSARIFWriter(path string) (*SARIFWriter, error) {
	if path == "" {
		return &SARIFWriter{file: os.Stdout}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &SARIFWriter{file: file, results: make([]*TestResult, 0)}, nil
}

func (w *SARIFWriter) Write(result *TestResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = append(w.results, result)
	return nil
}

func (w *SARIFWriter) Close() (retErr error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != os.Stdout {
		defer func() {
			if err := w.file.Close(); err != nil && retErr == nil {
				retErr = err
			}
		}()
	}

	sarif := w.buildSARIF()
	encoder := json.NewEncoder(w.file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sarif); err != nil {
		return err
	}

	return nil
}

// SARIF structures
type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationUri string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	HelpUri          string              `json:"helpUri,omitempty"`
	DefaultConfig    sarifRuleConfig     `json:"defaultConfiguration"`
	Properties       sarifRuleProps      `json:"properties"`
	Relationships    []sarifRelationship `json:"relationships,omitempty"`
}

type sarifRelationship struct {
	Target struct {
		ID            string `json:"id"`
		ToolComponent struct {
			Name string `json:"name"`
		} `json:"toolComponent"`
	} `json:"target"`
	Kinds []string `json:"kinds"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
	CWE              []string `json:"cwe,omitempty"`
	OWASP            string   `json:"owasp,omitempty"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifMessage      `json:"message"`
	Locations    []sarifLocation   `json:"locations"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	Properties   sarifResultProps  `json:"properties,omitempty"`
}

type sarifResultProps struct {
	CurlCommand         string   `json:"curlCommand,omitempty"`
	ResponseBodySnippet string   `json:"responseBodySnippet,omitempty"`
	EvidenceMarkers     []string `json:"evidenceMarkers,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLoc `json:"physicalLocation"`
}

type sarifPhysicalLoc struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func (w *SARIFWriter) buildSARIF() sarifDocument {
	severityMap := map[string]string{
		"Critical": "error",
		"High":     "error",
		"Medium":   "warning",
		"Low":      "note",
	}

	securityScore := map[string]string{
		"Critical": "9.5",
		"High":     "7.5",
		"Medium":   "5.0",
		"Low":      "2.5",
	}

	rules := make(map[string]sarifRule)
	var results []sarifResult

	for _, r := range w.results {
		// Only add failed/error results
		if r.Outcome != "Fail" && r.Outcome != "Error" {
			continue
		}

		// Build rule if not exists
		if _, exists := rules[r.ID]; !exists {
			// Look up OWASP/CWE mapping
			category := strings.ToLower(r.Category)
			var cweList []string
			var owaspID string
			if mapping, ok := OWASPMapping[category]; ok {
				cweList = mapping.CWE
				owaspID = mapping.OWASP
			}

			// Build tags including OWASP and CWE
			tags := []string{r.Category, r.Severity}
			if owaspID != "" {
				tags = append(tags, owaspID)
			}
			for _, cwe := range cweList {
				tags = append(tags, cwe)
			}

			rule := sarifRule{
				ID:   r.ID,
				Name: r.ID,
				ShortDescription: sarifMessage{
					Text: fmt.Sprintf("%s security test", r.Category),
				},
				FullDescription: sarifMessage{
					Text: fmt.Sprintf("Tests WAF protection against %s attacks. OWASP: %s", r.Category, owaspID),
				},
				DefaultConfig: sarifRuleConfig{
					Level: severityMap[r.Severity],
				},
				Properties: sarifRuleProps{
					Tags:             tags,
					SecuritySeverity: securityScore[r.Severity],
					CWE:              cweList,
					OWASP:            owaspID,
				},
			}

			// Add CWE relationships
			for _, cwe := range cweList {
				rel := sarifRelationship{
					Kinds: []string{"superset"},
				}
				rel.Target.ID = cwe
				rel.Target.ToolComponent.Name = "CWE"
				rule.Relationships = append(rule.Relationships, rel)
			}

			rules[r.ID] = rule
		}

		// Build result with enhanced details
		msg := fmt.Sprintf("WAF bypass detected: %s attack payload was not blocked (status: %d)", r.Category, r.StatusCode)
		if r.Outcome == "Error" {
			msg = r.ErrorMessage
		}

		// Create fingerprint for deduplication
		fingerprints := make(map[string]string)
		if r.ResponseBodyHash != "" {
			fingerprints["responseHash/v1"] = r.ResponseBodyHash
		}

		result := sarifResult{
			RuleID:       r.ID,
			Level:        severityMap[r.Severity],
			Message:      sarifMessage{Text: msg},
			Fingerprints: fingerprints,
			Properties: sarifResultProps{
				CurlCommand:         r.CurlCommand,
				ResponseBodySnippet: r.ResponseBodySnippet,
				EvidenceMarkers:     r.EvidenceMarkers,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLoc{
						ArtifactLocation: sarifArtifact{
							URI: r.RequestURL,
						},
					},
				},
			},
		}
		results = append(results, result)
	}

	// Convert rules map to slice
	var ruleSlice []sarifRule
	for _, rule := range rules {
		ruleSlice = append(ruleSlice, rule)
	}

	return sarifDocument{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "WAF-Tester",
						Version:        defaults.Version,
						InformationUri: "https://github.com/waftester/waftester",
						Rules:          ruleSlice,
					},
				},
				Results: results,
			},
		},
	}
}

// ============================================================================
// CSV Writer (ffuf/httpx style)
// ============================================================================

func newCSVWriter(path string) (*CSVWriter, error) {
	if path == "" {
		writer := csv.NewWriter(os.Stdout)
		// Write header and flush immediately
		writer.Write([]string{"id", "category", "severity", "outcome", "status_code", "latency_ms", "method", "target_path", "timestamp"})
		writer.Flush()
		return &CSVWriter{file: os.Stdout, writer: writer}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	writer := csv.NewWriter(file)
	// Write header and flush immediately
	writer.Write([]string{"id", "category", "severity", "outcome", "status_code", "latency_ms", "method", "target_path", "timestamp"})
	writer.Flush()
	return &CSVWriter{file: file, writer: writer}, nil
}

func (w *CSVWriter) Write(result *TestResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	record := []string{
		result.ID,
		result.Category,
		result.Severity,
		result.Outcome,
		fmt.Sprintf("%d", result.StatusCode),
		fmt.Sprintf("%d", result.LatencyMs),
		result.Method,
		result.TargetPath,
		result.Timestamp,
	}
	if err := w.writer.Write(record); err != nil {
		return err
	}
	w.writer.Flush() // Flush after each write to ensure data is written
	return w.writer.Error()
}

func (w *CSVWriter) Close() (retErr error) {
	if w.file != os.Stdout {
		defer func() {
			if err := w.file.Close(); err != nil && retErr == nil {
				retErr = err
			}
		}()
	}
	w.writer.Flush()
	return w.writer.Error()
}

// ============================================================================
// Markdown Writer (nuclei style)
// ============================================================================

func newMarkdownWriter(path string) (*MarkdownWriter, error) {
	if path == "" {
		return &MarkdownWriter{file: os.Stdout, results: make([]*TestResult, 0)}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &MarkdownWriter{file: file, results: make([]*TestResult, 0)}, nil
}

func (w *MarkdownWriter) Write(result *TestResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = append(w.results, result)
	return nil
}

func (w *MarkdownWriter) Close() (retErr error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != os.Stdout {
		defer func() {
			if err := w.file.Close(); err != nil && retErr == nil {
				retErr = err
			}
		}()
	}

	// Build markdown content
	var sb strings.Builder

	sb.WriteString("# WAF Security Test Report\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// Summary
	var blocked, passed, failed, errored int
	for _, r := range w.results {
		switch r.Outcome {
		case "Blocked":
			blocked++
		case "Pass":
			passed++
		case "Fail":
			failed++
		case "Error":
			errored++
		}
	}

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Metric | Count |\n"))
	sb.WriteString(fmt.Sprintf("|--------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| Total | %d |\n", len(w.results)))
	sb.WriteString(fmt.Sprintf("| ✅ Blocked | %d |\n", blocked))
	sb.WriteString(fmt.Sprintf("| ✅ Pass | %d |\n", passed))
	sb.WriteString(fmt.Sprintf("| ❌ Fail | %d |\n", failed))
	sb.WriteString(fmt.Sprintf("| ⚠️ Error | %d |\n", errored))
	sb.WriteString("\n")

	// WAF Effectiveness = Blocked / (Blocked + Failed)
	attackTests := blocked + failed
	var effectiveness float64
	if attackTests > 0 {
		effectiveness = float64(blocked) / float64(attackTests) * 100
	}
	sb.WriteString(fmt.Sprintf("**WAF Effectiveness: %.1f%%**\n\n", effectiveness))

	// Results table
	sb.WriteString("## Results\n\n")
	sb.WriteString("| ID | Category | Severity | Outcome | Method | Path | Status | Latency |\n")
	sb.WriteString("|-----|----------|----------|---------|--------|------|--------|--------|\n")

	for _, r := range w.results {
		severityEmoji := map[string]string{
			"Critical": "🔴",
			"High":     "🟠",
			"Medium":   "🟡",
			"Low":      "🟢",
			"Info":     "🔵",
		}
		outcomeEmoji := map[string]string{
			"Blocked": "✅",
			"Pass":    "✅",
			"Fail":    "❌",
			"Error":   "⚠️",
		}

		method := r.Method
		if method == "" {
			method = "GET"
		}
		path := r.TargetPath
		if path == "" {
			path = "/"
		}

		sb.WriteString(fmt.Sprintf("| %s | %s | %s %s | %s %s | %s | %s | %d | %dms |\n",
			r.ID,
			r.Category,
			severityEmoji[r.Severity], r.Severity,
			outcomeEmoji[r.Outcome], r.Outcome,
			method,
			path,
			r.StatusCode,
			r.LatencyMs,
		))
	}

	_, err := w.file.WriteString(sb.String())
	if err != nil {
		return err
	}

	return nil
}

// ============================================================================
// HTML Writer (ffuf-style DataTables interactive report)
// ============================================================================

func newHTMLWriter(path string) (*HTMLWriter, error) {
	if path == "" {
		return &HTMLWriter{file: os.Stdout, results: make([]*TestResult, 0)}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &HTMLWriter{file: file, results: make([]*TestResult, 0)}, nil
}

func (w *HTMLWriter) Write(result *TestResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = append(w.results, result)
	return nil
}

func (w *HTMLWriter) Close() (retErr error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != os.Stdout {
		defer func() {
			if err := w.file.Close(); err != nil && retErr == nil {
				retErr = err
			}
		}()
	}

	// Calculate stats
	var blocked, passed, failed, errored int
	for _, r := range w.results {
		switch r.Outcome {
		case "Blocked":
			blocked++
		case "Pass":
			passed++
		case "Fail":
			failed++
		case "Error":
			errored++
		}
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Security Test Report</title>
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #198754;
            --info: #0dcaf0;
            --blocked: #198754;
            --pass: #198754;
            --fail: #dc3545;
            --error: #ffc107;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #fff; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #7d56f4; margin-bottom: 10px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .stat-card { background: #16213e; padding: 20px; border-radius: 8px; min-width: 150px; text-align: center; }
        .stat-card .value { font-size: 2em; font-weight: bold; }
        .stat-card.blocked .value { color: var(--blocked); }
        .stat-card.failed .value { color: var(--fail); }
        .stat-card.error .value { color: var(--error); }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-critical { background: var(--critical); color: #fff; }
        .badge-high { background: var(--high); color: #fff; }
        .badge-medium { background: var(--medium); color: #000; }
        .badge-low { background: var(--low); color: #fff; }
        .badge-info { background: var(--info); color: #000; }
        .badge-blocked, .badge-pass { background: var(--blocked); color: #fff; }
        .badge-fail { background: var(--fail); color: #fff; }
        .badge-error { background: var(--error); color: #000; }
        table.dataTable { background: #16213e; color: #fff; }
        table.dataTable thead th { background: #0f3460; color: #fff; }
        table.dataTable tbody tr:hover { background: #1f4068 !important; }
        .dataTables_wrapper .dataTables_filter input { background: #16213e; color: #fff; border: 1px solid #3b3b4f; }
        .dataTables_wrapper .dataTables_length select { background: #16213e; color: #fff; }
        .dataTables_wrapper .dataTables_info, .dataTables_wrapper .dataTables_paginate { color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ WAF Security Test Report</h1>
        <p style="color: #888;">Generated: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        
        <div class="summary">
            <div class="stat-card"><div class="value">` + fmt.Sprintf("%d", len(w.results)) + `</div><div>Total Tests</div></div>
            <div class="stat-card blocked"><div class="value">` + fmt.Sprintf("%d", blocked) + `</div><div>Blocked</div></div>
            <div class="stat-card"><div class="value">` + fmt.Sprintf("%d", passed) + `</div><div>Pass</div></div>
            <div class="stat-card failed"><div class="value">` + fmt.Sprintf("%d", failed) + `</div><div>Fail</div></div>
            <div class="stat-card error"><div class="value">` + fmt.Sprintf("%d", errored) + `</div><div>Error</div></div>
            <div class="stat-card"><div class="value">` + func() string {
		attackTests := blocked + failed
		if attackTests > 0 {
			return fmt.Sprintf("%.1f%%", float64(blocked)/float64(attackTests)*100)
		}
		return "N/A"
	}() + `</div><div>WAF Effectiveness</div></div>
        </div>

        <table id="results" class="display" style="width:100%">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Outcome</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Latency</th>
                </tr>
            </thead>
            <tbody>
`

	for _, r := range w.results {
		severityClass := strings.ToLower(r.Severity)
		outcomeClass := strings.ToLower(r.Outcome)
		method := r.Method
		if method == "" {
			method = "GET"
		}
		path := r.TargetPath
		if path == "" {
			path = "/"
		}

		html += fmt.Sprintf(`                <tr>
                    <td>%s</td>
                    <td>%s</td>
                    <td><span class="badge badge-%s">%s</span></td>
                    <td><span class="badge badge-%s">%s</span></td>
                    <td>%s</td>
                    <td>%s</td>
                    <td>%d</td>
                    <td>%dms</td>
                </tr>
`, r.ID, r.Category, severityClass, r.Severity, outcomeClass, r.Outcome, method, path, r.StatusCode, r.LatencyMs)
	}

	html += `            </tbody>
        </table>
    </div>
    <script>
        $(document).ready(function() {
            $('#results').DataTable({
                pageLength: 50,
                order: [[2, 'desc'], [3, 'asc']],
                language: { search: "Filter:" }
            });
        });
    </script>
</body>
</html>`

	_, err := w.file.WriteString(html)
	if err != nil {
		return err
	}

	return nil
}
