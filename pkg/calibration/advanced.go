package calibration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/ui"
)

// AdvancedCalibrator provides ffuf-style advanced auto-calibration with
// per-host calibration, multiple strategies, and wildcard detection
type AdvancedCalibrator struct {
	timeout       time.Duration
	skipVerify    bool
	client        *http.Client
	strategies    []CalibrationStrategy
	perHost       bool
	hostBaselines map[string]*Baseline
	mu            sync.RWMutex
}

// Baseline represents the detected baseline for a target
type Baseline struct {
	Status          int             `json:"status"`
	Size            int             `json:"size"`
	Words           int             `json:"words"`
	Lines           int             `json:"lines"`
	ContentHash     string          `json:"content_hash,omitempty"`
	ResponseTime    time.Duration   `json:"response_time_ms"`
	Headers         map[string]bool `json:"significant_headers,omitempty"`
	IsWildcard      bool            `json:"is_wildcard"`
	WildcardType    string          `json:"wildcard_type,omitempty"` // "content", "status", "redirect"
	Calibrated      bool            `json:"calibrated"`
	CalibrationTime time.Time       `json:"calibration_time"`
}

// CalibrationStrategy defines a specific calibration approach
type CalibrationStrategy struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Paths       []string          `json:"paths"`
	Method      string            `json:"method,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	Keyword     string            `json:"keyword,omitempty"` // placeholder to replace
}

// AdvancedConfig configures the advanced calibrator
type AdvancedConfig struct {
	Timeout          time.Duration
	SkipVerify       bool
	PerHost          bool
	StrategyFiles    []string // JSON files with strategies
	CustomStrategies []CalibrationStrategy
	Keyword          string // default keyword for replacement
}

// DefaultStrategies returns built-in calibration strategies
func DefaultStrategies() []CalibrationStrategy {
	return []CalibrationStrategy{
		{
			Name:        "basic",
			Description: "Basic random path calibration",
			Paths: []string{
				"/CALIBRATION_RANDOM_" + randomString(16),
				"/CALIBRATION_PATH_" + randomString(12),
				"/" + randomString(20) + "/index.html",
				"/" + randomString(8) + ".php",
				"/" + randomString(10) + ".asp",
			},
			Method: "GET",
		},
		{
			Name:        "api",
			Description: "API-focused calibration for REST endpoints",
			Paths: []string{
				"/api/v1/CALIBRATION_" + randomString(12),
				"/api/CALIBRATION_" + randomString(8) + "/resource",
				"/v1/" + randomString(10),
				"/v2/" + randomString(10),
			},
			Method: "GET",
			Headers: map[string]string{
				"Accept": "application/json",
			},
		},
		{
			Name:        "admin",
			Description: "Admin path calibration",
			Paths: []string{
				"/admin/CALIBRATION_" + randomString(8),
				"/administrator/" + randomString(10),
				"/wp-admin/" + randomString(12),
				"/dashboard/" + randomString(8),
			},
			Method: "GET",
		},
		{
			Name:        "post",
			Description: "POST request calibration",
			Paths: []string{
				"/api/CALIBRATION_" + randomString(8),
				"/submit/" + randomString(10),
			},
			Method: "POST",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: `{"calibration": "` + randomString(16) + `"}`,
		},
		{
			Name:        "extensions",
			Description: "Extension-based calibration",
			Paths: []string{
				"/" + randomString(12) + ".json",
				"/" + randomString(12) + ".xml",
				"/" + randomString(12) + ".txt",
				"/" + randomString(12) + ".bak",
				"/" + randomString(12) + ".old",
			},
			Method: "GET",
		},
	}
}

// NewAdvancedCalibrator creates a new advanced calibrator
func NewAdvancedCalibrator(config AdvancedConfig) *AdvancedCalibrator {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipVerify},
	}

	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	calibrator := &AdvancedCalibrator{
		timeout:       config.Timeout,
		skipVerify:    config.SkipVerify,
		perHost:       config.PerHost,
		hostBaselines: make(map[string]*Baseline),
		client: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	// Load strategies
	calibrator.strategies = DefaultStrategies()

	// Load custom strategies from files
	for _, file := range config.StrategyFiles {
		if strategies, err := LoadStrategiesFromFile(file); err == nil {
			calibrator.strategies = append(calibrator.strategies, strategies...)
		}
	}

	// Add inline custom strategies
	calibrator.strategies = append(calibrator.strategies, config.CustomStrategies...)

	return calibrator
}

// LoadStrategiesFromFile loads calibration strategies from a JSON file
func LoadStrategiesFromFile(path string) ([]CalibrationStrategy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var strategies []CalibrationStrategy
	if err := json.Unmarshal(data, &strategies); err != nil {
		return nil, err
	}

	return strategies, nil
}

// calibrationResponse holds response data during calibration
type calibrationResponse struct {
	status  int
	size    int
	words   int
	lines   int
	latency time.Duration
	body    string
}

// CalibrateHost performs calibration for a specific host
func (c *AdvancedCalibrator) CalibrateHost(ctx context.Context, targetURL string) (*Baseline, error) {
	// Extract host for caching
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	host := parsed.Host

	// Check cache if per-host enabled
	if c.perHost {
		c.mu.RLock()
		if baseline, ok := c.hostBaselines[host]; ok {
			c.mu.RUnlock()
			return baseline, nil
		}
		c.mu.RUnlock()
	}

	baseline := &Baseline{
		CalibrationTime: time.Now(),
	}

	// Collect responses from all strategies
	var responses []calibrationResponse

	for _, strategy := range c.strategies {
		for _, pathTemplate := range strategy.Paths {
			path := pathTemplate
			if strategy.Keyword != "" {
				path = strings.ReplaceAll(path, strategy.Keyword, randomString(12))
			}

			reqURL := strings.TrimSuffix(targetURL, "/") + path

			method := strategy.Method
			if method == "" {
				method = "GET"
			}

			var bodyReader io.Reader
			if strategy.Body != "" {
				bodyReader = strings.NewReader(strategy.Body)
			}

			req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", ui.UserAgentWithContext("AutoCal"))
			for k, v := range strategy.Headers {
				req.Header.Set(k, v)
			}

			start := time.Now()
			resp, err := c.client.Do(req)
			if err != nil {
				continue
			}
			latency := time.Since(start)

			body, _ := iohelper.ReadBodyDefault(resp.Body)
			resp.Body.Close()

			responses = append(responses, calibrationResponse{
				status:  resp.StatusCode,
				size:    len(body),
				words:   len(strings.Fields(string(body))),
				lines:   len(strings.Split(string(body), "\n")),
				latency: latency,
				body:    string(body),
			})
		}
	}

	if len(responses) == 0 {
		return baseline, fmt.Errorf("no calibration responses received")
	}

	// Analyze responses to find baseline
	statusCounts := make(map[int]int)
	sizeCounts := make(map[int]int)
	wordCounts := make(map[int]int)
	lineCounts := make(map[int]int)
	var totalLatency time.Duration

	for _, r := range responses {
		statusCounts[r.status]++
		sizeCounts[r.size]++
		wordCounts[r.words]++
		lineCounts[r.lines]++
		totalLatency += r.latency
	}

	// Find most common values
	baseline.Status = findMostCommon(statusCounts)
	baseline.Size = findMostCommon(sizeCounts)
	baseline.Words = findMostCommon(wordCounts)
	baseline.Lines = findMostCommon(lineCounts)
	baseline.ResponseTime = totalLatency / time.Duration(len(responses))

	// Detect wildcard behavior
	baseline.IsWildcard, baseline.WildcardType = c.detectWildcard(responses, baseline)

	baseline.Calibrated = true

	// Cache if per-host
	if c.perHost {
		c.mu.Lock()
		c.hostBaselines[host] = baseline
		c.mu.Unlock()
	}

	return baseline, nil
}

// detectWildcard checks if the target has wildcard behavior
func (c *AdvancedCalibrator) detectWildcard(responses []calibrationResponse, baseline *Baseline) (bool, string) {
	if len(responses) < 3 {
		return false, ""
	}

	// Check if all responses are identical (strong wildcard indicator)
	allSameStatus := true
	allSameSize := true
	firstStatus := responses[0].status
	firstSize := responses[0].size

	for _, r := range responses[1:] {
		if r.status != firstStatus {
			allSameStatus = false
		}
		if r.size != firstSize {
			allSameSize = false
		}
	}

	// All 200s with same content = content wildcard
	if allSameStatus && firstStatus == 200 && allSameSize {
		return true, "content"
	}

	// All redirects = redirect wildcard
	if allSameStatus && (firstStatus == 301 || firstStatus == 302 || firstStatus == 307 || firstStatus == 308) {
		return true, "redirect"
	}

	// High percentage of same status codes
	statusCount := 0
	for _, r := range responses {
		if r.status == baseline.Status {
			statusCount++
		}
	}
	if float64(statusCount)/float64(len(responses)) > 0.9 {
		return true, "status"
	}

	return false, ""
}

// GetBaseline returns cached baseline for a host (nil if not calibrated)
func (c *AdvancedCalibrator) GetBaseline(host string) *Baseline {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hostBaselines[host]
}

// ToFilterConfig converts a baseline to filter configuration
func (b *Baseline) ToFilterConfig() map[string]interface{} {
	config := make(map[string]interface{})

	if b.Status > 0 {
		config["filter_status"] = []int{b.Status}
	}
	if b.Size > 0 {
		config["filter_size"] = []int{b.Size}
	}
	if b.Words > 0 {
		config["filter_words"] = []int{b.Words}
	}
	if b.Lines > 0 {
		config["filter_lines"] = []int{b.Lines}
	}

	return config
}

// ToLegacyResult converts to the legacy Result type for compatibility
func (b *Baseline) ToLegacyResult() *Result {
	return &Result{
		BaselineStatus: b.Status,
		BaselineSize:   b.Size,
		BaselineWords:  b.Words,
		BaselineLines:  b.Lines,
		Calibrated:     b.Calibrated,
		Suggestions: FilterSuggestion{
			FilterStatus: []int{b.Status},
			FilterSize:   []int{b.Size},
			FilterWords:  []int{b.Words},
			FilterLines:  []int{b.Lines},
		},
	}
}

// Describe returns a human-readable description of the baseline
func (b *Baseline) Describe() string {
	if !b.Calibrated {
		return "Not calibrated"
	}

	parts := []string{}
	if b.Status > 0 {
		parts = append(parts, fmt.Sprintf("Status: %d", b.Status))
	}
	if b.Size > 0 {
		parts = append(parts, fmt.Sprintf("Size: %d", b.Size))
	}
	if b.Words > 0 {
		parts = append(parts, fmt.Sprintf("Words: %d", b.Words))
	}
	if b.Lines > 0 {
		parts = append(parts, fmt.Sprintf("Lines: %d", b.Lines))
	}
	if b.IsWildcard {
		parts = append(parts, fmt.Sprintf("Wildcard: %s", b.WildcardType))
	}

	return fmt.Sprintf("Baseline: %s", strings.Join(parts, ", "))
}

// QuarantineManager tracks hosts that should be skipped due to wildcard behavior
type QuarantineManager struct {
	hosts     map[string]int // host -> consecutive hit count
	threshold int
	mu        sync.RWMutex
}

// NewQuarantineManager creates a quarantine manager with threshold
func NewQuarantineManager(threshold int) *QuarantineManager {
	if threshold <= 0 {
		threshold = 10 // default: quarantine after 10 consecutive hits
	}
	return &QuarantineManager{
		hosts:     make(map[string]int),
		threshold: threshold,
	}
}

// RecordHit records a "hit" (potential false positive) for a host
func (q *QuarantineManager) RecordHit(host string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.hosts[host]++
	return q.hosts[host] >= q.threshold
}

// Reset resets the hit counter for a host
func (q *QuarantineManager) Reset(host string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.hosts, host)
}

// IsQuarantined checks if a host should be skipped
func (q *QuarantineManager) IsQuarantined(host string) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.hosts[host] >= q.threshold
}

// GetQuarantinedHosts returns all quarantined hosts
func (q *QuarantineManager) GetQuarantinedHosts() []string {
	q.mu.RLock()
	defer q.mu.RUnlock()
	var hosts []string
	for host, count := range q.hosts {
		if count >= q.threshold {
			hosts = append(hosts, host)
		}
	}
	return hosts
}
