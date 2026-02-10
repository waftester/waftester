// Package falsepositive provides false positive detection and management
package falsepositive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/finding"
)

// Category defines the type of false positive
type Category string

const (
	CategoryKnown     Category = "known"     // Known false positive, documented
	CategorySuspected Category = "suspected" // Suspected false positive, needs verification
	CategoryConfirmed Category = "confirmed" // Confirmed false positive after analysis
	CategoryDismissed Category = "dismissed" // Dismissed as actual threat
)

// FalsePositive represents a detected false positive
type FalsePositive struct {
	ID          string            `json:"id" yaml:"id"`
	TestID      string            `json:"test_id" yaml:"test_id"`
	RuleID      string            `json:"rule_id" yaml:"rule_id"`
	Payload     string            `json:"payload" yaml:"payload"`
	Endpoint    string            `json:"endpoint" yaml:"endpoint"`
	Method      string            `json:"method" yaml:"method"`
	Category    Category          `json:"category" yaml:"category"`
	Severity    finding.Severity  `json:"severity" yaml:"severity"`
	Description string            `json:"description" yaml:"description"`
	Reason      string            `json:"reason" yaml:"reason"`
	Evidence    string            `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	FirstSeen   time.Time         `json:"first_seen" yaml:"first_seen"`
	LastSeen    time.Time         `json:"last_seen" yaml:"last_seen"`
	Count       int               `json:"count" yaml:"count"`
	Tags        []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// Fingerprint generates a unique fingerprint for the false positive
func (fp *FalsePositive) Fingerprint() string {
	data := fmt.Sprintf("%s|%s|%s|%s", fp.RuleID, fp.Payload, fp.Endpoint, fp.Method)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// IsRecent returns true if the false positive was seen recently
func (fp *FalsePositive) IsRecent(threshold time.Duration) bool {
	return time.Since(fp.LastSeen) < threshold
}

// Pattern represents a pattern for detecting false positives
type Pattern struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	RuleIDs     []string `json:"rule_ids,omitempty" yaml:"rule_ids,omitempty"`
	Endpoints   []string `json:"endpoints,omitempty" yaml:"endpoints,omitempty"`
	Payloads    []string `json:"payloads,omitempty" yaml:"payloads,omitempty"`
	Methods     []string `json:"methods,omitempty" yaml:"methods,omitempty"`
	Tags        []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Enabled     bool     `json:"enabled" yaml:"enabled"`
}

// Matches checks if a result matches this pattern
func (p *Pattern) Matches(result *TestResult) bool {
	if !p.Enabled {
		return false
	}

	// Check rule ID match
	if len(p.RuleIDs) > 0 && !containsPattern(p.RuleIDs, result.RuleID) {
		return false
	}

	// Check endpoint match
	if len(p.Endpoints) > 0 && !containsPattern(p.Endpoints, result.Endpoint) {
		return false
	}

	// Check method match
	if len(p.Methods) > 0 && !contains(p.Methods, result.Method) {
		return false
	}

	// Check payload match
	if len(p.Payloads) > 0 && !containsPattern(p.Payloads, result.Payload) {
		return false
	}

	return true
}

// TestResult represents a test result to analyze for false positives
type TestResult struct {
	TestID      string `json:"test_id"`
	RuleID      string `json:"rule_id"`
	Payload     string `json:"payload"`
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	StatusCode  int    `json:"status_code"`
	Blocked     bool   `json:"blocked"`
	ExpectBlock bool   `json:"expect_block"`
	Message     string `json:"message,omitempty"`
}

// IsFalsePositive returns true if this is a false positive
func (r *TestResult) IsFalsePositive() bool {
	return r.Blocked && !r.ExpectBlock
}

// IsFalseNegative returns true if this is a false negative
func (r *TestResult) IsFalseNegative() bool {
	return !r.Blocked && r.ExpectBlock
}

// Detector detects false positives from test results
type Detector struct {
	patterns []*Pattern
	knownFPs map[string]*FalsePositive
	mu       sync.RWMutex
	config   *Config
}

// Config configures the detector
type Config struct {
	EnablePatterns   bool          `json:"enable_patterns" yaml:"enable_patterns"`
	EnableHeuristics bool          `json:"enable_heuristics" yaml:"enable_heuristics"`
	SimilarityThresh float64       `json:"similarity_threshold" yaml:"similarity_threshold"`
	RecentThreshold  time.Duration `json:"recent_threshold" yaml:"recent_threshold"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		EnablePatterns:   true,
		EnableHeuristics: true,
		SimilarityThresh: 0.8,
		RecentThreshold:  24 * time.Hour,
	}
}

// NewDetector creates a new false positive detector
func NewDetector(config *Config) *Detector {
	if config == nil {
		config = DefaultConfig()
	}
	return &Detector{
		patterns: make([]*Pattern, 0),
		knownFPs: make(map[string]*FalsePositive),
		config:   config,
	}
}

// AddPattern adds a detection pattern
func (d *Detector) AddPattern(pattern *Pattern) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.patterns = append(d.patterns, pattern)
}

// AddKnownFP adds a known false positive
func (d *Detector) AddKnownFP(fp *FalsePositive) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.knownFPs[fp.Fingerprint()] = fp
}

// Analyze analyzes test results for false positives
func (d *Detector) Analyze(results []*TestResult) []*FalsePositive {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var fps []*FalsePositive

	for _, result := range results {
		if !result.IsFalsePositive() {
			continue
		}

		fp := d.detectFP(result)
		if fp != nil {
			fps = append(fps, fp)
		}
	}

	return fps
}

func (d *Detector) detectFP(result *TestResult) *FalsePositive {
	fp := &FalsePositive{
		ID:        result.TestID,
		TestID:    result.TestID,
		RuleID:    result.RuleID,
		Payload:   result.Payload,
		Endpoint:  result.Endpoint,
		Method:    result.Method,
		Category:  CategorySuspected,
		Severity:  finding.Medium,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Count:     1,
	}

	// Check against known false positives
	fingerprint := fp.Fingerprint()
	if known, exists := d.knownFPs[fingerprint]; exists {
		fp.Category = known.Category
		fp.Severity = known.Severity
		fp.Description = known.Description
		fp.Reason = known.Reason
		fp.Remediation = known.Remediation
		fp.Count = known.Count + 1
		fp.FirstSeen = known.FirstSeen
	}

	// Check against patterns
	if d.config.EnablePatterns {
		for _, pattern := range d.patterns {
			if pattern.Matches(result) {
				fp.Category = CategoryKnown
				fp.Description = pattern.Description
				fp.Tags = append(fp.Tags, pattern.Tags...)
				break
			}
		}
	}

	// Apply heuristics
	if d.config.EnableHeuristics {
		d.applyHeuristics(fp, result)
	}

	return fp
}

func (d *Detector) applyHeuristics(fp *FalsePositive, result *TestResult) {
	// Heuristic: Common false positive patterns

	// Static files often trigger false positives
	if isStaticFile(result.Endpoint) {
		fp.Reason = "Static file request - likely false positive"
		fp.Severity = finding.Low
	}

	// API health endpoints
	if isHealthEndpoint(result.Endpoint) {
		fp.Reason = "Health check endpoint - likely false positive"
		fp.Severity = finding.Low
	}

	// Common WAF rule false positives
	if result.RuleID != "" {
		if info := getCommonFPInfo(result.RuleID); info != "" {
			fp.Evidence = info
		}
	}
}

// GetStats returns detection statistics
func (d *Detector) GetStats() *Stats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := &Stats{
		TotalPatterns: len(d.patterns),
		KnownFPs:      len(d.knownFPs),
		ByCategory:    make(map[Category]int),
		BySeverity:    make(map[finding.Severity]int),
	}

	for _, fp := range d.knownFPs {
		stats.ByCategory[fp.Category]++
		stats.BySeverity[fp.Severity]++
	}

	return stats
}

// Stats contains detection statistics
type Stats struct {
	TotalPatterns int              `json:"total_patterns"`
	KnownFPs      int              `json:"known_fps"`
	ByCategory    map[Category]int `json:"by_category"`
	BySeverity    map[finding.Severity]int `json:"by_severity"`
}

// Database stores and manages false positives
type Database struct {
	FalsePositives []*FalsePositive `json:"false_positives"`
	Patterns       []*Pattern       `json:"patterns"`
	mu             sync.RWMutex
}

// NewDatabase creates a new false positive database
func NewDatabase() *Database {
	return &Database{
		FalsePositives: make([]*FalsePositive, 0),
		Patterns:       make([]*Pattern, 0),
	}
}

// Add adds a false positive to the database
func (db *Database) Add(fp *FalsePositive) {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Check if already exists
	fingerprint := fp.Fingerprint()
	for i, existing := range db.FalsePositives {
		if existing.Fingerprint() == fingerprint {
			// Update existing
			db.FalsePositives[i].LastSeen = time.Now()
			db.FalsePositives[i].Count++
			return
		}
	}

	// Add new
	fp.ID = fingerprint
	db.FalsePositives = append(db.FalsePositives, fp)
}

// AddPattern adds a pattern to the database
func (db *Database) AddPattern(pattern *Pattern) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.Patterns = append(db.Patterns, pattern)
}

// Get retrieves a false positive by fingerprint
func (db *Database) Get(fingerprint string) *FalsePositive {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, fp := range db.FalsePositives {
		if fp.Fingerprint() == fingerprint {
			return fp
		}
	}
	return nil
}

// List returns all false positives
func (db *Database) List() []*FalsePositive {
	db.mu.RLock()
	defer db.mu.RUnlock()

	result := make([]*FalsePositive, len(db.FalsePositives))
	copy(result, db.FalsePositives)
	return result
}

// ListByCategory returns false positives by category
func (db *Database) ListByCategory(category Category) []*FalsePositive {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []*FalsePositive
	for _, fp := range db.FalsePositives {
		if fp.Category == category {
			result = append(result, fp)
		}
	}
	return result
}

// Remove removes a false positive by fingerprint
func (db *Database) Remove(fingerprint string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, fp := range db.FalsePositives {
		if fp.Fingerprint() == fingerprint {
			db.FalsePositives = append(db.FalsePositives[:i], db.FalsePositives[i+1:]...)
			return true
		}
	}
	return false
}

// UpdateCategory updates the category of a false positive
func (db *Database) UpdateCategory(fingerprint string, category Category) bool {
	db.mu.Lock()
	defer db.mu.Unlock()

	for _, fp := range db.FalsePositives {
		if fp.Fingerprint() == fingerprint {
			fp.Category = category
			return true
		}
	}
	return false
}

// Save saves the database to a file
func (db *Database) Save(path string) error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// Load loads the database from a file
func (db *Database) Load(path string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	return json.Unmarshal(data, db)
}

// Count returns the total number of false positives
func (db *Database) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.FalsePositives)
}

// Report generates a report of false positives
type Report struct {
	GeneratedAt     time.Time        `json:"generated_at"`
	TotalFPs        int              `json:"total_fps"`
	ByCategory      map[Category]int `json:"by_category"`
	BySeverity      map[finding.Severity]int `json:"by_severity"`
	ByRule          map[string]int   `json:"by_rule"`
	TopEndpoints    []EndpointStats  `json:"top_endpoints"`
	RecentFPs       []*FalsePositive `json:"recent_fps"`
	Recommendations []string         `json:"recommendations"`
}

// EndpointStats contains statistics for an endpoint
type EndpointStats struct {
	Endpoint string `json:"endpoint"`
	Count    int    `json:"count"`
}

// GenerateReport generates a false positive report
func GenerateReport(db *Database) *Report {
	fps := db.List()

	report := &Report{
		GeneratedAt:     time.Now(),
		TotalFPs:        len(fps),
		ByCategory:      make(map[Category]int),
		BySeverity:      make(map[finding.Severity]int),
		ByRule:          make(map[string]int),
		Recommendations: make([]string, 0),
	}

	endpointCount := make(map[string]int)

	for _, fp := range fps {
		report.ByCategory[fp.Category]++
		report.BySeverity[fp.Severity]++
		if fp.RuleID != "" {
			report.ByRule[fp.RuleID]++
		}
		endpointCount[fp.Endpoint]++

		// Check for recent FPs
		if fp.IsRecent(24 * time.Hour) {
			report.RecentFPs = append(report.RecentFPs, fp)
		}
	}

	// Top endpoints
	for ep, count := range endpointCount {
		report.TopEndpoints = append(report.TopEndpoints, EndpointStats{ep, count})
	}
	sort.Slice(report.TopEndpoints, func(i, j int) bool {
		return report.TopEndpoints[i].Count > report.TopEndpoints[j].Count
	})
	if len(report.TopEndpoints) > 10 {
		report.TopEndpoints = report.TopEndpoints[:10]
	}

	// Generate recommendations
	if report.ByCategory[CategorySuspected] > 10 {
		report.Recommendations = append(report.Recommendations,
			"Review suspected false positives and confirm or dismiss")
	}

	for rule, count := range report.ByRule {
		if count > 5 {
			report.Recommendations = append(report.Recommendations,
				fmt.Sprintf("Consider tuning rule %s (triggered %d times)", rule, count))
		}
	}

	return report
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsPattern(patterns []string, item string) bool {
	for _, p := range patterns {
		if strings.Contains(item, p) {
			return true
		}
		// Try regex
		if re, err := regexp.Compile(p); err == nil && re.MatchString(item) {
			return true
		}
	}
	return false
}

func isStaticFile(endpoint string) bool {
	extensions := []string{".js", ".css", ".png", ".jpg", ".gif", ".ico", ".woff", ".woff2"}
	for _, ext := range extensions {
		if strings.HasSuffix(endpoint, ext) {
			return true
		}
	}
	return false
}

func isHealthEndpoint(endpoint string) bool {
	healthPaths := []string{"/health", "/healthz", "/ready", "/live", "/ping", "/-/health"}
	for _, path := range healthPaths {
		if strings.Contains(endpoint, path) {
			return true
		}
	}
	return false
}

func getCommonFPInfo(ruleID string) string {
	commonFPs := map[string]string{
		"920350": "Common false positive for multipart/form-data",
		"942100": "May trigger on legitimate SQL-like content",
		"941100": "Common XSS false positive for JavaScript code",
		"920420": "Request content type validation",
	}
	return commonFPs[ruleID]
}

// Analyzer provides analysis utilities
type Analyzer struct {
	detector *Detector
	db       *Database
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer(detector *Detector, db *Database) *Analyzer {
	return &Analyzer{
		detector: detector,
		db:       db,
	}
}

// AnalyzeAndStore analyzes results and stores detected false positives
func (a *Analyzer) AnalyzeAndStore(results []*TestResult) []*FalsePositive {
	fps := a.detector.Analyze(results)
	for _, fp := range fps {
		a.db.Add(fp)
	}
	return fps
}

// GetAnalysis returns analysis for a specific rule
func (a *Analyzer) GetAnalysis(ruleID string) *RuleAnalysis {
	fps := a.db.List()

	analysis := &RuleAnalysis{
		RuleID:   ruleID,
		FPCount:  0,
		Severity: finding.Low,
	}

	for _, fp := range fps {
		if fp.RuleID == ruleID {
			analysis.FPCount++
			analysis.Endpoints = append(analysis.Endpoints, fp.Endpoint)
			if fp.Severity == finding.Critical || fp.Severity == finding.High {
				analysis.Severity = fp.Severity
			}
		}
	}

	if analysis.FPCount > 10 {
		analysis.Recommendation = "Consider adding rule exception or tuning"
	} else if analysis.FPCount > 5 {
		analysis.Recommendation = "Monitor for additional occurrences"
	}

	return analysis
}

// RuleAnalysis contains analysis for a specific rule
type RuleAnalysis struct {
	RuleID         string   `json:"rule_id"`
	FPCount        int      `json:"fp_count"`
	Endpoints      []string `json:"endpoints"`
	Severity       finding.Severity `json:"severity"`
	Recommendation string   `json:"recommendation"`
}
