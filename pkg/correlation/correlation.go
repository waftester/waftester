// Package correlation provides vulnerability correlation and linking across scans
package correlation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/finding"
)

// FindingType represents the type of security finding
type FindingType string

const (
	FindingSQLi             FindingType = "sqli"
	FindingXSS              FindingType = "xss"
	FindingLFI              FindingType = "lfi"
	FindingRCE              FindingType = "rce"
	FindingSSRF             FindingType = "ssrf"
	FindingXXE              FindingType = "xxe"
	FindingSSTI             FindingType = "ssti"
	FindingAuthBypass       FindingType = "auth-bypass"
	FindingIDOR             FindingType = "idor"
	FindingOpenRedirect     FindingType = "open-redirect"
	FindingInfoLeak         FindingType = "info-leak"
	FindingMisconfiguration FindingType = "misconfiguration"
	FindingWeakCrypto       FindingType = "weak-crypto"
	FindingBrokenAccess     FindingType = "broken-access"
)

// Finding represents a security finding from a scan
type Finding struct {
	ID           string            `json:"id"`
	Hash         string            `json:"hash"` // Unique identifier for correlation
	Type         FindingType       `json:"type"`
	Severity     finding.Severity  `json:"severity"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	Target       string            `json:"target"`
	Endpoint     string            `json:"endpoint"`
	Method       string            `json:"method"`
	Parameter    string            `json:"parameter,omitempty"`
	Payload      string            `json:"payload,omitempty"`
	Evidence     string            `json:"evidence,omitempty"`
	CWE          string            `json:"cwe,omitempty"`
	CVE          string            `json:"cve,omitempty"`
	CVSS         float64           `json:"cvss,omitempty"`
	Confidence   float64           `json:"confidence"` // 0.0-1.0
	Scanner      string            `json:"scanner"`    // Which tool found it
	ScanID       string            `json:"scan_id"`
	Tags         []string          `json:"tags,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	DiscoveredAt time.Time         `json:"discovered_at"`
	Verified     bool              `json:"verified"`
}

// GenerateHash creates a unique hash for correlation
func (f *Finding) GenerateHash() string {
	data := strings.Join([]string{
		string(f.Type),
		f.Target,
		f.Endpoint,
		f.Method,
		f.Parameter,
	}, "|")
	hash := sha256.Sum256([]byte(data))
	f.Hash = hex.EncodeToString(hash[:8])
	return f.Hash
}

// CorrelatedFinding represents findings that are correlated together
type CorrelatedFinding struct {
	Hash            string     `json:"hash"`
	Findings        []*Finding `json:"findings"`
	FirstSeen       time.Time  `json:"first_seen"`
	LastSeen        time.Time  `json:"last_seen"`
	OccurrenceCount int        `json:"occurrence_count"`
	Scanners        []string   `json:"scanners"`
	IsRecurring     bool       `json:"is_recurring"`
	Status          string     `json:"status"` // new, open, fixed, false-positive
	Notes           string     `json:"notes,omitempty"`
}

// Correlation links related findings
type Correlation struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"` // same_vuln, related, pattern
	Findings   []string  `json:"finding_ids"`
	Reason     string    `json:"reason"`
	Confidence float64   `json:"confidence"`
	CreatedAt  time.Time `json:"created_at"`
}

// ScanResult represents results from a single scan
type ScanResult struct {
	ScanID    string      `json:"scan_id"`
	Target    string      `json:"target"`
	Scanner   string      `json:"scanner"`
	StartTime time.Time   `json:"start_time"`
	EndTime   time.Time   `json:"end_time"`
	Findings  []*Finding  `json:"findings"`
	Summary   ScanSummary `json:"summary"`
}

// ScanSummary provides scan statistics
type ScanSummary struct {
	TotalFindings     int                      `json:"total_findings"`
	BySeverity        map[finding.Severity]int `json:"by_severity"`
	ByType            map[FindingType]int      `json:"by_type"`
	NewFindings       int                      `json:"new_findings"`
	RecurringFindings int                      `json:"recurring_findings"`
	FixedFindings     int                      `json:"fixed_findings"`
}

// Correlator manages finding correlation
type Correlator struct {
	findings     map[string]*CorrelatedFinding // by hash
	correlations []*Correlation
	scanHistory  []*ScanResult
	rules        []CorrelationRule
	mu           sync.RWMutex
}

// CorrelationRule defines how to correlate findings
type CorrelationRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Condition   func(a, b *Finding) bool
	Weight      float64 `json:"weight"` // 0.0-1.0
}

// NewCorrelator creates a new correlator
func NewCorrelator() *Correlator {
	c := &Correlator{
		findings:     make(map[string]*CorrelatedFinding),
		correlations: make([]*Correlation, 0),
		scanHistory:  make([]*ScanResult, 0),
	}
	c.loadDefaultRules()
	return c
}

func (c *Correlator) loadDefaultRules() {
	c.rules = []CorrelationRule{
		{
			Name:        "Same Vulnerability",
			Description: "Identical vulnerability (same hash)",
			Condition: func(a, b *Finding) bool {
				return a.Hash != "" && a.Hash == b.Hash
			},
			Weight: 1.0,
		},
		{
			Name:        "Same Endpoint",
			Description: "Same target and endpoint",
			Condition: func(a, b *Finding) bool {
				return a.Target == b.Target && a.Endpoint == b.Endpoint
			},
			Weight: 0.8,
		},
		{
			Name:        "Same Parameter",
			Description: "Same vulnerable parameter",
			Condition: func(a, b *Finding) bool {
				return a.Parameter != "" && a.Parameter == b.Parameter &&
					a.Target == b.Target
			},
			Weight: 0.7,
		},
		{
			Name:        "Same Type Different Scanner",
			Description: "Same vulnerability type found by different scanners",
			Condition: func(a, b *Finding) bool {
				return a.Type == b.Type && a.Target == b.Target &&
					a.Scanner != b.Scanner
			},
			Weight: 0.9,
		},
		{
			Name:        "Related CWE",
			Description: "Related vulnerability based on CWE",
			Condition: func(a, b *Finding) bool {
				return a.CWE != "" && a.CWE == b.CWE
			},
			Weight: 0.6,
		},
	}
}

// AddScanResult adds scan results and correlates findings
func (c *Correlator) AddScanResult(ctx context.Context, result *ScanResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate hashes for all findings
	for _, f := range result.Findings {
		if f.Hash == "" {
			f.GenerateHash()
		}
	}

	// Correlate findings
	newCount := 0
	recurringCount := 0

	for _, f := range result.Findings {
		if existing, ok := c.findings[f.Hash]; ok {
			// Recurring finding
			existing.Findings = append(existing.Findings, f)
			existing.LastSeen = f.DiscoveredAt
			existing.OccurrenceCount++
			existing.IsRecurring = true
			if !containsScanner(existing.Scanners, f.Scanner) {
				existing.Scanners = append(existing.Scanners, f.Scanner)
			}
			recurringCount++
		} else {
			// New finding
			c.findings[f.Hash] = &CorrelatedFinding{
				Hash:            f.Hash,
				Findings:        []*Finding{f},
				FirstSeen:       f.DiscoveredAt,
				LastSeen:        f.DiscoveredAt,
				OccurrenceCount: 1,
				Scanners:        []string{f.Scanner},
				IsRecurring:     false,
				Status:          "new",
			}
			newCount++
		}
	}

	// Update summary
	result.Summary = c.computeSummary(result.Findings)
	result.Summary.NewFindings = newCount
	result.Summary.RecurringFindings = recurringCount

	// Store scan history
	c.scanHistory = append(c.scanHistory, result)

	return nil
}

func (c *Correlator) computeSummary(findings []*Finding) ScanSummary {
	summary := ScanSummary{
		TotalFindings: len(findings),
		BySeverity:    make(map[finding.Severity]int),
		ByType:        make(map[FindingType]int),
	}

	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByType[f.Type]++
	}

	return summary
}

// GetAllFindings returns all correlated findings
func (c *Correlator) GetAllFindings() []*CorrelatedFinding {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*CorrelatedFinding, 0, len(c.findings))
	for _, f := range c.findings {
		result = append(result, f)
	}

	// Sort by last seen
	sort.Slice(result, func(i, j int) bool {
		return result[i].LastSeen.After(result[j].LastSeen)
	})

	return result
}

// GetFindingByHash retrieves a specific correlated finding
func (c *Correlator) GetFindingByHash(hash string) *CorrelatedFinding {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.findings[hash]
}

// GetNewFindings returns findings first seen in the latest scan
func (c *Correlator) GetNewFindings() []*CorrelatedFinding {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*CorrelatedFinding
	for _, f := range c.findings {
		if f.Status == "new" {
			result = append(result, f)
		}
	}
	return result
}

// GetRecurringFindings returns findings that appeared in multiple scans
func (c *Correlator) GetRecurringFindings() []*CorrelatedFinding {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*CorrelatedFinding
	for _, f := range c.findings {
		if f.IsRecurring {
			result = append(result, f)
		}
	}
	return result
}

// GetFindingsBySeverity returns findings with minimum severity
func (c *Correlator) GetFindingsBySeverity(minSeverity finding.Severity) []*CorrelatedFinding {
	c.mu.RLock()
	defer c.mu.RUnlock()

	minOrder := minSeverity.Score()
	var result []*CorrelatedFinding
	for _, cf := range c.findings {
		if len(cf.Findings) > 0 {
			// Use highest severity from any finding
			maxSev := cf.Findings[0].Severity
			for _, f := range cf.Findings {
				if f.Severity.Score() > maxSev.Score() {
					maxSev = f.Severity
				}
			}
			if maxSev.Score() >= minOrder {
				result = append(result, cf)
			}
		}
	}
	return result
}

// GetFindingsByType returns findings of a specific type
func (c *Correlator) GetFindingsByType(findingType FindingType) []*CorrelatedFinding {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*CorrelatedFinding
	for _, cf := range c.findings {
		if len(cf.Findings) > 0 && cf.Findings[0].Type == findingType {
			result = append(result, cf)
		}
	}
	return result
}

// UpdateFindingStatus updates the status of a finding
func (c *Correlator) UpdateFindingStatus(hash, status, notes string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cf, ok := c.findings[hash]
	if !ok {
		return &NotFoundError{Hash: hash}
	}

	cf.Status = status
	if notes != "" {
		cf.Notes = notes
	}
	return nil
}

// NotFoundError indicates a finding was not found
type NotFoundError struct {
	Hash string
}

func (e *NotFoundError) Error() string {
	return "finding not found: " + e.Hash
}

// FindRelatedFindings finds findings related to a given finding
func (c *Correlator) FindRelatedFindings(hash string) []*CorrelatedFinding {
	c.mu.RLock()
	defer c.mu.RUnlock()

	target, ok := c.findings[hash]
	if !ok || len(target.Findings) == 0 {
		return nil
	}

	targetFinding := target.Findings[0]
	var related []*CorrelatedFinding

	for h, cf := range c.findings {
		if h == hash {
			continue
		}
		if len(cf.Findings) == 0 {
			continue
		}

		// Check rules
		for _, rule := range c.rules {
			if rule.Condition(targetFinding, cf.Findings[0]) {
				related = append(related, cf)
				break
			}
		}
	}

	return related
}

// GetScanHistory returns scan history
func (c *Correlator) GetScanHistory() []*ScanResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*ScanResult, len(c.scanHistory))
	copy(result, c.scanHistory)
	return result
}

// GetLatestScan returns the most recent scan
func (c *Correlator) GetLatestScan() *ScanResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.scanHistory) == 0 {
		return nil
	}
	return c.scanHistory[len(c.scanHistory)-1]
}

// DetectFixedFindings compares current scan to previous and identifies fixed issues
func (c *Correlator) DetectFixedFindings(currentScanID string) []*CorrelatedFinding {
	c.mu.Lock()
	defer c.mu.Unlock()

	var fixed []*CorrelatedFinding
	var currentScan *ScanResult

	for _, s := range c.scanHistory {
		if s.ScanID == currentScanID {
			currentScan = s
			break
		}
	}

	if currentScan == nil {
		return fixed
	}

	// Build set of current finding hashes and tested types
	currentHashes := make(map[string]bool)
	testedTypes := make(map[FindingType]bool)
	for _, f := range currentScan.Findings {
		currentHashes[f.Hash] = true
		testedTypes[f.Type] = true
	}

	// Only mark findings as fixed if they match the current scan's
	// target and a finding type that was actually tested. This prevents
	// partial scans (e.g., SQLi-only) from marking unrelated findings
	// (e.g., XSS) as fixed.
	for hash, cf := range c.findings {
		if !currentHashes[hash] && cf.Status != "fixed" && cf.Status != "false-positive" {
			// Only mark as fixed if we can confirm the scope was tested
			if len(cf.Findings) == 0 {
				continue
			}
			f := cf.Findings[0]
			if f.Target != currentScan.Target || !testedTypes[f.Type] {
				continue
			}
			cf.Status = "fixed"
			fixed = append(fixed, cf)
		}
	}

	return fixed
}

// TrendAnalysis analyzes trends across scans
type TrendAnalysis struct {
	TimeRange      TimeRange                  `json:"time_range"`
	TotalScans     int                        `json:"total_scans"`
	FindingTrend   []FindingTrendPoint        `json:"finding_trend"`
	SeverityTrend  map[finding.Severity][]int `json:"severity_trend"`
	NewVsRecurring []NewRecurringPoint        `json:"new_vs_recurring"`
	TopEndpoints   []EndpointStats            `json:"top_endpoints"`
	TopVulnTypes   []TypeStats                `json:"top_vuln_types"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// FindingTrendPoint is a data point in the trend
type FindingTrendPoint struct {
	Date   time.Time `json:"date"`
	Count  int       `json:"count"`
	ScanID string    `json:"scan_id"`
}

// NewRecurringPoint tracks new vs recurring findings
type NewRecurringPoint struct {
	Date      time.Time `json:"date"`
	New       int       `json:"new"`
	Recurring int       `json:"recurring"`
}

// EndpointStats tracks vulnerability counts per endpoint
type EndpointStats struct {
	Endpoint string `json:"endpoint"`
	Count    int    `json:"count"`
}

// TypeStats tracks vulnerability type counts
type TypeStats struct {
	Type  FindingType `json:"type"`
	Count int         `json:"count"`
}

// AnalyzeTrends performs trend analysis across scans
func (c *Correlator) AnalyzeTrends() *TrendAnalysis {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.scanHistory) == 0 {
		return &TrendAnalysis{}
	}

	analysis := &TrendAnalysis{
		TotalScans:     len(c.scanHistory),
		FindingTrend:   make([]FindingTrendPoint, 0),
		SeverityTrend:  make(map[finding.Severity][]int),
		NewVsRecurring: make([]NewRecurringPoint, 0),
	}

	// Time range
	analysis.TimeRange.Start = c.scanHistory[0].StartTime
	analysis.TimeRange.End = c.scanHistory[len(c.scanHistory)-1].EndTime

	// Build trends
	endpointCounts := make(map[string]int)
	typeCounts := make(map[FindingType]int)

	for _, scan := range c.scanHistory {
		// Finding trend
		analysis.FindingTrend = append(analysis.FindingTrend, FindingTrendPoint{
			Date:   scan.StartTime,
			Count:  len(scan.Findings),
			ScanID: scan.ScanID,
		})

		// New vs recurring
		analysis.NewVsRecurring = append(analysis.NewVsRecurring, NewRecurringPoint{
			Date:      scan.StartTime,
			New:       scan.Summary.NewFindings,
			Recurring: scan.Summary.RecurringFindings,
		})

		// Endpoint and type counts
		for _, f := range scan.Findings {
			endpointCounts[f.Endpoint]++
			typeCounts[f.Type]++
		}
	}

	// Top endpoints
	for endpoint, count := range endpointCounts {
		analysis.TopEndpoints = append(analysis.TopEndpoints, EndpointStats{
			Endpoint: endpoint,
			Count:    count,
		})
	}
	sort.Slice(analysis.TopEndpoints, func(i, j int) bool {
		return analysis.TopEndpoints[i].Count > analysis.TopEndpoints[j].Count
	})
	if len(analysis.TopEndpoints) > 10 {
		analysis.TopEndpoints = analysis.TopEndpoints[:10]
	}

	// Top vuln types
	for vt, count := range typeCounts {
		analysis.TopVulnTypes = append(analysis.TopVulnTypes, TypeStats{
			Type:  vt,
			Count: count,
		})
	}
	sort.Slice(analysis.TopVulnTypes, func(i, j int) bool {
		return analysis.TopVulnTypes[i].Count > analysis.TopVulnTypes[j].Count
	})

	return analysis
}

// AddRule adds a custom correlation rule
func (c *Correlator) AddRule(rule CorrelationRule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules = append(c.rules, rule)
}

// GetRules returns all correlation rules
func (c *Correlator) GetRules() []CorrelationRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rules
}

// Clear removes all findings and history
func (c *Correlator) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = make(map[string]*CorrelatedFinding)
	c.correlations = make([]*Correlation, 0)
	c.scanHistory = make([]*ScanResult, 0)
}

// GetStats returns correlator statistics
func (c *Correlator) GetStats() CorrelatorStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := CorrelatorStats{
		TotalFindings: len(c.findings),
		TotalScans:    len(c.scanHistory),
		ByStatus:      make(map[string]int),
	}

	for _, cf := range c.findings {
		stats.ByStatus[cf.Status]++
		if cf.IsRecurring {
			stats.RecurringFindings++
		}
	}

	return stats
}

// CorrelatorStats provides correlator statistics
type CorrelatorStats struct {
	TotalFindings     int            `json:"total_findings"`
	RecurringFindings int            `json:"recurring_findings"`
	TotalScans        int            `json:"total_scans"`
	ByStatus          map[string]int `json:"by_status"`
}

// Helper functions

func containsScanner(scanners []string, scanner string) bool {
	for _, s := range scanners {
		if s == scanner {
			return true
		}
	}
	return false
}
