// Package recon provides unified reconnaissance capabilities
// integrating all discovery modules (leakypaths, params, secrets, endpoints)
// for comprehensive attack surface mapping.
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/leakypaths"
	"github.com/waftester/waftester/pkg/params"
	"github.com/waftester/waftester/pkg/tls"
)

// FullReconResult contains all reconnaissance data
type FullReconResult struct {
	Target    string        `json:"target"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`

	// Leaky Paths Results
	LeakyPaths *leakypaths.ScanSummary `json:"leaky_paths,omitempty"`

	// Parameter Discovery Results
	Parameters *params.DiscoveryResult `json:"parameters,omitempty"`

	// JavaScript Analysis Results
	JSAnalysis *JSAnalysisResult `json:"js_analysis,omitempty"`

	// Combined Statistics
	Stats *ReconStats `json:"stats"`

	// Risk Assessment
	RiskScore float64  `json:"risk_score"`
	RiskLevel string   `json:"risk_level"`
	TopRisks  []string `json:"top_risks"`

	// JA3 Fingerprint Info
	JA3Profile string `json:"ja3_profile,omitempty"`
}

// JSAnalysisResult contains JS analysis findings
type JSAnalysisResult struct {
	FilesAnalyzed int               `json:"files_analyzed"`
	Secrets       []js.SecretInfo   `json:"secrets,omitempty"`
	Endpoints     []js.EndpointInfo `json:"endpoints,omitempty"`
	DOMSinks      []js.DOMSinkInfo  `json:"dom_sinks,omitempty"`
	CloudURLs     []js.CloudURL     `json:"cloud_urls,omitempty"`
	Subdomains    []string          `json:"subdomains,omitempty"`
}

// ReconStats provides aggregate statistics
type ReconStats struct {
	LeakyPathsFound  int `json:"leaky_paths_found"`
	ParametersFound  int `json:"parameters_found"`
	SecretsFound     int `json:"secrets_found"`
	EndpointsFound   int `json:"endpoints_found"`
	DOMSinksFound    int `json:"dom_sinks_found"`
	CloudURLsFound   int `json:"cloud_urls_found"`
	SubdomainsFound  int `json:"subdomains_found"`
	ReflectedParams  int `json:"reflected_params"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	MediumFindings   int `json:"medium_findings"`
}

// Config configures the full reconnaissance scan
type Config struct {
	// General settings
	Timeout       time.Duration
	Concurrency   int
	Verbose       bool
	SkipTLSVerify bool
	HTTPClient    *http.Client // Optional custom HTTP client (e.g., JA3-aware)

	// Module toggles
	EnableLeakyPaths     bool
	EnableParamDiscovery bool
	EnableJSAnalysis     bool
	EnableJA3Rotation    bool

	// Leaky paths settings
	LeakyPathCategories []string // Filter categories: config, debug, backup, etc.

	// Parameter discovery settings
	ParamMethods  []string // HTTP methods to test
	ParamWordlist string   // Custom wordlist file path (empty = built-in)

	// JavaScript analysis settings
	JSFiles []string // Specific JS files to analyze (auto-discovered if empty)

	// JA3 settings
	JA3Profile string // Specific profile or empty for rotation
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Timeout:              30 * time.Second,
		Concurrency:          20,
		Verbose:              false,
		EnableLeakyPaths:     true,
		EnableParamDiscovery: true,
		EnableJSAnalysis:     true,
		EnableJA3Rotation:    true,
		ParamMethods:         []string{"GET", "POST"},
	}
}

// Scanner performs comprehensive reconnaissance
type Scanner struct {
	config *Config
	tlsCfg *tls.Config
}

// NewScanner creates a new reconnaissance scanner
func NewScanner(cfg *Config) *Scanner {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	return &Scanner{
		config: cfg,
		tlsCfg: &tls.Config{
			RotateEvery: 25,
			Timeout:     cfg.Timeout,
			SkipVerify:  cfg.SkipTLSVerify,
		},
	}
}

// FullScan performs comprehensive reconnaissance on a target
func (s *Scanner) FullScan(ctx context.Context, targetURL string) (*FullReconResult, error) {
	start := time.Now()

	result := &FullReconResult{
		Target:    targetURL,
		Timestamp: start,
		Stats:     &ReconStats{},
		TopRisks:  make([]string, 0),
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	errChan := make(chan error, 3)

	// Run modules concurrently
	if s.config.EnableLeakyPaths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			leakyResult, err := s.scanLeakyPaths(ctx, targetURL)
			if err != nil {
				errChan <- fmt.Errorf("leaky paths scan failed: %w", err)
				return
			}
			mu.Lock()
			result.LeakyPaths = leakyResult
			result.Stats.LeakyPathsFound = leakyResult.InterestingHits
			mu.Unlock()
		}()
	}

	if s.config.EnableParamDiscovery {
		wg.Add(1)
		go func() {
			defer wg.Done()
			paramResult, err := s.discoverParams(ctx, targetURL)
			if err != nil {
				errChan <- fmt.Errorf("param discovery failed: %w", err)
				return
			}
			mu.Lock()
			result.Parameters = paramResult
			result.Stats.ParametersFound = paramResult.FoundParams
			result.Stats.ReflectedParams = len(paramResult.ReflectedParams)
			mu.Unlock()
		}()
	}

	// Wait for all modules
	wg.Wait()
	close(errChan)

	// Collect any errors
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	// Calculate risk score
	result.RiskScore, result.RiskLevel, result.TopRisks = s.calculateRisk(result)

	result.Duration = time.Since(start)

	// Set JA3 profile info if enabled
	if s.config.EnableJA3Rotation {
		if s.config.JA3Profile != "" {
			result.JA3Profile = s.config.JA3Profile
		} else {
			result.JA3Profile = "rotating"
		}
	}

	return result, nil
}

// scanLeakyPaths scans for leaky paths
func (s *Scanner) scanLeakyPaths(ctx context.Context, targetURL string) (*leakypaths.ScanSummary, error) {
	scanner := leakypaths.NewScanner(&leakypaths.Config{
		Concurrency: s.config.Concurrency,
		Timeout:     s.config.Timeout,
		Verbose:     s.config.Verbose,
		HTTPClient:  s.config.HTTPClient, // JA3 TLS fingerprint rotation
	})

	return scanner.Scan(ctx, targetURL, s.config.LeakyPathCategories...)
}

// discoverParams discovers hidden parameters
func (s *Scanner) discoverParams(ctx context.Context, targetURL string) (*params.DiscoveryResult, error) {
	discoverer := params.NewDiscoverer(&params.Config{
		Concurrency:  s.config.Concurrency,
		Timeout:      s.config.Timeout,
		Verbose:      s.config.Verbose,
		WordlistFile: s.config.ParamWordlist,
		HTTPClient:   s.config.HTTPClient, // JA3 TLS fingerprint rotation
	})

	return discoverer.Discover(ctx, targetURL, s.config.ParamMethods...)
}

// calculateRisk calculates overall risk score
func (s *Scanner) calculateRisk(result *FullReconResult) (float64, string, []string) {
	score := 0.0
	var topRisks []string

	// Leaky paths contribute to risk
	if result.LeakyPaths != nil {
		criticalLeaks := result.LeakyPaths.BySeverity["critical"]
		highLeaks := result.LeakyPaths.BySeverity["high"]
		mediumLeaks := result.LeakyPaths.BySeverity["medium"]

		score += float64(criticalLeaks) * 25.0
		score += float64(highLeaks) * 15.0
		score += float64(mediumLeaks) * 5.0

		result.Stats.CriticalFindings += criticalLeaks
		result.Stats.HighFindings += highLeaks
		result.Stats.MediumFindings += mediumLeaks

		if criticalLeaks > 0 {
			topRisks = append(topRisks, fmt.Sprintf("%d critical leaky paths exposed", criticalLeaks))
		}
		if result.LeakyPaths.ByCategory["config"] > 0 {
			topRisks = append(topRisks, "Configuration files exposed")
		}
		if result.LeakyPaths.ByCategory["vcs"] > 0 {
			topRisks = append(topRisks, "Version control (.git) exposed")
		}
	}

	// Parameters contribute to risk
	if result.Parameters != nil {
		if len(result.Parameters.ReflectedParams) > 0 {
			score += float64(len(result.Parameters.ReflectedParams)) * 10.0
			topRisks = append(topRisks, fmt.Sprintf("%d reflected parameters (potential XSS)", len(result.Parameters.ReflectedParams)))
		}
	}

	// JS analysis contributes to risk
	if result.JSAnalysis != nil {
		if result.JSAnalysis.Secrets != nil {
			for _, secret := range result.JSAnalysis.Secrets {
				switch secret.Confidence {
				case "high":
					score += 30.0
					result.Stats.CriticalFindings++
				case "medium":
					score += 15.0
					result.Stats.HighFindings++
				default:
					score += 5.0
					result.Stats.MediumFindings++
				}
			}
			if len(result.JSAnalysis.Secrets) > 0 {
				topRisks = append(topRisks, fmt.Sprintf("%d secrets exposed in JavaScript", len(result.JSAnalysis.Secrets)))
			}
		}

		if len(result.JSAnalysis.DOMSinks) > 0 {
			score += float64(len(result.JSAnalysis.DOMSinks)) * 8.0
			topRisks = append(topRisks, fmt.Sprintf("%d potential DOM XSS sinks", len(result.JSAnalysis.DOMSinks)))
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	// Determine level
	level := "low"
	if score >= 75 {
		level = "critical"
	} else if score >= 50 {
		level = "high"
	} else if score >= 25 {
		level = "medium"
	}

	// Limit top risks to 5
	if len(topRisks) > 5 {
		topRisks = topRisks[:5]
	}

	return score, level, topRisks
}

// QuickScan performs a faster scan with reduced coverage
func (s *Scanner) QuickScan(ctx context.Context, targetURL string) (*FullReconResult, error) {
	// Use reduced settings for quick scan
	originalConcurrency := s.config.Concurrency
	s.config.Concurrency = 50                                         // Higher concurrency
	s.config.LeakyPathCategories = []string{"config", "vcs", "debug"} // Only high-value categories

	result, err := s.FullScan(ctx, targetURL)

	// Restore settings
	s.config.Concurrency = originalConcurrency
	s.config.LeakyPathCategories = nil

	return result, err
}

// ToJSON serializes the result to JSON
func (r *FullReconResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// PrintSummary prints a human-readable summary
func (r *FullReconResult) PrintSummary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("═══════════════════════════════════════════════════════════════\n"))
	sb.WriteString(fmt.Sprintf("                    RECONNAISSANCE SUMMARY\n"))
	sb.WriteString(fmt.Sprintf("═══════════════════════════════════════════════════════════════\n\n"))

	sb.WriteString(fmt.Sprintf("Target:    %s\n", r.Target))
	sb.WriteString(fmt.Sprintf("Duration:  %s\n", r.Duration.Round(time.Millisecond)))
	sb.WriteString(fmt.Sprintf("JA3:       %s\n\n", r.JA3Profile))

	sb.WriteString(fmt.Sprintf("Risk Score: %.0f/100 [%s]\n\n", r.RiskScore, strings.ToUpper(r.RiskLevel)))

	sb.WriteString("Discovery Results:\n")
	sb.WriteString(fmt.Sprintf("  • Leaky Paths Found:     %d\n", r.Stats.LeakyPathsFound))
	sb.WriteString(fmt.Sprintf("  • Parameters Found:      %d (%d reflected)\n", r.Stats.ParametersFound, r.Stats.ReflectedParams))
	sb.WriteString(fmt.Sprintf("  • Secrets Found:         %d\n", r.Stats.SecretsFound))
	sb.WriteString(fmt.Sprintf("  • API Endpoints Found:   %d\n", r.Stats.EndpointsFound))
	sb.WriteString(fmt.Sprintf("  • DOM XSS Sinks Found:   %d\n", r.Stats.DOMSinksFound))
	sb.WriteString(fmt.Sprintf("  • Cloud URLs Found:      %d\n", r.Stats.CloudURLsFound))
	sb.WriteString(fmt.Sprintf("  • Subdomains Found:      %d\n\n", r.Stats.SubdomainsFound))

	sb.WriteString("Finding Severity Breakdown:\n")
	sb.WriteString(fmt.Sprintf("  🔴 Critical: %d\n", r.Stats.CriticalFindings))
	sb.WriteString(fmt.Sprintf("  🟠 High:     %d\n", r.Stats.HighFindings))
	sb.WriteString(fmt.Sprintf("  🟡 Medium:   %d\n\n", r.Stats.MediumFindings))

	if len(r.TopRisks) > 0 {
		sb.WriteString("Top Risks:\n")
		for i, risk := range r.TopRisks {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, risk))
		}
	}

	sb.WriteString(fmt.Sprintf("\n═══════════════════════════════════════════════════════════════\n"))

	return sb.String()
}
