// Package osint provides additional OSINT data sources for reconnaissance
package osint

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Source represents an OSINT data source
type Source string

const (
	SourceShodan         Source = "shodan"
	SourceCensys         Source = "censys"
	SourceCrtsh          Source = "crtsh"
	SourceSecurityTrails Source = "securitytrails"
	SourceDNSDumpster    Source = "dnsdumpster"
	SourceChaos          Source = "chaos"
	SourceWayback        Source = "wayback"
	SourceCommonCrawl    Source = "commoncrawl"
	SourceOTX            Source = "otx"
	SourceVirusTotal     Source = "virustotal"
	SourceBinaryEdge     Source = "binaryedge"
	SourceFullHunt       Source = "fullhunt"
	SourceHunterIO       Source = "hunterio"
	SourceZoomEye        Source = "zoomeye"
	SourceFofa           Source = "fofa"
)

// Result represents a discovery result
type Result struct {
	Source    Source            `json:"source"`
	Type      string            `json:"type"` // subdomain, ip, port, service
	Value     string            `json:"value"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// SourceConfig configures an OSINT source
type SourceConfig struct {
	Source    Source `json:"source"`
	APIKey    string `json:"api_key,omitempty"`
	APISecret string `json:"api_secret,omitempty"`
	Enabled   bool   `json:"enabled"`
	RateLimit int    `json:"rate_limit"` // requests per minute
}

// Client interface for OSINT sources
type Client interface {
	Name() Source
	Validate() error
	FetchSubdomains(ctx context.Context, domain string) ([]Result, error)
	FetchIPs(ctx context.Context, domain string) ([]Result, error)
	FetchPorts(ctx context.Context, ip string) ([]Result, error)
}

// Manager manages multiple OSINT sources
type Manager struct {
	clients   map[Source]Client
	configs   map[Source]SourceConfig
	results   []Result
	mu        sync.RWMutex
	rateLimit *RateLimiter
}

// NewManager creates a new OSINT manager
func NewManager() *Manager {
	return &Manager{
		clients:   make(map[Source]Client),
		configs:   make(map[Source]SourceConfig),
		results:   make([]Result, 0),
		rateLimit: NewRateLimiter(60), // 60 requests per minute default
	}
}

// RegisterSource registers an OSINT source
func (m *Manager) RegisterSource(config SourceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.configs[config.Source] = config

	if !config.Enabled {
		return nil
	}

	var client Client
	switch config.Source {
	case SourceShodan:
		client = NewShodanClient(config.APIKey)
	case SourceCensys:
		client = NewCensysClient(config.APIKey, config.APISecret)
	case SourceCrtsh:
		client = NewCrtshClient()
	case SourceSecurityTrails:
		client = NewSecurityTrailsClient(config.APIKey)
	case SourceDNSDumpster:
		client = NewDNSDumpsterClient()
	case SourceChaos:
		client = NewChaosClient(config.APIKey)
	case SourceBinaryEdge:
		client = NewBinaryEdgeClient(config.APIKey)
	case SourceFullHunt:
		client = NewFullHuntClient(config.APIKey)
	default:
		return fmt.Errorf("unknown source: %s", config.Source)
	}

	if err := client.Validate(); err != nil {
		return fmt.Errorf("source %s validation failed: %w", config.Source, err)
	}

	m.clients[config.Source] = client
	return nil
}

// GetSources returns all registered sources
func (m *Manager) GetSources() []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sources := make([]Source, 0, len(m.clients))
	for s := range m.clients {
		sources = append(sources, s)
	}
	return sources
}

// FetchSubdomains queries all sources for subdomains
func (m *Manager) FetchSubdomains(ctx context.Context, domain string) ([]Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var wg sync.WaitGroup
	resultChan := make(chan []Result, len(m.clients))
	errChan := make(chan error, len(m.clients))

	for _, client := range m.clients {
		wg.Add(1)
		go func(c Client) {
			defer wg.Done()

			// Rate limit
			m.rateLimit.Wait()

			results, err := c.FetchSubdomains(ctx, domain)
			if err != nil {
				errChan <- fmt.Errorf("%s: %w", c.Name(), err)
				return
			}
			resultChan <- results
		}(client)
	}

	wg.Wait()
	close(resultChan)
	close(errChan)

	// Collect results
	var allResults []Result
	for results := range resultChan {
		allResults = append(allResults, results...)
	}

	// Deduplicate
	allResults = deduplicateResults(allResults)
	m.results = append(m.results, allResults...)

	return allResults, nil
}

// GetResults returns all collected results
func (m *Manager) GetResults() []Result {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.results
}

// Clear removes all results
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = make([]Result, 0)
}

// RateLimiter limits API request rates
type RateLimiter struct {
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a rate limiter
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	return &RateLimiter{
		tokens:     requestsPerMinute,
		maxTokens:  requestsPerMinute,
		refillRate: time.Minute / time.Duration(requestsPerMinute),
		lastRefill: time.Now(),
	}
}

// Wait blocks until a request token is available
func (r *RateLimiter) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Refill tokens based on elapsed time
	elapsed := time.Since(r.lastRefill)
	refillCount := int(elapsed / r.refillRate)
	if refillCount > 0 {
		r.tokens += refillCount
		if r.tokens > r.maxTokens {
			r.tokens = r.maxTokens
		}
		r.lastRefill = time.Now()
	}

	// Wait if no tokens available
	if r.tokens <= 0 {
		time.Sleep(r.refillRate)
		r.tokens = 1
	}

	r.tokens--
}

// Helper functions
func deduplicateResults(results []Result) []Result {
	seen := make(map[string]bool)
	var unique []Result
	for _, r := range results {
		key := fmt.Sprintf("%s:%s:%s", r.Source, r.Type, r.Value)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, r)
		}
	}
	return unique
}

// ExtractDomainFromURL extracts domain from URL
func ExtractDomainFromURL(rawURL string) (string, error) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

// IsValidDomain checks if a string is a valid domain
func IsValidDomain(domain string) bool {
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, domain)
	return matched
}
