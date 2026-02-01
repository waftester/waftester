// Package osint provides additional OSINT data sources for reconnaissance
package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/iohelper"
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

// ShodanClient implements Shodan API
type ShodanClient struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

// NewShodanClient creates a Shodan client
func NewShodanClient(apiKey string) *ShodanClient {
	return &ShodanClient{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.shodan.io",
	}
}

func (c *ShodanClient) Name() Source { return SourceShodan }

func (c *ShodanClient) Validate() error {
	if c.apiKey == "" {
		return fmt.Errorf("Shodan API key required")
	}
	return nil
}

func (c *ShodanClient) FetchSubdomains(ctx context.Context, domain string) ([]Result, error) {
	url := fmt.Sprintf("%s/dns/domain/%s?key=%s", c.baseURL, domain, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("shodan API error: %d", resp.StatusCode)
	}

	var data struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, sub := range data.Subdomains {
		results = append(results, Result{
			Source:    SourceShodan,
			Type:      "subdomain",
			Value:     sub + "." + domain,
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

func (c *ShodanClient) FetchIPs(ctx context.Context, domain string) ([]Result, error) {
	url := fmt.Sprintf("%s/dns/resolve?hostnames=%s&key=%s", c.baseURL, domain, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for host, ip := range data {
		results = append(results, Result{
			Source:    SourceShodan,
			Type:      "ip",
			Value:     ip,
			Metadata:  map[string]string{"host": host},
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

func (c *ShodanClient) FetchPorts(ctx context.Context, ip string) ([]Result, error) {
	url := fmt.Sprintf("%s/shodan/host/%s?key=%s", c.baseURL, ip, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		Ports []int `json:"ports"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, port := range data.Ports {
		results = append(results, Result{
			Source:    SourceShodan,
			Type:      "port",
			Value:     fmt.Sprintf("%d", port),
			Metadata:  map[string]string{"ip": ip},
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

// CensysClient implements Censys API
type CensysClient struct {
	apiKey     string
	apiSecret  string
	httpClient *http.Client
	baseURL    string
}

// NewCensysClient creates a Censys client
func NewCensysClient(apiKey, apiSecret string) *CensysClient {
	return &CensysClient{
		apiKey:     apiKey,
		apiSecret:  apiSecret,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://search.censys.io/api/v2",
	}
}

func (c *CensysClient) Name() Source { return SourceCensys }

func (c *CensysClient) Validate() error {
	if c.apiKey == "" || c.apiSecret == "" {
		return fmt.Errorf("Censys API key and secret required")
	}
	return nil
}

func (c *CensysClient) FetchSubdomains(ctx context.Context, domain string) ([]Result, error) {
	endpoint := fmt.Sprintf("%s/hosts/search", c.baseURL)
	query := fmt.Sprintf("names: %s", domain)

	body := fmt.Sprintf(`{"q": "%s", "per_page": 100}`, query)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.apiKey, c.apiSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("censys API error: %d", resp.StatusCode)
	}

	var data struct {
		Result struct {
			Hits []struct {
				Name string `json:"name"`
			} `json:"hits"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, hit := range data.Result.Hits {
		if strings.HasSuffix(hit.Name, domain) {
			results = append(results, Result{
				Source:    SourceCensys,
				Type:      "subdomain",
				Value:     hit.Name,
				Timestamp: time.Now(),
			})
		}
	}

	return results, nil
}

func (c *CensysClient) FetchIPs(ctx context.Context, domain string) ([]Result, error) {
	// Censys provides IP addresses for hosts
	endpoint := fmt.Sprintf("%s/hosts/search", c.baseURL)
	query := fmt.Sprintf("names: %s", domain)

	body := fmt.Sprintf(`{"q": "%s", "per_page": 100}`, query)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.apiKey, c.apiSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Censys API error: %d", resp.StatusCode)
	}

	var data struct {
		Result struct {
			Hits []struct {
				IP string `json:"ip"`
			} `json:"hits"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	seen := make(map[string]bool)

	for _, hit := range data.Result.Hits {
		if !seen[hit.IP] {
			seen[hit.IP] = true
			results = append(results, Result{
				Source:    SourceCensys,
				Type:      "ip",
				Value:     hit.IP,
				Metadata:  map[string]string{"domain": domain},
				Timestamp: time.Now(),
			})
		}
	}

	return results, nil
}

func (c *CensysClient) FetchPorts(ctx context.Context, ip string) ([]Result, error) {
	// Censys provides detailed port information for hosts
	endpoint := fmt.Sprintf("%s/hosts/%s", c.baseURL, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.apiKey, c.apiSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Censys API error: %d", resp.StatusCode)
	}

	var data struct {
		Result struct {
			Services []struct {
				Port        int    `json:"port"`
				ServiceName string `json:"service_name"`
				Transport   string `json:"transport_protocol"`
			} `json:"services"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, svc := range data.Result.Services {
		results = append(results, Result{
			Source: SourceCensys,
			Type:   "port",
			Value:  fmt.Sprintf("%d", svc.Port),
			Metadata: map[string]string{
				"ip":        ip,
				"service":   svc.ServiceName,
				"transport": svc.Transport,
			},
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

// CrtshClient queries crt.sh certificate transparency logs
type CrtshClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewCrtshClient creates a crt.sh client
func NewCrtshClient() *CrtshClient {
	return &CrtshClient{
		httpClient: &http.Client{Timeout: 60 * time.Second},
		baseURL:    "https://crt.sh",
	}
}

func (c *CrtshClient) Name() Source { return SourceCrtsh }

func (c *CrtshClient) Validate() error {
	return nil // No API key required
}

func (c *CrtshClient) FetchSubdomains(ctx context.Context, domain string) ([]Result, error) {
	url := fmt.Sprintf("%s/?q=%%.%s&output=json", c.baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh error: %d", resp.StatusCode)
	}

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		// crt.sh might return empty array or error
		return []Result{}, nil
	}

	seen := make(map[string]bool)
	var results []Result
	for _, entry := range entries {
		// Handle wildcard and multi-domain certs
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimPrefix(name, "*.")
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true

			if strings.HasSuffix(name, domain) {
				results = append(results, Result{
					Source:    SourceCrtsh,
					Type:      "subdomain",
					Value:     name,
					Timestamp: time.Now(),
				})
			}
		}
	}

	return results, nil
}

func (c *CrtshClient) FetchIPs(ctx context.Context, domain string) ([]Result, error) {
	// crt.sh doesn't provide IP addresses directly - it only has certificate data
	// To get IPs, we would need to resolve the discovered subdomains via DNS
	// This requires the net package's LookupIP function

	// First, fetch subdomains
	subdomains, err := c.FetchSubdomains(ctx, domain)
	if err != nil {
		return nil, err
	}

	var results []Result
	seen := make(map[string]bool)

	for _, sub := range subdomains {
		// Resolve each subdomain to IPs
		ips, err := net.LookupIP(sub.Value)
		if err != nil {
			continue // Skip unresolvable domains
		}

		for _, ip := range ips {
			ipStr := ip.String()
			if !seen[ipStr] {
				seen[ipStr] = true
				results = append(results, Result{
					Source:    SourceCrtsh,
					Type:      "ip",
					Value:     ipStr,
					Metadata:  map[string]string{"domain": sub.Value},
					Timestamp: time.Now(),
				})
			}
		}
	}

	return results, nil
}

func (c *CrtshClient) FetchPorts(ctx context.Context, ip string) ([]Result, error) {
	// crt.sh doesn't provide port information - it's a certificate transparency log
	// Port scanning requires active probing or a service like Shodan
	return nil, fmt.Errorf("crt.sh does not provide port information; use Shodan or Censys for port data")
}

// SecurityTrailsClient implements SecurityTrails API
type SecurityTrailsClient struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

// NewSecurityTrailsClient creates a SecurityTrails client
func NewSecurityTrailsClient(apiKey string) *SecurityTrailsClient {
	return &SecurityTrailsClient{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.securitytrails.com/v1",
	}
}

func (c *SecurityTrailsClient) Name() Source { return SourceSecurityTrails }

func (c *SecurityTrailsClient) Validate() error {
	if c.apiKey == "" {
		return fmt.Errorf("SecurityTrails API key required")
	}
	return nil
}

func (c *SecurityTrailsClient) FetchSubdomains(ctx context.Context, domain string) ([]Result, error) {
	url := fmt.Sprintf("%s/domain/%s/subdomains", c.baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("SecurityTrails API error: %d", resp.StatusCode)
	}

	var data struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, sub := range data.Subdomains {
		results = append(results, Result{
			Source:    SourceSecurityTrails,
			Type:      "subdomain",
			Value:     sub + "." + domain,
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

func (c *SecurityTrailsClient) FetchIPs(ctx context.Context, domain string) ([]Result, error) {
	// SecurityTrails has a DNS history endpoint that includes IP addresses
	url := fmt.Sprintf("%s/domain/%s/dns", c.baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("SecurityTrails API error: %d", resp.StatusCode)
	}

	var data struct {
		CurrentDNS struct {
			A struct {
				Values []struct {
					IP string `json:"ip"`
				} `json:"values"`
			} `json:"a"`
		} `json:"current_dns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, v := range data.CurrentDNS.A.Values {
		results = append(results, Result{
			Source:    SourceSecurityTrails,
			Type:      "ip",
			Value:     v.IP,
			Metadata:  map[string]string{"domain": domain},
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

func (c *SecurityTrailsClient) FetchPorts(ctx context.Context, ip string) ([]Result, error) {
	// SecurityTrails doesn't provide port information - it's primarily a DNS intelligence platform
	return nil, fmt.Errorf("SecurityTrails does not provide port data; use Shodan or Censys for port scanning")
}

// DNSDumpsterClient scrapes DNSDumpster
type DNSDumpsterClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewDNSDumpsterClient creates a DNSDumpster client
func NewDNSDumpsterClient() *DNSDumpsterClient {
	return &DNSDumpsterClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://dnsdumpster.com",
	}
}

func (c *DNSDumpsterClient) Name() Source { return SourceDNSDumpster }

func (c *DNSDumpsterClient) Validate() error {
	return nil // No API key required
}

func (c *DNSDumpsterClient) FetchSubdomains(ctx context.Context, domain string) ([]Result, error) {
	// DNSDumpster requires CSRF token and form submission
	// Simplified implementation - in production would need proper scraping
	return []Result{}, nil
}

func (c *DNSDumpsterClient) FetchIPs(ctx context.Context, domain string) ([]Result, error) {
	// DNSDumpster provides IP data but requires session-based scraping
	// For now, fall back to DNS resolution of the main domain
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}

	var results []Result
	for _, ip := range ips {
		results = append(results, Result{
			Source:    SourceDNSDumpster,
			Type:      "ip",
			Value:     ip.String(),
			Metadata:  map[string]string{"domain": domain},
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

func (c *DNSDumpsterClient) FetchPorts(ctx context.Context, ip string) ([]Result, error) {
	// DNSDumpster doesn't provide port information
	return nil, fmt.Errorf("DNSDumpster does not provide port data; use Shodan or Censys for port scanning")
}

// ChaosClient implements ProjectDiscovery Chaos API
type ChaosClient struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

// NewChaosClient creates a Chaos client
func NewChaosClient(apiKey string) *ChaosClient {
	return &ChaosClient{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://dns.projectdiscovery.io",
	}
}

func (c *ChaosClient) Name() Source { return SourceChaos }

func (c *ChaosClient) Validate() error {
	if c.apiKey == "" {
		return fmt.Errorf("Chaos API key required")
	}
	return nil
}

func (c *ChaosClient) FetchSubdomains(ctx context.Context, domain string) ([]Result, error) {
	url := fmt.Sprintf("%s/dns/%s/subdomains", c.baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Chaos API error: %d", resp.StatusCode)
	}

	var data struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, sub := range data.Subdomains {
		results = append(results, Result{
			Source:    SourceChaos,
			Type:      "subdomain",
			Value:     sub + "." + domain,
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

func (c *ChaosClient) FetchIPs(ctx context.Context, domain string) ([]Result, error) {
	// Chaos is primarily a subdomain discovery service
	// We can resolve the discovered subdomains to get IPs
	subdomains, err := c.FetchSubdomains(ctx, domain)
	if err != nil {
		return nil, err
	}

	var results []Result
	seen := make(map[string]bool)

	for _, sub := range subdomains {
		ips, err := net.LookupIP(sub.Value)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			ipStr := ip.String()
			if !seen[ipStr] {
				seen[ipStr] = true
				results = append(results, Result{
					Source:    SourceChaos,
					Type:      "ip",
					Value:     ipStr,
					Metadata:  map[string]string{"domain": sub.Value},
					Timestamp: time.Now(),
				})
			}
		}
	}

	return results, nil
}

func (c *ChaosClient) FetchPorts(ctx context.Context, ip string) ([]Result, error) {
	// Chaos doesn't provide port information
	return nil, fmt.Errorf("Chaos does not provide port data; use Shodan or BinaryEdge for port scanning")
}

// BinaryEdgeClient implements BinaryEdge API
type BinaryEdgeClient struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

// NewBinaryEdgeClient creates a BinaryEdge client
func NewBinaryEdgeClient(apiKey string) *BinaryEdgeClient {
	return &BinaryEdgeClient{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.binaryedge.io/v2",
	}
}

func (c *BinaryEdgeClient) Name() Source { return SourceBinaryEdge }

func (c *BinaryEdgeClient) Validate() error {
	if c.apiKey == "" {
		return fmt.Errorf("BinaryEdge API key required")
	}
	return nil
}

func (c *BinaryEdgeClient) FetchSubdomains(ctx context.Context, domain string) ([]Result, error) {
	url := fmt.Sprintf("%s/query/domains/subdomain/%s", c.baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("BinaryEdge API error: %d", resp.StatusCode)
	}

	var data struct {
		Events []string `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, sub := range data.Events {
		results = append(results, Result{
			Source:    SourceBinaryEdge,
			Type:      "subdomain",
			Value:     sub,
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

func (c *BinaryEdgeClient) FetchIPs(ctx context.Context, domain string) ([]Result, error) {
	// BinaryEdge has IP data in its host endpoint
	url := fmt.Sprintf("%s/query/domains/dns/%s", c.baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("BinaryEdge API error: %d", resp.StatusCode)
	}

	var data struct {
		Events []struct {
			A []string `json:"A"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	seen := make(map[string]bool)

	for _, event := range data.Events {
		for _, ip := range event.A {
			if !seen[ip] {
				seen[ip] = true
				results = append(results, Result{
					Source:    SourceBinaryEdge,
					Type:      "ip",
					Value:     ip,
					Metadata:  map[string]string{"domain": domain},
					Timestamp: time.Now(),
				})
			}
		}
	}

	return results, nil
}

func (c *BinaryEdgeClient) FetchPorts(ctx context.Context, ip string) ([]Result, error) {
	// BinaryEdge has excellent port scanning data
	url := fmt.Sprintf("%s/query/ip/%s", c.baseURL, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("BinaryEdge API error: %d", resp.StatusCode)
	}

	var data struct {
		Events []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Service  string `json:"service"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, event := range data.Events {
		results = append(results, Result{
			Source: SourceBinaryEdge,
			Type:   "port",
			Value:  fmt.Sprintf("%d", event.Port),
			Metadata: map[string]string{
				"ip":       ip,
				"protocol": event.Protocol,
				"service":  event.Service,
			},
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

// FullHuntClient implements FullHunt API
type FullHuntClient struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
}

// NewFullHuntClient creates a FullHunt client
func NewFullHuntClient(apiKey string) *FullHuntClient {
	return &FullHuntClient{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://fullhunt.io/api/v1",
	}
}

func (c *FullHuntClient) Name() Source { return SourceFullHunt }

func (c *FullHuntClient) Validate() error {
	if c.apiKey == "" {
		return fmt.Errorf("FullHunt API key required")
	}
	return nil
}

func (c *FullHuntClient) FetchSubdomains(ctx context.Context, domain string) ([]Result, error) {
	endpoint := fmt.Sprintf("%s/domain/%s/subdomains", c.baseURL, url.PathEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("FullHunt API error: %d", resp.StatusCode)
	}

	var data struct {
		Hosts []string `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, host := range data.Hosts {
		results = append(results, Result{
			Source:    SourceFullHunt,
			Type:      "subdomain",
			Value:     host,
			Timestamp: time.Now(),
		})
	}

	return results, nil
}

func (c *FullHuntClient) FetchIPs(ctx context.Context, domain string) ([]Result, error) {
	// FullHunt provides host details including IP addresses
	endpoint := fmt.Sprintf("%s/domain/%s/details", c.baseURL, url.PathEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("FullHunt API error: %d", resp.StatusCode)
	}

	var data struct {
		Hosts []struct {
			Host string   `json:"host"`
			IPs  []string `json:"ip_addresses"`
		} `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	seen := make(map[string]bool)

	for _, host := range data.Hosts {
		for _, ip := range host.IPs {
			if !seen[ip] {
				seen[ip] = true
				results = append(results, Result{
					Source:    SourceFullHunt,
					Type:      "ip",
					Value:     ip,
					Metadata:  map[string]string{"host": host.Host},
					Timestamp: time.Now(),
				})
			}
		}
	}

	return results, nil
}

func (c *FullHuntClient) FetchPorts(ctx context.Context, ip string) ([]Result, error) {
	// FullHunt provides port data for hosts
	endpoint := fmt.Sprintf("%s/host/%s", c.baseURL, ip)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("FullHunt API error: %d", resp.StatusCode)
	}

	var data struct {
		Ports []struct {
			Port    int    `json:"port"`
			Service string `json:"service"`
		} `json:"ports"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var results []Result
	for _, port := range data.Ports {
		results = append(results, Result{
			Source: SourceFullHunt,
			Type:   "port",
			Value:  fmt.Sprintf("%d", port.Port),
			Metadata: map[string]string{
				"ip":      ip,
				"service": port.Service,
			},
			Timestamp: time.Now(),
		})
	}

	return results, nil
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
