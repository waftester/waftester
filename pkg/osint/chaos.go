package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

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
		httpClient: httpclient.Spraying(),
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
	defer iohelper.DrainAndClose(resp.Body)

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
