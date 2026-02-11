package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

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
		httpClient: httpclient.Spraying(),
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
	defer iohelper.DrainAndClose(resp.Body)

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
	defer iohelper.DrainAndClose(resp.Body)

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
	defer iohelper.DrainAndClose(resp.Body)

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
