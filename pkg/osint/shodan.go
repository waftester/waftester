package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

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
		httpClient: httpclient.Spraying(),
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

// redactAPIKey removes the API key from error messages to prevent leakage in logs.
func redactAPIKey(err error, key string) error {
	if err == nil || key == "" {
		return err
	}
	return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), key, "[REDACTED]"))
}

func (c *ShodanClient) FetchSubdomains(ctx context.Context, domain string) ([]Result, error) {
	url := fmt.Sprintf("%s/dns/domain/%s?key=%s", c.baseURL, domain, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, redactAPIKey(err, c.apiKey)
	}
	defer iohelper.DrainAndClose(resp.Body)

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
		return nil, redactAPIKey(err, c.apiKey)
	}
	defer iohelper.DrainAndClose(resp.Body)

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
		return nil, redactAPIKey(err, c.apiKey)
	}
	defer iohelper.DrainAndClose(resp.Body)

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
