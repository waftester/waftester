package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

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
		httpClient: httpclient.Spraying(),
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
	req.Header.Set("Content-Type", defaults.ContentTypeJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

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
	req.Header.Set("Content-Type", defaults.ContentTypeJSON)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

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
	defer iohelper.DrainAndClose(resp.Body)

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
