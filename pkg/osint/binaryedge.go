package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

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
		httpClient: httpclient.Spraying(),
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
	defer iohelper.DrainAndClose(resp.Body)

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
	defer iohelper.DrainAndClose(resp.Body)

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
	defer iohelper.DrainAndClose(resp.Body)

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
