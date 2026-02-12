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
		httpClient: httpclient.Spraying(),
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
	defer iohelper.DrainAndClose(resp.Body)

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
	defer iohelper.DrainAndClose(resp.Body)

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
