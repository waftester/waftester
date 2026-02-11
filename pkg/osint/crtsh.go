package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// CrtshClient queries crt.sh certificate transparency logs
type CrtshClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewCrtshClient creates a crt.sh client
func NewCrtshClient() *CrtshClient {
	return &CrtshClient{
		httpClient: httpclient.New(httpclient.WithTimeout(duration.HTTPAPI)),
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
	defer iohelper.DrainAndClose(resp.Body)

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
