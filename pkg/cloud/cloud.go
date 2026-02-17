// Package cloud provides cloud provider integration for target discovery
package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// ErrNotImplemented is returned by cloud provider stubs that require SDK integration.
var ErrNotImplemented = errors.New("cloud: not yet implemented")

// Provider represents a cloud service provider
type Provider string

const (
	ProviderAWS          Provider = "aws"
	ProviderGCP          Provider = "gcp"
	ProviderAzure        Provider = "azure"
	ProviderDigitalOcean Provider = "digitalocean"
	ProviderCloudflare   Provider = "cloudflare"
	ProviderAkamai       Provider = "akamai"
	ProviderOracle       Provider = "oracle"
)

// Resource represents a discovered cloud resource
type Resource struct {
	Provider     Provider          `json:"provider"`
	Type         string            `json:"type"` // instance, load_balancer, cdn, storage, etc.
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Region       string            `json:"region"`
	Endpoints    []string          `json:"endpoints"` // URLs, IPs, domains
	PublicIPs    []string          `json:"public_ips,omitempty"`
	PrivateIPs   []string          `json:"private_ips,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	DiscoveredAt time.Time         `json:"discovered_at"`
	Accessible   bool              `json:"accessible,omitempty"` // Whether resource is publicly accessible
	URL          string            `json:"url,omitempty"`        // Primary URL for the resource
	Details      map[string]string `json:"details,omitempty"`    // Additional resource details
}

// ResourceType represents a type of cloud resource
type ResourceType string

const (
	TypeStorage      ResourceType = "storage"
	TypeCompute      ResourceType = "compute"
	TypeDatabase     ResourceType = "database"
	TypeLoadBalancer ResourceType = "load_balancer"
	TypeCDN          ResourceType = "cdn"
	TypeFunction     ResourceType = "function"
	TypeFunctions    ResourceType = "functions"
	TypeContainer    ResourceType = "container"
	TypeAPIGateway   ResourceType = "api_gateway"
	TypeAPI          ResourceType = "api"
	TypeDNS          ResourceType = "dns"
	TypeVPC          ResourceType = "vpc"
)

// DiscovererConfig configures a cloud resource discoverer
type DiscovererConfig struct {
	Providers    []Provider        // Which cloud providers to scan
	Regions      []string          // Specific regions to scan
	Credentials  map[string]string // Provider credentials
	Timeout      time.Duration     // Discovery timeout
	MaxResults   int               // Maximum resources per type
	PublicOnly   bool              // Only discover publicly accessible resources
	Concurrency  int               // Number of concurrent requests
	RateLimit    float64           // Requests per second
	PassiveOnly  bool              // Only use passive discovery techniques
	UseCT        bool              // Use Certificate Transparency logs
	UseDNS       bool              // Use DNS enumeration
	WordlistPath string            // Path to wordlist for brute forcing
}

// DiscoveryRequest represents a request for cloud resource discovery
type DiscoveryRequest struct {
	Types     []ResourceType // Resource types to discover
	Regions   []string       // Regions to scan
	Tags      map[string]string
	Domain    string     // Target domain
	OrgName   string     // Organization name
	Providers []Provider // Cloud providers to scan
}

// DiscoveryResults holds the results of a cloud discovery
type DiscoveryResults struct {
	Resources []*Resource `json:"resources"`
	Targets   []string    `json:"targets"`
	Stats     *DiscoveryStats
}

// Discoverer provides cloud resource discovery functionality
type Discoverer struct {
	config  DiscovererConfig
	manager *Manager
}

// NewDiscoverer creates a new cloud discoverer
func NewDiscoverer(config DiscovererConfig) *Discoverer {
	d := &Discoverer{
		config:  config,
		manager: NewManager(),
	}
	return d
}

// Discover finds cloud resources matching the request
func (d *Discoverer) Discover(ctx context.Context, req DiscoveryRequest) (*DiscoveryResults, error) {
	// Use providers from request if specified, otherwise use config
	providers := req.Providers
	if len(providers) == 0 {
		providers = d.config.Providers
	}

	// Register clients based on available credentials
	for _, provider := range providers {
		if _, exists := d.manager.GetClient(provider); !exists {
			switch provider {
			case ProviderAWS:
				if d.config.Credentials != nil {
					if accessKey, ok := d.config.Credentials["aws_access_key"]; ok {
						secretKey := d.config.Credentials["aws_secret_key"]
						regions := d.config.Regions
						if len(regions) == 0 {
							regions = []string{"us-east-1"}
						}
						client := NewAWSClient(accessKey, secretKey, regions[0])
						d.manager.RegisterClient(client)
					}
				}
			case ProviderAzure:
				if d.config.Credentials != nil {
					if tenantID, ok := d.config.Credentials["azure_tenant_id"]; ok {
						clientID := d.config.Credentials["azure_client_id"]
						clientSecret := d.config.Credentials["azure_client_secret"]
						subID := d.config.Credentials["azure_subscription_id"]
						client := NewAzureClient(subID, tenantID, clientID, clientSecret)
						d.manager.RegisterClient(client)
					}
				}
			case ProviderGCP:
				if d.config.Credentials != nil {
					if projectID, ok := d.config.Credentials["gcp_project_id"]; ok {
						client := NewGCPClient(projectID, d.config.Credentials["gcp_credentials_file"])
						d.manager.RegisterClient(client)
					}
				}
			}
		}
	}

	filter := &Filter{
		Regions:    req.Regions,
		Types:      resourceTypesToStrings(req.Types),
		Tags:       req.Tags,
		PublicOnly: d.config.PublicOnly,
		MaxResults: d.config.MaxResults,
	}

	resources, err := d.manager.DiscoverAll(ctx, filter)
	if err != nil {
		return nil, err
	}

	targets := d.manager.ExtractTargets(resources)

	return &DiscoveryResults{
		Resources: resources,
		Targets:   targets,
	}, nil
}

// resourceTypesToStrings converts ResourceType slice to string slice
func resourceTypesToStrings(types []ResourceType) []string {
	result := make([]string, len(types))
	for i, t := range types {
		result[i] = string(t)
	}
	return result
}

// CloudClient is the interface for cloud provider clients
type CloudClient interface {
	// Provider returns the provider name
	Provider() Provider

	// Discover finds resources matching the filter
	Discover(ctx context.Context, filter *Filter) ([]*Resource, error)

	// GetResource retrieves a specific resource by ID
	GetResource(ctx context.Context, resourceType, id string) (*Resource, error)

	// ListRegions returns available regions
	ListRegions(ctx context.Context) ([]string, error)

	// Validate checks if credentials are valid
	Validate(ctx context.Context) error
}

// Filter defines discovery filtering options
type Filter struct {
	Regions     []string          // Filter by regions
	Types       []string          // Resource types: instance, load_balancer, etc.
	Tags        map[string]string // Filter by tags
	NamePattern string            // Filter by name pattern (glob)
	PublicOnly  bool              // Only resources with public endpoints
	MaxResults  int               // Maximum results per resource type
}

// Manager orchestrates multi-cloud discovery
type Manager struct {
	clients  map[Provider]CloudClient
	mu       sync.RWMutex
	cache    map[string][]*Resource
	cacheTTL time.Duration
}

// NewManager creates a new cloud manager
func NewManager() *Manager {
	return &Manager{
		clients:  make(map[Provider]CloudClient),
		cache:    make(map[string][]*Resource),
		cacheTTL: duration.CacheMedium,
	}
}

// RegisterClient registers a cloud provider client
func (m *Manager) RegisterClient(client CloudClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[client.Provider()] = client
}

// GetClient returns a registered client
func (m *Manager) GetClient(provider Provider) (CloudClient, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client, ok := m.clients[provider]
	return client, ok
}

// ListProviders returns registered providers
func (m *Manager) ListProviders() []Provider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	providers := make([]Provider, 0, len(m.clients))
	for p := range m.clients {
		providers = append(providers, p)
	}
	return providers
}

// DiscoverAll runs discovery across all registered providers
func (m *Manager) DiscoverAll(ctx context.Context, filter *Filter) ([]*Resource, error) {
	m.mu.RLock()
	clients := make([]CloudClient, 0, len(m.clients))
	for _, c := range m.clients {
		clients = append(clients, c)
	}
	m.mu.RUnlock()

	var wg sync.WaitGroup
	results := make(chan []*Resource, len(clients))
	errors := make(chan error, len(clients))

	for _, client := range clients {
		wg.Add(1)
		go func(c CloudClient) {
			defer wg.Done()
			resources, err := c.Discover(ctx, filter)
			if err != nil {
				errors <- fmt.Errorf("%s: %w", c.Provider(), err)
				return
			}
			results <- resources
		}(client)
	}

	wg.Wait()
	close(results)
	close(errors)

	var allResources []*Resource
	for resources := range results {
		allResources = append(allResources, resources...)
	}

	// Collect errors
	var errs []string
	for err := range errors {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return allResources, fmt.Errorf("discovery errors: %s", strings.Join(errs, "; "))
	}

	return allResources, nil
}

// ExtractTargets converts resources to scannable target URLs
func (m *Manager) ExtractTargets(resources []*Resource) []string {
	targetSet := make(map[string]bool)

	for _, r := range resources {
		// Add endpoints
		for _, ep := range r.Endpoints {
			if ep != "" {
				targetSet[normalizeEndpoint(ep)] = true
			}
		}

		// Add public IPs
		for _, ip := range r.PublicIPs {
			if ip != "" {
				targetSet[fmt.Sprintf("http://%s", ip)] = true
			}
		}
	}

	targets := make([]string, 0, len(targetSet))
	for t := range targetSet {
		targets = append(targets, t)
	}
	return targets
}

// normalizeEndpoint ensures a URL has a scheme
func normalizeEndpoint(ep string) string {
	if strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") {
		return ep
	}
	return "https://" + ep
}

// AWSClient implements CloudClient for AWS
type AWSClient struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
	httpClient      *http.Client
}

// NewAWSClient creates a new AWS client
func NewAWSClient(accessKeyID, secretAccessKey, region string) *AWSClient {
	return &AWSClient{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Region:          region,
		httpClient:      httpclient.Default(),
	}
}

func (c *AWSClient) Provider() Provider {
	return ProviderAWS
}

func (c *AWSClient) Discover(ctx context.Context, filter *Filter) ([]*Resource, error) {
	var resources []*Resource

	// Discover EC2 instances
	if filter == nil || len(filter.Types) == 0 || slices.Contains(filter.Types, "instance") {
		instances, err := c.discoverEC2(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("EC2 discovery: %w", err)
		}
		resources = append(resources, instances...)
	}

	// Discover Load Balancers
	if filter == nil || len(filter.Types) == 0 || slices.Contains(filter.Types, "load_balancer") {
		lbs, err := c.discoverELB(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("ELB discovery: %w", err)
		}
		resources = append(resources, lbs...)
	}

	// Discover CloudFront distributions
	if filter == nil || len(filter.Types) == 0 || slices.Contains(filter.Types, "cdn") {
		cdns, err := c.discoverCloudFront(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("CloudFront discovery: %w", err)
		}
		resources = append(resources, cdns...)
	}

	// Discover API Gateway
	if filter == nil || len(filter.Types) == 0 || slices.Contains(filter.Types, "api_gateway") {
		apis, err := c.discoverAPIGateway(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("API Gateway discovery: %w", err)
		}
		resources = append(resources, apis...)
	}

	return resources, nil
}

func (c *AWSClient) discoverEC2(ctx context.Context, _ *Filter) ([]*Resource, error) {
	return nil, ErrNotImplemented
}

func (c *AWSClient) discoverELB(ctx context.Context, _ *Filter) ([]*Resource, error) {
	return nil, ErrNotImplemented
}

func (c *AWSClient) discoverCloudFront(ctx context.Context, _ *Filter) ([]*Resource, error) {
	return nil, ErrNotImplemented
}

func (c *AWSClient) discoverAPIGateway(ctx context.Context, _ *Filter) ([]*Resource, error) {
	return nil, ErrNotImplemented
}

func (c *AWSClient) GetResource(ctx context.Context, resourceType, id string) (*Resource, error) {
	// AWS SDK integration for specific resource lookup
	// Real implementation would use type-specific AWS SDK calls:
	// - ec2.DescribeInstances for instances
	// - elbv2.DescribeLoadBalancers for load_balancer
	// - cloudfront.GetDistribution for cdn
	// - apigateway.GetRestApi for api_gateway

	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil, fmt.Errorf("AWS credentials required for resource lookup")
	}

	switch resourceType {
	case "instance":
		// ec2.DescribeInstances with InstanceIds filter
		return nil, fmt.Errorf("EC2 instance lookup requires AWS SDK: go get github.com/aws/aws-sdk-go-v2")
	case "load_balancer":
		return nil, fmt.Errorf("ELB lookup requires AWS SDK: go get github.com/aws/aws-sdk-go-v2")
	case "cdn":
		return nil, fmt.Errorf("CloudFront lookup requires AWS SDK: go get github.com/aws/aws-sdk-go-v2")
	case "api_gateway":
		return nil, fmt.Errorf("API Gateway lookup requires AWS SDK: go get github.com/aws/aws-sdk-go-v2")
	default:
		return nil, fmt.Errorf("unknown resource type: %s", resourceType)
	}
}

func (c *AWSClient) ListRegions(ctx context.Context) ([]string, error) {
	return []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
		"ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
		"sa-east-1", "ca-central-1",
	}, nil
}

func (c *AWSClient) Validate(ctx context.Context) error {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return fmt.Errorf("missing AWS credentials")
	}
	return nil
}

// GCPClient implements CloudClient for Google Cloud Platform
type GCPClient struct {
	ProjectID      string
	ServiceAccount string // JSON key file path or content
	httpClient     *http.Client
}

// NewGCPClient creates a new GCP client
func NewGCPClient(projectID, serviceAccount string) *GCPClient {
	return &GCPClient{
		ProjectID:      projectID,
		ServiceAccount: serviceAccount,
		httpClient:     httpclient.Default(),
	}
}

func (c *GCPClient) Provider() Provider {
	return ProviderGCP
}

func (c *GCPClient) Discover(ctx context.Context, filter *Filter) ([]*Resource, error) {
	var resources []*Resource

	// Discover Compute Engine instances
	if filter == nil || len(filter.Types) == 0 || slices.Contains(filter.Types, "instance") {
		instances, err := c.discoverCompute(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("Compute discovery: %w", err)
		}
		resources = append(resources, instances...)
	}

	// Discover Load Balancers
	if filter == nil || len(filter.Types) == 0 || slices.Contains(filter.Types, "load_balancer") {
		lbs, err := c.discoverLoadBalancers(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("LB discovery: %w", err)
		}
		resources = append(resources, lbs...)
	}

	// Discover Cloud Run services
	if filter == nil || len(filter.Types) == 0 || slices.Contains(filter.Types, "serverless") {
		runs, err := c.discoverCloudRun(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("Cloud Run discovery: %w", err)
		}
		resources = append(resources, runs...)
	}

	return resources, nil
}

func (c *GCPClient) discoverCompute(ctx context.Context, _ *Filter) ([]*Resource, error) {
	return nil, ErrNotImplemented
}

func (c *GCPClient) discoverLoadBalancers(ctx context.Context, _ *Filter) ([]*Resource, error) {
	return nil, ErrNotImplemented
}

func (c *GCPClient) discoverCloudRun(ctx context.Context, _ *Filter) ([]*Resource, error) {
	return nil, ErrNotImplemented
}

func (c *GCPClient) GetResource(ctx context.Context, resourceType, id string) (*Resource, error) {
	// GCP SDK integration for specific resource lookup
	// Real implementation would use type-specific GCP SDK calls:
	// - compute.InstancesClient.Get for instances
	// - compute.ForwardingRulesClient.Get for load_balancer
	// - run.ServicesClient.GetService for serverless

	if c.ProjectID == "" {
		return nil, fmt.Errorf("GCP project ID required for resource lookup")
	}

	switch resourceType {
	case "instance":
		return nil, fmt.Errorf("Compute Engine instance lookup requires GCP SDK: go get cloud.google.com/go/compute")
	case "load_balancer":
		return nil, fmt.Errorf("load balancer lookup requires GCP SDK: go get cloud.google.com/go/compute")
	case "serverless":
		return nil, fmt.Errorf("Cloud Run lookup requires GCP SDK: go get cloud.google.com/go/run")
	default:
		return nil, fmt.Errorf("unknown resource type: %s", resourceType)
	}
}

func (c *GCPClient) ListRegions(ctx context.Context) ([]string, error) {
	return []string{
		"us-central1", "us-east1", "us-west1", "us-west2",
		"europe-west1", "europe-west2", "europe-west3", "europe-west4",
		"asia-east1", "asia-northeast1", "asia-southeast1",
		"australia-southeast1", "southamerica-east1",
	}, nil
}

func (c *GCPClient) Validate(ctx context.Context) error {
	if c.ProjectID == "" {
		return fmt.Errorf("missing GCP project ID")
	}
	return nil
}

// AzureClient implements CloudClient for Microsoft Azure
type AzureClient struct {
	SubscriptionID string
	TenantID       string
	ClientID       string
	ClientSecret   string
	httpClient     *http.Client
}

// NewAzureClient creates a new Azure client
func NewAzureClient(subscriptionID, tenantID, clientID, clientSecret string) *AzureClient {
	return &AzureClient{
		SubscriptionID: subscriptionID,
		TenantID:       tenantID,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		httpClient:     httpclient.Default(),
	}
}

func (c *AzureClient) Provider() Provider {
	return ProviderAzure
}

func (c *AzureClient) Discover(ctx context.Context, filter *Filter) ([]*Resource, error) {
	var resources []*Resource

	// Discover VMs
	if filter == nil || len(filter.Types) == 0 || slices.Contains(filter.Types, "instance") {
		vms, err := c.discoverVMs(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("VM discovery: %w", err)
		}
		resources = append(resources, vms...)
	}

	// Discover App Services
	if filter == nil || len(filter.Types) == 0 || slices.Contains(filter.Types, "app_service") {
		apps, err := c.discoverAppServices(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("App Service discovery: %w", err)
		}
		resources = append(resources, apps...)
	}

	// Discover Front Door / CDN
	if filter == nil || len(filter.Types) == 0 || slices.Contains(filter.Types, "cdn") {
		cdns, err := c.discoverFrontDoor(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("Front Door discovery: %w", err)
		}
		resources = append(resources, cdns...)
	}

	return resources, nil
}

func (c *AzureClient) discoverVMs(ctx context.Context, _ *Filter) ([]*Resource, error) {
	return nil, ErrNotImplemented
}

func (c *AzureClient) discoverAppServices(ctx context.Context, _ *Filter) ([]*Resource, error) {
	return nil, ErrNotImplemented
}

func (c *AzureClient) discoverFrontDoor(ctx context.Context, _ *Filter) ([]*Resource, error) {
	return nil, ErrNotImplemented
}

func (c *AzureClient) GetResource(ctx context.Context, resourceType, id string) (*Resource, error) {
	// Azure SDK integration for specific resource lookup
	// Real implementation would use type-specific Azure SDK calls:
	// - armcompute.VirtualMachinesClient.Get for instances
	// - armappservice.WebAppsClient.Get for app_service
	// - armfrontdoor.FrontDoorsClient.Get for cdn

	if c.SubscriptionID == "" {
		return nil, fmt.Errorf("Azure subscription ID required for resource lookup")
	}

	switch resourceType {
	case "instance":
		return nil, fmt.Errorf("VM lookup requires Azure SDK: go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute")
	case "app_service":
		return nil, fmt.Errorf("App Service lookup requires Azure SDK: go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice")
	case "cdn":
		return nil, fmt.Errorf("Front Door lookup requires Azure SDK: go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor")
	default:
		return nil, fmt.Errorf("unknown resource type: %s", resourceType)
	}
}

func (c *AzureClient) ListRegions(ctx context.Context) ([]string, error) {
	return []string{
		"eastus", "eastus2", "westus", "westus2", "centralus",
		"northeurope", "westeurope", "uksouth", "ukwest",
		"eastasia", "southeastasia", "japaneast", "japanwest",
		"australiaeast", "australiasoutheast", "brazilsouth",
	}, nil
}

func (c *AzureClient) Validate(ctx context.Context) error {
	if c.SubscriptionID == "" || c.TenantID == "" {
		return fmt.Errorf("missing Azure credentials")
	}
	return nil
}

// IPRangeChecker validates if IPs belong to known cloud providers
type IPRangeChecker struct {
	awsRanges   []net.IPNet
	gcpRanges   []net.IPNet
	azureRanges []net.IPNet
	mu          sync.RWMutex
}

// NewIPRangeChecker creates a new IP range checker
func NewIPRangeChecker() *IPRangeChecker {
	return &IPRangeChecker{}
}

// LoadAWSRanges loads AWS IP ranges from the published JSON
func (c *IPRangeChecker) LoadAWSRanges(ctx context.Context) error {
	// AWS publishes IP ranges at https://ip-ranges.amazonaws.com/ip-ranges.json
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ip-ranges.amazonaws.com/ip-ranges.json", nil)
	if err != nil {
		return err
	}
	resp, err := httpclient.Default().Do(req)
	if err != nil {
		return err
	}
	defer iohelper.DrainAndClose(resp.Body)

	var data struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.awsRanges = make([]net.IPNet, 0, len(data.Prefixes))
	for _, p := range data.Prefixes {
		_, ipNet, err := net.ParseCIDR(p.IPPrefix)
		if err == nil {
			c.awsRanges = append(c.awsRanges, *ipNet)
		}
	}
	return nil
}

// CheckIP determines which cloud provider owns an IP
func (c *IPRangeChecker) CheckIP(ip string) Provider {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, r := range c.awsRanges {
		if r.Contains(parsedIP) {
			return ProviderAWS
		}
	}
	for _, r := range c.gcpRanges {
		if r.Contains(parsedIP) {
			return ProviderGCP
		}
	}
	for _, r := range c.azureRanges {
		if r.Contains(parsedIP) {
			return ProviderAzure
		}
	}
	return ""
}

// Discovery represents a complete cloud discovery session
type Discovery struct {
	ID          string          `json:"id"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	Providers   []Provider      `json:"providers"`
	Filter      *Filter         `json:"filter,omitempty"`
	Resources   []*Resource     `json:"resources"`
	Targets     []string        `json:"targets"`
	Stats       *DiscoveryStats `json:"stats"`
	Error       string          `json:"error,omitempty"`
}

// DiscoveryStats contains discovery statistics
type DiscoveryStats struct {
	TotalResources int              `json:"total_resources"`
	TotalTargets   int              `json:"total_targets"`
	ByProvider     map[Provider]int `json:"by_provider"`
	ByType         map[string]int   `json:"by_type"`
	ByRegion       map[string]int   `json:"by_region"`
	Duration       time.Duration    `json:"duration"`
}

// NewDiscovery creates a new discovery session
func NewDiscovery(id string, providers []Provider, filter *Filter) *Discovery {
	return &Discovery{
		ID:        id,
		StartedAt: time.Now(),
		Providers: providers,
		Filter:    filter,
		Resources: make([]*Resource, 0),
		Targets:   make([]string, 0),
		Stats: &DiscoveryStats{
			ByProvider: make(map[Provider]int),
			ByType:     make(map[string]int),
			ByRegion:   make(map[string]int),
		},
	}
}

// Complete marks the discovery as complete and calculates stats
func (d *Discovery) Complete(resources []*Resource, targets []string) {
	now := time.Now()
	d.CompletedAt = &now
	d.Resources = resources
	d.Targets = targets

	d.Stats.TotalResources = len(resources)
	d.Stats.TotalTargets = len(targets)
	d.Stats.Duration = now.Sub(d.StartedAt)

	for _, r := range resources {
		d.Stats.ByProvider[r.Provider]++
		d.Stats.ByType[r.Type]++
		d.Stats.ByRegion[r.Region]++
	}
}

// Fail marks the discovery as failed
func (d *Discovery) Fail(err error) {
	now := time.Now()
	d.CompletedAt = &now
	d.Error = err.Error()
	d.Stats.Duration = now.Sub(d.StartedAt)
}
